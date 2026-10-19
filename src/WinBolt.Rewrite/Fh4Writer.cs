using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Rewrite;

/// <summary>
/// Regenerates the <c>__CxxFrameHandler4</c> tables of a function whose blocks were reordered
/// (DesignDoc Stage 6). FH4 keys its IP-to-state map by offsets from the frame's function start,
/// so a reordered function needs a new map; the unwind map (destructor and unwind-funclet RVAs)
/// is unchanged, since those funclets do not move. Only unwind-only functions are handled here:
/// no try blocks, not separated, not a catch funclet, no BBT flags (<see cref="CanLayout"/>).
/// </summary>
public static class Fh4Writer
{
    /// <summary>
    /// True if <paramref name="f"/>'s FH4 tables can be regenerated for a reordered layout: the
    /// FuncInfo4 parsed, it is a plain unwind-only function, and its header carries no BBT flags.
    /// </summary>
    public static bool CanLayout(BinaryImage image, Function f)
    {
        // A plain __CxxFrameHandler4 (handler data = the FuncInfo4 RVA) or its GS wrapper
        // __GSHandlerCheck_EH4 (the FuncInfo4 RVA then stack-cookie data, preserved in UnwindCopy).
        if (f.ExceptionHandler is not { Kind: ExceptionHandlerKind.CxxFrameHandler4, Name: "__CxxFrameHandler4" or "__GSHandlerCheck_EH4" } ||
            f.CxxEh is not { Version: 4, Problem: null } eh || eh.IsSeparated || eh.IsCatch || eh.HasTryBlocks || f.Ranges.Count != 1)
        {
            return false;
        }

        var layout = CxxEhParser.ReadFh4Layout(image, eh.FuncInfoRva, f.EntryRva);
        return layout is { Segments.Count: 1 } && (layout.Header & Fh4Layout.BbtFlag) == 0 &&
               (layout.Header & (Fh4Layout.IsCatchFlag | Fh4Layout.IsSeparatedFlag | Fh4Layout.TryBlockMapFlag)) == 0;
    }

    /// <summary>
    /// The regenerated .wbdata for a reordered FH4 function: an IP-to-state map per code piece (the
    /// hot copy at <paramref name="copyStart"/>, and each cold segment), the FuncInfo4 that points at
    /// them (and at the original, unmoved unwind map), and a copy of the function's UNWIND_INFO whose
    /// handler data names the new FuncInfo4. When the function is split, the FuncInfo4 is marked
    /// separated and holds a (segment start, map) pair per piece: the CRT keys a separated function's
    /// map by the code piece's own start (<c>FunctionEntry->BeginAddress</c>), so each piece's map is
    /// delta-encoded from its own start. All bytes lie from <paramref name="baseRva"/>; the returned
    /// RVA is where the UNWIND_INFO landed, for the copied .pdata entry.
    /// </summary>
    public static (byte[] Bytes, uint UnwindRva) Build(BinaryImage image, Function f, IReadOnlyDictionary<uint, uint> addressMap, uint copyStart,
        IReadOnlyList<(uint Start, uint End)> coldSegments, uint baseRva)
    {
        var eh = f.CxxEh!;
        var layout = CxxEhParser.ReadFh4Layout(image, eh.FuncInfoRva, f.EntryRva)!;
        var originalMap = layout.Segments[0].Map;

        // Every instruction's original state at its new address, minus dropped jmps (no bytes).
        var points = new List<(uint NewRva, int State)>();
        foreach (var block in f.EntryBlocks)
        {
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var instruction = image.Instructions[k];
                uint originalRva = (uint)instruction.IP;
                if (addressMap.TryGetValue(originalRva, out uint newRva) && !DroppedJump(instruction, addressMap))
                {
                    points.Add((newRva, Fh4Layout.StateAt(originalMap, originalRva)));
                }
            }
        }

        var pieceStarts = new List<uint> { copyStart };
        pieceStarts.AddRange(coldSegments.Select(s => s.Start));
        pieceStarts.Sort();
        uint PieceOf(uint rva) => pieceStarts.Last(s => s <= rva);

        var bytes = new List<byte>();
        var mapRvaOf = new Dictionary<uint, uint>();
        foreach (uint start in pieceStarts)
        {
            mapRvaOf[start] = baseRva + (uint)bytes.Count;
            bytes.AddRange(StateMap(points.Where(p => PieceOf(p.NewRva) == start), start));
        }

        bool separated = pieceStarts.Count > 1;
        uint ipMapRva;
        if (separated)
        {
            ipMapRva = baseRva + (uint)bytes.Count;
            AppendUnsigned(bytes, (uint)pieceStarts.Count);
            foreach (uint start in pieceStarts)
            {
                AppendInt(bytes, start);
                AppendInt(bytes, mapRvaOf[start]);
            }
        }
        else
        {
            ipMapRva = mapRvaOf[copyStart];
        }

        uint funcInfoRva = baseRva + (uint)bytes.Count;
        bytes.Add((byte)(separated ? layout.Header | Fh4Layout.IsSeparatedFlag : layout.Header));
        if ((layout.Header & Fh4Layout.UnwindMapFlag) != 0)
        {
            AppendInt(bytes, layout.UnwindMapRva);
        }

        AppendInt(bytes, ipMapRva);

        while (bytes.Count % 4 != 0)
        {
            bytes.Add(0);
        }

        uint unwindRva = baseRva + (uint)bytes.Count;
        bytes.AddRange(UnwindCopy(image, f, funcInfoRva));
        return (bytes.ToArray(), unwindRva);
    }

    /// <summary>
    /// One IP-to-state map: the points (new RVA, state) of one code piece, delta-encoded from
    /// <paramref name="start"/> in ascending RVA, one entry per state transition.
    /// </summary>
    private static byte[] StateMap(IEnumerable<(uint NewRva, int State)> points, uint start)
    {
        var entries = new List<(uint Rva, int State)>();
        int previous = -1;
        foreach (var (rva, state) in points.OrderBy(p => p.NewRva))
        {
            if (state != previous)
            {
                entries.Add((rva, state));
                previous = state;
            }
        }

        var bytes = new List<byte>();
        AppendUnsigned(bytes, (uint)entries.Count);
        uint ip = start;
        foreach (var (rva, state) in entries)
        {
            AppendUnsigned(bytes, rva - ip);
            AppendUnsigned(bytes, (uint)(state + 1));
            ip = rva;
        }

        return bytes.ToArray();
    }

    /// <summary>
    /// A copy of the function's UNWIND_INFO: header, unwind codes and the handler RVA verbatim (the
    /// prologue is preserved, so the codes still describe it), the new FuncInfo4 RVA in place of the
    /// original, then any trailing handler data. A plain <c>__CxxFrameHandler4</c> has none;
    /// <c>__GSHandlerCheck_EH4</c> appends stack-cookie data (frame-relative, so position-independent),
    /// which the GS handler reads at a fixed offset after the FuncInfo4 RVA and which is copied verbatim.
    /// </summary>
    private static byte[] UnwindCopy(BinaryImage image, Function f, uint funcInfoRva)
    {
        var entry = image.ExceptionData.First(e => e.BeginAddress == f.EntryRva && !e.IsChained);
        var original = image.ReadFrom(entry.UnwindInfoAddress).Span;
        int trailer = FunctionRewriter.UnwindTrailerOffset(original);
        var bytes = new List<byte>(original[..(trailer + 4)].ToArray()); // header, codes, handler RVA
        AppendInt(bytes, funcInfoRva);

        // GS cookie data (at most 8 bytes) follows the FuncInfo4 RVA for a GS wrapper; the handler
        // reads a fixed layout there, so copying a few trailing bytes verbatim (clamped) is safe.
        if (f.ExceptionHandler!.Name == "__GSHandlerCheck_EH4")
        {
            int gs = Math.Min(8, original.Length - (trailer + 8));
            if (gs > 0)
            {
                bytes.AddRange(original.Slice(trailer + 8, gs).ToArray());
            }
        }

        return bytes.ToArray();
    }

    /// <summary>
    /// A block-terminating <c>jmp</c> the layout dropped because its target is placed right after it:
    /// it occupies no bytes in the output (its original IP maps to the target's address), so it is
    /// no control-PC location and carries no EH state of its own.
    /// </summary>
    public static bool DroppedJump(in Instruction instruction, IReadOnlyDictionary<uint, uint> addressMap)
    {
        if (!instruction.IsJmpShortOrNear)
        {
            return false;
        }

        uint ip = (uint)instruction.IP, target = (uint)instruction.NearBranchTarget;
        return ip != target && addressMap.TryGetValue(ip, out uint a) && addressMap.TryGetValue(target, out uint b) && a == b;
    }

    private static void AppendInt(List<byte> bytes, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    /// <summary>
    /// FH4's compressed unsigned encoding: the low bits of the first byte give the byte count
    /// (1: xxxxxxx0, 2: xxxxxx01, 3: xxxxx011, 4: xxxx0111, 5: xxxx1111 with the value in 4 raw
    /// bytes). For 1-4 bytes the value is shifted left by the count and the marker fills the low bits.
    /// </summary>
    internal static void AppendUnsigned(List<byte> bytes, uint value)
    {
        if (value < 1u << 7)
        {
            bytes.Add((byte)(value << 1));
        }
        else if (value < 1u << 14)
        {
            AppendShifted(bytes, value << 2 | 0b01, 2);
        }
        else if (value < 1u << 21)
        {
            AppendShifted(bytes, value << 3 | 0b011, 3);
        }
        else if (value < 1u << 28)
        {
            AppendShifted(bytes, value << 4 | 0b0111, 4);
        }
        else
        {
            bytes.Add(0x0F);
            AppendInt(bytes, value);
        }
    }

    private static void AppendShifted(List<byte> bytes, uint encoded, int length)
    {
        for (int i = 0; i < length; i++)
        {
            bytes.Add((byte)(encoded >> (8 * i)));
        }
    }
}
