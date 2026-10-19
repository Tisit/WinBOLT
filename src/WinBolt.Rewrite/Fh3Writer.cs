using System.Buffers.Binary;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Rewrite;

/// <summary>
/// Regenerates the <c>__CxxFrameHandler3</c> IP-to-state map of a function whose blocks were reordered
/// (and possibly split into hot and cold parts). FH3 keys its map by absolute RVAs and looks a state
/// up in the whole sorted array, wherever the code piece lies, so the regenerated map is one array over
/// the hot copy and every cold segment. Everything else in the FuncInfo (unwind and try block maps,
/// funclets) is shared with the original: the funclets do not move, and a catch funclet returns a
/// continuation address inside the original body, which stays intact (see the byte-copy notes on
/// <see cref="FunctionRewriter.Fh3UnwindCopy"/>).
/// </summary>
public static class Fh3Writer
{
    /// <summary>
    /// True if <paramref name="f"/>'s FH3 map can be regenerated: a plain or GS-wrapped FH3 handler, the
    /// FuncInfo parsed, one code range, and not a catch funclet (which the runtime identifies by its
    /// original entry address and so cannot move).
    /// </summary>
    public static bool CanLayout(BinaryImage image, Function f) =>
        f.ExceptionHandler is { Kind: ExceptionHandlerKind.CxxFrameHandler3, Name: "__CxxFrameHandler3" or "__CxxFrameHandler" or "__GSHandlerCheck_EH" } &&
        f.CxxEh is { Version: 3, Problem: null } eh && f.Ranges.Count == 1 &&
        !CxxEhParser.Fh3CatchHandlers(image, eh.FuncInfoRva).Contains(f.EntryRva);

    /// <summary>The state of <paramref name="ip"/> under a sorted map: that of the last entry at or below it, else -1.</summary>
    public static int StateAt(IReadOnlyList<(uint Ip, int State)> map, uint ip)
    {
        int state = -1;
        foreach (var (entryIp, entryState) in map)
        {
            if (ip < entryIp)
            {
                break;
            }

            state = entryState;
        }

        return state;
    }

    /// <summary>The original IP-to-state entries of an FH3 FuncInfo.</summary>
    public static List<(uint Ip, int State)> ReadMap(BinaryImage image, uint funcInfoRva)
    {
        var info = image.ReadFrom(funcInfoRva).Span;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(info[20..]);
        var map = image.ReadFrom(BinaryPrimitives.ReadUInt32LittleEndian(info[24..])).Span;
        var entries = new List<(uint, int)>();
        for (int i = 0; i < count; i++)
        {
            entries.Add((BinaryPrimitives.ReadUInt32LittleEndian(map[(8 * i)..]), BinaryPrimitives.ReadInt32LittleEndian(map[(8 * i + 4)..])));
        }

        return entries;
    }

    /// <summary>
    /// The bytes appended to .wbdata for a reordered FH3 function, from <paramref name="baseRva"/>: a copy of
    /// the FuncInfo pointing at a new IP-to-state map, the map, and a copy of the function's UNWIND_INFO
    /// naming the new FuncInfo (header, codes, handler RVA and a GS wrapper's cookie data verbatim).
    /// The map holds, first, the original entries outside the function (its catch funclets' addresses,
    /// which this FuncInfo shares) and then one entry per state change along the new layout: every
    /// instruction (but a dropped <c>jmp</c>) at its new address carries the state it had originally.
    /// Returns the RVA the UNWIND_INFO landed at, for the copied .pdata entry.
    /// </summary>
    public static (byte[] Bytes, uint UnwindRva) Build(BinaryImage image, Function f, IReadOnlyDictionary<uint, uint> addressMap, uint baseRva)
    {
        var entry = image.ExceptionData.First(e => e.BeginAddress == f.EntryRva && !e.IsChained);
        var unwind = image.ReadFrom(entry.UnwindInfoAddress).Span;
        int data = (int)(entry.HandlerDataRva - entry.UnwindInfoAddress);
        uint funcInfoRva = BinaryPrimitives.ReadUInt32LittleEndian(unwind[data..]);
        var funcInfo = image.ReadFrom(funcInfoRva).Span;
        var originalMap = ReadMap(image, funcInfoRva);

        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        var outside = originalMap.Where(e => e.Ip < start || e.Ip >= end).ToList();

        var points = new List<(uint NewRva, int State)>();
        foreach (var block in f.EntryBlocks)
        {
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var instruction = image.Instructions[k];
                uint originalRva = (uint)instruction.IP;
                if (addressMap.TryGetValue(originalRva, out uint newRva) && !Fh4Writer.DroppedJump(instruction, addressMap))
                {
                    points.Add((newRva, StateAt(originalMap, originalRva)));
                }
            }
        }

        var inside = new List<(uint Ip, int State)>();
        int previous = int.MinValue;
        foreach (var (rva, state) in points.OrderBy(p => p.NewRva))
        {
            if (state != previous)
            {
                inside.Add((rva, state));
                previous = state;
            }
        }

        var entries = outside.Concat(inside).ToList();
        uint funcInfoAt = baseRva;
        uint mapAt = funcInfoAt + FunctionRewriter.Fh3FuncInfoSize;
        uint unwindAt = (mapAt + 8 * (uint)entries.Count + 3) & ~3u;

        var bytes = new byte[unwindAt - baseRva + (uint)((data + 4 + 12 + 3) & ~3)];
        funcInfo[..FunctionRewriter.Fh3FuncInfoSize].CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), (uint)entries.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(24), mapAt);
        int position = FunctionRewriter.Fh3FuncInfoSize;
        foreach (var (ip, state) in entries)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position), ip);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(position + 4), state);
            position += 8;
        }

        int unwindOffset = (int)(unwindAt - baseRva);
        unwind[..Math.Min(unwind.Length, data + 4 + 12)].CopyTo(bytes.AsSpan(unwindOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(unwindOffset + data), funcInfoAt);
        return (bytes, unwindAt);
    }
}
