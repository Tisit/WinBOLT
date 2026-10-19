using Iced.Intel;
using WinBolt.Core.Ir;
using WinBolt.Pe;

namespace WinBolt.Rewrite;

/// <summary>Profiled control transfers between blocks of moved functions, and how many fall through.</summary>
/// <param name="Transfers">Executions of branch and fall-through edges with a profile count.</param>
/// <param name="FallThroughBefore">Of those, executions that fell through in the original layout.</param>
/// <param name="FallThroughAfter">Of those, executions that fall through in the output (no taken branch).</param>
public sealed record LayoutStatistics(double Transfers, double FallThroughBefore, double FallThroughAfter)
{
    /// <summary>
    /// JCC erratum (Intel Skylake-family with the 2019 microcode update, e.g. Coffee Lake): a
    /// 32-byte code window holding a jump, call or return that crosses a 32-byte boundary or ends
    /// on one (a macro-fused compare and jcc counted as one) is not cached in the decoded ICache
    /// (DSB); every pass through it is decoded again by the legacy decoders (MITE).
    /// </summary>
    public static bool OnJccBoundary(ulong start, ulong end) => start >> 5 != (end - 1) >> 5 || (end & 31) == 0;

    /// <summary>Jumps, calls and returns: the instructions the JCC erratum is about.</summary>
    public static bool IsBranch(in Instruction instruction) =>
        instruction.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
            or FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return;

    /// <summary>Whether <paramref name="first"/> macro-fuses with the conditional branch after it (Skylake rules, approximately).</summary>
    public static bool Fuses(in Instruction first, in Instruction branch) =>
        branch.FlowControl == FlowControl.ConditionalBranch && first.NextIP == branch.IP &&
        first.Mnemonic is Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Add or Mnemonic.Sub or Mnemonic.And or Mnemonic.Inc or Mnemonic.Dec &&
        !first.IsIPRelativeMemoryOperand &&
        !(first.OpCount == 2 && (first.Op0Kind == OpKind.Memory || first.Op1Kind == OpKind.Memory) && first.Op1Kind is OpKind.Immediate8 or OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate16);

    /// <summary>
    /// Executions of <paramref name="f"/>'s branches that would sit on a 32-byte boundary if its
    /// bytes were moved by <paramref name="shift"/> (only the shift modulo 32 matters).
    /// </summary>
    public static double ExposureAt(BinaryImage image, Function f, long shift)
    {
        double exposed = 0;
        foreach (var block in f.EntryBlocks.Where(b => (b.ExecutionCount ?? 0) > 0))
        {
            Instruction previous = default;
            for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
            {
                var instruction = image.Instructions[k];
                if (IsBranch(instruction))
                {
                    ulong start = k > block.InstructionStart && Fuses(previous, instruction) ? previous.IP : instruction.IP;
                    exposed += OnJccBoundary((ulong)((long)start + shift), (ulong)((long)instruction.NextIP + shift)) ? block.ExecutionCount!.Value : 0;
                }

                previous = instruction;
            }
        }

        return exposed;
    }

    /// <summary>
    /// Executions (block counts) of branches in the hot blocks of the moved functions, and how
    /// many of them sit on a 32-byte boundary (<see cref="OnJccBoundary"/>) in the original and in
    /// the output. A rebuilt function's output is decoded as laid out, inserted jumps included; a
    /// byte copy is the original shifted by a constant.
    /// </summary>
    public static (double Branches, double OnBoundaryBefore, double OnBoundaryAfter, double Instructions, double PaddingNops) JccErratum(BinaryImage original, RewriteResult result)
    {
        var output = PeImageReader.Read(original.FilePath, result.Output);
        double branches = 0, before = 0, after = 0, instructions = 0, padding = 0;
        foreach (var moved in result.Moved)
        {
            var function = original.Functions[moved.FunctionId];
            foreach (var block in function.EntryBlocks.Where(b => (b.ExecutionCount ?? 0) > 0))
            {
                Instruction previous = default;
                for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
                {
                    var instruction = original.Instructions[k];
                    if (IsBranch(instruction))
                    {
                        ulong start = k > block.InstructionStart && Fuses(previous, instruction) ? previous.IP : instruction.IP;
                        branches += block.ExecutionCount!.Value;
                        before += OnJccBoundary(start, instruction.NextIP) ? block.ExecutionCount.Value : 0;
                        if (moved.AddressMap is null)
                        {
                            ulong shift = moved.CopyStart - moved.Start;
                            after += OnJccBoundary(start + shift, instruction.NextIP + shift) ? block.ExecutionCount.Value : 0;
                        }
                    }

                    if (moved.AddressMap is null)
                    {
                        instructions += block.ExecutionCount!.Value;
                    }

                    previous = instruction;
                }
            }

            if (moved.AddressMap is null)
            {
                continue;
            }

            var mapped = moved.AddressMap.Values.ToHashSet();

            // The output as laid out: each instruction weighted by the block it belongs to (an
            // inserted jmp by the block before it).
            var blockAt = function.EntryBlocks.Select(b => (At: moved.Map((uint)b.StartRva), Count: (double)(b.ExecutionCount ?? 0)))
                .GroupBy(b => b.At).Select(g => g.First()).OrderBy(b => b.At).ToArray();
            var starts = blockAt.Select(b => b.At).ToArray();
            foreach (var (from, length) in new[] { (moved.CopyStart, moved.CopyLength), (moved.ColdStart, moved.ColdLength) })
            {
                if (length == 0)
                {
                    continue;
                }

                var decoder = Decoder.Create(64, new ByteArrayCodeReader(output.ReadFrom(from)[..(int)length].ToArray()));
                decoder.IP = from;
                Instruction previous = default;
                bool unreachable = false; // padding after an unconditional transfer, until the next block
                while (decoder.IP < from + length)
                {
                    var instruction = decoder.Decode();
                    bool isPadding = instruction.Mnemonic == Mnemonic.Nop && !mapped.Contains((uint)instruction.IP);
                    unreachable = isPadding && (unreachable || previous.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
                        or FlowControl.Return or FlowControl.Interrupt);
                    int i = Array.BinarySearch(starts, (uint)instruction.IP);
                    double count = unreachable ? 0 : (i >= 0 ? i : ~i - 1) is var b && b >= 0 ? blockAt[b].Count : 0;
                    instructions += count;
                    padding += isPadding ? count : 0;
                    if (count > 0 && IsBranch(instruction))
                    {
                        ulong start = Fuses(previous, instruction) ? previous.IP : instruction.IP;
                        after += OnJccBoundary(start, instruction.NextIP) ? count : 0;
                    }

                    previous = instruction;
                }
            }
        }

        return (branches, before, after, instructions, padding);
    }

    /// <summary>
    /// Measured on the output itself: an edge falls through when its target starts where the
    /// source block's last instruction ends (or that instruction was a dropped jmp to it).
    /// </summary>
    public static LayoutStatistics Measure(BinaryImage original, RewriteResult result)
    {
        var output = PeImageReader.Read(original.FilePath, result.Output);
        double transfers = 0, before = 0, after = 0;
        foreach (var moved in result.Moved.Where(m => m.AddressMap is not null))
        {
            foreach (var block in original.Functions[moved.FunctionId].EntryBlocks)
            {
                var last = original.Instructions[block.InstructionStart + block.InstructionCount - 1];
                uint at = moved.Map((uint)last.IP);
                var bytes = output.ReadFrom(at);
                var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes[..Math.Min(bytes.Length, 15)].ToArray()));
                decoder.IP = at;
                var now = decoder.Decode();
                uint continuesAt = (uint)now.NextIP;
                for (var padding = Decode(output, continuesAt); padding is { Mnemonic: Mnemonic.Nop } nop; padding = Decode(output, continuesAt))
                {
                    continuesAt += (uint)nop.Length;
                }

                foreach (var edge in block.Successors.Where(e => e.Kind is EdgeKind.FallThrough or EdgeKind.Branch && (e.ExecutionCount ?? 0) > 0))
                {
                    double count = edge.ExecutionCount!.Value;
                    uint target = moved.Place((uint)edge.Target.StartRva);
                    bool elided = last.IsJmpShortOrNear && at == target;
                    bool fallsThrough = elided || (now.FlowControl != FlowControl.UnconditionalBranch && continuesAt == target);
                    transfers += count;
                    before += edge.Kind == EdgeKind.FallThrough ? count : 0;
                    after += fallsThrough ? count : 0;
                }
            }
        }

        return new LayoutStatistics(transfers, before, after);
    }

    private static Instruction? Decode(BinaryImage image, uint rva)
    {
        var bytes = image.ReadFrom(rva);
        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes[..Math.Min(bytes.Length, 15)].ToArray()));
        decoder.IP = rva;
        var instruction = decoder.Decode();
        return instruction.IsInvalid ? null : instruction;
    }
}
