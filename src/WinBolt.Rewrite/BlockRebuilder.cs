using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>A function re-encoded from its CFG: the new bytes (hot part, cold part), and where each original instruction went.</summary>
/// <param name="AddressMap">Original instruction RVA → new RVA, plus the range end → the end of the hot part.</param>
/// <param name="ColdSegments">The cold code of each unwind entry that has any, in cold-code order.</param>
internal sealed record RebuiltCode(byte[] Bytes, byte[] ColdBytes, Dictionary<uint, uint> AddressMap, IReadOnlyList<ColdSegment> ColdSegments)
{
    /// <summary>JCC erratum padding: profiled executions of the NOP instructions it inserted.</summary>
    public double PaddingExecutions { get; init; }

    /// <summary>JCC erratum padding: executions of branches left on a 32-byte boundary (nowhere to pad, or no room).</summary>
    public double UnfixedExecutions { get; init; }

    /// <summary>Indirect calls promoted to a guarded direct call: call site RVA → target RVA (<see cref="BlockRebuilder.Encode"/>).</summary>
    public IReadOnlyDictionary<uint, uint> Promoted { get; init; } = new Dictionary<uint, uint>();
}

/// <summary>Cold code [<paramref name="Start"/>, <paramref name="End"/>) described by the original unwind entry at <paramref name="EntryBegin"/>.</summary>
internal readonly record struct ColdSegment(uint EntryBegin, uint Start, uint End);

/// <summary>
/// Stage 6 groundwork (DesignDoc Stage 6, step 1): re-encode a function from its basic blocks
/// with iced's <see cref="BlockEncoder"/> instead of copying its bytes. Padding and table data
/// between blocks are dropped; branches are re-encoded (short or near as the distance allows);
/// RIP-relative operands keep their absolute targets.
/// <para>
/// One encoder call per function: the encoder links any branch <em>or RIP-relative operand</em>
/// whose target is an instruction in the same call, so encoding several functions together
/// would silently point <c>lea reg,[f]</c> at f's copy and break the one-value rule for function
/// pointers (§6.1). Calls and jumps to other moved functions are pointed at their copies
/// explicitly instead; a function with a RIP-relative operand into its own code is not rebuilt.
/// </para>
/// </summary>
internal static class BlockRebuilder
{
    private const ulong InsertedIp = 0xF000_0000_0000_0000;

    /// <summary>A table displacement large enough to force a 32-bit field in the trial encoding.</summary>
    public const uint PlaceholderTable = 0x7FFF_FFF0;

    /// <summary>Where the trial encoding puts a cold part: far enough that branches to and from it take their long forms.</summary>
    public const uint TrialColdDistance = 0x1000_0000;

    /// <summary>Step between candidate start offsets (mod 32) tried under the JCC erratum option.</summary>
    public const uint ShiftStep = 4;

    /// <summary>
    /// Sizes <paramref name="f"/> by encoding it near its original address. Under the JCC erratum
    /// option the function's start offset modulo 32 decides how much padding its hot loops need and
    /// which branches fall where nothing can be padded (a prologue): the 4-byte step with the fewest
    /// branches left on a boundary is kept, then the fewest executed padding NOPs. Null with
    /// <paramref name="error"/> when the function does not encode; <paramref name="residue"/> is the
    /// chosen start offset past the 32-byte-aligned slot (0 without the option). <paramref name="alignment"/>
    /// is the alignment the copy's slot will have.
    /// </summary>
    public static RebuiltCode? TrialEncode(BinaryImage image, Function f, BlockOrder order, IReadOnlyDictionary<uint, uint> tableFields,
        bool jccErratum, bool alignLoops, uint alignment, out string? error, out uint residue, IReadOnlyDictionary<uint, uint>? promotions = null)
    {
        var noCopies = new Dictionary<uint, uint>();
        uint trialRip = f.EntryRva & ~(alignment - 1);
        var trial = Encode(image, f, order, trialRip, f.EntryRva + TrialColdDistance, noCopies, tableFields, out error, jccErratum, null, alignLoops, null, promotions);
        residue = 0;
        for (uint step = ShiftStep; jccErratum && trial is { PaddingExecutions: > 0 } or { UnfixedExecutions: > 0 } && step < 32; step += ShiftStep)
        {
            var shifted = Encode(image, f, order, trialRip + step, f.EntryRva + TrialColdDistance, noCopies, tableFields, out _, jccErratum, null, alignLoops, null, promotions);
            if (shifted is not null && (shifted.UnfixedExecutions, shifted.PaddingExecutions).CompareTo((trial!.UnfixedExecutions, trial.PaddingExecutions)) < 0 &&
                CheckPrologues(image, f, shifted) is null)
            {
                trial = shifted;
                residue = step;
            }
        }

        return trial;
    }

    /// <summary>Why a function cannot be rebuilt (on top of the copy rules), or null.</summary>
    public static string? Reason(BinaryImage image, Function f)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        var index = ImageIndex.For(image);
        if (index.HasDir64In(start, end))
        {
            return "rebuild: absolute addresses in the code";
        }

        if (f.JumpTables.Any(t => t.Encoding is not (JumpTableEncoding.ImageRelativeOffset32 or JumpTableEncoding.TwoLevelMsvc or JumpTableEncoding.TableRelativeOffset32)))
        {
            return "rebuild: jump table encoding the writer cannot rebuild";
        }

        var starts = Instructions(image, f).Select(i => (uint)i.IP).ToHashSet();
        foreach (var instruction in Instructions(image, f))
        {
            if (instruction.IsIPRelativeMemoryOperand && instruction.IPRelativeMemoryAddress >= start && instruction.IPRelativeMemoryAddress < end)
            {
                return $"rebuild: RIP-relative reference into its own code at 0x{instruction.IP:X}";
            }
        }

        foreach (var entry in index.EntriesBeginningIn(start, end).Where(e => !IsTableEntry(image, f, e)))
        {
            // An entry may end where table data or padding starts: its end then maps to the end of
            // the last instruction before it.
            if (!starts.Contains(entry.BeginAddress) || entry.EndAddress > end || !starts.Any(i => i < entry.EndAddress))
            {
                return $"rebuild: unwind entry [0x{entry.BeginAddress:X}, 0x{entry.EndAddress:X}) does not start on an instruction";
            }

            var info = image.ReadFrom(entry.UnwindInfoAddress & ~1u).Span;
            if (info.Length < 4 || (info[0] & 7) != 1)
            {
                return $"rebuild: unwind info version {(info.Length > 0 ? info[0] & 7 : 0)} at 0x{entry.UnwindInfoAddress:X} (epilogue codes need regenerating)";
            }
        }

        return null;
    }

    /// <summary>The function's instructions in block order (ascending RVA).</summary>
    public static IEnumerable<Instruction> Instructions(BinaryImage image, Function f) =>
        f.EntryBlocks.OrderBy(b => b.StartRva)
            .SelectMany(b => Enumerable.Range(b.InstructionStart, b.InstructionCount))
            .Select(i => image.Instructions[i]);

    /// <summary>
    /// The unwind entries beginning in the function's range, by address (none for a leaf
    /// function), without <see cref="IsTableEntry">table entries</see>.
    /// </summary>
    public static List<ExceptionInfo> Entries(BinaryImage image, Function f)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        return ImageIndex.For(image).EntriesBeginningIn(start, end).Where(e => !IsTableEntry(image, f, e))
            .GroupBy(e => e.BeginAddress).Select(g => g.First()).OrderBy(e => e.BeginAddress).ToList();
    }

    /// <summary>
    /// An unwind entry that describes no code: MSVC gives the switch tables it places after a
    /// function's last instruction a chained entry of their own, with no unwind codes (SQLite's
    /// sqlite3_step, sqlite3_config). Every byte of it is recovered table data or int3 padding, so
    /// no instruction ever runs under it and unwinding never consults it. A rebuilt function drops
    /// it: its tables are rebuilt elsewhere.
    /// </summary>
    public static bool IsTableEntry(BinaryImage image, Function f, ExceptionInfo e)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        if (!e.IsChained || e.BeginAddress <= start || e.EndAddress > end || e.EndAddress <= e.BeginAddress || f.JumpTables.Count == 0)
        {
            return false;
        }

        var info = image.ReadFrom(e.UnwindInfoAddress & ~1u).Span;
        if (info.Length < 4 || info[1] != 0 || info[2] != 0)
        {
            return false;
        }

        var bytes = image.ReadFrom(e.BeginAddress).Span;
        for (uint rva = e.BeginAddress; rva < e.EndAddress; rva++)
        {
            bool table = f.JumpTables.Any(t => (rva >= t.Rva && rva < t.Rva + 4 * (ulong)t.EntryCount) ||
                                               (t.IndexTableRva is { } index && rva >= index && rva < index + (ulong)t.IndexEntryCount));
            if (!table && (rva - e.BeginAddress >= bytes.Length || bytes[(int)(rva - e.BeginAddress)] != 0xCC))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Index into <paramref name="entries"/> of the entry covering <paramref name="rva"/>, or -1.</summary>
    private static int Owner(List<ExceptionInfo> entries, ulong rva) =>
        entries.FindIndex(e => rva >= e.BeginAddress && rva < e.EndAddress);

    /// <summary>
    /// Why the blocks of <paramref name="f"/> cannot be laid out in another order (on top of
    /// <see cref="Reason"/>), or null. Unwind data locates the frame state by address, so every
    /// block must stay inside the entry that describes it: each block lies wholly in one entry
    /// (with entries, all code is covered), and each entry begins a block. Blocks are then laid
    /// out per entry (a segment), starting with the blocks that begin inside the entry's
    /// prologue, in their original order (see <see cref="Encode"/>).
    /// </summary>
    public static string? LayoutReason(BinaryImage image, Function f)
    {
        var entries = Entries(image, f);
        var blockAt = f.EntryBlocks.Select(b => (uint)b.StartRva).ToHashSet();
        if (entries.FirstOrDefault(e => !blockAt.Contains(e.BeginAddress)) is { } inside)
        {
            return $"layout: unwind entry 0x{inside.BeginAddress:X} begins inside a block";
        }

        foreach (var block in f.EntryBlocks)
        {
            int owner = Owner(entries, block.StartRva);
            if (entries.Count > 0 && owner < 0)
            {
                return $"layout: code outside the unwind entries at 0x{block.StartRva:X}";
            }

            var last = image.Instructions[block.InstructionStart + block.InstructionCount - 1];
            if (owner >= 0 && last.NextIP > entries[owner].EndAddress)
            {
                return $"layout: the block at 0x{block.StartRva:X} crosses the end of its unwind entry";
            }

            bool afterCall = block.InstructionCount > 1 && last.Mnemonic is Mnemonic.Nop or Mnemonic.Int3 &&
                             image.Instructions[block.InstructionStart + block.InstructionCount - 2].FlowControl is FlowControl.Call or FlowControl.IndirectCall;
            if (last.FlowControl is FlowControl.Next or FlowControl.ConditionalBranch && !blockAt.Contains((uint)last.NextIP) && !afterCall)
            {
                return $"layout: execution falls out of the block at 0x{last.IP:X} into no block";
            }
        }

        return null;
    }

    /// <summary>
    /// Encodes <paramref name="f"/> in the block order <paramref name="order"/>: its hot blocks at
    /// <paramref name="rip"/>, its cold blocks (if any) at <paramref name="coldRip"/>.
    /// <paramref name="copyOf"/> retargets direct branches and calls to other moved functions'
    /// entries; <paramref name="tableFields"/> gives table loads (by original RVA) their new
    /// 32-bit displacement.
    /// <para>
    /// A block whose fall-through successor is not placed right after it gets a <c>jmp</c> to it,
    /// unless it ends in a conditional branch to the block placed next: that branch is inverted
    /// to target the fall-through successor instead. A block ending in a <c>jmp</c> to the block
    /// placed next drops the <c>jmp</c> (the original address of the <c>jmp</c> then maps to the
    /// target). A call with no fall-through successor (noreturn) gets an <c>int3</c> after it, so
    /// its return address stays inside the function.
    /// </para>
    /// <para>
    /// With <paramref name="alignBranches"/>, executed jumps, calls and returns in the hot part
    /// (with a compare that macro-fuses into them) are moved off 32-byte boundaries by NOP
    /// padding in front of them (<see cref="LayoutStatistics.OnJccBoundary"/>, the JCC
    /// erratum), without growing the hot part past <paramref name="hotLimit"/>.
    /// With <paramref name="alignLoops"/>, hot loop heads start on a 32-byte boundary (one
    /// decoded-ICache window), padded where the loop is entered, not where it iterates.
    /// </para>
    /// </summary>
    /// <param name="pointerTargets">Redirected entries (original → copy): a <c>lea</c> of one yields the copy.</param>
    /// <param name="promotions">
    /// Indirect calls to promote (call site RVA → dominant target RVA): each becomes
    /// <c>lea s,[V]; cmp operand,s; je fast; call operand; jmp after; fast: call T; after:</c>, where V
    /// is the value a pointer to T holds (its copy when redirected), T the target's copy when it
    /// moved and s r11 (r10 if the operand uses r11). An indirect callee is unknown to the
    /// compiler, so the call follows the ABI: r10/r11 and the flags are volatile and carry no
    /// argument, and the direct call sees the same inputs. Sites that <see cref="PromotionScratch"/>
    /// rejects, noreturn calls and targets inside the function are left as they are.
    /// </param>
    public static RebuiltCode? Encode(BinaryImage image, Function f, BlockOrder order, uint rip, uint coldRip,
        IReadOnlyDictionary<uint, uint> copyOf, IReadOnlyDictionary<uint, uint> tableFields, out string? error,
        bool alignBranches = false, long? hotLimit = null, bool alignLoops = false, IReadOnlyDictionary<uint, uint>? pointerTargets = null,
        IReadOnlyDictionary<uint, uint>? promotions = null)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        var blockAt = f.EntryBlocks.ToDictionary(b => (uint)b.StartRva);
        var elided = new Dictionary<uint, uint>(); // dropped jmp → the block it jumped to

        // Branches to code outside the function (tail jumps to another function's copy). iced decides
        // such a branch short or near while it shrinks the encoding, and cannot widen it again when the
        // distance to the fixed target grows because instructions before it shrank: it then fails with
        // "branch distance is too far away". They are emitted as fixed-size near forms and their
        // displacement is filled in once the final addresses are known.
        var externalBranches = new Dictionary<uint, (uint Target, int Length)>();

        Instruction Relocate(Instruction original)
        {
            var instruction = original;
            if (instruction.Op0Kind == OpKind.NearBranch64 && (instruction.NearBranchTarget < start || instruction.NearBranchTarget >= end) &&
                copyOf.TryGetValue((uint)instruction.NearBranchTarget, out uint copy))
            {
                instruction.NearBranch64 = copy;
            }

            if (pointerTargets is not null && instruction.IsIPRelativeMemoryOperand && instruction.Mnemonic == Mnemonic.Lea &&
                pointerTargets.TryGetValue((uint)instruction.IPRelativeMemoryAddress, out uint pointer))
            {
                instruction.MemoryDisplacement64 = pointer;
            }

            bool isTableLoad = tableFields.TryGetValue((uint)instruction.IP, out uint table);
            if (isTableLoad)
            {
                instruction.MemoryDisplacement64 = table;
            }

            if (instruction.Op0Kind == OpKind.NearBranch64 && (instruction.NearBranchTarget < start || instruction.NearBranchTarget >= end) &&
                (instruction.IsJmpShortOrNear || instruction.IsJccShortOrNear))
            {
                byte[] form = instruction.IsJmpShortOrNear
                    ? [0xE9, 0, 0, 0, 0]
                    : [0x0F, (byte)(0x80 + (int)instruction.ConditionCode - 1), 0, 0, 0, 0];
                externalBranches[(uint)original.IP] = ((uint)instruction.NearBranchTarget, form.Length);
                var placeholder = Instruction.CreateDeclareByte(form);
                placeholder.IP = original.IP;
                return placeholder;
            }

            // Only address-dependent instructions are re-encoded. Everything else keeps its exact
            // bytes: the encoder would drop redundant prefixes (MSVC's 2-byte 'push rbx' for
            // hot-patching) and shift the prologue offsets unwind codes rely on.
            if (instruction.Op0Kind != OpKind.NearBranch64 && !instruction.IsIPRelativeMemoryOperand && !isTableLoad)
            {
                var originalBytes = image.ReadFrom((uint)original.IP).Span[..original.Length].ToArray();
                instruction = Instruction.CreateDeclareByte(originalBytes);
                instruction.IP = original.IP;
            }

            return instruction;
        }

        // Inserted instructions get unique IPs above any RVA: the encoder links branches and
        // RIP-relative operands to whatever instruction has their target as IP, and IP 0 would
        // capture 'lea reg,[__ImageBase]'.
        ulong inserted = InsertedIp;
        Instruction Inserted(Instruction instruction)
        {
            instruction.IP = inserted++;
            return instruction;
        }

        // Per emitted hot instruction: the decoded instruction it stands for (Relocate turns most
        // into raw bytes), and its block's profiled executions.
        var hotInfo = new List<(Instruction Original, double Count, BasicBlock Block)>();
        var promoted = new Dictionary<uint, uint>();
        List<Instruction> Emit(IReadOnlyList<BasicBlock> blocks, List<(Instruction, double, BasicBlock)>? info = null)
        {
            var list = new List<Instruction>();
            void Add(Instruction encoded, Instruction original, BasicBlock block)
            {
                list.Add(encoded);
                info?.Add((original, block.ExecutionCount ?? 0, block));
            }

            // A promoted call (see the promotions parameter); after: where the call returns to.
            bool Promote(Instruction call, ulong after, BasicBlock block)
            {
                if (promotions is null || !promotions.TryGetValue((uint)call.IP, out uint target) || (target >= start && target < end) ||
                    PromotionScratch(call) is not { } scratch)
                {
                    return false;
                }

                uint value = pointerTargets is not null && pointerTargets.TryGetValue(target, out uint redirected) ? redirected : target;
                var direct = Inserted(Instruction.CreateBranch(Code.Call_rel32_64, copyOf.TryGetValue(target, out uint copy) ? copy : target));
                var lea = Instruction.Create(Code.Lea_r64_m, scratch, new MemoryOperand(Register.RIP, (long)value));
                lea.IP = call.IP;
                var compare = Inserted(call.Op0Kind == OpKind.Register
                    ? Instruction.Create(Code.Cmp_rm64_r64, call.Op0Register, scratch)
                    : Instruction.Create(Code.Cmp_rm64_r64, MemoryOperandOf(call), scratch));
                var je = Inserted(Instruction.CreateBranch(Code.Je_rel32_64, direct.IP));
                var slow = Inserted(Instruction.CreateDeclareByte(image.ReadFrom((uint)call.IP).Span[..call.Length].ToArray()));
                var slowInfo = call;
                slowInfo.IP = slow.IP;
                var back = Inserted(Instruction.CreateBranch(Code.Jmp_rel32_64, after));
                Add(lea, lea, block);
                Add(compare, compare, block);
                Add(je, je, block);
                Add(slow, slowInfo, block);
                Add(back, back, block);
                Add(direct, direct, block);
                promoted[(uint)call.IP] = target;
                return true;
            }

            for (int n = 0; n < blocks.Count; n++)
            {
                var block = blocks[n];
                var next = n + 1 < blocks.Count ? blocks[n + 1] : null;
                int lastIndex = block.InstructionStart + block.InstructionCount - 1;
                var last = image.Instructions[lastIndex];
                bool fallsThrough = last.FlowControl is FlowControl.Next or FlowControl.Call or FlowControl.IndirectCall or FlowControl.ConditionalBranch;
                var successor = fallsThrough && blockAt.TryGetValue((uint)last.NextIP, out var s) ? s : null;
                bool targetsNext = next is not null && last.Op0Kind == OpKind.NearBranch64 && last.NearBranchTarget == next.StartRva;
                bool elideLast = last.IsJmpShortOrNear && targetsNext && block.InstructionCount > 1;

                for (int k = block.InstructionStart; k < lastIndex; k++)
                {
                    var instruction = image.Instructions[k];
                    ulong after = k + 1 == lastIndex && elideLast ? next!.StartRva : instruction.NextIP;
                    if (!Promote(instruction, after, block))
                    {
                        Add(Relocate(instruction), instruction, block);
                    }
                }

                if (elideLast)
                {
                    elided[(uint)last.IP] = (uint)next!.StartRva;
                    continue;
                }

                if (last.IsJccShortOrNear && targetsNext && successor is not null && successor != next)
                {
                    var inverted = Relocate(last);
                    inverted.NegateConditionCode();
                    inverted.NearBranch64 = successor.StartRva;
                    Add(inverted, inverted, block);
                    continue;
                }

                if (successor is null || !Promote(last, successor.StartRva, block))
                {
                    Add(Relocate(last), last, block);
                }

                if (successor is not null && successor != next)
                {
                    var jump = Inserted(Instruction.CreateBranch(Code.Jmp_rel32_64, successor.StartRva));
                    Add(jump, jump, block);
                }
                else if (successor is null && last.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                {
                    var int3 = Inserted(Instruction.Create(Code.Int3));
                    Add(int3, int3, block);
                }
            }

            return list;
        }

        // Segments: blocks grouped by the unwind entry describing them, in address order. Each
        // segment starts with the blocks that begin inside its prologue, in their original order
        // and hot: unwind codes locate prologue instructions by offset from the entry's start, and
        // a prologue may span blocks (shrink-wrapped saves interleaved with branches and calls).
        // The original order needs no segments (and a function whose blocks cannot move,
        // LayoutReason, only ever gets that); a leaf function is one segment.
        var entries = Entries(image, f);
        var hotBlocks = order.Hot;
        var coldBlocks = order.Cold;
        var coldSegmentStarts = new List<(uint EntryBegin, int Block)>();
        bool originalOrder = order.Cold.Count == 0 && order.Hot.Zip(order.Hot.Skip(1)).All(p => p.First.StartRva < p.Second.StartRva);
        if (entries.Count > 0 && !originalOrder)
        {
            var segmentHot = new List<BasicBlock>();
            var segmentCold = new List<BasicBlock>();
            var byAddress = f.EntryBlocks.OrderBy(b => b.StartRva).ToList();
            foreach (var entry in entries)
            {
                uint prologueEnd = entry.BeginAddress + image.ReadFrom(entry.UnwindInfoAddress & ~1u).Span[1];
                var head = byAddress.Where(b => b.StartRva >= entry.BeginAddress && b.StartRva <= prologueEnd && b.StartRva < entry.EndAddress).ToHashSet();
                bool Mine(BasicBlock b) => !head.Contains(b) && b.StartRva >= entry.BeginAddress && b.StartRva < entry.EndAddress;
                segmentHot.AddRange(byAddress.Where(head.Contains));
                segmentHot.AddRange(order.Hot.Where(Mine));
                if (order.Cold.Any(Mine))
                {
                    coldSegmentStarts.Add((entry.BeginAddress, segmentCold.Count));
                    segmentCold.AddRange(order.Cold.Where(Mine));
                }
            }

            hotBlocks = segmentHot;
            coldBlocks = segmentCold;
        }

        var unpadded = Emit(hotBlocks, hotInfo);
        var cold = Emit(coldBlocks);

        // JCC erratum padding: never before the entry (trampolines and calls land on the copy's
        // first byte) or inside a prologue (unwind codes locate its instructions by offset).
        bool PadAllowed(Instruction instruction) =>
            instruction.IP >= InsertedIp ||
            (instruction.IP != start && !entries.Any(e => instruction.IP >= e.BeginAddress &&
                                                          instruction.IP <= e.BeginAddress + image.ReadFrom(e.UnwindInfoAddress & ~1u).Span[1]));

        // Prefix padding first (as GNU as does): redundant CS segment prefixes, ignored in 64-bit
        // mode, on instructions kept as raw bytes. Not on branches (3E on an indirect branch is
        // CET's notrack), not on instructions with a segment prefix, a lock prefix or a VEX/EVEX/XOP
        // encoding, not in a prologue; at most MaxPrefixes each and 15 bytes in all.
        bool PrefixAllowed(int i, int added)
        {
            var original = hotInfo[i].Original;
            return added < MaxPrefixes && unpadded[i].Code == Code.DeclareByte && original.IP < InsertedIp && PadAllowed(original) &&
                   !LayoutStatistics.IsBranch(original) && original.SegmentPrefix == Register.None && !original.HasLockPrefix &&
                   original.Encoding == EncodingKind.Legacy && original.Length + added < 15;
        }

        // Executions that run into padding placed before hot instruction j: none after an
        // unconditional transfer, otherwise those of the instruction before it.
        double FallsInto(int j) =>
            j == 0 ? double.PositiveInfinity
            : hotInfo[j - 1].Original.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch or FlowControl.Return or FlowControl.Interrupt ? 0
            : hotInfo[j - 1].Count;

        // Hot loop heads: blocks that a block placed at or after them branches back to, with at
        // least 4 iterations per entry on average.
        var loopHeadAt = new HashSet<int>();
        if (alignLoops)
        {
            var layoutIndex = new Dictionary<BasicBlock, int>();
            foreach (var block in hotBlocks)
            {
                layoutIndex.TryAdd(block, layoutIndex.Count);
            }

            for (int i = 0; i < hotInfo.Count; i++)
            {
                var block = hotInfo[i].Block;
                if ((i > 0 && hotInfo[i - 1].Block == block) || (ulong)hotInfo[i].Original.IP != block.StartRva)
                {
                    continue;
                }

                double back = block.Predecessors
                    .Where(e => e.Kind is EdgeKind.Branch or EdgeKind.FallThrough && layoutIndex.TryGetValue(e.Source, out int k) && k >= layoutIndex[block])
                    .Sum(e => (double)(e.ExecutionCount ?? 0));
                if (back > 0 && back >= 4 * Math.Max(1, (block.ExecutionCount ?? 0) - back))
                {
                    loopHeadAt.Add(i);
                }
            }
        }

        var pads = new Dictionary<int, int>(); // index into unpadded → NOP bytes before it
        var prefixes = new Dictionary<int, int>(); // index into unpadded → CS prefixes added to it
        double unfixed = 0; // of the last pass

        // Moves hot instruction 'first' by 'need' bytes, padding after 'earliest' only, where it
        // costs least: a gap no execution falls into (after a jmp, ret or int3), then prefixes,
        // then NOPs where the fewest executions pass. Returns the bytes placed.
        int Place(int first, int earliest, int need)
        {
            int nopAt = -1;
            double nopCost = double.PositiveInfinity;
            for (int j = first; j >= earliest; j--)
            {
                double cost = FallsInto(j);
                if (PadAllowed(hotInfo[j].Original) && cost < nopCost)
                {
                    (nopAt, nopCost) = (j, cost);
                }
            }

            if (nopCost == 0)
            {
                pads[nopAt] = pads.GetValueOrDefault(nopAt) + need;
                return need;
            }

            int remaining = need;
            for (int j = first - 1; j >= earliest && j >= first - 8 && remaining > 0; j--)
            {
                while (remaining > 0 && PrefixAllowed(j, prefixes.GetValueOrDefault(j)))
                {
                    prefixes[j] = prefixes.GetValueOrDefault(j) + 1;
                    remaining--;
                }
            }

            if (remaining > 0 && nopAt >= 0)
            {
                pads[nopAt] = pads.GetValueOrDefault(nopAt) + remaining;
                remaining = 0;
            }

            return need - remaining;
        }
        List<Instruction> hot;
        BytesWriter hotWriter, coldWriter;
        InstructionBlock[] blocks;
        BlockEncoderResult[] results;
        for (int round = 0; ; round++)
        {
            hot = [];
            var position = new int[unpadded.Count];
            for (int i = 0; i < unpadded.Count; i++)
            {
                if (pads.TryGetValue(i, out int pad))
                {
                    hot.AddRange(Nops(pad).Select(Inserted));
                }

                position[i] = hot.Count;
                if (prefixes.TryGetValue(i, out int count))
                {
                    var original = hotInfo[i].Original;
                    var prefixed = Instruction.CreateDeclareByte([.. Enumerable.Repeat((byte)0x2E, count), .. image.ReadFrom((uint)original.IP).Span[..original.Length]]);
                    prefixed.IP = original.IP;
                    hot.Add(prefixed);
                }
                else
                {
                    hot.Add(unpadded[i]);
                }
            }

            hotWriter = new BytesWriter();
            coldWriter = new BytesWriter();
            blocks = cold.Count == 0
                ? [new InstructionBlock(hotWriter, hot, rip)]
                : [new InstructionBlock(hotWriter, hot, rip), new InstructionBlock(coldWriter, cold, coldRip)];
            if (!BlockEncoder.TryEncode(64, blocks, out error, out results, BlockEncoderOptions.ReturnNewInstructionOffsets))
            {
                return null;
            }

            if (!(alignBranches || alignLoops) || round == MaxPadRounds)
            {
                break;
            }

            // One pass in order: each pad shifts everything after it, assuming branch sizes stay;
            // the next round re-encodes and catches what moved anyway. Pads only grow.
            var offsets = results[0].NewInstructionOffsets;
            long length = hotWriter.Length, shift = 0;
            bool changed = false;
            int previousBranch = -1;
            unfixed = 0;
            for (int i = 0; i < unpadded.Count; i++)
            {
                var (original, count, _) = hotInfo[i];
                if (loopHeadAt.Contains(i))
                {
                    // Align the head to 32 bytes; later padding must not move it again.
                    int earliestHere = previousBranch + 1;
                    previousBranch = i - 1;
                    ulong head = rip + offsets[position[i]] + (ulong)shift;
                    int needHead = (int)((32 - head % 32) % 32);
                    if (needHead > 0 && !(hotLimit is { } headLimit && length + shift + needHead > headLimit))
                    {
                        int placedHead = Place(i, earliestHere, needHead);
                        shift += placedHead;
                        changed |= placedHead > 0;
                    }

                    previousBranch = i;
                }

                if (!alignBranches || count <= 0 || !LayoutStatistics.IsBranch(original))
                {
                    continue;
                }

                // Prefixes go on instructions after the previous branch only: moving a branch
                // already checked in this pass could put it back on a boundary.
                int earliest = previousBranch + 1;
                previousBranch = i;
                int first = i > 0 && LayoutStatistics.Fuses(hotInfo[i - 1].Original, original) ? i - 1 : i;
                int p = position[i];
                ulong from = rip + offsets[position[first]] + (ulong)shift;
                ulong to = rip + (p + 1 < hot.Count ? offsets[p + 1] : (uint)length) + (ulong)shift;
                if (!LayoutStatistics.OnJccBoundary(from, to))
                {
                    continue;
                }

                int need = 32 - (int)(from % 32);
                if (hotLimit is { } limit && length + shift + need > limit)
                {
                    unfixed += count;
                    continue;
                }

                // Padding anywhere after the previous branch moves this one.
                int placed = first >= earliest ? Place(first, earliest, need) : 0;
                if (placed < need)
                {
                    unfixed += count; // nowhere to pad (prologue or entry)
                }

                shift += placed;
                changed |= placed > 0;
            }

            if (!changed)
            {
                break;
            }
        }

        var map = new Dictionary<uint, uint>();
        for (int b = 0; b < blocks.Length; b++)
        {
            var list = b == 0 ? hot : cold;
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].IP < InsertedIp && externalBranches.TryGetValue((uint)list[i].IP, out var external))
                {
                    long at = results[b].NewInstructionOffsets[i];
                    long next = (long)results[b].RIP + at + external.Length;
                    (b == 0 ? hotWriter : coldWriter).PatchInt32((int)at + external.Length - 4, (int)(external.Target - next));
                }

                if (list[i].IP < InsertedIp)
                {
                    map[(uint)list[i].IP] = (uint)results[b].RIP + results[b].NewInstructionOffsets[i];
                }
            }
        }

        foreach (var (jump, target) in elided)
        {
            map[jump] = map[target];
        }

        var bytes = hotWriter.ToArray();
        var coldBytes = coldWriter.ToArray();
        map[end] = rip + (uint)bytes.Length;

        // Unwind entries ending at data or padding end where the code after them now starts:
        // the next entry's first block, or the end of the hot code.
        var starts = Instructions(image, f).Select(i => (uint)i.IP).Order().ToArray();
        foreach (var entry in entries.Where(e => !map.ContainsKey(e.EndAddress)))
        {
            int next = Array.BinarySearch(starts, entry.EndAddress);
            next = next >= 0 ? next : ~next;
            map[entry.EndAddress] = next < starts.Length ? map[starts[next]] : rip + (uint)bytes.Length;
        }

        // Each segment's cold blocks run up to the next segment's (or the end of the cold code).
        var coldSegments = new List<ColdSegment>();
        for (int s = 0; s < coldSegmentStarts.Count; s++)
        {
            uint begin = map[(uint)coldBlocks[coldSegmentStarts[s].Block].StartRva];
            uint segmentEnd = s + 1 < coldSegmentStarts.Count ? map[(uint)coldBlocks[coldSegmentStarts[s + 1].Block].StartRva] : coldRip + (uint)coldBytes.Length;
            coldSegments.Add(new ColdSegment(coldSegmentStarts[s].EntryBegin, begin, segmentEnd));
        }

        double paddingExecutions = pads.Sum(p => FallsInto(p.Key) * Nops(p.Value).Count());
        return new RebuiltCode(bytes, coldBytes, map, coldSegments) { PaddingExecutions = paddingExecutions, UnfixedExecutions = unfixed, Promoted = promoted };
    }

    /// <summary>
    /// The scratch register for promoting an indirect call (r11, or r10 when the operand uses
    /// r11), or null when the call cannot be promoted: only <c>call r64</c> and <c>call qword
    /// [base + index*scale + disp]</c> without a segment prefix; RIP-relative calls (imports, CFG
    /// dispatch) have one fixed pointer and are not promoted.
    /// </summary>
    public static Register? PromotionScratch(in Instruction call)
    {
        if (call.Code != Code.Call_rm64 || call.IsIPRelativeMemoryOperand || call.SegmentPrefix != Register.None)
        {
            return null;
        }

        Register[] used = call.Op0Kind == OpKind.Register
            ? [call.Op0Register.GetFullRegister()]
            : [call.MemoryBase.GetFullRegister(), call.MemoryIndex.GetFullRegister()];
        return !used.Contains(Register.R11) ? Register.R11 : !used.Contains(Register.R10) ? Register.R10 : null;
    }

    /// <summary>The memory operand of <paramref name="instruction"/>, to encode in another instruction.</summary>
    private static MemoryOperand MemoryOperandOf(in Instruction instruction)
    {
        long displacement = (long)instruction.MemoryDisplacement64;
        int size = instruction.MemoryBase == Register.None ? 4 : displacement != 0 ? 1 : 0;
        return new MemoryOperand(instruction.MemoryBase, instruction.MemoryIndex, instruction.MemoryIndexScale, displacement, size);
    }

    /// <summary>
    /// Unwind codes locate prologue instructions by byte offset from the entry's start, so every
    /// instruction boundary inside each rebuilt entry's prologue must keep its offset (the bytes
    /// may differ: a RIP-relative load in the prologue re-encodes with a new displacement).
    /// </summary>
    public static string? CheckPrologues(BinaryImage image, Function f, RebuiltCode code)
    {
        uint start = f.EntryRva, end = start + f.EntryRange.Length;
        var boundaries = code.AddressMap.Keys.ToHashSet();
        foreach (var entry in ImageIndex.For(image).EntriesBeginningIn(start, end).Where(e => !IsTableEntry(image, f, e)))
        {
            uint prologue = image.ReadFrom(entry.UnwindInfoAddress & ~1u).Span[1];
            uint begin = entry.BeginAddress, newBegin = code.AddressMap[begin];
            for (uint ip = begin; ip <= begin + prologue; ip++)
            {
                if (boundaries.Contains(ip) && code.AddressMap[ip] - newBegin != ip - begin)
                {
                    return $"rebuild: the prologue at 0x{begin:X} does not keep its instruction offsets (0x{ip:X})";
                }
            }

            if (!boundaries.Contains(begin + prologue))
            {
                return $"rebuild: the prologue at 0x{begin:X} does not end on an instruction";
            }
        }

        return null;
    }

    private const int MaxPadRounds = 8;


    /// <summary>Redundant prefixes added to one instruction at most (GNU as allows 5; more than 3 slows legacy decoding on some cores).</summary>
    private const int MaxPrefixes = 3;

    /// <summary>Intel's recommended multi-byte NOPs, as raw-byte instructions covering <paramref name="length"/> bytes.</summary>
    private static IEnumerable<Instruction> Nops(int length)
    {
        byte[][] forms =
        [
            [0x90],
            [0x66, 0x90],
            [0x0F, 0x1F, 0x00],
            [0x0F, 0x1F, 0x40, 0x00],
            [0x0F, 0x1F, 0x44, 0x00, 0x00],
            [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
            [0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
            [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        while (length > 0)
        {
            int take = Math.Min(length, forms.Length);
            yield return Instruction.CreateDeclareByte(forms[take - 1]);
            length -= take;
        }
    }

    private sealed class BytesWriter : CodeWriter
    {
        private readonly List<byte> _bytes = [];

        public long Length => _bytes.Count;

        public override void WriteByte(byte value) => _bytes.Add(value);

        public byte[] ToArray() => _bytes.ToArray();

        public void PatchInt32(int at, int value) => BinaryPrimitives.WriteInt32LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_bytes).Slice(at, 4), value);
    }
}
