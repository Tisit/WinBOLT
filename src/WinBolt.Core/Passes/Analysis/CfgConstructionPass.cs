using System.Buffers.Binary;
using Iced.Intel;
using WinBolt.Core.Arch;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// CFG reconstruction. For each discovered function:
/// <list type="number">
/// <item>Recursive-descent disassembly from the entry and from each range start, following
/// direct branches that stay inside the function's ranges. Code is never swept linearly: a
/// range may hold data (jump tables), and only reached bytes count as instructions.</item>
/// <item>Instructions are cut into basic blocks at branch targets and after block-ending
/// instructions, stored contiguously in the flat <see cref="InstructionStore"/> (§5.3), and
/// linked with fall-through and branch edges. Calls do not end a block.</item>
/// <item>Calls and branches leaving the function become <see cref="CallSite"/>s.</item>
/// </list>
/// <para>
/// A register-indirect <c>jmp</c> is resolved through MSVC jump table recovery
/// (<see cref="JumpTableRecovery"/>): the table's targets become roots with
/// <see cref="EdgeKind.IndirectBranch"/> edges, and its bytes count as the function's data.
/// A table is accepted only if no branch target lands inside the instruction sequence its
/// proof walked, since the proof follows the fall-through path only.
/// </para>
/// <para>
/// An indirect <c>jmp</c> no table explains is an indirect tail call only when it provably
/// cannot land inside its own function: no address inside the function exists as a value. Such
/// an address can only come from a <c>lea</c> into the function (a <see cref="CodePointer"/>;
/// its entry counts only when the lea is in the function itself), a relocated absolute pointer
/// into it, or an image-relative table, which needs the function to load <c>__ImageBase</c>. With
/// none of those, the jump leaves the function. A function that is one block also qualifies:
/// its only internal target would be itself. So does, per site, a REX.W indirect jmp that ends
/// an epilogue (<see cref="EndsEpilogue"/>). Otherwise the function is frozen.
/// </para>
/// <para>
/// Downgrades (§5.5), with reason codes: <c>indirect-branch</c> (a register-indirect jmp no
/// table explains), <c>undecodable</c>, <c>falls-off-range</c>, <c>falls-into-data</c>
/// (execution runs into a recovered jump table other than after a noreturn call), <c>overlapping-instructions</c>,
/// <c>uncovered-bytes</c> (non-padding bytes of the ranges disassembly never reached),
/// <c>branches-into-invalid-chain</c> (§5.5), and <c>scope-table</c> (an SEH scope table that
/// does not fit the function).
/// </para>
/// <para>
/// <c>lea reg,[rip+X]</c> into code is recorded as a <see cref="CodePointer"/> when recursive
/// descent reaches it. A pre-scan of every function first collects such targets, so a target
/// inside a function becomes one of that function's roots: code whose address escapes is
/// reachable even if no branch leads to it. A target that is a function entry marks that
/// function address-taken (<see cref="DiscoverySource.CodePointer"/>).
/// </para>
/// <para>
/// Each function also gets its exception handler attached. A validated SEH scope table's
/// <c>__except</c> targets become extra roots: they are reached only through the table.
/// </para>
/// </summary>
[RegisterPass(DependsOn = [FunctionDiscoveryPass.PassName])]
public sealed class CfgConstructionPass : IAnalysisPass
{
    public const string PassName = "CfgConstruction";

    public string Name => PassName;

    public void Run(BinaryImage image, PassContext context)
    {
        var entryToId = new Dictionary<uint, int>(image.Functions.Count);
        foreach (var function in image.Functions)
        {
            entryToId.TryAdd(function.EntryRva, function.Id);
        }

        var invalidFragments = image.UnclaimedCode
            .Where(u => u.Kind == UnclaimedKind.InvalidChainFragment)
            .OrderBy(u => u.Rva)
            .ToArray();

        var handlerByEntry = new Dictionary<uint, uint>();
        foreach (var entry in image.ExceptionData)
        {
            if (!entry.IsChained && entry.HasHandler)
            {
                handlerByEntry[entry.BeginAddress] = entry.HandlerRva;
            }
        }

        // An unwind entry's start begins a block: the frame state changes there, so a layout
        // must be able to keep the code on each side under its own entry.
        var unwindStarts = image.ExceptionData.Select(e => e.BeginAddress).ToHashSet();
        var ranges = new RangeIndex(image.Functions);
        var extraRoots = PreScanCodePointers(image, context.Architecture, ranges, out var dataReferences);
        var unresolved = new List<(Function Function, Builder Builder)>();

        foreach (var function in image.Functions)
        {
            if (handlerByEntry.TryGetValue(function.EntryRva, out uint handlerRva))
            {
                function.ExceptionHandler = image.ExceptionHandlers.GetValueOrDefault(handlerRva)
                    ?? new ExceptionHandlerInfo(handlerRva, ExceptionHandlerKind.Unknown, null, "not identified");
            }

            var roots = extraRoots.GetValueOrDefault(function.Id) ?? [];
            var builder = new Builder(image, context.Architecture, function, entryToId, invalidFragments, ranges, roots, unwindStarts, dataReferences);
            builder.Build();
            if (builder.UnresolvedJumps.Count > 0)
            {
                unresolved.Add((function, builder));
            }
        }

        foreach (var pointer in image.CodePointers)
        {
            if (pointer is { IsEntry: true, TargetFunctionId: { } target })
            {
                image.Functions[target].DiscoveredBy |= DiscoverySource.CodePointer;
            }
        }

        ResolveUnexplainedJumps(image, ranges, unresolved);
        RelabelTableData(image);
    }

    /// <summary>The tail-call rule (see the class summary); needs every function's code pointers.</summary>
    private static void ResolveUnexplainedJumps(BinaryImage image, RangeIndex ranges, List<(Function Function, Builder Builder)> unresolved)
    {
        if (unresolved.Count == 0)
        {
            return;
        }

        var escaped = new HashSet<int>();
        foreach (var pointer in image.CodePointers)
        {
            if (pointer.TargetFunctionId is { } target && (!pointer.IsEntry || pointer.FunctionId == target))
            {
                escaped.Add(target);
            }
        }

        foreach (var relocation in image.Relocations)
        {
            if (relocation.Type != RelocationType.Dir64 || image.ReadFrom(relocation.Rva).Span is not { Length: >= 8 } site)
            {
                continue;
            }

            ulong va = BinaryPrimitives.ReadUInt64LittleEndian(site);
            if (va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage &&
                ranges.Find((uint)(va - image.ImageBase)) is { } owner &&
                image.Functions[owner].EntryRva != (uint)(va - image.ImageBase))
            {
                escaped.Add(owner);
            }
        }

        foreach (var (function, builder) in unresolved)
        {
            bool cannotLandInside = function.BasicBlocks.Count == 1 || (!escaped.Contains(function.Id) && !builder.LoadsImageBase);
            foreach (var (site, failure) in builder.UnresolvedJumps)
            {
                if (cannotLandInside || EndsEpilogue(image, function, site))
                {
                    image.CallSites.Add(new CallSite(function.Id, site, CallKind.IndirectTailJump, null, null));
                }
                else
                {
                    function.Downgrade(Transformability.Frozen, $"indirect-branch: unresolved jmp at 0x{site:X}: {failure}");
                }
            }
        }
    }

    /// <summary>
    /// An indirect jmp that ends an epilogue is a tail call. The x64 ABI marks it: the unwinder
    /// recognizes an epilogue (<c>add rsp,N</c> or <c>lea rsp,[..]</c>, then pops) only when it
    /// ends in <c>ret</c>, a direct jmp, or an indirect jmp with a REX.W prefix (<c>48 FF /4</c>);
    /// MSVC and LLVM emit that prefix for epilogue tail calls and never for switch dispatch. Past
    /// the epilogue the frame is gone, so the target cannot be a block of this function (only its
    /// entry, which is a call like any other). Needs the frame teardown in the jmp's own block.
    /// </summary>
    public static bool EndsEpilogue(BinaryImage image, Function function, uint site)
    {
        if (image.ReadFrom(site).Span is not { Length: >= 3 } bytes || (bytes[0] & 0xF8) != 0x48 || bytes[1] != 0xFF || ((bytes[2] >> 3) & 7) != 4)
        {
            return false;
        }

        var block = function.BasicBlocks.FirstOrDefault(b => site >= b.StartRva && site < b.StartRva + b.Length);
        if (block is null)
        {
            return false;
        }

        var instructions = image.Instructions.Slice(block.InstructionStart, block.InstructionCount);
        int at = instructions.Length - 1;
        while (at >= 0 && instructions[at].IP != site)
        {
            at--;
        }

        int teardown = 0;
        int i = at - 1;
        while (i >= 0 && instructions[i].Mnemonic == Mnemonic.Pop && instructions[i].Op0Kind == OpKind.Register && instructions[i].Op0Register.IsGPR64())
        {
            teardown++;
            i--;
        }

        if (i >= 0 && instructions[i].Op0Kind == OpKind.Register && instructions[i].Op0Register == Register.RSP &&
            (instructions[i].Mnemonic == Mnemonic.Add && instructions[i].Op1Kind is OpKind.Immediate8to64 or OpKind.Immediate32to64 ||
             instructions[i].Mnemonic == Mnemonic.Lea))
        {
            teardown++;
        }

        return at >= 0 && teardown > 0;
    }

    /// <summary>
    /// Jump tables MSVC places after a function's last instruction lie outside every function,
    /// so discovery reported them as unattributed code. Once recovered, they are known data.
    /// </summary>
    private static void RelabelTableData(BinaryImage image)
    {
        var extents = image.Functions.SelectMany(f => f.JumpTables).SelectMany(t =>
                t.IndexTableRva is { } index
                    ? new[] { ((uint)t.Rva, (uint)t.Rva + (uint)t.EntryCount * 4), ((uint)index, (uint)index + (uint)t.IndexEntryCount) }
                    : new[] { ((uint)t.Rva, (uint)t.Rva + (uint)t.EntryCount * 4) })
            .OrderBy(e => e.Item1)
            .ToList();
        if (extents.Count == 0)
        {
            return;
        }

        var relabelled = new List<UnclaimedRange>();
        foreach (var range in image.UnclaimedCode)
        {
            if (range.Kind != UnclaimedKind.Unattributed)
            {
                relabelled.Add(range);
                continue;
            }

            uint cursor = range.Rva, end = range.Rva + range.Length;
            foreach (var (start, stop) in extents)
            {
                if (stop <= cursor || start >= end)
                {
                    continue;
                }

                if (start > cursor)
                {
                    relabelled.Add(range with { Rva = cursor, Length = start - cursor });
                }

                uint dataEnd = Math.Min(stop, end);
                relabelled.Add(new UnclaimedRange(Math.Max(cursor, start), dataEnd - Math.Max(cursor, start), UnclaimedKind.KnownData));
                cursor = dataEnd;
            }

            if (cursor < end)
            {
                relabelled.Add(range with { Rva = cursor, Length = end - cursor });
            }
        }

        image.UnclaimedCode.Clear();
        image.UnclaimedCode.AddRange(relabelled);
    }

    /// <summary>
    /// Linear scan of every function's ranges for <c>lea [rip+X]</c> landing inside another
    /// (or the same) function, not at its entry. Only a hint: CFG construction confirms the lea
    /// by reaching it. A false hint from data costs at worst a spurious root, which then fails
    /// to decode and freezes that function; it never marks anything address-taken.
    /// </summary>
    private static Dictionary<int, List<uint>> PreScanCodePointers(BinaryImage image, IArchitecture architecture, RangeIndex ranges, out uint[] dataReferences)
    {
        var roots = new Dictionary<int, List<uint>>();
        var data = new HashSet<uint>();
        foreach (var function in image.Functions)
        {
            foreach (var range in function.Ranges)
            {
                var code = image.ReadFrom((uint)range.StartRva);
                int length = (int)Math.Min(code.Length, range.Length);
                if (length <= 0)
                {
                    continue;
                }

                var decoder = architecture.CreateDecoder(code[..length], range.StartRva);
                while (decoder.TryDecodeNext(out var instruction) && !instruction.IsInvalid)
                {
                    if (instruction.IsIPRelativeMemoryOperand && ranges.Find((uint)instruction.IPRelativeMemoryAddress) is null)
                    {
                        data.Add((uint)instruction.IPRelativeMemoryAddress);
                    }

                    if (FunctionDiscoveryPass.CodePointerTarget(instruction) is { } target &&
                        ranges.Find(target) is { } owner &&
                        image.Functions[owner].EntryRva != target)
                    {
                        (roots.TryGetValue(owner, out var list) ? list : roots[owner] = []).Add(target);
                    }
                }
            }
        }

        dataReferences = data.Order().ToArray();
        return roots;
    }

    /// <summary>Sorted function ranges for "which function contains this RVA".</summary>
    private sealed class RangeIndex
    {
        private readonly uint[] _starts;
        private readonly uint[] _ends;
        private readonly int[] _owners;

        public RangeIndex(List<Function> functions)
        {
            var spans = functions
                .SelectMany(f => f.Ranges.Select(r => (Start: (uint)r.StartRva, End: (uint)r.StartRva + r.Length, f.Id)))
                .OrderBy(s => s.Start)
                .ToArray();
            _starts = spans.Select(s => s.Start).ToArray();
            _ends = spans.Select(s => s.End).ToArray();
            _owners = spans.Select(s => s.Id).ToArray();
        }

        public int? Find(uint rva)
        {
            int i = Array.BinarySearch(_starts, rva);
            if (i < 0)
            {
                i = ~i - 1;
            }

            return i >= 0 && rva < _ends[i] ? _owners[i] : null;
        }
    }

    /// <summary>ret, jmp, register/memory-indirect jmp, ud2, and int 29h (__fastfail) end a path.</summary>
    internal static bool IsTerminator(in Instruction instruction) => instruction.FlowControl switch
    {
        FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch => true,
        FlowControl.Exception => instruction.Mnemonic == Mnemonic.Ud2,
        FlowControl.Interrupt => instruction.Mnemonic == Mnemonic.Int && instruction.Immediate8 == 0x29,
        _ => false,
    };

    private static bool EndsBlock(in Instruction instruction) =>
        IsTerminator(instruction) || instruction.FlowControl == FlowControl.ConditionalBranch;

    private sealed class Builder(
        BinaryImage image,
        IArchitecture architecture,
        Function function,
        Dictionary<uint, int> entryToId,
        UnclaimedRange[] invalidFragments,
        RangeIndex ranges,
        List<uint> extraRoots,
        HashSet<uint> unwindStarts,
        uint[] dataReferences) : IControlFlow
    {
        private const int MaxTableRounds = 50;

        private readonly Dictionary<uint, Instruction> _decoded = [];
        private readonly HashSet<uint> _leaders = [];
        private readonly Stack<uint> _work = new();
        private readonly Dictionary<uint, uint> _endsAt = [];
        private readonly List<uint> _indirectJumps = [];
        private readonly Dictionary<uint, JumpTable> _tables = [];
        private readonly Dictionary<uint, string> _tableFailures = [];

        // Backward flow for the table proof: direct branches per target, roots control can reach
        // from outside the graph, and addresses enqueued as some table's targets.
        private readonly Dictionary<uint, List<uint>> _branchesTo = [];
        private readonly HashSet<uint> _roots = [];
        private readonly HashSet<uint> _tableTargets = [];

        /// <summary>Tables proven once and refuted on a later, larger graph; never retried (keeps the loop monotone).</summary>
        private readonly Dictionary<uint, string> _refuted = [];

        // Results are buffered and committed once: a second exploration (see Build) must not
        // leave the first one's call sites, code pointers or downgrades behind.
        private readonly List<CallSite> _callSites = [];
        private readonly List<CodePointer> _codePointers = [];
        private readonly List<string> _downgrades = [];

        /// <summary>Where a decode run met an invalid instruction: possibly the first byte of a table.</summary>
        private readonly List<uint> _invalidAt = [];

        /// <summary>Recovered table extents that decoding must not run into (second exploration only).</summary>
        private List<(uint Start, uint End)> _barriers = [];

        /// <summary>Indirect jumps no table explains, with the reason; decided by the pass once all functions exist.</summary>
        public List<(uint Site, string Failure)> UnresolvedJumps { get; } = [];

        /// <summary>The function materializes <c>__ImageBase</c> (lea reg,[rip → 0]), the prerequisite of an image-relative table.</summary>
        public bool LoadsImageBase { get; private set; }

        public void Build()
        {
            Explore();

            // MSVC may place a jump table inside the function's range, right after a call to a
            // noreturn function, and the first exploration decodes straight through into it (or
            // stops at its first byte, when that byte does not decode). Now that the tables are
            // known, explore again with them as data barriers.
            var extents = TableExtents().ToList();
            if (_decoded.Values.Any(i => extents.Any(e => i.IP < e.End && i.NextIP > e.Start)) ||
                _invalidAt.Any(a => extents.Any(e => a >= e.Start && a < e.End)))
            {
                Reset();
                _barriers = extents;
                Explore();
            }

            var addresses = _decoded.Keys.ToArray();
            Array.Sort(addresses);
            CheckOverlaps(addresses);
            BuildBlocks(addresses);
            UnresolvedJumps.AddRange(_tableFailures.Select(kv => (kv.Key, kv.Value)));
            LinkEdges();
            CheckCoverage(addresses);
            Commit();
        }

        private void Reset()
        {
            _decoded.Clear();
            _leaders.Clear();
            _work.Clear();
            _endsAt.Clear();
            _indirectJumps.Clear();
            _tables.Clear();
            _tableFailures.Clear();
            _branchesTo.Clear();
            _roots.Clear();
            _tableTargets.Clear();
            _callSites.Clear();
            _codePointers.Clear();
            _downgrades.Clear();
            _invalidAt.Clear();
            LoadsImageBase = false;
        }

        private void Commit()
        {
            image.CallSites.AddRange(_callSites);
            image.CodePointers.AddRange(_codePointers);
            function.JumpTables.AddRange(_tables.Values);
            foreach (string reason in _downgrades)
            {
                function.Downgrade(Transformability.Frozen, reason);
            }
        }

        /// <summary>
        /// The first non-code address above <paramref name="address"/> that any function's code
        /// addresses RIP-relatively (pre-scanned linearly, so it does not wait for blocks to be
        /// decoded): where the next data object starts (another switch's table, typically), which
        /// bounds a table whose extent has to be read off the data.
        /// </summary>
        private uint? NextDataReference(uint address)
        {
            int at = Array.BinarySearch(dataReferences, address);
            at = at >= 0 ? at + 1 : ~at;
            return at < dataReferences.Length ? dataReferences[at] : null;
        }

        private void Explore()
        {
            foreach (var range in function.Ranges)
            {
                EnqueueRoot((uint)range.StartRva);
            }

            AttachScopeTable();
            AttachCxxEh();
            foreach (uint root in extraRoots)
            {
                EnqueueRoot(root);
            }

            Drain();

            // Recovered tables add code, which can expose more indirect jumps and more paths into
            // a dispatch. Every round re-proves every table on the graph as it now stands: a
            // failed proof can succeed once more of the preceding code is decoded, and an accepted
            // one can be refuted by a case block that branches back into its dispatch sequence.
            // Refuted tables are not retried, so the loop only grows the code and shrinks the
            // candidates, and ends with every table proven on the final graph.
            for (int round = 0; round < MaxTableRounds; round++)
            {
                bool progress = false;
                foreach (uint site in _indirectJumps.Where(s => !_refuted.ContainsKey(s)).ToList())
                {
                    var result = JumpTableRecovery.TryRecover(image, _decoded[site], this, rva => RangeEnd(rva) is not null, NextDataReference);
                    if (result.Table is not { } table)
                    {
                        if (_tables.Remove(site))
                        {
                            _refuted[site] = result.Failure!;
                            progress = true;
                        }

                        _tableFailures[site] = result.Failure!;
                        continue;
                    }

                    _tableFailures.Remove(site);
                    if (_tables.TryGetValue(site, out var previous) && previous.TargetRvas.SequenceEqual(table.TargetRvas) && previous.BaseSites.SequenceEqual(table.BaseSites) &&
                        (previous.Rva, previous.IndexTableRva, previous.IndexEntryCount, previous.ExtentInferred) == (table.Rva, table.IndexTableRva, table.IndexEntryCount, table.ExtentInferred))
                    {
                        continue;
                    }

                    _tables[site] = table;
                    foreach (ulong target in table.TargetRvas)
                    {
                        _tableTargets.Add((uint)target);
                        Enqueue((uint)target);
                    }

                    progress = true;
                }

                Drain();
                if (!progress)
                {
                    return;
                }
            }

            // Did not settle: trust none of this function's tables.
            foreach (uint site in _tables.Keys.ToList())
            {
                _tables.Remove(site);
                _tableFailures[site] = "jump table proofs did not settle";
            }
        }

        private void Drain()
        {
            while (_work.TryPop(out uint start))
            {
                if (!_decoded.ContainsKey(start))
                {
                    DecodeRun(start);
                }
            }
        }

        /// <inheritdoc/>
        /// <remarks>
        /// Fall-through from the instruction ending at <paramref name="ip"/> (unless it is a jump,
        /// return or int3), direct branches to it, and the dispatch of every recovered table that
        /// lists it. Roots, and targets of tables no longer recovered, are unknown entries. The
        /// targets a refuted table added stay decoded: they are code either way, and the jump is
        /// frozen.
        /// </remarks>
        public IReadOnlyList<(Instruction Instruction, bool Taken)>? Predecessors(uint ip)
        {
            if (_roots.Contains(ip))
            {
                return null;
            }

            var predecessors = new List<(Instruction, bool)>();
            if (_endsAt.TryGetValue(ip, out uint previous) &&
                _decoded[previous].FlowControl is FlowControl.Next or FlowControl.Call or FlowControl.IndirectCall or FlowControl.ConditionalBranch)
            {
                predecessors.Add((_decoded[previous], false));
            }

            if (_branchesTo.TryGetValue(ip, out var branches))
            {
                predecessors.AddRange(branches.Select(b => (_decoded[b], true)));
            }

            bool explained = false;
            foreach (var (site, table) in _tables)
            {
                if (table.TargetRvas.Contains(ip))
                {
                    predecessors.Add((_decoded[site], true));
                    explained = true;
                }
            }

            return _tableTargets.Contains(ip) && !explained ? null : predecessors;
        }

        private void AttachScopeTable()
        {
            if (function.ExceptionHandler?.Kind != ExceptionHandlerKind.CSpecific)
            {
                return;
            }

            if (!image.ScopeTables.TryGetValue(function.EntryRva, out var table))
            {
                Downgrade("scope-table: __C_specific_handler with an unreadable scope table");
                return;
            }

            foreach (var entry in table)
            {
                // EndAddress is exclusive and may equal a range end.
                bool fits = RangeEnd(entry.BeginRva) is not null &&
                            entry.EndRva > entry.BeginRva &&
                            (RangeEnd(entry.EndRva) is not null || RangeEnd(entry.EndRva - 1) is not null) &&
                            (entry.IsFinally || RangeEnd(entry.JumpTargetRva) is not null) &&
                            (entry.HandlerRva == 1 || image.FindSection(entry.HandlerRva) is { IsExecutable: true });
                if (!fits)
                {
                    Downgrade($"scope-table: entry [0x{entry.BeginRva:X}, 0x{entry.EndRva:X}) handler 0x{entry.HandlerRva:X} " +
                              $"target 0x{entry.JumpTargetRva:X} does not fit the function");
                    return;
                }
            }

            function.ScopeTable = table;
            foreach (var entry in table)
            {
                if (!entry.IsFinally)
                {
                    EnqueueRoot(entry.JumpTargetRva);
                }
            }
        }

        /// <summary>
        /// Attaches the parsed C++ EH table. FH4 catch continuations inside the function are
        /// reached only through the table (the runtime resumes there after a catch), so they are
        /// roots. The gate validates the rest.
        /// </summary>
        private void AttachCxxEh()
        {
            if (function.ExceptionHandler?.Kind is not (ExceptionHandlerKind.CxxFrameHandler3 or ExceptionHandlerKind.CxxFrameHandler4) ||
                !image.CxxEhTables.TryGetValue(function.EntryRva, out var table))
            {
                return;
            }

            function.CxxEh = table;
            foreach (uint continuation in table.ContinuationRvas)
            {
                if (RangeEnd(continuation) is not null)
                {
                    EnqueueRoot(continuation);
                }
            }
        }

        /// <summary>An address control reaches from outside the function's own branches.</summary>
        private void EnqueueRoot(uint rva)
        {
            _roots.Add(rva);
            Enqueue(rva);
        }

        private void Enqueue(uint rva)
        {
            _leaders.Add(rva);
            if (!_decoded.ContainsKey(rva))
            {
                _work.Push(rva);
            }
        }

        /// <summary>Decodes straight-line code from <paramref name="start"/> until a terminator or already-decoded code.</summary>
        private void DecodeRun(uint start)
        {
            if (RangeEnd(start) is not { } rangeEnd)
            {
                return;
            }

            if (_barriers.Any(b => start >= b.Start && start < b.End))
            {
                return; // a root inside table data; the table's own checks cover it
            }

            // Stop at the range end, or at recovered table data, whichever comes first.
            uint stop = rangeEnd;
            foreach (var barrier in _barriers)
            {
                if (barrier.Start > start && barrier.Start < stop)
                {
                    stop = barrier.Start;
                }
            }

            var code = image.ReadFrom(start);
            int limit = (int)Math.Min(code.Length, stop - start);
            if (limit <= 0)
            {
                Downgrade($"undecodable: no file-backed bytes at 0x{start:X}");
                return;
            }

            var decoder = architecture.CreateDecoder(code[..limit], start);
            bool lastWasCall = false;
            while (true)
            {
                if (!decoder.TryDecodeNext(out var instruction))
                {
                    // Falling off the end after a call is how a call to a noreturn function looks.
                    if (!lastWasCall)
                    {
                        Downgrade(stop == rangeEnd
                            ? $"falls-off-range: execution continues past the range end at 0x{rangeEnd:X}"
                            : $"falls-into-data: execution runs into the jump table at 0x{stop:X}");
                    }

                    return;
                }

                if (instruction.IsInvalid)
                {
                    _invalidAt.Add((uint)instruction.IP);
                    Downgrade($"undecodable: invalid or truncated instruction at 0x{instruction.IP:X}");
                    return;
                }

                uint ip = (uint)instruction.IP;
                _decoded[ip] = instruction;
                _endsAt[(uint)instruction.NextIP] = ip;

                // MSVC places int3 or nop after a call to a noreturn function; filler does not
                // change whether running off the range end is expected.
                bool isCall = HandleFlow(instruction);
                if (instruction.Mnemonic is not (Mnemonic.Int3 or Mnemonic.Nop))
                {
                    lastWasCall = isCall;
                }

                if (IsTerminator(instruction))
                {
                    return;
                }

                uint next = (uint)instruction.NextIP;
                if (instruction.FlowControl == FlowControl.ConditionalBranch)
                {
                    _leaders.Add(next);
                }

                if (_decoded.ContainsKey(next))
                {
                    _leaders.Add(next);
                    return;
                }
            }
        }

        /// <summary>Records branch targets and call sites. Returns true for calls.</summary>
        private bool HandleFlow(in Instruction instruction)
        {
            uint ip = (uint)instruction.IP;
            if (FunctionDiscoveryPass.CodePointerTarget(instruction) == 0)
            {
                LoadsImageBase = true;
            }

            if (FunctionDiscoveryPass.CodePointerTarget(instruction) is { } pointer &&
                image.FindSection(pointer) is { IsExecutable: true })
            {
                int? owner = ranges.Find(pointer);
                bool isEntry = owner is { } o && image.Functions[o].EntryRva == pointer;
                _codePointers.Add(new CodePointer(function.Id, ip, pointer, owner, isEntry));
                return false;
            }

            if (instruction.IsJmpShortOrNear || instruction.IsJccShortOrNear)
            {
                uint target = (uint)instruction.NearBranchTarget;
                if (RangeEnd(target) is not null)
                {
                    if (!_branchesTo.TryGetValue(target, out var sources))
                    {
                        _branchesTo[target] = sources = [];
                    }

                    sources.Add(ip);
                    Enqueue(target);
                }
                else
                {
                    AddCallSite(ip, instruction.IsJmpShortOrNear ? CallKind.TailJump : CallKind.ConditionalTailJump, target);
                }

                return false;
            }

            if (instruction.IsCallNear)
            {
                AddCallSite(ip, CallKind.Call, (uint)instruction.NearBranchTarget);
                return true;
            }

            switch (instruction.FlowControl)
            {
                case FlowControl.IndirectCall:
                    AddCallSite(ip, CallKind.IndirectCall, null, PointerOf(instruction));
                    return true;
                case FlowControl.IndirectBranch when instruction.IsIPRelativeMemoryOperand:
                    AddCallSite(ip, CallKind.IndirectTailJump, null, PointerOf(instruction));
                    return false;
                case FlowControl.IndirectBranch:
                    _indirectJumps.Add(ip); // resolved or downgraded once decoding settles
                    return false;
                default:
                    return false;
            }
        }

        private static uint? PointerOf(in Instruction instruction) =>
            instruction.IsIPRelativeMemoryOperand ? (uint)instruction.IPRelativeMemoryAddress : null;

        private void AddCallSite(uint site, CallKind kind, uint? target, uint? pointer = null)
        {
            int? callee = target is { } t && entryToId.TryGetValue(t, out int id) ? id : null;
            _callSites.Add(new CallSite(function.Id, site, kind, target, callee, pointer));

            if (target is { } rva && kind != CallKind.Call && InInvalidFragment(rva))
            {
                Downgrade($"branches-into-invalid-chain: jump at 0x{site:X} targets 0x{rva:X}, a fragment whose unwind chain is invalid");
            }
        }

        private bool InInvalidFragment(uint rva)
        {
            int lo = 0, hi = invalidFragments.Length - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                var fragment = invalidFragments[mid];
                if (rva < fragment.Rva)
                {
                    hi = mid - 1;
                }
                else if (rva >= fragment.Rva + fragment.Length)
                {
                    lo = mid + 1;
                }
                else
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>End of the function range containing <paramref name="rva"/>, or null if it is outside the function.</summary>
        private uint? RangeEnd(uint rva)
        {
            foreach (var range in function.Ranges)
            {
                if (rva >= range.StartRva && rva < range.StartRva + range.Length)
                {
                    return (uint)range.StartRva + range.Length;
                }
            }

            return null;
        }

        /// <summary>A branch into the middle of an instruction means two decodings of the same bytes.</summary>
        private void CheckOverlaps(uint[] addresses)
        {
            for (int i = 1; i < addresses.Length; i++)
            {
                uint previousEnd = (uint)_decoded[addresses[i - 1]].NextIP;
                if (previousEnd > addresses[i])
                {
                    Downgrade($"overlapping-instructions: instruction at 0x{addresses[i]:X} starts inside the one at 0x{addresses[i - 1]:X}");
                    return;
                }
            }
        }

        private void BuildBlocks(uint[] addresses)
        {
            BasicBlock? current = null;
            Instruction previous = default;
            foreach (uint ip in addresses)
            {
                var instruction = _decoded[ip];
                bool startsBlock = current is null || _leaders.Contains(ip) || unwindStarts.Contains(ip) || EndsBlock(previous) || (uint)previous.NextIP != ip;
                if (startsBlock)
                {
                    current = new BasicBlock
                    {
                        Id = function.BasicBlocks.Count,
                        StartRva = ip,
                        InstructionStart = image.Instructions.Count,
                    };
                    function.BasicBlocks.Add(current);
                }

                image.Instructions.Add(instruction);
                current!.InstructionCount++;
                current.Length = (uint)(instruction.NextIP - current.StartRva);
                previous = instruction;
            }
        }

        private void LinkEdges()
        {
            var byStart = function.BasicBlocks.ToDictionary(b => (uint)b.StartRva);
            foreach (var block in function.BasicBlocks)
            {
                ref readonly var last = ref image.Instructions[block.InstructionStart + block.InstructionCount - 1];
                uint next = (uint)last.NextIP;

                if (_tables.TryGetValue((uint)last.IP, out var table))
                {
                    foreach (ulong target in table.TargetRvas.Distinct())
                    {
                        if (byStart.TryGetValue((uint)target, out var targetBlock))
                        {
                            Link(block, targetBlock, EdgeKind.IndirectBranch);
                        }
                    }
                }
                else if (last.IsJccShortOrNear || last.IsJmpShortOrNear)
                {
                    if (byStart.TryGetValue((uint)last.NearBranchTarget, out var target))
                    {
                        Link(block, target, EdgeKind.Branch);
                    }

                    if (last.IsJccShortOrNear && byStart.TryGetValue(next, out var fallThrough))
                    {
                        Link(block, fallThrough, EdgeKind.FallThrough);
                    }
                }
                else if (!IsTerminator(last) && byStart.TryGetValue(next, out var fallThrough))
                {
                    Link(block, fallThrough, EdgeKind.FallThrough);
                }
            }
        }

        private static void Link(BasicBlock source, BasicBlock target, EdgeKind kind)
        {
            var edge = new Edge { Source = source, Target = target, Kind = kind };
            source.Successors.Add(edge);
            target.Predecessors.Add(edge);
        }

        /// <summary>
        /// Every non-padding byte of a .pdata-backed range is code or data the function owns. If
        /// disassembly never reached it, something (jump table data, a switch case, an exception
        /// handler block) is not modelled, and the function cannot be rearranged safely.
        /// </summary>
        private void CheckCoverage(uint[] addresses)
        {
            long uncovered = 0;
            uint? first = null;
            int next = 0;
            foreach (var range in function.Ranges)
            {
                uint cursor = (uint)range.StartRva;
                uint end = (uint)range.StartRva + range.Length;
                while (next < addresses.Length && addresses[next] < end)
                {
                    uint ip = addresses[next];
                    if (ip > cursor)
                    {
                        Gap(cursor, ip);
                    }

                    cursor = Math.Max(cursor, (uint)_decoded[ip].NextIP);
                    next++;
                }

                if (cursor < end)
                {
                    Gap(cursor, end);
                }
            }

            if (uncovered > 0)
            {
                Downgrade($"uncovered-bytes: {uncovered} bytes of the function's ranges not reached by disassembly, first at 0x{first:X} " +
                          "(jump table data, or code reached only through an indirect branch or exception handler)");
            }

            void Gap(uint start, uint end)
            {
                // Recovered table bytes inside the ranges are the function's data, not missed code.
                foreach (var (dataStart, dataEnd) in TableExtents().OrderBy(e => e.Start))
                {
                    if (dataEnd <= start || dataStart >= end)
                    {
                        continue;
                    }

                    if (dataStart > start)
                    {
                        Gap(start, dataStart);
                    }

                    start = Math.Max(start, dataEnd);
                }

                if (start >= end)
                {
                    return;
                }

                var bytes = image.ReadFrom(start).Span;
                bytes = bytes[..(int)Math.Min(bytes.Length, end - start)];
                if (!CodePadding.IsPadding(architecture, bytes, start))
                {
                    uncovered += end - start;
                    first ??= start;
                }
            }
        }

        private IEnumerable<(uint Start, uint End)> TableExtents() => _tables.Values.SelectMany(t =>
            t.IndexTableRva is { } index
                ? new[] { ((uint)t.Rva, (uint)t.Rva + (uint)t.EntryCount * 4), ((uint)index, (uint)index + (uint)t.IndexEntryCount) }
                : new[] { ((uint)t.Rva, (uint)t.Rva + (uint)t.EntryCount * 4) });

        private void Downgrade(string reason) => _downgrades.Add(reason);
    }
}
