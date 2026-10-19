using Iced.Intel;
using WinBolt.Core.Arch;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// Function discovery (DesignDoc.md Stage 1, "Function discovery on x64 PE").
/// <list type="number">
/// <item>Every unchained .pdata entry starts a function; chained entries attach to the
/// function at the root of their chain (§5.1). Fragments with an invalid chain are not
/// attributed to any function (§5.5).</item>
/// <item>Leaf functions, which need no .pdata, are found from exports, the entry point, TLS
/// callbacks, GuardCFFunctionTable, base-relocation targets, and direct call/jump targets in
/// already-discovered code. Their extent comes from a bounded sweep.</item>
/// <item>Whatever executable bytes remain are recorded as <see cref="BinaryImage.UnclaimedCode"/>,
/// split into padding and unattributed code.</item>
/// </list>
/// Anything discovery cannot model downgrades the function with a reason (§5.5). The reason
/// starts with a stable code (<c>interior-entry</c>, <c>leaf-extent</c>, …) followed by detail.
/// </summary>
[RegisterPass(DependsOn = [ExceptionHandlerPass.PassName])]
public sealed class FunctionDiscoveryPass : IAnalysisPass
{
    public const string PassName = "FunctionDiscovery";

    public string Name => PassName;

    public void Run(BinaryImage image, PassContext context) => new Discovery(image, context.Architecture).Run();

    /// <summary>
    /// Target of <c>lea reg,[rip+X]</c>, or null. Callers keep only executable targets. As a
    /// discovery candidate it is weak (a lea into read-only data merged into .text is common),
    /// so a leaf found this way must sweep cleanly.
    /// </summary>
    internal static uint? CodePointerTarget(in Instruction instruction) =>
        instruction.Mnemonic == Mnemonic.Lea && instruction.IsIPRelativeMemoryOperand
            ? (uint)instruction.IPRelativeMemoryAddress
            : null;

    private sealed class Draft(uint entry)
    {
        public uint Entry { get; } = entry;

        public List<(uint Start, uint End)> Spans { get; } = [];

        public DiscoverySource Sources { get; set; }

        public List<(Transformability Level, string Reason)> Downgrades { get; } = [];

        public bool EndsInIndirectJump { get; set; }

        /// <summary>Branch targets leaving a swept leaf; followed only if the leaf is accepted.</summary>
        public List<(uint Rva, DiscoverySource Source)> Targets { get; } = [];
    }

    private sealed class Discovery(BinaryImage image, IArchitecture architecture)
    {
        private const int MaxChainDepth = 32;
        private const int MaxLeafRounds = 16;
        private const int MaxThunkHops = 4;

        // Sources that assert "execution enters here". Landing inside another function is then
        // a real interior entry. Jump and relocation targets inside a function are expected
        // (branches, jump tables) and prove nothing.
        private const DiscoverySource EntryAssertingSources =
            DiscoverySource.Export | DiscoverySource.EntryPoint | DiscoverySource.TlsCallback |
            DiscoverySource.CfgTarget | DiscoverySource.CallTarget | DiscoverySource.ExceptionTable | DiscoverySource.Symbol |
            DiscoverySource.EntryJump;

        private readonly Dictionary<uint, Draft> _drafts = [];
        private readonly List<(uint Start, uint End)> _invalidFragments = [];
        private List<(uint Start, uint End)> _knownData = [];
        private SpanIndex _index = SpanIndex.Empty;

        public void Run()
        {
            AddPdataFunctions();
            _index = SpanIndex.Build(_drafts.Values);

            var pending = new Dictionary<uint, DiscoverySource>();
            CollectDeclaredEntries(pending);
            foreach (var draft in _drafts.Values.ToList())
            {
                foreach (var span in draft.Spans)
                {
                    ScanForTargets(draft, span.Start, span.End, pending);
                }
            }

            DiscoverLeaves(pending);
            BuildFunctions();
        }

        private void AddPdataFunctions()
        {
            foreach (var entry in image.ExceptionData)
            {
                if (!entry.IsChained && entry.EndAddress > entry.BeginAddress)
                {
                    var draft = GetOrAdd(entry.BeginAddress);
                    draft.Spans.Add((entry.BeginAddress, entry.EndAddress));
                    draft.Sources |= DiscoverySource.Pdata;
                }
            }

            foreach (var entry in image.ExceptionData)
            {
                if (!entry.IsChained || entry.EndAddress <= entry.BeginAddress)
                {
                    continue;
                }

                if (Root(entry) is { } root && _drafts.TryGetValue(root.BeginAddress, out var owner))
                {
                    owner.Spans.Add((entry.BeginAddress, entry.EndAddress));
                }
                else
                {
                    _invalidFragments.Add((entry.BeginAddress, entry.EndAddress));
                }
            }
        }

        /// <summary>The unchained entry at the end of the chain, or null if the chain is invalid or cyclic.</summary>
        private static ExceptionInfo? Root(ExceptionInfo entry)
        {
            var current = entry;
            for (int depth = 0; depth < MaxChainDepth; depth++)
            {
                if (!current.IsChained)
                {
                    return current;
                }

                if (current.ChainedParent is not { } parent)
                {
                    return null;
                }

                current = parent;
            }

            return null;
        }

        private void CollectDeclaredEntries(Dictionary<uint, DiscoverySource> pending)
        {
            foreach (var export in image.Exports)
            {
                if (!export.IsForwarder)
                {
                    AddCandidate(pending, export.Rva, DiscoverySource.Export);
                }
            }

            if (image.EntryPointRva != 0)
            {
                AddCandidate(pending, image.EntryPointRva, DiscoverySource.EntryPoint);
            }

            // PDB function symbols, already translated through OMAP when the image was rewritten.
            foreach (var symbol in image.Symbols)
            {
                if (symbol.IsFunction)
                {
                    AddCandidate(pending, symbol.Rva, DiscoverySource.Symbol);
                }
            }

            foreach (var callback in image.TlsCallbacks)
            {
                AddCandidate(pending, callback, DiscoverySource.TlsCallback);
            }

            // The OS calls handlers through the RVA in unwind info; import-thunk handlers
            // (jmp [rip+slot]) have no .pdata entry.
            foreach (var entry in image.ExceptionData)
            {
                if (entry.HasHandler)
                {
                    AddCandidate(pending, entry.HandlerRva, DiscoverySource.ExceptionTable);
                }
            }

            // Filter and __finally funclets are named only by scope tables; most have .pdata
            // entries, but a trivial filter (mov eax,1 / ret) needs none.
            foreach (var table in image.ScopeTables.Values)
            {
                foreach (var entry in table)
                {
                    if (entry.FuncletRva is { } funclet)
                    {
                        AddCandidate(pending, funclet, DiscoverySource.ExceptionTable);
                    }
                }
            }

            // C++ EH unwind and catch funclets, and destructors the EH runtime calls: often
            // referenced nowhere else, and unwind funclets usually have no .pdata entry.
            foreach (var table in image.CxxEhTables.Values)
            {
                foreach (uint funclet in table.FuncletRvas)
                {
                    AddCandidate(pending, funclet, DiscoverySource.ExceptionTable);
                }
            }

            if (image.LoadConfig is { } loadConfig)
            {
                foreach (var target in loadConfig.GuardCfFunctionTable)
                {
                    AddCandidate(pending, target, DiscoverySource.CfgTarget);
                }
            }

            foreach (var relocation in image.Relocations)
            {
                if (relocation.Type != RelocationType.Dir64)
                {
                    continue;
                }

                var site = image.ReadFrom(relocation.Rva).Span;
                if (site.Length < 8)
                {
                    continue;
                }

                ulong va = BitConverter.ToUInt64(site[..8]);
                if (va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage)
                {
                    AddCandidate(pending, (uint)(va - image.ImageBase), DiscoverySource.RelocationTarget);
                }
            }
        }

        /// <summary>
        /// Records a candidate function start. Starts of known functions just gain a source;
        /// starts inside a known function are interior entries; anything else waits for the
        /// leaf sweep.
        /// </summary>
        private void AddCandidate(Dictionary<uint, DiscoverySource> pending, uint rva, DiscoverySource source)
        {
            if (image.FindSection(rva) is not { IsExecutable: true })
            {
                return;
            }

            if (_drafts.TryGetValue(rva, out var existing))
            {
                existing.Sources |= source;
                return;
            }

            if (_index.Find(rva) is { } owner)
            {
                if ((source & EntryAssertingSources) != 0)
                {
                    owner.Downgrades.Add((Transformability.Frozen,
                        $"interior-entry: {source} target at 0x{rva:X}, +0x{rva - owner.Entry:X} from the entry, " +
                        "so an external party depends on an address inside the function"));
                }

                return;
            }

            pending[rva] = pending.GetValueOrDefault(rva) | source;
        }

        /// <summary>Linear decode of known code, collecting direct call targets and jumps that leave the function.</summary>
        private void ScanForTargets(Draft draft, uint start, uint end, Dictionary<uint, DiscoverySource> pending)
        {
            var code = image.ReadFrom(start);
            int length = (int)Math.Min(code.Length, end - start);
            if (length <= 0)
            {
                return;
            }

            var decoder = architecture.CreateDecoder(code[..length], start);
            while (decoder.TryDecodeNext(out var instruction))
            {
                if (instruction.IsInvalid)
                {
                    return; // data in the code stream; the CFG pass classifies it
                }

                if (instruction.IsCallNear)
                {
                    AddCandidate(pending, (uint)instruction.NearBranchTarget, DiscoverySource.CallTarget);
                }
                else if (CodePointerTarget(instruction) is { } pointer)
                {
                    AddCandidate(pending, pointer, DiscoverySource.CodePointer);
                }
                else if ((instruction.IsJmpShortOrNear || instruction.IsJccShortOrNear) &&
                         _index.Find((uint)instruction.NearBranchTarget) != draft)
                {
                    AddCandidate(pending, (uint)instruction.NearBranchTarget,
                        instruction.IsJmpShortOrNear && instruction.IP == draft.Entry ? DiscoverySource.EntryJump : DiscoverySource.JumpTarget);
                }
            }
        }

        private void DiscoverLeaves(Dictionary<uint, DiscoverySource> pending)
        {
            for (int round = 0; round < MaxLeafRounds && pending.Count > 0; round++)
            {
                // Only entry-asserting candidates bound a sweep. A jump or relocation target may
                // point into the middle of a leaf, and bounding at it would truncate the leaf.
                uint[] Bounds() => _index.Starts
                    .Concat(pending.Where(p => IsStrong(p.Value)).Select(p => p.Key))
                    .Distinct()
                    .Order()
                    .ToArray();
                var bounds = Bounds();

                // A thunk's target (a jmp that is a strong candidate's first instruction, leaving its
                // sweep) is an entry too. Found before this round's sweeps, it bounds them, instead
                // of arriving a round later inside a leaf swept past it (trampolines to adjacent copies).
                for (int hop = 0; hop < MaxThunkHops && AddThunkTargets(pending, bounds); hop++)
                {
                    bounds = Bounds();
                }

                var next = new Dictionary<uint, DiscoverySource>();

                // Ascending order: a weak candidate below coveredUntil lies inside a leaf found
                // earlier in this round. Strong candidates never do, since they bound the sweeps.
                uint coveredUntil = 0;
                foreach (var (rva, source) in pending.OrderBy(p => p.Key))
                {
                    if (rva < coveredUntil || SweepLeaf(rva, NextBound(bounds, rva), source) is not { } leaf)
                    {
                        continue;
                    }

                    // Weak evidence (only jump or relocation targets) is not enough to call bytes
                    // a function unless they also sweep cleanly. Relocations point at data in
                    // .text often enough, in rewritten images, that anything less admits junk.
                    if (!IsStrong(source) && leaf.Downgrades.Count > 0)
                    {
                        continue;
                    }

                    _drafts[rva] = leaf;
                    coveredUntil = leaf.Spans[0].End;
                    foreach (var (target, targetSource) in leaf.Targets)
                    {
                        next[target] = next.GetValueOrDefault(target) | targetSource;
                    }
                }

                _index = SpanIndex.Build(_drafts.Values);

                // Targets found this round may land inside leaves found this round; re-filter.
                pending = [];
                foreach (var (rva, source) in next)
                {
                    AddCandidate(pending, rva, source);
                }
            }
        }

        /// <summary>Adds the targets of strong candidates that are thunks; true if any source changed.</summary>
        private bool AddThunkTargets(Dictionary<uint, DiscoverySource> pending, uint[] bounds)
        {
            bool changed = false;
            foreach (var (rva, source) in pending.Where(p => IsStrong(p.Value)).ToList())
            {
                var code = image.ReadFrom(rva);
                if (code.IsEmpty ||
                    !architecture.CreateDecoder(code[..Math.Min(code.Length, 15)], rva).TryDecodeNext(out var first) ||
                    first.IsInvalid || !first.IsJmpShortOrNear)
                {
                    continue;
                }

                uint target = (uint)first.NearBranchTarget;
                if (target >= rva && target < NextBound(bounds, rva) && !JumpsOverPadding(first, target))
                {
                    continue; // a rotated loop's jump to its condition, not a thunk
                }

                var before = pending.GetValueOrDefault(target);
                AddCandidate(pending, target, DiscoverySource.EntryJump);
                changed |= pending.GetValueOrDefault(target) != before;
            }

            return changed;
        }

        /// <summary>
        /// A forward jmp whose skipped bytes are nothing but alignment filler: not a rotated loop
        /// (whose jump skips the loop body) but a thunk to the next function, which a rewriter's
        /// copy of a thunk is when its target's copy sits right behind it.
        /// </summary>
        private bool JumpsOverPadding(in Instruction jump, uint target)
        {
            uint from = (uint)jump.NextIP;
            if (target <= from || target - from > 64)
            {
                return false;
            }

            var gap = image.ReadFrom(from);
            return gap.Length >= target - from && CodePadding.IsPadding(architecture, gap.Span[..(int)(target - from)], from);
        }

        private static bool IsStrong(DiscoverySource source) => (source & EntryAssertingSources) != 0;

        /// <summary>The first bound strictly above <paramref name="rva"/>, or uint.MaxValue.</summary>
        private static uint NextBound(uint[] bounds, uint rva)
        {
            int i = Array.BinarySearch(bounds, rva);
            int next = i >= 0 ? i + 1 : ~i;
            return next < bounds.Length ? bounds[next] : uint.MaxValue;
        }

        /// <summary>
        /// Finds a leaf's extent by sweeping forward from its entry: the function ends at the
        /// first terminator (ret, jmp, ud2, int 29h) past the furthest internal forward branch.
        /// Stops at <paramref name="bound"/> (the next known start) and at the end of file-backed
        /// data. Returns null when the entry is not decodable code at all.
        /// </summary>
        private Draft? SweepLeaf(uint entry, uint bound, DiscoverySource source)
        {
            var code = image.ReadFrom(entry);
            int limit = (int)Math.Min(code.Length, (long)bound - entry);
            if (limit <= 0)
            {
                return null;
            }

            var draft = new Draft(entry) { Sources = source };
            var decoder = architecture.CreateDecoder(code[..limit], entry);
            uint maxInternalTarget = entry;
            uint end = entry;
            bool terminated = false;

            while (decoder.TryDecodeNext(out var instruction))
            {
                if (instruction.IsInvalid)
                {
                    break;
                }

                end = (uint)instruction.NextIP;

                if (instruction.IsCallNear || instruction.FlowControl == FlowControl.IndirectCall)
                {
                    draft.Downgrades.Add((Transformability.Frozen,
                        $"leaf-calls: call at 0x{instruction.IP:X} in a function with no .pdata entry; " +
                        "x64 requires unwind data for any function that calls, so this is likely hand-written assembly"));
                    if (instruction.IsCallNear)
                    {
                        draft.Targets.Add(((uint)instruction.NearBranchTarget, DiscoverySource.CallTarget));
                    }
                }
                else if (CodePointerTarget(instruction) is { } pointer)
                {
                    draft.Targets.Add((pointer, DiscoverySource.CodePointer));
                }
                else if (instruction.IsJmpShortOrNear || instruction.IsJccShortOrNear)
                {
                    // A jmp at the entry may also be a rotated loop's jump to its condition (MSVC,
                    // frameless leaves), so only a target outside the sweep marks a thunk.
                    uint target = (uint)instruction.NearBranchTarget;
                    if (target >= entry && target < bound && !(instruction.IP == entry && JumpsOverPadding(instruction, target)))
                    {
                        maxInternalTarget = Math.Max(maxInternalTarget, target);
                    }
                    else
                    {
                        draft.Targets.Add((target, instruction.IsJmpShortOrNear && instruction.IP == entry && IsStrong(source)
                            ? DiscoverySource.EntryJump : DiscoverySource.JumpTarget));
                    }
                }

                if (IsTerminator(instruction) && end > maxInternalTarget)
                {
                    terminated = true;
                    // jmp [rip+x] is an import thunk or tail call through a pointer; only a
                    // register-indirect jmp looks like switch dispatch.
                    draft.EndsInIndirectJump = instruction.FlowControl == FlowControl.IndirectBranch &&
                                               !instruction.IsIPRelativeMemoryOperand;
                    break;
                }
            }

            if (end == entry)
            {
                return null; // first instruction undecodable: not code
            }

            if (!terminated)
            {
                string why = end >= bound && bound != uint.MaxValue
                    ? $"runs into the next known start at 0x{bound:X} without a terminator"
                    : $"no terminator found before undecodable bytes at 0x{end:X}";
                draft.Downgrades.Add((Transformability.Frozen, $"leaf-extent: sweep from 0x{entry:X} {why}"));
            }

            draft.Spans.Add((entry, end));
            return draft;
        }

        private static bool IsTerminator(in Instruction instruction) => instruction.FlowControl switch
        {
            FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch => true,
            FlowControl.Exception => instruction.Mnemonic == Mnemonic.Ud2,
            FlowControl.Interrupt => instruction.Mnemonic == Mnemonic.Int && instruction.Immediate8 == 0x29, // __fastfail
            _ => false,
        };

        private void BuildFunctions()
        {
            // Export names first (the external name), then PDB function symbols.
            var names = new Dictionary<uint, string>();
            foreach (var export in image.Exports)
            {
                if (!export.IsForwarder && export.Name is not null)
                {
                    names.TryAdd(export.Rva, export.Name);
                }
            }

            foreach (var symbol in image.Symbols)
            {
                if (symbol.IsFunction)
                {
                    names.TryAdd(symbol.Rva, symbol.Name);
                }
            }

            FlagOverlaps();

            int id = 0;
            foreach (var draft in _drafts.Values.OrderBy(d => d.Entry))
            {
                var function = new Function
                {
                    Id = id++,
                    Name = names.GetValueOrDefault(draft.Entry),
                    DiscoveredBy = draft.Sources,
                };

                foreach (var (start, end) in Coalesce(draft.Spans, draft.Entry))
                {
                    function.Ranges.Add(new FunctionRange
                    {
                        StartRva = start,
                        Length = end - start,
                        IsEntryRange = start == draft.Entry,
                    });
                }

                foreach (var (level, reason) in draft.Downgrades)
                {
                    function.Downgrade(level, reason);
                }

                image.Functions.Add(function);
            }

            ComputeUnclaimedCode();
        }

        /// <summary>
        /// Two functions claiming the same bytes means one of the inputs is wrong, and neither
        /// function's extent can be trusted.
        /// </summary>
        private void FlagOverlaps()
        {
            var spans = _drafts.Values
                .SelectMany(d => d.Spans.Select(s => (s.Start, s.End, Draft: d)))
                .OrderBy(s => s.Start)
                .ToList();

            var furthest = (End: 0u, Draft: (Draft?)null);
            foreach (var span in spans)
            {
                if (furthest.Draft is { } previous && previous != span.Draft && span.Start < furthest.End)
                {
                    previous.Downgrades.Add((Transformability.Frozen, $"range-overlap: overlaps function at 0x{span.Draft.Entry:X}"));
                    span.Draft.Downgrades.Add((Transformability.Frozen, $"range-overlap: overlaps function at 0x{previous.Entry:X}"));
                }

                if (span.End > furthest.End)
                {
                    furthest = (span.End, span.Draft);
                }
            }
        }

        /// <summary>
        /// Merges overlapping and adjacent spans into maximal ranges, except that a range always
        /// starts at the entry point, so the entry range is identifiable (§5.1).
        /// </summary>
        private static List<(uint Start, uint End)> Coalesce(List<(uint Start, uint End)> spans, uint entry)
        {
            var result = new List<(uint Start, uint End)>();
            foreach (var (start, end) in spans.OrderBy(s => s.Start))
            {
                // Never merge into the previous range when this span begins the entry range,
                // unless the previous range already is the entry range (duplicate .pdata entries).
                bool beginsEntryRange = start == entry && result.Count > 0 && result[^1].Start != entry;
                if (result.Count > 0 && start <= result[^1].End && !beginsEntryRange)
                {
                    result[^1] = (result[^1].Start, Math.Max(result[^1].End, end));
                }
                else
                {
                    result.Add((start, end));
                }
            }

            // A span that started before the entry and was merged past it: split at the entry.
            for (int i = 0; i < result.Count; i++)
            {
                if (result[i].Start < entry && entry < result[i].End)
                {
                    result.Insert(i + 1, (entry, result[i].End));
                    result[i] = (result[i].Start, entry);
                    break;
                }
            }

            return result;
        }

        private void ComputeUnclaimedCode()
        {
            var covered = image.Functions
                .SelectMany(f => f.Ranges.Select(r => ((uint)r.StartRva, (uint)r.StartRva + r.Length)))
                .Concat(_invalidFragments)
                .OrderBy(s => s.Item1)
                .ToList();

            foreach (var (start, end) in Coalesce(_invalidFragments, entry: uint.MaxValue))
            {
                image.UnclaimedCode.Add(new UnclaimedRange(start, end - start, UnclaimedKind.InvalidChainFragment));
            }

            var knownData = image.DataDirectories.Select(d => (d.Rva, End: d.Rva + d.Size))
                .Concat(image.DebugEntries.Where(e => e.AddressOfRawData != 0).Select(e => (Rva: e.AddressOfRawData, End: e.AddressOfRawData + e.SizeOfData)))
                .ToList();
            _knownData = Coalesce(knownData, entry: uint.MaxValue);

            foreach (var section in image.Sections.Where(s => s.IsExecutable))
            {
                uint cursor = section.Rva;
                uint sectionEnd = section.Rva + section.MappedSize;
                foreach (var (start, end) in covered)
                {
                    if (end <= cursor || start >= sectionEnd)
                    {
                        continue;
                    }

                    if (start > cursor)
                    {
                        AddGap(cursor, start);
                    }

                    cursor = Math.Max(cursor, end);
                }

                if (cursor < sectionEnd)
                {
                    AddGap(cursor, sectionEnd);
                }
            }

            DowngradeIndirectJumpTails();
        }

        /// <summary>Records a gap: PE-described data first, then the rest as padding or unattributed code.</summary>
        private void AddGap(uint start, uint end)
        {
            uint cursor = start;
            foreach (var (dataStart, dataEnd) in _knownData)
            {
                if (dataEnd <= cursor || dataStart >= end)
                {
                    continue;
                }

                if (dataStart > cursor)
                {
                    AddCodeGap(cursor, dataStart);
                }

                uint clippedEnd = Math.Min(dataEnd, end);
                image.UnclaimedCode.Add(new UnclaimedRange(Math.Max(cursor, dataStart), clippedEnd - Math.Max(cursor, dataStart), UnclaimedKind.KnownData));
                cursor = clippedEnd;
            }

            if (cursor < end)
            {
                AddCodeGap(cursor, end);
            }
        }

        /// <summary>Records a gap, trimming int3/nop/zero padding off both ends of any real code in it.</summary>
        private void AddCodeGap(uint start, uint end)
        {
            var bytes = image.ReadFrom(start).Span;
            int fileBacked = (int)Math.Min(bytes.Length, end - start);
            bytes = bytes[..fileBacked];

            int lead = 0;
            while (lead < bytes.Length && CodePadding.IsPaddingByte(bytes[lead]))
            {
                lead++;
            }

            int trail = bytes.Length;
            while (trail > lead && CodePadding.IsPaddingByte(bytes[trail - 1]))
            {
                trail--;
            }

            if (lead == trail || CodePadding.IsPadding(architecture, bytes[lead..trail], start + (uint)lead))
            {
                image.UnclaimedCode.Add(new UnclaimedRange(start, end - start, UnclaimedKind.Padding));
                return;
            }

            if (lead > 0)
            {
                image.UnclaimedCode.Add(new UnclaimedRange(start, (uint)lead, UnclaimedKind.Padding));
            }

            image.UnclaimedCode.Add(new UnclaimedRange(start + (uint)lead, (uint)(trail - lead), UnclaimedKind.Unattributed));

            // Trailing padding plus any zero-fill past the file-backed bytes.
            if (start + (uint)trail < end)
            {
                image.UnclaimedCode.Add(new UnclaimedRange(start + (uint)trail, end - start - (uint)trail, UnclaimedKind.Padding));
            }
        }

        /// <summary>
        /// A leaf whose sweep ended on an indirect jump, followed directly by unattributed code,
        /// most likely has switch cases after the jump that the sweep could not see.
        /// </summary>
        private void DowngradeIndirectJumpTails()
        {
            var unattributedStarts = image.UnclaimedCode
                .Where(u => u.Kind == UnclaimedKind.Unattributed)
                .Select(u => u.Rva)
                .ToHashSet();
            var tails = image.UnclaimedCode.Where(u => u.Kind == UnclaimedKind.Padding).ToDictionary(u => u.Rva, u => u.Rva + u.Length);

            foreach (var function in image.Functions)
            {
                if (!_drafts[function.EntryRva].EndsInIndirectJump)
                {
                    continue;
                }

                uint after = (uint)function.Ranges[^1].StartRva + function.Ranges[^1].Length;
                if (tails.TryGetValue(after, out var paddingEnd))
                {
                    after = paddingEnd;
                }

                if (unattributedStarts.Contains(after))
                {
                    function.Downgrade(Transformability.Frozen,
                        $"leaf-extent: sweep ended on an indirect jump and unattributed code follows at 0x{after:X}; " +
                        "the extent likely misses switch cases");
                }
            }
        }

        private Draft GetOrAdd(uint entry)
        {
            if (!_drafts.TryGetValue(entry, out var draft))
            {
                draft = new Draft(entry);
                _drafts[entry] = draft;
            }

            return draft;
        }
    }

    /// <summary>Sorted spans for "which function contains this RVA" lookups.</summary>
    private sealed class SpanIndex
    {
        public static readonly SpanIndex Empty = new([], [], []);

        private readonly uint[] _starts;
        private readonly uint[] _ends;
        private readonly Draft[] _owners;

        private SpanIndex(uint[] starts, uint[] ends, Draft[] owners)
        {
            _starts = starts;
            _ends = ends;
            _owners = owners;
        }

        public IEnumerable<uint> Starts => _starts;

        public static SpanIndex Build(IEnumerable<Draft> drafts)
        {
            var spans = drafts
                .SelectMany(d => d.Spans.Select(s => (s.Start, s.End, Draft: d)))
                .OrderBy(s => s.Start)
                .ToArray();
            return new SpanIndex(
                spans.Select(s => s.Start).ToArray(),
                spans.Select(s => s.End).ToArray(),
                spans.Select(s => s.Draft).ToArray());
        }

        public Draft? Find(uint rva)
        {
            int i = Array.BinarySearch(_starts, rva);
            if (i < 0)
            {
                i = ~i - 1;
            }
            else
            {
                // Several spans can share a start (duplicate .pdata entries); take the last.
                // Nested spans from different functions can still hide each other here, but
                // FlagOverlaps freezes both functions in that case anyway.
                while (i + 1 < _starts.Length && _starts[i + 1] == rva)
                {
                    i++;
                }
            }

            return i >= 0 && rva < _ends[i] ? _owners[i] : null;
        }
    }
}
