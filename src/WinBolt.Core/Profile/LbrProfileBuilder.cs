using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Profile;

/// <summary>
/// One taken branch from a hardware branch record, in image RVAs. A null end lies outside the
/// image being profiled (another module, or code the image does not contain).
/// </summary>
public readonly record struct BranchRecord(uint? From, uint? To);

/// <summary>
/// What applying a profile to an image found (DesignDoc Stage 2: "profile coverage and binding
/// report"). Every record is either matched to the CFG or counted under a reason; nothing is
/// silently dropped.
/// </summary>
public sealed class ProfileSummary
{
    /// <summary>Edge-accurate when branch records were applied; sampling-only when the trace had IP samples alone.</summary>
    public WinBolt.Core.Passes.ProfileFidelity Fidelity { get; set; }

    /// <summary>How the profile was bound to this image, in words (which processes, which identity check).</summary>
    public string Binding { get; set; } = string.Empty;

    public long Samples { get; set; }

    /// <summary>Records whose source lies in the image.</summary>
    public long Records { get; set; }

    public long TakenBranches { get; set; }

    public long Calls { get; set; }

    public long Returns { get; set; }

    public long TailCalls { get; set; }

    /// <summary>Straight-line runs between consecutive records that followed fall-through edges.</summary>
    public long FallThroughRuns { get; set; }

    public long FallThroughEdges { get; set; }

    /// <summary>Straight-line runs the CFG cannot explain (no fall-through path between the two records).</summary>
    public long UnexplainedRuns { get; set; }

    public long IpSamples { get; set; }

    /// <summary>Profiled executions per call site RVA (direct and indirect calls), for call frequency.</summary>
    public Dictionary<uint, long> CallCounts { get; } = [];

    /// <summary>
    /// Observed targets per indirect call site: target RVA in the image, or
    /// <see cref="OutsideImage"/>. Only calls through a register or a non-RIP-relative pointer:
    /// those are the virtual and function-pointer calls (import calls through the IAT have one
    /// fixed target).
    /// </summary>
    public Dictionary<uint, Dictionary<uint, long>> IndirectTargets { get; } = [];

    /// <summary>Key in <see cref="IndirectTargets"/> for a target outside the image.</summary>
    public const uint OutsideImage = uint.MaxValue;

    /// <summary>Records that did not fit the CFG, by reason. Never assigned to an edge.</summary>
    public Dictionary<string, long> Unmatched { get; } = [];

    public long MatchedRecords => TakenBranches + Calls + Returns + TailCalls;

    public long UnmatchedRecords => Unmatched.Values.Sum();
}

/// <summary>
/// Applies LBR samples to an analyzed image: taken branches increment their CFG edge
/// (<see cref="Edge.ExecutionCount"/>), and the straight-line run between two consecutive
/// records increments every fall-through edge it crosses. LBR records only taken branches, so
/// that run is the only evidence of not-taken conditional branches.
/// <para>
/// Callers pass each sample's records newest first, all known to belong to the sampled thread
/// (for ETW, the user-mode prefix newer than the newest kernel entry). A record that does not
/// fit the CFG is counted as unmatched and never assigned to an edge: a profile of code that is
/// not the file (runtime patches, hooks) must not become layout evidence.
/// </para>
/// </summary>
public sealed class LbrProfileBuilder
{
    private const int MaxStraightLineBlocks = 4096;

    private readonly BinaryImage _image;
    private readonly BlockIndex _index;
    private readonly Dictionary<uint, (Function Function, BasicBlock Block)> _byLastInstruction = [];
    private readonly HashSet<uint> _callSites = [];
    private readonly HashSet<uint> _dynamicCallSites = [];
    private readonly Dictionary<BasicBlock, ulong> _visits = [];

    public ProfileSummary Summary { get; } = new();

    public LbrProfileBuilder(BinaryImage image)
    {
        _image = image;
        _index = new BlockIndex(image);

        foreach (var (function, block) in _index.Blocks)
        {
            ref readonly var last = ref image.Instructions[block.InstructionStart + block.InstructionCount - 1];
            _byLastInstruction[(uint)last.IP] = (function, block);
        }

        foreach (var site in image.CallSites)
        {
            if (site.Kind is CallKind.Call or CallKind.IndirectCall)
            {
                _callSites.Add(site.SiteRva);
            }

            if (site is { Kind: CallKind.IndirectCall, PointerRva: null })
            {
                _dynamicCallSites.Add(site.SiteRva);
            }
        }
    }

    /// <summary>A sampled instruction pointer inside the image: counts toward its function's samples.</summary>
    public void AddIpSample(uint rva)
    {
        Summary.IpSamples++;
        if (Find(rva) is { } found)
        {
            var profile = found.Function.Profile ??= new ProfileInfo();
            profile.SampleCount++;
        }
    }

    /// <param name="records">The sample's branch records, newest first.</param>
    public void AddSample(ReadOnlySpan<BranchRecord> records)
    {
        Summary.Samples++;
        for (int i = 0; i < records.Length; i++)
        {
            if (records[i].From is { } from)
            {
                Summary.Records++;
                ApplyTaken(from, records[i].To);
            }

            // records[i + 1] is older: execution ran straight from its target to records[i]'s source.
            if (i + 1 < records.Length && records[i + 1].To is { } runStart && records[i].From is { } runEnd)
            {
                ApplyStraightLine(runStart, runEnd);
            }
        }
    }

    private void ApplyTaken(uint from, uint? to)
    {
        if (_byLastInstruction.TryGetValue(from, out var owner))
        {
            ref readonly var last = ref _image.Instructions[owner.Block.InstructionStart + owner.Block.InstructionCount - 1];
            switch (last.FlowControl)
            {
                case FlowControl.Return:
                    Summary.Returns++;
                    return;
                case FlowControl.Call or FlowControl.IndirectCall:
                    CountCall(from, to);
                    return;
                case FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch:
                    if (to is { } target && owner.Block.Successors.FirstOrDefault(e => e.Kind != EdgeKind.FallThrough && (uint)e.Target.StartRva == target) is { } edge)
                    {
                        edge.ExecutionCount = (edge.ExecutionCount ?? 0) + 1;
                        Summary.TakenBranches++;
                        MarkEdgeProfile(owner.Function);
                    }
                    else if (to is not { } inside || !InFunction(owner.Function, inside))
                    {
                        Summary.TailCalls++; // leaves the function: a tail call or a thunk
                    }
                    else
                    {
                        Count("taken branch has no CFG edge");
                    }

                    return;
                default:
                    Count("source is not a branch (an interrupt or exception at that instruction)");
                    return;
            }
        }

        if (_callSites.Contains(from))
        {
            CountCall(from, to);
            return;
        }

        Count("source is not a decoded branch instruction (code not in the file, e.g. a runtime patch)");
    }

    /// <summary>
    /// Follows fall-through edges from the block containing <paramref name="start"/> to the block
    /// containing <paramref name="end"/>, counting each; a run that cannot be followed is only
    /// counted as unexplained.
    /// </summary>
    private void ApplyStraightLine(uint start, uint end)
    {
        if (end < start || Find(start) is not { } current || Find(end) is not { } last || current.Function != last.Function)
        {
            Summary.UnexplainedRuns++;
            return;
        }

        var path = new List<Edge>();
        var block = current.Block;
        for (int steps = 0; block != last.Block; steps++)
        {
            var next = block.Successors.FirstOrDefault(e => e.Kind == EdgeKind.FallThrough);
            if (next is null || steps > MaxStraightLineBlocks)
            {
                Summary.UnexplainedRuns++;
                return;
            }

            path.Add(next);
            block = next.Target;
        }

        // The run executed every block on it, also a function's only block, which has no edges
        // to count (a small leaf entered by a call and left by ret).
        _visits[current.Block] = _visits.GetValueOrDefault(current.Block) + 1;
        foreach (var edge in path)
        {
            edge.ExecutionCount = (edge.ExecutionCount ?? 0) + 1;
            _visits[edge.Target] = _visits.GetValueOrDefault(edge.Target) + 1;
        }

        Summary.FallThroughRuns++;
        Summary.FallThroughEdges += path.Count;
        if (path.Count > 0)
        {
            MarkEdgeProfile(current.Function);
        }
    }

    private void CountCall(uint site, uint? to)
    {
        Summary.Calls++;
        Summary.CallCounts[site] = Summary.CallCounts.GetValueOrDefault(site) + 1;
        if (_dynamicCallSites.Contains(site))
        {
            var targets = Summary.IndirectTargets.TryGetValue(site, out var t) ? t : Summary.IndirectTargets[site] = [];
            uint key = to ?? ProfileSummary.OutsideImage;
            targets[key] = targets.GetValueOrDefault(key) + 1;
        }
    }

    /// <summary>
    /// Derives <see cref="BasicBlock.ExecutionCount"/> from the edge counts and the straight-line
    /// runs through the block (a function's only block has no edges). Call once, after the last sample.
    /// </summary>
    public void Finish()
    {
        foreach (var (_, block) in _index.Blocks)
        {
            ulong incoming = 0, outgoing = 0;
            foreach (var edge in block.Predecessors)
            {
                incoming += edge.ExecutionCount ?? 0;
            }

            foreach (var edge in block.Successors)
            {
                outgoing += edge.ExecutionCount ?? 0;
            }

            ulong count = Math.Max(Math.Max(incoming, outgoing), _visits.GetValueOrDefault(block));
            block.ExecutionCount = count > 0 ? count : null;
        }
    }

    private static void MarkEdgeProfile(Function function) =>
        (function.Profile ??= new ProfileInfo()).HasEdgeCounts = true;

    private (Function Function, BasicBlock Block)? Find(uint rva) => _index.Find(rva);

    private static bool InFunction(Function function, uint rva) =>
        function.Ranges.Any(r => rva >= r.StartRva && rva < r.StartRva + r.Length);

    private void Count(string reason) => Summary.Unmatched[reason] = Summary.Unmatched.GetValueOrDefault(reason) + 1;
}
