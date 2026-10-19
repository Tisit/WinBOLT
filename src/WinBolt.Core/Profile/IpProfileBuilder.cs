using WinBolt.Core.Ir;
using WinBolt.Core.Passes;

namespace WinBolt.Core.Profile;

/// <summary>How a block's execution count is estimated from the samples that landed in it.</summary>
public enum IpEstimator
{
    /// <summary>Samples in the block divided by its instruction count: uniform time per instruction.</summary>
    Mean,

    /// <summary>The most-sampled instruction's samples: the block ran at least that often (AutoFDO's choice).</summary>
    Max,
}

/// <summary>
/// A profile from sampled instruction pointers alone (DesignDoc Step 22): no branch records, so no CPU
/// with an LBR, only the periodic sample every ETW profile session takes. Block counts are estimated
/// from the samples (<see cref="IpEstimator"/>), made consistent along straight-line code, and edge
/// counts are the balance of the block counts (iterative proportional fitting of each block's outgoing
/// edges to its own count and its incoming edges to the count of the block they enter). Direct call
/// counts are the count of the block holding the call. Indirect targets are not known.
/// <para>
/// The result is an <em>estimate</em>: its fidelity is <see cref="ProfileFidelity.SamplingOnly"/>, and
/// a block sampled zero times is treated as never executed, so a cold-splitting layout may move code
/// that runs. Callers ask for it explicitly.
/// </para>
/// </summary>
public sealed class IpProfileBuilder
{
    private const double Scale = 1000;
    private const int PropagationRounds = 8;
    private const int FittingRounds = 12;

    /// <summary>
    /// Samples a predecessor needs for an unsampled successor to count as cold. Measured on four targets
    /// (DesignDoc Step 22): at 16 samples the estimate moves executed code to the cold part (speedtest1
    /// lost all of its gain), at 500 ripgrep, zopfli and 7-Zip reach the gain of a branch-record profile.
    /// </summary>
    private const double MinEvidenceSamples = 500;

    /// <summary>Warm blocks run this fraction as often as their most-sampled predecessor.</summary>
    private const double WarmFraction = 0.25;

    private readonly BinaryImage _image;
    private readonly IpEstimator _estimator;
    private readonly BlockIndex _index;
    private readonly Dictionary<uint, int> _instructionSamples = [];
    private readonly Dictionary<BasicBlock, long> _blockSamples = [];

    public ProfileSummary Summary { get; } = new();

    public IpProfileBuilder(BinaryImage image, IpEstimator estimator = IpEstimator.Mean)
    {
        _image = image;
        _estimator = estimator;
        _index = new BlockIndex(image);
    }

    /// <summary>A sampled instruction pointer inside the image.</summary>
    public void AddSample(uint rva)
    {
        Summary.IpSamples++;
        if (_index.Find(rva) is not { } found)
        {
            return;
        }

        var (function, block) = found;
        (function.Profile ??= new ProfileInfo()).SampleCount++;
        _blockSamples[block] = _blockSamples.GetValueOrDefault(block) + 1;

        // The sample belongs to the instruction containing it.
        for (int k = block.InstructionStart; k < block.InstructionStart + block.InstructionCount; k++)
        {
            ref readonly var x = ref _image.Instructions[k];
            if (rva >= x.IP && rva < x.NextIP)
            {
                _instructionSamples[(uint)x.IP] = _instructionSamples.GetValueOrDefault((uint)x.IP) + 1;
                break;
            }
        }
    }

    /// <summary>Derives block, edge and call counts from the samples. Call once, after the last sample.</summary>
    public void Finish()
    {
        var count = new Dictionary<BasicBlock, double>();
        foreach (var (_, block) in _index.Blocks)
        {
            if (!_blockSamples.TryGetValue(block, out long samples))
            {
                continue;
            }

            count[block] = _estimator == IpEstimator.Max
                ? Enumerable.Range(block.InstructionStart, block.InstructionCount).Max(k => _instructionSamples.GetValueOrDefault((uint)_image.Instructions[k].IP))
                : (double)samples / block.InstructionCount;
        }

        // Straight-line code runs as often at both ends: a block whose only way in (or out) is an edge
        // to (from) a block with no other way out (in) is executed exactly as often as that block. Short
        // blocks a sample never hit inherit the count of their neighbours.
        for (int round = 0; round < PropagationRounds; round++)
        {
            bool changed = false;
            foreach (var (_, block) in _index.Blocks)
            {
                double own = count.GetValueOrDefault(block);
                double best = own;
                if (block.Predecessors.Count == 1 && block.Predecessors[0].Source.Successors.Count == 1)
                {
                    best = Math.Max(best, count.GetValueOrDefault(block.Predecessors[0].Source));
                }

                if (block.Successors.Count == 1 && block.Successors[0].Target.Predecessors.Count == 1)
                {
                    best = Math.Max(best, count.GetValueOrDefault(block.Successors[0].Target));
                }

                if (best > own)
                {
                    count[block] = best;
                    changed = true;
                }
            }

            if (!changed)
            {
                break;
            }
        }

        // A block no sample hit is only known to be cold if the code that leads to it was itself seen
        // often enough to have shown it: a predecessor with too few samples proves nothing (the sqlite
        // interpreter has 800 functions and a few thousand samples), and moving code that runs to the
        // cold part costs more than leaving code that does not run in the hot one. Such a block is
        // treated as warm: a fraction of its most-sampled predecessor.
        var warm = new Dictionary<BasicBlock, double>();
        foreach (var (_, block) in _index.Blocks)
        {
            if (count.GetValueOrDefault(block) > 0)
            {
                continue;
            }

            double best = 0;
            foreach (var edge in block.Predecessors)
            {
                double evidence = count.GetValueOrDefault(edge.Source) * edge.Source.InstructionCount; // the predecessor's samples
                if (evidence > 0 && evidence < MinEvidenceSamples)
                {
                    best = Math.Max(best, count.GetValueOrDefault(edge.Source));
                }
            }

            if (best > 0)
            {
                warm[block] = best * WarmFraction;
            }
        }

        foreach (var (block, n) in warm)
        {
            count[block] = n;
        }

        foreach (var (_, block) in _index.Blocks)
        {
            double n = count.GetValueOrDefault(block) * Scale;
            block.ExecutionCount = n >= 1 ? (ulong)Math.Round(n) : null;
        }

        FitEdges(count);

        foreach (var site in _image.CallSites)
        {
            if (site.Kind is not (CallKind.Call or CallKind.IndirectCall) || (site.PointerRva is null && site.Kind == CallKind.IndirectCall))
            {
                continue;
            }

            if (BlockContaining(site.SiteRva) is { } block && block.ExecutionCount is { } executions)
            {
                Summary.CallCounts[site.SiteRva] = (long)executions;
                Summary.Calls += (long)executions;
            }
        }

        Summary.Samples = _blockSamples.Values.Sum();
        Summary.Fidelity = ProfileFidelity.SamplingOnly;
    }

    /// <summary>
    /// Edge counts that add up: start each block's execution count spread over its outgoing edges, then
    /// alternately scale the edges into each block to that block's count and the edges out of each block
    /// to its count, until both sums are as close as the graph allows. Only edges whose both ends were
    /// executed get a count.
    /// </summary>
    private void FitEdges(Dictionary<BasicBlock, double> count)
    {
        var edges = new List<(Edge Edge, double Weight)>();
        foreach (var (_, block) in _index.Blocks)
        {
            double n = count.GetValueOrDefault(block);
            if (n <= 0 || block.Successors.Count == 0)
            {
                continue;
            }

            var live = block.Successors.Where(e => count.GetValueOrDefault(e.Target) > 0).ToList();
            foreach (var edge in live)
            {
                edges.Add((edge, n / live.Count));
            }
        }

        var weights = edges.Select(e => e.Weight).ToArray();
        var bySource = edges.Select((e, i) => (e.Edge.Source, Index: i)).GroupBy(x => x.Source).ToDictionary(g => g.Key, g => g.Select(x => x.Index).ToArray());
        var byTarget = edges.Select((e, i) => (e.Edge.Target, Index: i)).GroupBy(x => x.Target).ToDictionary(g => g.Key, g => g.Select(x => x.Index).ToArray());
        for (int round = 0; round < FittingRounds; round++)
        {
            foreach (var (target, indexes) in byTarget)
            {
                Rescale(weights, indexes, count.GetValueOrDefault(target));
            }

            foreach (var (source, indexes) in bySource)
            {
                Rescale(weights, indexes, count.GetValueOrDefault(source));
            }
        }

        for (int i = 0; i < edges.Count; i++)
        {
            double n = weights[i] * Scale;
            edges[i].Edge.ExecutionCount = n >= 1 ? (ulong)Math.Round(n) : null;
        }

        foreach (var (function, _) in _index.Blocks.DistinctBy(b => b.Function))
        {
            if (function.Profile is { } profile)
            {
                profile.HasEdgeCounts = true;
            }
        }
    }

    private static void Rescale(double[] weights, int[] indexes, double target)
    {
        double sum = 0;
        foreach (int i in indexes)
        {
            sum += weights[i];
        }

        if (sum <= 0)
        {
            return;
        }

        double factor = target / sum;
        foreach (int i in indexes)
        {
            weights[i] *= factor;
        }
    }

    private BasicBlock? BlockContaining(uint rva) => _index.Find(rva)?.Block;
}
