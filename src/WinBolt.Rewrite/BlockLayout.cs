using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// A function's block order: hot blocks (entry first) stay at the function's new address, cold
/// blocks go to a separate cold area. Every block appears in exactly one list.
/// </summary>
public sealed record BlockOrder(IReadOnlyList<BasicBlock> Hot, IReadOnlyList<BasicBlock> Cold)
{
    /// <summary>The original order: every block, by address, none cold.</summary>
    public static BlockOrder Original(Function f) => new(f.EntryBlocks.OrderBy(b => b.StartRva).ToList(), []);

    /// <summary>Why this is not a valid order for <paramref name="f"/>, or null.</summary>
    public string? Problem(Function f)
    {
        if (Hot.Count == 0 || Hot[0].StartRva != f.EntryRva)
        {
            return "the entry block is not the first hot block";
        }

        var all = Hot.Concat(Cold).ToList();
        var blocks = f.EntryBlocks.ToHashSet();
        return all.Count == blocks.Count && all.ToHashSet().SetEquals(blocks) ? null : "the order does not list every block of the entry range exactly once";
    }
}

public enum BlockLayoutAlgorithm
{
    /// <summary>Pettis–Hansen: greedy chaining along the heaviest edges. The default: faster on speedtest1 (DesignDoc Stage 6, step 3).</summary>
    Chains,

    /// <summary>
    /// Extended TSP (Newell and Pupyrev, 2020), BOLT's default: maximizes fall-throughs and short
    /// jumps. More fall-throughs than <see cref="Chains"/> on speedtest1, but measurably slower.
    /// </summary>
    ExtTsp,
}

/// <summary>
/// Stage 6 block layout from an edge profile. Hot blocks (executed in the profile, plus the
/// entry) are ordered by <see cref="BlockLayoutAlgorithm"/>; the entry block comes first (the
/// prologue must start the function). Cold blocks (never executed in the profile) keep their
/// original order and, with <c>split</c>, go to the cold area, away from the hot code;
/// otherwise they follow the hot blocks.
/// </summary>
public static class BlockLayout
{
    public static BlockOrder Order(Function f, bool split = true, BlockLayoutAlgorithm algorithm = BlockLayoutAlgorithm.Chains)
    {
        var blocks = f.EntryBlocks.OrderBy(b => b.StartRva).ToList();
        var entry = blocks.First(b => b.StartRva == f.EntryRva);
        var hot = blocks.Where(b => b == entry || (b.ExecutionCount ?? 0) > 0).ToList();
        var ordered = algorithm == BlockLayoutAlgorithm.ExtTsp ? ExtTsp.Order(hot, entry) : Chains(hot, entry);
        var cold = blocks.Where(b => b != entry && (b.ExecutionCount ?? 0) == 0).ToList();
        return split ? new BlockOrder(ordered, cold) : new BlockOrder([.. ordered, .. cold], []);
    }

    /// <summary>
    /// The ext-TSP score of a sequence of blocks laid out contiguously (original block sizes):
    /// the profiled edges it turns into fall-throughs, plus a little for short jumps.
    /// </summary>
    public static double Score(IReadOnlyList<BasicBlock> sequence)
    {
        var at = new Dictionary<BasicBlock, long>();
        long offset = 0;
        foreach (var block in sequence)
        {
            at[block] = offset;
            offset += ExtTsp.Size(block);
        }

        return sequence.SelectMany(b => b.Successors)
            .Where(e => e.Kind is EdgeKind.FallThrough or EdgeKind.Branch && e.Source != e.Target && at.ContainsKey(e.Target))
            .Sum(e => ExtTsp.EdgeScore(e.ExecutionCount ?? 0, at[e.Source] + ExtTsp.Size(e.Source), at[e.Target]));
    }

    /// <summary>
    /// Pettis and Hansen's bottom-up positioning: an edge u→v, heaviest first, merges the chain
    /// ending in u with the chain starting at v, so the hot successor becomes the fall-through.
    /// The entry block's chain comes first; the other chains follow by density.
    /// </summary>
    private static List<BasicBlock> Chains(List<BasicBlock> hotBlocks, BasicBlock entry)
    {
        var hot = hotBlocks.ToHashSet();
        var chainOf = hot.ToDictionary(b => b, b => new List<BasicBlock> { b });
        var edges = hot
            .SelectMany(b => b.Successors)
            .Where(e => e.Kind is EdgeKind.FallThrough or EdgeKind.Branch && hot.Contains(e.Target) && e.Target != e.Source)
            .OrderByDescending(e => e.ExecutionCount ?? 0)
            .ThenBy(e => e.Kind == EdgeKind.FallThrough ? 0 : 1) // ties keep the original fall-through
            .ThenBy(e => e.Source.StartRva);
        foreach (var edge in edges)
        {
            var head = chainOf[edge.Source];
            var tail = chainOf[edge.Target];
            if (head == tail || head[^1] != edge.Source || tail[0] != edge.Target || edge.Target == entry)
            {
                continue;
            }

            head.AddRange(tail);
            foreach (var block in tail)
            {
                chainOf[block] = head;
            }
        }

        var chains = chainOf.Values.Distinct().ToList();
        static double Density(List<BasicBlock> chain) =>
            chain.Sum(b => (double)(b.ExecutionCount ?? 0)) / Math.Max(1, chain.Sum(b => (long)b.Length));
        return chains.Where(c => c.Contains(entry))
            .Concat(chains.Where(c => !c.Contains(entry)).OrderByDescending(Density).ThenBy(c => c[0].StartRva))
            .SelectMany(c => c)
            .ToList();
    }
}
