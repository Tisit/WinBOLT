using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>
/// Extended TSP block ordering (Newell and Pupyrev, "Improved Basic Block Reordering", IEEE
/// TC 2020), the layout BOLT uses by default. A layout scores every profiled edge by where
/// its target lands relative to the end of its source: a fall-through scores the edge's count,
/// a forward jump of up to 1024 bytes or a backward jump of up to 640 bytes scores a tenth of
/// it, decreasing linearly with distance, anything farther nothing.
/// <para>
/// Every hot block starts as its own chain. Repeatedly, the pair of chains joined by an edge
/// whose merge gains the most score is merged, trying X·Y, Y·X and, when X has at most 128
/// blocks, every split of X into X1·X2 as X1·Y·X2, Y·X2·X1 and X2·X1·Y (and the same with the
/// roles swapped). A merge that would move the entry block off the front is not allowed.
/// Merging stops when no pair gains; the remaining chains follow the entry's chain by density.
/// </para>
/// </summary>
internal static class ExtTsp
{
    private const double FallThroughWeight = 1.0;
    private const double ForwardWeight = 0.1;
    private const double BackwardWeight = 0.1;
    private const long ForwardDistance = 1024;
    private const long BackwardDistance = 640;
    private const int SplitThreshold = 128;

    public static long Size(BasicBlock block) => Math.Max(1, block.Length);

    /// <summary>Score of an edge executed <paramref name="count"/> times whose source ends at <paramref name="sourceEnd"/> and target starts at <paramref name="target"/>.</summary>
    public static double EdgeScore(double count, long sourceEnd, long target)
    {
        if (target == sourceEnd)
        {
            return count * FallThroughWeight;
        }

        if (target > sourceEnd)
        {
            long distance = target - sourceEnd;
            return distance <= ForwardDistance ? count * ForwardWeight * (1 - (double)distance / ForwardDistance) : 0;
        }

        long back = sourceEnd - target;
        return back <= BackwardDistance ? count * BackwardWeight * (1 - (double)back / BackwardDistance) : 0;
    }

    private sealed class Chain(int id, List<int> blocks)
    {
        public int Id { get; } = id;

        public List<int> Blocks { get; } = blocks;

        public long Size { get; set; }

        public double Executions { get; set; }

        public HashSet<Chain> Neighbors { get; } = [];

        /// <summary>Best merge with each higher-numbered neighbour, by that neighbour's id. Dropped with the chain when it is merged away.</summary>
        public Dictionary<int, (double Gain, Slice[] Slices)> Merges { get; } = [];
    }

    private readonly record struct Slice(Chain Chain, int From, int To);

    private sealed class Graph
    {
        public required long[] Size { get; init; }

        public required double[] Executions { get; init; }

        public required List<(int To, double Count)>[] Out { get; init; }

        public required List<(int From, double Count)>[] In { get; init; }

        /// <summary>Per block: its chain, its index in the chain, and its byte offset in the chain.</summary>
        public required Chain[] ChainOf { get; init; }

        public required int[] Index { get; init; }

        public required long[] Offset { get; init; }
    }

    /// <summary>Orders <paramref name="hot"/>; <paramref name="entry"/> comes first.</summary>
    public static List<BasicBlock> Order(IReadOnlyList<BasicBlock> hot, BasicBlock entry)
    {
        // Block 0 is the entry.
        var blocks = new List<BasicBlock> { entry };
        blocks.AddRange(hot.Where(b => b != entry).OrderBy(b => b.StartRva));
        int n = blocks.Count;
        var index = blocks.Select((b, i) => (b, i)).ToDictionary(x => x.b, x => x.i);

        var weights = new Dictionary<(int, int), double>();
        foreach (var block in blocks)
        {
            foreach (var edge in block.Successors)
            {
                if (edge.Kind is EdgeKind.FallThrough or EdgeKind.Branch && edge.Target != block &&
                    index.TryGetValue(edge.Target, out int to) && (edge.ExecutionCount ?? 0) > 0)
                {
                    var key = (index[block], to);
                    weights[key] = weights.GetValueOrDefault(key) + edge.ExecutionCount!.Value;
                }
            }
        }

        var graph = new Graph
        {
            Size = blocks.Select(Size).ToArray(),
            Executions = blocks.Select(b => (double)(b.ExecutionCount ?? 0)).ToArray(),
            Out = Enumerable.Range(0, n).Select(_ => new List<(int, double)>()).ToArray(),
            In = Enumerable.Range(0, n).Select(_ => new List<(int, double)>()).ToArray(),
            ChainOf = new Chain[n],
            Index = new int[n],
            Offset = new long[n],
        };

        foreach (var ((from, to), count) in weights.OrderBy(kv => kv.Key))
        {
            graph.Out[from].Add((to, count));
            graph.In[to].Add((from, count));
        }

        var alive = new SortedDictionary<int, Chain>();
        for (int b = 0; b < n; b++)
        {
            var chain = new Chain(b, [b]) { Size = graph.Size[b], Executions = graph.Executions[b] };
            graph.ChainOf[b] = chain;
            alive[b] = chain;
        }

        foreach (var ((from, to), _) in weights)
        {
            graph.ChainOf[from].Neighbors.Add(graph.ChainOf[to]);
            graph.ChainOf[to].Neighbors.Add(graph.ChainOf[from]);
        }

        int nextId = n;
        while (true)
        {
            (double Gain, Slice[] Slices, Chain X, Chain Y)? best = null;
            foreach (var x in alive.Values)
            {
                foreach (var y in x.Neighbors.Where(y => y.Id > x.Id).OrderBy(y => y.Id))
                {
                    if (!x.Merges.TryGetValue(y.Id, out var merge))
                    {
                        x.Merges[y.Id] = merge = BestMerge(graph, x, y);
                    }

                    if (merge.Slices.Length > 0 && (best is null || merge.Gain > best.Value.Gain))
                    {
                        best = (merge.Gain, merge.Slices, x, y);
                    }
                }
            }

            if (best is not { Gain: > 1e-9 } chosen)
            {
                break;
            }

            var merged = new Chain(nextId++, chosen.Slices.SelectMany(s => s.Chain.Blocks.GetRange(s.From, s.To - s.From)).ToList())
            {
                Size = chosen.X.Size + chosen.Y.Size,
                Executions = chosen.X.Executions + chosen.Y.Executions,
            };

            long offset = 0;
            for (int i = 0; i < merged.Blocks.Count; i++)
            {
                int b = merged.Blocks[i];
                graph.ChainOf[b] = merged;
                graph.Index[b] = i;
                graph.Offset[b] = offset;
                offset += graph.Size[b];
            }

            foreach (var neighbor in chosen.X.Neighbors.Concat(chosen.Y.Neighbors).Where(c => c != chosen.X && c != chosen.Y).Distinct())
            {
                neighbor.Neighbors.Remove(chosen.X);
                neighbor.Neighbors.Remove(chosen.Y);
                neighbor.Merges.Remove(chosen.X.Id);
                neighbor.Merges.Remove(chosen.Y.Id);
                neighbor.Neighbors.Add(merged);
                merged.Neighbors.Add(neighbor);
            }

            alive.Remove(chosen.X.Id);
            alive.Remove(chosen.Y.Id);
            alive[merged.Id] = merged;
        }

        var entryChain = graph.ChainOf[0];
        return new[] { entryChain }
            .Concat(alive.Values.Where(c => c != entryChain)
                .OrderByDescending(c => c.Executions / c.Size)
                .ThenBy(c => blocks[c.Blocks[0]].StartRva))
            .SelectMany(c => c.Blocks)
            .Select(b => blocks[b])
            .ToList();
    }

    /// <summary>The best way to merge chains <paramref name="x"/> and <paramref name="y"/>, with its gain (no slices if none is allowed).</summary>
    private static (double Gain, Slice[] Slices) BestMerge(Graph graph, Chain x, Chain y)
    {
        // Edges between the two chains; before the merge they score nothing.
        var (small, large) = x.Blocks.Count <= y.Blocks.Count ? (x, y) : (y, x);
        var cross = new List<(int From, int To, double Count)>();
        foreach (int b in small.Blocks)
        {
            cross.AddRange(graph.Out[b].Where(e => graph.ChainOf[e.To] == large).Select(e => (b, e.To, e.Count)));
            cross.AddRange(graph.In[b].Where(e => graph.ChainOf[e.From] == large).Select(e => (e.From, b, e.Count)));
        }

        double bestGain = double.NegativeInfinity;
        Slice[] bestSlices = [];
        void Consider(Slice[] slices, List<(int From, int To, double Count)> edges, double before)
        {
            // The entry block must stay in front.
            if ((graph.ChainOf[0] == x || graph.ChainOf[0] == y) && slices[0].Chain.Blocks[slices[0].From] != 0)
            {
                return;
            }

            double gain = Score(graph, slices, edges) - before;
            if (gain > bestGain + 1e-12)
            {
                bestGain = gain;
                bestSlices = slices;
            }
        }

        foreach (var (a, b) in new[] { (x, y), (y, x) })
        {
            Consider([new Slice(a, 0, a.Blocks.Count), new Slice(b, 0, b.Blocks.Count)], cross, 0);
        }

        // Splits: the split chain's own edges across the split change score too.
        foreach (var (a, b) in new[] { (x, y), (y, x) })
        {
            if (a.Blocks.Count < 2 || a.Blocks.Count > SplitThreshold)
            {
                continue;
            }

            var inside = a.Blocks.SelectMany(from => graph.Out[from].Where(e => graph.ChainOf[e.To] == a).Select(e => (from, e.To, e.Count))).ToList();
            var edges = cross.Concat(inside).ToList();
            double before = Score(graph, [new Slice(a, 0, a.Blocks.Count)], inside);
            var whole = new Slice(b, 0, b.Blocks.Count);
            for (int k = 1; k < a.Blocks.Count; k++)
            {
                var a1 = new Slice(a, 0, k);
                var a2 = new Slice(a, k, a.Blocks.Count);
                Consider([a1, whole, a2], edges, before);
                Consider([whole, a2, a1], edges, before);
                Consider([a2, a1, whole], edges, before);
            }
        }

        return (bestGain, bestSlices);
    }

    /// <summary>Score of <paramref name="edges"/> with the blocks laid out as <paramref name="slices"/> in a row.</summary>
    private static double Score(Graph graph, Slice[] slices, List<(int From, int To, double Count)> edges)
    {
        var bases = new long[slices.Length];
        long at = 0;
        for (int s = 0; s < slices.Length; s++)
        {
            bases[s] = at;
            var slice = slices[s];
            long first = graph.Offset[slice.Chain.Blocks[slice.From]];
            long end = slice.To < slice.Chain.Blocks.Count ? graph.Offset[slice.Chain.Blocks[slice.To]] : slice.Chain.Size;
            at += end - first;
        }

        long Position(int block)
        {
            var chain = graph.ChainOf[block];
            int i = graph.Index[block];
            for (int s = 0; s < slices.Length; s++)
            {
                var slice = slices[s];
                if (slice.Chain == chain && i >= slice.From && i < slice.To)
                {
                    return bases[s] + graph.Offset[block] - graph.Offset[chain.Blocks[slice.From]];
                }
            }

            throw new InvalidOperationException("block outside the slices");
        }

        double score = 0;
        foreach (var (from, to, count) in edges)
        {
            score += EdgeScore(count, Position(from) + graph.Size[from], Position(to));
        }

        return score;
    }
}
