using WinBolt.Core.Ir;

namespace WinBolt.Rewrite;

/// <summary>One function's place in a layout, with the profile weight that put it there.</summary>
public sealed record OrderedFunction(Function Function, ulong Weight, int Cluster);

/// <summary>
/// Stage 5 function ordering: C3 call-chain clustering (Ottoni and Maher, CGO 2017, the
/// algorithm behind HFSort and BOLT's <c>-reorder-functions=hfsort</c>). Only functions the
/// profile saw executing are ordered; everything else stays where the linker put it.
/// <list type="number">
/// <item>Weight: executed instructions (block execution count x instruction count).</item>
/// <item>Call graph: profiled call counts per site (direct callee, or the observed targets of an
/// indirect call), plus unconditional tail-jump edges from their block counts (a conditional
/// one's block count would overstate it).</item>
/// <item>Walking functions from hottest down, append each one's cluster to the cluster of its
/// hottest caller, unless the result would exceed <see cref="MaxClusterBytes"/> or the
/// caller's cluster is much colder (density below 1/<see cref="DensityRatio"/> of the
/// callee's), which would drag cold code between hot code.</item>
/// <item>Emit clusters by density (weight per byte), hottest first.</item>
/// </list>
/// </summary>
public static class FunctionOrdering
{
    /// <summary>C3 merges up to a page, so a caller and its hot callees share I-TLB entries.</summary>
    public const uint MaxClusterBytes = 4096;

    public const double DensityRatio = 8;

    public static List<OrderedFunction> C3(BinaryImage image)
    {
        var summary = image.ProfileSummary ?? throw new InvalidOperationException("C3 ordering needs a profile");
        var weight = new ulong[image.Functions.Count];
        foreach (var f in image.Functions)
        {
            weight[f.Id] = f.BasicBlocks.Aggregate(0UL, (sum, b) => sum + (b.ExecutionCount ?? 0) * (ulong)b.InstructionCount);
        }

        var byEntry = image.Functions.ToDictionary(f => f.EntryRva, f => f.Id);

        // Caller -> callee weights.
        var calls = new Dictionary<(int Caller, int Callee), ulong>();
        void Add(int caller, int callee, ulong count)
        {
            if (caller != callee && count > 0)
            {
                calls[(caller, callee)] = calls.GetValueOrDefault((caller, callee)) + count;
            }
        }

        foreach (var site in image.CallSites)
        {
            if (site.Kind == CallKind.Call && site.CalleeId is { } callee)
            {
                Add(site.CallerId, callee, (ulong)summary.CallCounts.GetValueOrDefault(site.SiteRva));
            }
            else if (site.Kind == CallKind.TailJump && site.CalleeId is { } tail)
            {
                Add(site.CallerId, tail, BlockCountAt(image, site));
            }
            else if (summary.IndirectTargets.TryGetValue(site.SiteRva, out var targets))
            {
                foreach (var (target, count) in targets)
                {
                    if (byEntry.TryGetValue(target, out int indirect))
                    {
                        Add(site.CallerId, indirect, (ulong)count);
                    }
                }
            }
        }

        var hottestCaller = calls
            .GroupBy(c => c.Key.Callee)
            .ToDictionary(g => g.Key, g => g.MaxBy(c => c.Value).Key.Caller);

        // Clusters: ordered member lists, merged by appending the callee's cluster to the caller's.
        var hot = image.Functions.Where(f => weight[f.Id] > 0).OrderByDescending(f => weight[f.Id]).ThenBy(f => f.EntryRva).ToList();
        var clusterOf = hot.ToDictionary(f => f.Id, f => f.Id);
        var members = hot.ToDictionary(f => f.Id, f => new List<Function> { f });
        var size = hot.ToDictionary(f => f.Id, f => (ulong)f.TotalLength);
        var clusterWeight = hot.ToDictionary(f => f.Id, f => weight[f.Id]);
        double Density(int cluster) => (double)clusterWeight[cluster] / Math.Max(1UL, size[cluster]);

        foreach (var f in hot)
        {
            if (!hottestCaller.TryGetValue(f.Id, out int caller) || !clusterOf.TryGetValue(caller, out int into))
            {
                continue;
            }

            int from = clusterOf[f.Id];
            if (into == from || size[into] + size[from] > MaxClusterBytes || Density(into) * DensityRatio < Density(from))
            {
                continue;
            }

            foreach (var member in members[from])
            {
                clusterOf[member.Id] = into;
            }

            members[into].AddRange(members[from]);
            size[into] += size[from];
            clusterWeight[into] += clusterWeight[from];
            members.Remove(from);
        }

        var order = new List<OrderedFunction>();
        int index = 0;
        foreach (var cluster in members.Keys.OrderByDescending(Density).ThenBy(c => members[c][0].EntryRva))
        {
            order.AddRange(members[cluster].Select(f => new OrderedFunction(f, weight[f.Id], index)));
            index++;
        }

        return order;
    }

    /// <summary>
    /// Startup order (DesignDoc "Step 27"): every function the trace touched, in the order it
    /// first ran (<paramref name="firstTouch"/>: function id → ms, EtwLbrProfile.FirstTouch). Code
    /// that starts together sits together, so a run that has touched its first k functions has
    /// faulted in about as many pages as those k functions fill, not one page per function
    /// scattered over the image. Each function is its own cluster; weight as in <see cref="C3"/>.
    /// </summary>
    public static List<OrderedFunction> FirstUse(BinaryImage image, IReadOnlyDictionary<int, double> firstTouch)
    {
        var order = new List<OrderedFunction>();
        foreach (var (id, _) in firstTouch.OrderBy(t => t.Value).ThenBy(t => image.Functions[t.Key].EntryRva))
        {
            var f = image.Functions[id];
            ulong weight = f.BasicBlocks.Aggregate(0UL, (sum, b) => sum + (b.ExecutionCount ?? 0) * (ulong)b.InstructionCount);
            order.Add(new OrderedFunction(f, weight, order.Count));
        }

        return order;
    }

    /// <summary>A tail jump runs as often as the block containing it.</summary>
    private static ulong BlockCountAt(BinaryImage image, CallSite site) =>
        image.Functions[site.CallerId].BasicBlocks
            .FirstOrDefault(b => b.StartRva <= site.SiteRva && site.SiteRva < b.StartRva + b.Length)?.ExecutionCount ?? 0;
}
