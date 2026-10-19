using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Reports;

namespace WinBolt.Core.Profile;

public enum RecommendationKind
{
    FrontEndTriage,
    BiasedBranch,
    ColdCodeInHotFunction,
    HotTinyFunction,
    DominantIndirectTarget,
    CpuDispatch,
}

/// <summary>One Stage 3 finding. <see cref="Suggestion"/> names the stage or source change that acts on it.</summary>
public sealed record Recommendation(RecommendationKind Kind, ReportConfidence Confidence, string Where, string Finding, string Suggestion);

/// <summary>
/// Stage 3 static performance advisor over a profiled image. Every finding is computed from
/// measured data (profile edge counts, observed call targets, the hot footprint) against
/// the thresholds below; nothing is inferred from names or guessed.
/// </summary>
public static class Advisor
{
    /// <summary>A branch or call site needs this many profiled executions before its ratio means anything.</summary>
    public const long MinExecutions = 100;

    /// <summary>Share of a conditional branch's executions going to the taken side to call it biased.</summary>
    public const double BiasThreshold = 0.90;

    /// <summary>Share of an indirect call site's calls going to one target to call it dominant.</summary>
    public const double DominanceThreshold = 0.90;

    /// <summary>Largest function (bytes) counted as tiny for inlining.</summary>
    public const int TinyFunctionBytes = 32;

    /// <summary>A hot function whose executed bytes are below this share of its bytes carries cold code.</summary>
    public const double ColdShareThreshold = 0.50;

    /// <summary>Smallest function (bytes) worth splitting.</summary>
    public const int MinSplitBytes = 256;

    private const int MaxPerKind = 8;

    public static IReadOnlyList<Recommendation> Analyze(BinaryImage image, CpuModel cpu)
    {
        var results = new List<Recommendation>();
        if (image.ProfileSummary is not { } summary)
        {
            return results;
        }

        var footprint = CodeFootprint.Compute(image, 0.90, 0.99);
        var hot = HotFunctions(image);
        results.AddRange(FrontEnd(footprint, cpu));
        results.AddRange(BiasedBranches(image));
        results.AddRange(ColdCode(hot));
        results.AddRange(TinyFunctions(image, summary));
        results.AddRange(IndirectCalls(image, summary));
        return results;
    }

    /// <summary>Functions owning the blocks that cover 90% of executed bytes.</summary>
    private static HashSet<Function> HotFunctions(BinaryImage image)
    {
        var blocks = image.Functions
            .SelectMany(f => f.BasicBlocks.Where(b => b.ExecutionCount > 0).Select(b => (Function: f, Weight: (double)b.ExecutionCount!.Value * b.Length)))
            .OrderByDescending(x => x.Weight)
            .ToList();
        double total = blocks.Sum(x => x.Weight), covered = 0;
        var hot = new HashSet<Function>();
        foreach (var (function, weight) in blocks)
        {
            if (covered >= 0.90 * total)
            {
                break;
            }

            hot.Add(function);
            covered += weight;
        }

        return hot;
    }

    /// <summary>
    /// Proxy triage: the image's hot footprint against L1i and I-TLB reach. It is a lower bound
    /// on front-end pressure (other modules and the OS share both), so a footprint that fits
    /// means little headroom from laying out this image, not a proven front-end-bound verdict.
    /// The verdict uses the 90% footprint, the steady-state working set; the 99% one is shown
    /// for context, because its tail is often one-time code (process start-up) that never
    /// competes for the cache in steady state.
    /// </summary>
    private static IEnumerable<Recommendation> FrontEnd(IReadOnlyList<FootprintLevel> levels, CpuModel cpu)
    {
        if (levels.FirstOrDefault(l => l.Coverage >= 0.90) is not { } level)
        {
            yield break;
        }

        string tail = levels.LastOrDefault() is { } wide && wide != level
            ? $" At {wide.Coverage:P0}: {wide.LinesNow:N0} lines, {wide.PagesNow:N0} pages."
            : string.Empty;

        double lineShare = (double)level.LinesNow / cpu.L1iLines;
        double pageShare = (double)level.PagesNow / cpu.ItlbEntries;
        string verdict = lineShare > 1 || pageShare > 1
            ? "exceeds the L1i or I-TLB on its own: front-end pressure from this image is likely, and layout has headroom"
            : lineShare > 0.5 || pageShare > 0.5
                ? "takes a large share of the L1i or I-TLB: layout headroom is plausible once other code competes"
                : "fits comfortably: little front-end headroom from laying out this image";
        yield return new Recommendation(
            RecommendationKind.FrontEndTriage,
            ReportConfidence.Medium,
            "image",
            $"code covering {level.Coverage:P0} of executed bytes touches {level.LinesNow:N0} lines ({lineShare:P0} of L1i) and {level.PagesNow:N0} pages ({pageShare:P0} of I-TLB reach); {verdict}.{tail} [{cpu.Source}]",
            $"packed by range {level.PagesPackedRanges} pages / {level.LinesPackedRanges} lines (Stages 4-5), by block {level.PagesPackedBlocks} / {level.LinesPackedBlocks} (Stage 6); confirm with VTune's Front-End Bound metric before optimizing");
    }

    /// <summary>
    /// Taken-biased forward conditional branches: the hot path jumps and the cold path falls
    /// through. Backward branches are excluded: a mostly-taken backward branch is a loop, and
    /// that is its correct layout.
    /// </summary>
    private static IEnumerable<Recommendation> BiasedBranches(BinaryImage image)
    {
        var candidates = new List<(Function Function, BasicBlock Block, ulong Taken, ulong NotTaken)>();
        foreach (var function in image.Functions)
        {
            foreach (var block in function.BasicBlocks)
            {
                var taken = block.Successors.FirstOrDefault(e => e.Kind == EdgeKind.Branch);
                var notTaken = block.Successors.FirstOrDefault(e => e.Kind == EdgeKind.FallThrough);
                if (taken is null || notTaken is null || taken.Target.StartRva <= block.StartRva)
                {
                    continue; // not a forward conditional branch with both sides in the function
                }

                ulong t = taken.ExecutionCount ?? 0, n = notTaken.ExecutionCount ?? 0;
                if (t + n >= MinExecutions && t >= BiasThreshold * (t + n))
                {
                    candidates.Add((function, block, t, n));
                }
            }
        }

        foreach (var (function, block, t, n) in candidates.OrderByDescending(c => c.Taken).Take(MaxPerKind))
        {
            yield return new Recommendation(
                RecommendationKind.BiasedBranch,
                ReportConfidence.High,
                $"{Name(function)} block 0x{block.StartRva:X}",
                $"taken {t:N0} of {t + n:N0} times ({(double)t / (t + n):P0}); the cold side is the fall-through",
                function.SafetyStatus.Level == Transformability.FullyTransformable
                    ? "invert the branch so the hot side falls through (Stage 6 branch layout)"
                    : $"source change: mark the fall-through path unlikely; WinBolt cannot reorder this function ({function.SafetyStatus.Level})");
        }
    }

    private static IEnumerable<Recommendation> ColdCode(HashSet<Function> hot)
    {
        foreach (var function in hot.OrderByDescending(f => f.BasicBlocks.Sum(b => (double)(b.ExecutionCount ?? 0) * b.Length)).Take(MaxPerKind * 2))
        {
            long total = function.TotalLength;
            long executed = function.BasicBlocks.Where(b => b.ExecutionCount > 0).Sum(b => (long)b.Length);
            if (total < MinSplitBytes || executed >= ColdShareThreshold * total)
            {
                continue;
            }

            yield return new Recommendation(
                RecommendationKind.ColdCodeInHotFunction,
                ReportConfidence.Medium,
                Name(function),
                $"hot, but only {executed:N0} of {total:N0} bytes ({(double)executed / total:P0}) executed in the profile",
                function.Ranges.Count > 1
                    ? "already split; move its cold ranges away from hot code (Stage 5 hot/cold placement)"
                    : "hot/cold splitting would keep the cold bytes out of hot pages (Stage 6; or /LTCG:PGO at source)");
        }
    }

    private static IEnumerable<Recommendation> TinyFunctions(BinaryImage image, ProfileSummary summary)
    {
        var callsTo = new Dictionary<int, long>();
        foreach (var site in image.CallSites)
        {
            if (site.CalleeId is { } callee && summary.CallCounts.TryGetValue(site.SiteRva, out long count))
            {
                callsTo[callee] = callsTo.GetValueOrDefault(callee) + count;
            }
        }

        foreach (var (id, calls) in callsTo.Where(kv => kv.Value >= MinExecutions).OrderByDescending(kv => kv.Value).Take(MaxPerKind * 4))
        {
            var function = image.Functions[id];
            if (function.TotalLength > TinyFunctionBytes)
            {
                continue;
            }

            yield return new Recommendation(
                RecommendationKind.HotTinyFunction,
                ReportConfidence.Medium,
                Name(function),
                $"{function.TotalLength} bytes, called {calls:N0} times in the profile",
                "inline it at source (or with LTCG); a post-link rewriter does not inline");
        }
    }

    private static IEnumerable<Recommendation> IndirectCalls(BinaryImage image, ProfileSummary summary)
    {
        var entries = image.Functions.ToDictionary(f => f.EntryRva);
        var sites = image.CallSites.GroupBy(c => c.SiteRva).ToDictionary(g => g.Key, g => g.First());
        foreach (var (site, targets) in summary.IndirectTargets.OrderByDescending(kv => kv.Value.Values.Sum()).Take(MaxPerKind * 4))
        {
            long total = targets.Values.Sum();
            var (target, count) = targets.MaxBy(kv => kv.Value);
            if (total < MinExecutions || count < DominanceThreshold * total)
            {
                continue;
            }

            string caller = sites.TryGetValue(site, out var call) ? Name(image.Functions[call.CallerId]) : "?";
            entries.TryGetValue(target, out var callee);
            string calleeName = target == ProfileSummary.OutsideImage ? "a target outside the image" : callee is null ? $"0x{target:X}" : Name(callee);
            var tier = callee is null ? FeatureTier.Base : Tier(image, callee);

            if (targets.Count == 1 && tier > FeatureTier.Sse2Baseline)
            {
                yield return new Recommendation(
                    RecommendationKind.CpuDispatch,
                    ReportConfidence.Medium,
                    $"{caller} call at 0x{site:X}",
                    $"always calls {calleeName} ({count:N0} calls), which needs {tier}: a CPU dispatch that never varies here",
                    "specialize for the deployment CPU (Stage 7), or build with that target");
            }
            else
            {
                yield return new Recommendation(
                    RecommendationKind.DominantIndirectTarget,
                    ReportConfidence.High,
                    $"{caller} call at 0x{site:X}",
                    $"{(double)count / total:P0} of {total:N0} calls go to {calleeName} ({targets.Count} targets seen)",
                    "guarded direct call to the dominant target (indirect call promotion, Stage 8), or devirtualize at source");
            }
        }
    }

    private static FeatureTier Tier(BinaryImage image, Function function)
    {
        var tier = FeatureTier.Base;
        foreach (var block in function.BasicBlocks)
        {
            foreach (ref readonly var instruction in image.Instructions.Slice(block.InstructionStart, block.InstructionCount))
            {
                var t = InstructionHistogram.TierOf(instruction);
                if (t > tier)
                {
                    tier = t;
                }
            }
        }

        return tier;
    }

    private static string Name(Function f)
    {
        string name = f.DisplayName;
        return name.Length > 48 ? name[..45] + "..." : name;
    }
}
