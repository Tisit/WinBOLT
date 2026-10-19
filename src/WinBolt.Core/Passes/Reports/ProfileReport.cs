using System.Text;
using WinBolt.Core.Ir;
using WinBolt.Core.Profile;

namespace WinBolt.Core.Passes.Reports;

/// <summary>
/// Stage 2 "profile coverage and binding report": how the profile was bound, how much of it
/// the CFG explains, and where the time goes.
/// </summary>
[RegisterPass]
public sealed class ProfileReport : IReportProvider
{
    private const int TopFunctions = 12;
    private const int TopCallSites = 10;

    public string Name => "Profile";

    public bool AppliesTo(BinaryImage image) => image.ProfileSummary is not null;

    public Report Generate(BinaryImage image, PassContext context)
    {
        var summary = image.ProfileSummary!;
        var body = new StringBuilder();
        body.AppendLine($"Binding: {summary.Binding}");
        body.AppendLine($"Fidelity: {summary.Fidelity}");
        body.AppendLine($"{summary.Samples:N0} LBR samples touching the image, {summary.Records:N0} branch records from it, {summary.IpSamples:N0} IP samples in it");

        if (summary.Records > 0)
        {
            body.AppendLine($"Records matched to the CFG: {Percent(summary.MatchedRecords, summary.Records)} " +
                            $"(taken branches {summary.TakenBranches:N0}, calls {summary.Calls:N0}, returns {summary.Returns:N0}, tail calls {summary.TailCalls:N0})");
            foreach (var (reason, count) in summary.Unmatched.OrderByDescending(kv => kv.Value))
            {
                body.AppendLine($"  unmatched: {reason}: {count:N0}");
            }

            long runs = summary.FallThroughRuns + summary.UnexplainedRuns;
            body.AppendLine($"Straight-line runs explained by fall-through edges: {Percent(summary.FallThroughRuns, runs)} " +
                            $"({summary.FallThroughEdges:N0} fall-through edge executions recovered)");
        }

        var levels = CodeFootprint.Compute(image, 0.90, 0.99);
        if (levels.Count > 0)
        {
            body.AppendLine();
            body.AppendLine("Hot code footprint: fewest blocks covering a share of executed bytes, and the 4 KB pages / 64 B lines");
            body.AppendLine("they touch now against packed layouts (ideal lower bounds, alignment ignored):");
            body.AppendLine($"  {"coverage",8} {"blocks",7} {"funcs",6}   {"now",-13}   {"by range (St. 4-5)",-19}   {"by block (St. 6)",-17}");
            foreach (var level in levels)
            {
                body.AppendLine($"  {level.Coverage,8:P0} {level.Blocks,7:N0} {level.Functions,6:N0}   " +
                                $"{$"{level.PagesNow} pg / {level.LinesNow} ln",-13}   " +
                                $"{$"{level.PagesPackedRanges} pg / {level.LinesPackedRanges} ln",-19}   " +
                                $"{$"{level.PagesPackedBlocks} pg / {level.LinesPackedBlocks} ln",-17}");
            }
        }

        if (summary.CallCounts.Count > 0)
        {
            var sites = image.CallSites.GroupBy(c => c.SiteRva).ToDictionary(g => g.Key, g => g.First());
            var imports = image.Imports.GroupBy(i => i.IatSlotRva).ToDictionary(g => g.Key, g => g.First());
            body.AppendLine();
            body.AppendLine("Most frequent call sites (profiled executions):");
            foreach (var (site, count) in summary.CallCounts.OrderByDescending(kv => kv.Value).Take(TopCallSites))
            {
                string caller = "?", callee = "?";
                if (sites.TryGetValue(site, out var call))
                {
                    caller = Describe(image.Functions[call.CallerId]);
                    callee = call.CalleeId is { } id ? Describe(image.Functions[id])
                        : call.PointerRva is { } slot && imports.TryGetValue(slot, out var import) ? $"{import.Dll}!{import.Name ?? $"#{import.Ordinal}"}"
                        : call.Kind == CallKind.IndirectCall ? "(indirect)"
                        : call.TargetRva is { } t ? $"0x{t:X}" : "?";
                }

                body.AppendLine($"  {count,10:N0}  0x{site:X}  {caller} -> {callee}");
            }
        }

        var hot = image.Functions.Where(f => f.Profile is { SampleCount: > 0 }).OrderByDescending(f => f.Profile!.SampleCount).Take(TopFunctions).ToList();
        if (hot.Count > 0)
        {
            ulong inFunctions = (ulong)image.Functions.Sum(f => (long)(f.Profile?.SampleCount ?? 0));
            body.AppendLine();
            body.AppendLine("Hottest functions (IP samples; edges with a count / all edges; safety level):");
            foreach (var f in hot)
            {
                var edges = f.BasicBlocks.SelectMany(b => b.Successors).ToList();
                int counted = edges.Count(e => e.ExecutionCount is > 0);
                string name = f.DisplayName;
                if (name.Length > 48)
                {
                    name = name[..45] + "...";
                }

                body.AppendLine($"  {name,-48} {f.Profile!.SampleCount,10:N0} {Percent((long)f.Profile.SampleCount, (long)inFunctions),7}  " +
                                $"edges {counted,4}/{edges.Count,-4}  {f.SafetyStatus.Level}");
            }
        }

        var confidence = summary.Fidelity == ProfileFidelity.EdgeAccurate ? ReportConfidence.High : ReportConfidence.Medium;
        return new Report { Title = "Profile", Body = body.ToString(), Confidence = confidence };
    }

    private static string Describe(Function f)
    {
        string name = f.DisplayName;
        return name.Length > 40 ? name[..37] + "..." : name;
    }

    private static string Percent(long part, long whole) => whole == 0 ? "-" : $"{100.0 * part / whole:F1}%";
}
