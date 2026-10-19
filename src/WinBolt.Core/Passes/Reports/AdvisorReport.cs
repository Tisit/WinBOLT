using System.Text;
using WinBolt.Core.Ir;
using WinBolt.Core.Profile;

namespace WinBolt.Core.Passes.Reports;

/// <summary>Stage 3 static performance advisor: <see cref="Advisor"/> findings grouped by kind, each with its confidence (§12).</summary>
[RegisterPass]
public sealed class AdvisorReport : IReportProvider
{
    public string Name => "Advisor";

    public bool AppliesTo(BinaryImage image) => image.ProfileSummary is not null;

    public Report Generate(BinaryImage image, PassContext context)
    {
        var findings = Advisor.Analyze(image, CpuModel.Detect());
        var body = new StringBuilder();
        if (findings.Count == 0)
        {
            body.AppendLine("No findings: nothing in the profile crosses the advisor's thresholds.");
        }

        foreach (var group in findings.GroupBy(f => f.Kind))
        {
            body.AppendLine($"{Title(group.Key)} (confidence: {group.First().Confidence})");
            foreach (var finding in group)
            {
                body.AppendLine($"  {finding.Where}");
                body.AppendLine($"      {finding.Finding}");
                body.AppendLine($"      -> {finding.Suggestion}");
            }

            body.AppendLine();
        }

        body.AppendLine($"Thresholds: at least {Advisor.MinExecutions} executions; branch bias {Advisor.BiasThreshold:P0}; " +
                        $"dominant target {Advisor.DominanceThreshold:P0}; tiny function <= {Advisor.TinyFunctionBytes} B; " +
                        $"cold code when under {Advisor.ColdShareThreshold:P0} of a >= {Advisor.MinSplitBytes} B hot function executes.");

        return new Report { Title = "Advisor (Stage 3)", Body = body.ToString(), Confidence = ReportConfidence.Medium };
    }

    private static string Title(RecommendationKind kind) => kind switch
    {
        RecommendationKind.FrontEndTriage => "Front-end triage (proxy: hot footprint against L1i / I-TLB)",
        RecommendationKind.BiasedBranch => "Biased branches laid out against the hot path",
        RecommendationKind.ColdCodeInHotFunction => "Cold code in hot functions",
        RecommendationKind.HotTinyFunction => "Hot tiny functions",
        RecommendationKind.DominantIndirectTarget => "Indirect calls with a dominant target",
        RecommendationKind.CpuDispatch => "CPU dispatch that always selects the same implementation",
        _ => kind.ToString(),
    };
}
