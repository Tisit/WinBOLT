namespace WinBolt.Core.Passes;

public enum ReportConfidence
{
    High,
    Medium,
    Experimental,
}

/// <summary>One finding or section of a Stage 3+ report (§12). Rendering to HTML/Markdown is a writer concern, not this type's.</summary>
public sealed class Report
{
    public required string Title { get; init; }

    public required string Body { get; init; }

    public ReportConfidence Confidence { get; init; } = ReportConfidence.Medium;
}
