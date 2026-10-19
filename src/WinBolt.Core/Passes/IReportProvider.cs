using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes;

/// <summary>Produces a human-readable report from an analyzed image (§12, Stage 3).</summary>
public interface IReportProvider
{
    string Name { get; }

    /// <summary>Whether the report has anything to say about this image (e.g. a profile report needs a profile).</summary>
    bool AppliesTo(BinaryImage image) => true;

    Report Generate(BinaryImage image, PassContext context);
}
