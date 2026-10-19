using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes;

/// <summary>
/// Populates or refines the IR without modifying it toward an output binary — CFG
/// recovery, jump table recovery, the safety gate, etc. (§7, Stage 1).
/// </summary>
public interface IAnalysisPass
{
    string Name { get; }

    /// <summary>Names of passes (their <see cref="Name"/>) that must run first.</summary>
    IReadOnlyCollection<string> DependsOn => [];

    /// <summary>Null when the pass needs no profile at all.</summary>
    ProfileFidelity? RequiredProfileFidelity => null;

    void Run(BinaryImage image, PassContext context);
}
