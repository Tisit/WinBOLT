using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes;

/// <summary>Transforms the IR toward a better output binary (§7, Stages 4+).</summary>
public interface IOptimizationPass
{
    string Name { get; }

    IReadOnlyCollection<string> DependsOn => [];

    /// <summary>
    /// Null when the pass needs no profile. A pass requiring
    /// <see cref="ProfileFidelity.EdgeAccurate"/> must refuse to run rather than silently
    /// degrade when only a sampling profile is available (Stage 2).
    /// </summary>
    ProfileFidelity? RequiredProfileFidelity => null;

    /// <summary>Minimum <see cref="Transformability"/> a function must have to be considered by this pass.</summary>
    Transformability MinimumTransformability => Transformability.FullyTransformable;

    void Run(BinaryImage image, PassContext context);
}
