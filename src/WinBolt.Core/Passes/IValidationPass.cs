using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes;

/// <summary>Compares original and rewritten images (§9). Every optimization pass must provide validation.</summary>
public interface IValidationPass
{
    string Name { get; }

    IReadOnlyCollection<string> DependsOn => [];

    ValidationResult Run(BinaryImage original, BinaryImage rewritten, PassContext context);
}
