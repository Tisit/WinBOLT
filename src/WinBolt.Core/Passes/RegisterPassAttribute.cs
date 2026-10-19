namespace WinBolt.Core.Passes;

/// <summary>
/// Marks a pass type for discovery by <see cref="PassRegistry"/> (§11). Stages 1-5 use
/// attribute-based registration within the main assembly rather than dynamic plugin
/// loading — see DesignDoc.md §11 for why that boundary is deferred.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class RegisterPassAttribute : Attribute
{
    /// <summary>Names (matching another registered pass's <c>Name</c> property) that must run before this one.</summary>
    public string[] DependsOn { get; init; } = [];
}
