namespace WinBolt.Core.Ir;

/// <summary>
/// See DesignDoc.md §5.5. Default on any unrecognized construct is downgrade, not proceed.
/// </summary>
public enum Transformability
{
    /// <summary>Analysis has not yet computed a status for this function.</summary>
    Unanalyzed,

    /// <summary>Blocks may be reordered and rewritten.</summary>
    FullyTransformable,

    /// <summary>May be moved as a unit; contents frozen.</summary>
    RelocatableOnly,

    /// <summary>Must remain byte-identical at its original address.</summary>
    Frozen,
}

/// <summary>
/// A function's transformability plus, for any downgrade, a recorded machine-readable
/// reason (§5.5 requires downgrades to never be silent).
/// </summary>
public sealed record SafetyStatus(Transformability Level, string? DowngradeReason = null)
{
    public static readonly SafetyStatus Unanalyzed = new(Transformability.Unanalyzed);

    public static SafetyStatus FullyTransformable() =>
        new(Transformability.FullyTransformable);

    public static SafetyStatus RelocatableOnly(string reason) =>
        new(Transformability.RelocatableOnly, reason);

    public static SafetyStatus Frozen(string reason) =>
        new(Transformability.Frozen, reason);
}
