namespace WinBolt.Core.Ir;

/// <summary>
/// CFGuard/XFG tables from the load config directory (§5.4). Where present these are
/// authoritative ground truth for address-taken analysis and should be preferred over
/// inference; where absent, that absence is itself worth reporting as a confidence
/// reduction.
/// </summary>
public sealed class LoadConfigTables
{
    /// <summary>
    /// CFG is enforced by the loader: the image's GUARD_CF characteristic and the load config's
    /// CF_INSTRUMENTED flag are both set. Only then must a rewrite keep the tables valid.
    /// </summary>
    public required bool HasCfg { get; init; }

    /// <summary>RVAs of every valid indirect-call target known to the compiler.</summary>
    public List<uint> GuardCfFunctionTable { get; } = [];

    public List<uint> GuardAddressTakenIatEntryTable { get; } = [];

    public List<uint> GuardLongJumpTargetTable { get; } = [];

    /// <summary>Present only when the image was built with /guard:ehcont.</summary>
    public List<uint>? GuardEhContinuationTable { get; set; }

    public bool HasXfg { get; init; }
}
