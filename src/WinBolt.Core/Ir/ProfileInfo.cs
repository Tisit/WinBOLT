namespace WinBolt.Core.Ir;

/// <summary>
/// Per-function runtime profile data (Stage 2). <see cref="HasEdgeCounts"/> distinguishes
/// IP-sampling-derived data (function/block hotness only) from edge-accurate data (LBR,
/// Intel PT, or instrumentation) — see DesignDoc.md Stage 2 for why this distinction is
/// load-bearing for Stages 5-6.
/// </summary>
public sealed class ProfileInfo
{
    public ulong SampleCount { get; set; }

    public bool HasEdgeCounts { get; set; }
}
