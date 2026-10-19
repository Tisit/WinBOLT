namespace WinBolt.Core.Passes;

/// <summary>
/// See DesignDoc.md Stage 2. IP sampling cannot supply edge counts — only function/block
/// hotness. Passes that need edge counts must declare <see cref="EdgeAccurate"/> and
/// refuse to run rather than silently degrade when handed a sampling-only profile.
/// </summary>
public enum ProfileFidelity
{
    SamplingOnly,
    EdgeAccurate,
}
