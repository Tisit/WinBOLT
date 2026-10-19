using WinBolt.Core.Ir;
using WinBolt.Core.Profile;

namespace WinBolt.Rewrite;

/// <summary>
/// Indirect call promotion (DesignDoc "Step 26"): profiled indirect call sites whose
/// calls go almost all to one function in the image become a guarded direct call
/// (<see cref="BlockRebuilder.Encode"/> emits it, <see cref="RewriteVerifier"/> checks it). A
/// mispredicted or BTB-missing indirect call resolves only at execute; a direct call is resteered
/// at decode, and the guard is one fused compare-and-branch.
/// </summary>
public static class CallPromotion
{
    /// <summary>Share of a site's calls the dominant target must take.</summary>
    public const double MinShare = 0.9;

    /// <summary>Profile records of the dominant target, at least: fewer is not evidence.</summary>
    public const long MinCalls = 16;

    /// <summary>Call site RVA → dominant target RVA, for sites whose target is a function entry in the image.</summary>
    public static Dictionary<uint, uint> Plan(BinaryImage image, double minShare = MinShare, long minCalls = MinCalls)
    {
        var plan = new Dictionary<uint, uint>();
        if (image.ProfileSummary is not { } summary)
        {
            return plan;
        }

        var entries = image.Functions.Select(f => f.EntryRva).ToHashSet();
        foreach (var (site, targets) in summary.IndirectTargets)
        {
            long total = targets.Values.Sum();
            var (target, calls) = targets.MaxBy(kv => kv.Value);
            if (target != ProfileSummary.OutsideImage && calls >= minCalls && calls >= minShare * total && entries.Contains(target))
            {
                plan[site] = target;
            }
        }

        return plan;
    }
}
