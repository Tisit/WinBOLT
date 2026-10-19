using WinBolt.Core.Ir;

namespace WinBolt.Core.Analysis;

/// <summary>What produced the image's code layout. See DesignDoc.md Stage 1, layout provenance.</summary>
public enum LayoutOrigin
{
    /// <summary>OMAP (or, once PDBs are read, original section headers): code was moved after the linker.</summary>
    PostLinkRewrite,

    /// <summary>No OMAP in the image, but the undocumented Reserved10 debug entry that rewritten images carry.</summary>
    LikelyPostLinkRewrite,

    /// <summary>POGO entry with a used-profile signature (PGU/PGO) and no post-link evidence.</summary>
    CompilerPgo,

    /// <summary>Instrumented (PGI) training build.</summary>
    PgoInstrumented,

    /// <summary>LTCG without a profile.</summary>
    LtcgNoProfile,

    /// <summary>Far fragments present with nothing to attribute them to.</summary>
    Inconclusive,

    /// <summary>No sign of profile-guided layout.</summary>
    NoProfileGuidedLayout,
}

/// <summary>Statistics over chained .pdata entries (§5.1).</summary>
public sealed record ChainStats(int ChainedEntries, int SplitFunctions, int FarFragments, long MaxFragmentDistance, int InvalidChains)
{
    /// <summary>Distance in bytes above which a fragment counts as moved away from its parent, not a local chain.</summary>
    public const long FarThreshold = 64 * 1024;
}

public sealed record LayoutProvenance(LayoutOrigin Origin, ChainStats Chains, IReadOnlyList<string> Evidence);

/// <summary>
/// PE-only layout provenance. PDB evidence (OMAP streams, SectionHdrOrig, S_SEPCODE) is added
/// when the PDB reader lands; until then a rewriter that left OMAP only in the PDB is caught by
/// the Reserved10 entry alone.
/// </summary>
public static class LayoutProvenanceClassifier
{
    // Guards against cyclic chains in damaged unwind data.
    private const int MaxChainDepth = 32;

    public static LayoutProvenance Classify(BinaryImage image)
    {
        var chains = ComputeChainStats(image.ExceptionData);
        var evidence = new List<string>();

        bool omap = image.DebugEntries.Any(e => e.Type is DebugDirectoryType.OmapToSrc or DebugDirectoryType.OmapFromSrc);
        bool reserved10 = image.DebugEntries.Any(e => e.Type == DebugDirectoryType.Reserved10);

        if (omap)
        {
            evidence.Add("debug directory has OMAP_TO_SRC/OMAP_FROM_SRC entries: code was moved after linking; PDB symbol addresses need OMAP translation (§3.3)");
        }

        if (reserved10)
        {
            evidence.Add("debug directory has a Reserved10 (type 10) entry: empirically present on post-link-rewritten images only");
        }

        if (image.Pogo is { } pogo)
        {
            evidence.Add($"POGO entry, signature {pogo.Signature}, {pogo.Contributions.Count} contributions " +
                         $"({pogo.ProfileOrderedGroups} profile-ordered, {pogo.ColdGroups} cold)");
        }

        if (chains.ChainedEntries > 0)
        {
            evidence.Add($".pdata: {chains.ChainedEntries:N0} chained entries across {chains.SplitFunctions:N0} functions, " +
                         $"{chains.FarFragments:N0} more than 64 KB from their parent");
        }

        if (chains.InvalidChains > 0)
        {
            evidence.Add($".pdata: {chains.InvalidChains:N0} chained entries whose parent is not a .pdata entry (§5.1); excluded from the above");
        }

        // Chains alone are common (the static CRT ships ~200 local ones), so only far fragments count as splitting.
        bool splitCode = chains.FarFragments > 0;

        LayoutOrigin origin;
        if (omap)
        {
            origin = LayoutOrigin.PostLinkRewrite;
        }
        else if (reserved10)
        {
            origin = LayoutOrigin.LikelyPostLinkRewrite;
        }
        else if (image.Pogo is { IsProfileOptimized: true })
        {
            origin = LayoutOrigin.CompilerPgo;
        }
        else if (image.Pogo is { RawSignature: PogoInfo.SignaturePgi })
        {
            origin = LayoutOrigin.PgoInstrumented;
        }
        else if (image.Pogo is { RawSignature: PogoInfo.SignatureLtcg })
        {
            origin = splitCode ? LayoutOrigin.Inconclusive : LayoutOrigin.LtcgNoProfile;
        }
        else
        {
            origin = splitCode ? LayoutOrigin.Inconclusive : LayoutOrigin.NoProfileGuidedLayout;
        }

        return new LayoutProvenance(origin, chains, evidence);
    }

    public static ChainStats ComputeChainStats(IReadOnlyList<ExceptionInfo> exceptionData)
    {
        int chained = 0, far = 0, invalid = 0;
        long max = 0;
        var parents = new HashSet<uint>();

        foreach (var entry in exceptionData)
        {
            if (!entry.IsChained)
            {
                continue;
            }

            if (entry.ChainedParent is not { } parent)
            {
                invalid++;
                continue;
            }

            // Measure from the primary function, not the immediate parent: a fragment chained
            // to another fragment is far if the primary is far, however close the link is.
            var root = parent;
            for (int depth = 0; depth < MaxChainDepth && root.ChainedParent is { } next; depth++)
            {
                root = next;
            }

            chained++;
            parents.Add(root.BeginAddress);
            long distance = Math.Abs((long)entry.BeginAddress - root.BeginAddress);
            max = Math.Max(max, distance);
            if (distance > ChainStats.FarThreshold)
            {
                far++;
            }
        }

        return new ChainStats(chained, parents.Count, far, max, invalid);
    }
}
