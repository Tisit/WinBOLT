using WinBolt.Core.Analysis;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class LayoutProvenanceTests
{
    private static BinaryImage NewImage() => new()
    {
        FilePath = "synthetic.exe",
        ImageBase = 0x140000000,
        SizeOfImage = 0x100000,
        TimeDateStamp = 0,
        Checksum = 0,
    };

    private static ExceptionInfo Entry(uint begin, ExceptionInfo? parent = null, bool chained = false) => new()
    {
        BeginAddress = begin,
        EndAddress = begin + 0x10,
        UnwindInfoAddress = 0,
        IsChained = chained || parent is not null,
        ChainedParent = parent,
    };

    private static DebugDirectoryEntry Debug(uint type) => new(type, 0, 0, 0);

    [Fact]
    public void Omap_entries_mean_post_link_rewrite_even_with_pogo()
    {
        var image = NewImage();
        image.DebugEntries.Add(Debug(DebugDirectoryType.OmapToSrc));
        image.Pogo = new PogoInfo(PogoInfo.SignaturePgu, []);

        Assert.Equal(LayoutOrigin.PostLinkRewrite, LayoutProvenanceClassifier.Classify(image).Origin);
    }

    [Fact]
    public void Reserved10_without_omap_is_likely_post_link_rewrite()
    {
        var image = NewImage();
        image.DebugEntries.Add(Debug(DebugDirectoryType.Reserved10));

        Assert.Equal(LayoutOrigin.LikelyPostLinkRewrite, LayoutProvenanceClassifier.Classify(image).Origin);
    }

    [Theory]
    [InlineData(PogoInfo.SignaturePgu, LayoutOrigin.CompilerPgo)]
    [InlineData(PogoInfo.SignaturePgo, LayoutOrigin.CompilerPgo)]
    [InlineData(PogoInfo.SignaturePgi, LayoutOrigin.PgoInstrumented)]
    [InlineData(PogoInfo.SignatureLtcg, LayoutOrigin.LtcgNoProfile)]
    public void Pogo_signature_selects_origin(uint signature, LayoutOrigin expected)
    {
        var image = NewImage();
        image.Pogo = new PogoInfo(signature, []);

        Assert.Equal(expected, LayoutProvenanceClassifier.Classify(image).Origin);
    }

    [Fact]
    public void Local_chains_are_not_split_code()
    {
        // Static-CRT shape: chained entries right next to their parent.
        var image = NewImage();
        var parent = Entry(0x1000);
        image.ExceptionData.AddRange([parent, Entry(0x1040, parent), Entry(0x1080, parent)]);

        var result = LayoutProvenanceClassifier.Classify(image);

        Assert.Equal(LayoutOrigin.NoProfileGuidedLayout, result.Origin);
        Assert.Equal(2, result.Chains.ChainedEntries);
        Assert.Equal(1, result.Chains.SplitFunctions);
        Assert.Equal(0, result.Chains.FarFragments);
    }

    [Fact]
    public void Far_fragment_without_paperwork_is_inconclusive()
    {
        var image = NewImage();
        var parent = Entry(0x1000);
        image.ExceptionData.AddRange([parent, Entry(0x1000 + 0x20000, parent)]);

        var result = LayoutProvenanceClassifier.Classify(image);

        Assert.Equal(LayoutOrigin.Inconclusive, result.Origin);
        Assert.Equal(1, result.Chains.FarFragments);
    }

    [Fact]
    public void Invalid_chains_are_counted_and_not_treated_as_split_code()
    {
        var image = NewImage();
        image.ExceptionData.AddRange([Entry(0x1000), Entry(0x90000, parent: null, chained: true)]);

        var result = LayoutProvenanceClassifier.Classify(image);

        Assert.Equal(LayoutOrigin.NoProfileGuidedLayout, result.Origin);
        Assert.Equal(1, result.Chains.InvalidChains);
        Assert.Equal(0, result.Chains.ChainedEntries);
    }
}
