using Iced.Intel;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Reports;

namespace WinBolt.Core.Tests;

public class InstructionHistogramTests
{
    // vaddps ymm0,ymm1,ymm2 (AVX) / vpaddd ymm0,ymm1,ymm2 (AVX2) / popcnt eax,ecx / mov eax,ecx / ret
    private static readonly byte[] Mixed =
    [
        0xC5, 0xF4, 0x58, 0xC2,
        0xC5, 0xF5, 0xFE, 0xC2,
        0xF3, 0x0F, 0xB8, 0xC1,
        0x8B, 0xC1,
        0xC3,
    ];

    [Fact]
    public void Instructions_are_counted_by_mnemonic_and_feature_tier()
    {
        var image = new SyntheticImage().Code(0x1000, Mixed).Pdata(0x1000, 0x100F).Analyze();

        var histogram = InstructionHistogram.Compute(image);

        Assert.Equal(5, histogram.Instructions);
        Assert.Equal(15, histogram.Bytes);
        Assert.Contains((Mnemonic.Vpaddd, 1L), histogram.Mnemonics);
        Assert.Equal(1, histogram.TierInstructions[FeatureTier.Avx]);
        Assert.Equal(1, histogram.TierInstructions[FeatureTier.Avx2]);
        Assert.Equal(1, histogram.TierInstructions[FeatureTier.BitManipulation]);
        Assert.Equal(2, histogram.TierInstructions[FeatureTier.Base]);
        Assert.Equal(1, histogram.TierFunctions[FeatureTier.Avx2]);
        Assert.Equal(1, histogram.ControlFlow[FlowControl.Return]);
    }

    [Fact]
    public void Report_is_registered_and_flags_tiers_above_the_x64_baseline()
    {
        var image = new SyntheticImage().Code(0x1000, Mixed).Pdata(0x1000, 0x100F).Analyze();

        var provider = Assert.Single(
            PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateReportProviders(),
            p => p.Name == "InstructionMix");
        var report = provider.Generate(image, new PassContext());

        Assert.Equal(ReportConfidence.High, report.Confidence);
        Assert.Contains(report.Body.Split('\n'), line => line.Contains("Avx2") && line.Contains("needs dispatch"));
        Assert.DoesNotContain(report.Body.Split('\n'), line => line.Contains("Base") && line.Contains("needs dispatch"));
    }
}
