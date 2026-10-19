using WinBolt.Core.Ir;
using WinBolt.Core.Profile;

namespace WinBolt.Core.Tests;

public class AdvisorTests
{
    private static BranchRecord R(uint? from, uint? to) => new(from, to);

    private static IReadOnlyList<Recommendation> Advise(BinaryImage image, Action<LbrProfileBuilder> samples)
    {
        var builder = new LbrProfileBuilder(image);
        samples(builder);
        builder.Finish();
        image.ProfileSummary = builder.Summary;
        return Advisor.Analyze(image, CpuModel.Default);
    }

    private static void Repeat(int times, Action action)
    {
        for (int i = 0; i < times; i++)
        {
            action();
        }
    }

    [Fact]
    public void Forward_branch_taken_almost_always_is_a_layout_candidate()
    {
        // Diamond: 1002 jz 100B is taken every time.
        var image = new SyntheticImage()
            .Code(0x1000, 0x85, 0xC9, 0x74, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3)
            .Pdata(0x1000, 0x1011)
            .Analyze();

        var findings = Advise(image, b => Repeat(150, () => b.AddSample([R(0x1010, null), R(0x1002, 0x100B), R(null, 0x1000)])));

        var biased = Assert.Single(findings, f => f.Kind == RecommendationKind.BiasedBranch);
        Assert.Contains("block 0x1000", biased.Where);
        Assert.Contains("150 of 150", biased.Finding);
    }

    [Fact]
    public void Loop_back_edge_is_not_a_layout_candidate()
    {
        // 1000 dec ecx / 1002 jnz 1000 / 1004 ret: the backward branch is taken almost always, correctly.
        var image = new SyntheticImage().Code(0x1000, 0xFF, 0xC9, 0x75, 0xFC, 0xC3).Pdata(0x1000, 0x1005).Analyze();

        var findings = Advise(image, b => b.AddSample(Enumerable.Repeat(R(0x1002, 0x1000), 32).ToArray()));

        Assert.DoesNotContain(findings, f => f.Kind == RecommendationKind.BiasedBranch);
    }

    // 1000 sub rsp,28h / 1004 call rax / 1006 add rsp,28h / 100A ret; targets at 1020 and 1030.
    private static SyntheticImage IndirectCaller(byte[] target1020) => new SyntheticImage()
        .Code(0x1000, 0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3).Pdata(0x1000, 0x100B)
        .Code(0x1020, target1020).Pdata(0x1020, 0x1020 + (uint)target1020.Length)
        .Code(0x1030, 0xC3).Pdata(0x1030, 0x1031);

    [Fact]
    public void Indirect_call_with_a_dominant_target_is_a_promotion_candidate()
    {
        var image = IndirectCaller([0x31, 0xC0, 0xC3]).Analyze();

        var findings = Advise(image, b =>
        {
            Repeat(190, () => b.AddSample([R(0x1004, 0x1020)]));
            Repeat(10, () => b.AddSample([R(0x1004, 0x1030)]));
        });

        var finding = Assert.Single(findings, f => f.Kind == RecommendationKind.DominantIndirectTarget);
        Assert.Contains("95% of 200 calls", finding.Finding);
        Assert.Contains("2 targets", finding.Finding);
    }

    [Fact]
    public void Indirect_call_that_always_reaches_an_avx2_function_is_a_cpu_dispatch()
    {
        // The only target uses vpaddd ymm (AVX2).
        var image = IndirectCaller([0xC5, 0xF5, 0xFE, 0xC2, 0xC3]).Analyze();

        var findings = Advise(image, b => Repeat(200, () => b.AddSample([R(0x1004, 0x1020)])));

        var finding = Assert.Single(findings, f => f.Kind == RecommendationKind.CpuDispatch);
        Assert.Contains("Avx2", finding.Finding);
    }

    [Fact]
    public void Nothing_is_reported_without_a_profile()
    {
        var image = new SyntheticImage().Code(0x1000, 0xC3).Pdata(0x1000, 0x1001).Analyze();

        Assert.Empty(Advisor.Analyze(image, CpuModel.Default));
    }
}
