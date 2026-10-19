using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;

namespace WinBolt.Core.Tests;

public class IpProfileBuilderTests
{
    // A diamond at 0x1000:
    //   A 1000 cmp ecx,1 / 1003 je C
    //   B 1005 xor eax,eax / 1007 jmp D
    //   C 1009 mov eax,1
    //   D 100E ret
    private static BinaryImage Diamond() => new SyntheticImage()
        .Code(0x1000, 0x83, 0xF9, 0x01, 0x74, 0x04,
            0x31, 0xC0, 0xEB, 0x05,
            0xB8, 0x01, 0x00, 0x00, 0x00,
            0xC3)
        .Pdata(0x1000, 0x100F)
        .Analyze();

    private static BasicBlock Block(BinaryImage image, uint rva) => image.Functions.Single().BasicBlocks.Single(b => b.StartRva == rva);

    private static IpProfileBuilder Sample(BinaryImage image, int a, int b, int c, int d, IpEstimator estimator = IpEstimator.Mean)
    {
        var builder = new IpProfileBuilder(image, estimator);
        for (int i = 0; i < a; i++) builder.AddSample(0x1000);
        for (int i = 0; i < b; i++) builder.AddSample(0x1005);
        for (int i = 0; i < c; i++) builder.AddSample(0x1009);
        for (int i = 0; i < d; i++) builder.AddSample(0x100E);
        builder.Finish();
        return builder;
    }

    [Fact]
    public void Block_counts_follow_the_samples_per_instruction_and_edges_balance_them()
    {
        var image = Diamond();
        var builder = Sample(image, 300, 600, 100, 800);

        Assert.Equal(ProfileFidelity.SamplingOnly, builder.Summary.Fidelity);
        // A: 300 samples over 2 instructions; B: 600 over 2; C: 100 over 1; D: 800 over 1.
        Assert.Equal(150_000ul, Block(image, 0x1000).ExecutionCount);
        Assert.Equal(300_000ul, Block(image, 0x1005).ExecutionCount);
        Assert.Equal(100_000ul, Block(image, 0x1009).ExecutionCount);
        Assert.Equal(800_000ul, Block(image, 0x100E).ExecutionCount);

        // The edges out of A split its count between B and C in proportion to what they run.
        var a = Block(image, 0x1000);
        double toB = a.Successors.Single(e => e.Target.StartRva == 0x1005).ExecutionCount!.Value;
        double toC = a.Successors.Single(e => e.Target.StartRva == 0x1009).ExecutionCount!.Value;
        Assert.True(toB > toC, $"{toB} vs {toC}");
        Assert.All(image.Functions.Single().BasicBlocks.SelectMany(b => b.Successors), e => Assert.NotNull(e.ExecutionCount));
    }

    [Fact]
    public void A_block_no_sample_hit_is_cold_only_when_its_predecessor_was_sampled_enough()
    {
        // Plenty of samples in A: nothing in C means C did not run.
        var plenty = Diamond();
        Sample(plenty, 2000, 2000, 0, 2000);
        Assert.Null(Block(plenty, 0x1009).ExecutionCount);

        // Few samples: the evidence is too thin to call C cold; it stays warm, below its predecessor.
        var few = Diamond();
        Sample(few, 20, 20, 0, 20);
        var warm = Block(few, 0x1009).ExecutionCount;
        Assert.NotNull(warm);
        Assert.True(warm < Block(few, 0x1000).ExecutionCount);
    }

    [Fact]
    public void Max_estimator_uses_the_most_sampled_instruction()
    {
        var image = Diamond();
        var builder = new IpProfileBuilder(image, IpEstimator.Max);
        for (int i = 0; i < 90; i++) builder.AddSample(0x1000); // cmp
        for (int i = 0; i < 10; i++) builder.AddSample(0x1003); // je
        builder.Finish();

        Assert.Equal(90_000ul, Block(image, 0x1000).ExecutionCount);
    }
}
