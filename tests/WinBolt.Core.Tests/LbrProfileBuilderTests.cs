using WinBolt.Core.Ir;
using WinBolt.Core.Profile;

namespace WinBolt.Core.Tests;

public class LbrProfileBuilderTests
{
    // Diamond: 1000 test ecx,ecx / 1002 jz 100B | 1004 mov eax,1 / 1009 jmp 1010 | 100B mov eax,2 | 1010 ret
    // Blocks: B0 [1000,1004) B1 [1004,100B) B2 [100B,1010) B3 [1010,1011)
    private static (BinaryImage Image, Function F, LbrProfileBuilder Builder) Diamond()
    {
        var image = new SyntheticImage()
            .Code(0x1000, 0x85, 0xC9, 0x74, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3)
            .Pdata(0x1000, 0x1011)
            .Analyze();
        return (image, image.Functions.Single(f => f.EntryRva == 0x1000), new LbrProfileBuilder(image));
    }

    private static ulong? Count(Function f, uint from, uint to, EdgeKind kind) =>
        f.BasicBlocks.Single(b => (uint)b.StartRva == from).Successors.Single(e => (uint)e.Target.StartRva == to && e.Kind == kind).ExecutionCount;

    // Newest first, as LBR delivers them. null = outside the image.
    private static BranchRecord R(uint? from, uint? to) => new(from, to);

    [Fact]
    public void Taken_branch_and_the_run_after_it_count_their_edges()
    {
        var (_, f, builder) = Diamond();

        // Entered at 1000 from outside, jz taken to 100B, fell into 1010, returned.
        builder.AddSample([R(0x1010, null), R(0x1002, 0x100B), R(null, 0x1000)]);

        Assert.Equal(1ul, Count(f, 0x1000, 0x100B, EdgeKind.Branch));
        Assert.Equal(1ul, Count(f, 0x100B, 0x1010, EdgeKind.FallThrough));
        Assert.Null(Count(f, 0x1000, 0x1004, EdgeKind.FallThrough));
        Assert.Equal((1L, 1L, 0L), (builder.Summary.TakenBranches, builder.Summary.Returns, builder.Summary.UnmatchedRecords));
        Assert.True(f.Profile!.HasEdgeCounts);
    }

    [Fact]
    public void Not_taken_branch_is_recovered_from_the_straight_line_run()
    {
        var (_, f, builder) = Diamond();

        // Entered at 1000, jz not taken (fell into 1004), jmp 1010, returned.
        builder.AddSample([R(0x1010, null), R(0x1009, 0x1010), R(null, 0x1000)]);

        Assert.Equal(1ul, Count(f, 0x1000, 0x1004, EdgeKind.FallThrough));
        Assert.Equal(1ul, Count(f, 0x1004, 0x1010, EdgeKind.Branch));
        Assert.Null(Count(f, 0x1000, 0x100B, EdgeKind.Branch));
        Assert.Equal(2, builder.Summary.FallThroughRuns);
    }

    [Fact]
    public void Record_from_a_non_branch_address_is_unmatched_and_never_counted()
    {
        var (_, f, builder) = Diamond();

        builder.AddSample([R(0x1005, 0x1010)]); // inside "mov eax,1": code that is not this file

        Assert.Equal(1, builder.Summary.UnmatchedRecords);
        Assert.All(f.BasicBlocks.SelectMany(b => b.Successors), e => Assert.Null(e.ExecutionCount));
    }

    [Fact]
    public void Run_that_the_cfg_cannot_explain_is_counted_not_applied()
    {
        var (_, f, builder) = Diamond();

        // Target 100B, next source 1009: 1009 is not reachable from 100B by falling through.
        builder.AddSample([R(0x1009, 0x1010), R(0x1002, 0x100B)]);

        Assert.Equal(1, builder.Summary.UnexplainedRuns);
        Assert.Null(Count(f, 0x100B, 0x1010, EdgeKind.FallThrough));
    }

    [Fact]
    public void Block_counts_come_from_edge_counts()
    {
        var (_, f, builder) = Diamond();
        builder.AddSample([R(0x1010, null), R(0x1002, 0x100B), R(null, 0x1000)]);

        builder.Finish();

        // B0 is the entry (no counted predecessor): its count is its outgoing total.
        Assert.Equal([1ul, null, 1ul, 1ul], f.BasicBlocks.OrderBy(b => b.StartRva).Select(b => b.ExecutionCount));
    }

    [Fact]
    public void Footprint_takes_the_hottest_bytes_first()
    {
        var (image, _, builder) = Diamond();
        builder.AddSample([R(0x1010, null), R(0x1002, 0x100B), R(null, 0x1000)]);
        builder.Finish();

        var levels = CodeFootprint.Compute(image, 0.5, 1.0);

        // Executed bytes: B0 4 + B2 5 + B3 1 = 10. Half needs B0 and B2; all needs all three.
        Assert.Equal([2, 3], levels.Select(l => l.Blocks));
        Assert.All(levels, l => Assert.Equal((1, 1, 1), (l.Functions, l.PagesNow, l.LinesNow)));
    }

    [Fact]
    public void Calls_are_counted_per_call_site()
    {
        // 1000 sub rsp,28h / 1004 call 1020 / add rsp,28h / jmp 1020 ; 1020 ret
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xEB, 0x11)
            .Code(0x1020, 0xC3)
            .Pdata(0x1000, 0x100F)
            .Analyze();
        var builder = new LbrProfileBuilder(image);

        builder.AddSample([R(0x1020, 0x1009), R(0x1004, 0x1020)]);

        Assert.Equal(1, builder.Summary.CallCounts[0x1004]);
        Assert.Equal((1L, 1L), (builder.Summary.Calls, builder.Summary.Returns));
    }

    [Fact]
    public void A_single_block_leaf_counts_as_executed()
    {
        // As above: the leaf at 1020 is one block with no edges, entered by the call, left by ret.
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xEB, 0x11)
            .Code(0x1020, 0xC3)
            .Pdata(0x1000, 0x100F)
            .Analyze();
        var builder = new LbrProfileBuilder(image);

        builder.AddSample([R(0x1020, 0x1009), R(0x1004, 0x1020)]);
        builder.AddSample([R(0x1020, 0x1009), R(0x1004, 0x1020)]);
        builder.Finish();

        Assert.Equal(2ul, image.Functions.Single(f => f.EntryRva == 0x1020).BasicBlocks.Single().ExecutionCount);
    }

    [Fact]
    public void Ip_samples_count_toward_their_function()
    {
        var (_, f, builder) = Diamond();

        builder.AddIpSample(0x1005);
        builder.AddIpSample(0x100C);
        builder.AddIpSample(0x2000); // outside every function

        Assert.Equal(2ul, f.Profile!.SampleCount);
        Assert.Equal(3, builder.Summary.IpSamples);
    }
}
