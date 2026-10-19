using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class CfgConstructionTests
{
    // 0x1000: test ecx,ecx / jz 0x100B / mov eax,1 / jmp 0x1010 / 0x100B: mov eax,2 / 0x1010: ret
    private static readonly byte[] Diamond =
    [
        0x85, 0xC9, 0x74, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05,
        0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3,
    ];

    private static Function Only(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    [Fact]
    public void Diamond_splits_into_four_blocks_with_the_right_edges()
    {
        var image = new SyntheticImage().Code(0x1000, Diamond).Pdata(0x1000, 0x1011).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal([0x1000ul, 0x1004, 0x100B, 0x1010], f.BasicBlocks.Select(b => b.StartRva));
        Assert.Equal([4u, 7, 5, 1], f.BasicBlocks.Select(b => b.Length));

        string Edges(BasicBlock b) => string.Join(",", b.Successors.Select(e => $"{e.Kind}->{e.Target.StartRva:X}"));
        Assert.Equal("Branch->100B,FallThrough->1004", Edges(f.BasicBlocks[0]));
        Assert.Equal("Branch->1010", Edges(f.BasicBlocks[1]));
        Assert.Equal("FallThrough->1010", Edges(f.BasicBlocks[2]));
        Assert.Empty(f.BasicBlocks[3].Successors);
        Assert.Equal(2, f.BasicBlocks[3].Predecessors.Count);

        Assert.Equal(Transformability.FullyTransformable, f.SafetyStatus.Level);
    }

    [Fact]
    public void Blocks_index_contiguous_instructions_in_the_flat_store()
    {
        var image = new SyntheticImage().Code(0x1000, Diamond).Pdata(0x1000, 0x1011).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(6, f.BasicBlocks.Sum(b => b.InstructionCount));
        foreach (var block in f.BasicBlocks)
        {
            var instructions = image.Instructions.Slice(block.InstructionStart, block.InstructionCount);
            Assert.Equal(block.StartRva, instructions[0].IP);
            Assert.Equal(block.StartRva + block.Length, instructions[^1].NextIP);
        }
    }

    [Fact]
    public void Register_indirect_jump_in_a_single_block_function_is_a_tail_call()
    {
        // mov eax,ecx / jmp rax: a dispatch thunk; its only internal target would be itself.
        // Freezing on unexplained jumps is covered in JumpTableTests.
        var image = new SyntheticImage().Code(0x1000, 0x8B, 0xC1, 0xFF, 0xE0).Pdata(0x1000, 0x1004).Analyze();

        Assert.Contains(image.CallSites, c => c is { SiteRva: 0x1002, Kind: CallKind.IndirectTailJump });
        Assert.Empty(Only(image, 0x1000).DowngradeReasons);
    }

    [Fact]
    public void Noreturn_call_followed_by_filler_does_not_fall_off_the_range()
    {
        // sub rsp,28h / call 0x1100 / nop / int3   (range ends after the int3)
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0xF7, 0x00, 0x00, 0x00, 0x90, 0xCC)
            .Code(0x1100, 0xC3)
            .Pdata(0x1000, 0x100B)
            .Analyze();

        Assert.DoesNotContain(Only(image, 0x1000).DowngradeReasons, r => r.StartsWith("falls-off-range:"));
    }

    [Fact]
    public void Non_padding_bytes_disassembly_never_reaches_are_uncovered()
    {
        // ret, then 4 bytes of data inside the .pdata range
        var image = new SyntheticImage().Code(0x1000, 0xC3, 0xDE, 0xAD, 0xBE, 0xEF).Pdata(0x1000, 0x1005).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
        Assert.StartsWith("uncovered-bytes: 4 bytes", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Calls_and_tail_jumps_become_call_sites_resolved_to_callees()
    {
        // 0x1000: sub rsp,28h / call 0x1020 / add rsp,28h / jmp 0x1020 ; 0x1020: ret
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xEB, 0x11)
            .Code(0x1020, 0xC3)
            .Pdata(0x1000, 0x100F)
            .Analyze();
        int callee = Only(image, 0x1020).Id;

        Assert.Equal(
            [(0x1004u, CallKind.Call), (0x100Du, CallKind.TailJump)],
            image.CallSites.Select(c => (c.SiteRva, c.Kind)));
        Assert.All(image.CallSites, c => Assert.Equal(callee, c.CalleeId));
    }
}
