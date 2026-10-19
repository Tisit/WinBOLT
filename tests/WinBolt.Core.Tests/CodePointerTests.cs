using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class CodePointerTests
{
    private static Function At(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    [Fact]
    public void Function_reached_only_by_lea_is_discovered_and_address_taken()
    {
        // 0x1000: lea rcx,[rip+0x19] (-> 0x1020) / ret     0x1020: xor eax,eax / ret (no .pdata)
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x0D, 0x19, 0x00, 0x00, 0x00, 0xC3).Pdata(0x1000, 0x1008)
            .Code(0x1020, 0x31, 0xC0, 0xC3)
            .Analyze();
        var target = At(image, 0x1020);

        Assert.Equal(DiscoverySource.CodePointer, target.DiscoveredBy);
        Assert.Equal(new CodePointer(At(image, 0x1000).Id, 0x1000, 0x1020, target.Id, IsEntry: true), Assert.Single(image.CodePointers));

        // Address-taken, and 3 bytes is too short for the entry trampoline §6.1 requires.
        Assert.StartsWith("trampoline-window:", target.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Interior_lea_roots_the_target_and_makes_its_function_relocatable()
    {
        // 0x1000: lea rax,[rip+0x39] (-> 0x1040) / ret     (like an FH3 catch funclet returning a continuation)
        // 0x1030: xor eax,eax / ret / int3 padding / 0x1040: mov eax,1 / ret   (0x1040 has no other path in)
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x05, 0x39, 0x00, 0x00, 0x00, 0xC3).Pdata(0x1000, 0x1008)
            .Code(0x1030, 0x31, 0xC0, 0xC3)
            .Code(0x1040, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3).Pdata(0x1030, 0x1046)
            .Analyze();
        var owner = At(image, 0x1030);

        Assert.Contains(owner.BasicBlocks, b => b.StartRva == 0x1040);
        Assert.DoesNotContain(owner.DowngradeReasons, r => r.StartsWith("uncovered-bytes:"));
        Assert.Equal(Transformability.RelocatableOnly, owner.SafetyStatus.Level);
        Assert.StartsWith("interior-pointer:", owner.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Lea_into_data_is_recorded_but_creates_no_function()
    {
        // 0x1000: lea rcx,[rip+0x49] (-> 0x1050) / ret     0x1050: FF bytes (not code)
        var image = new SyntheticImage()
            .Code(0x1000, 0x48, 0x8D, 0x0D, 0x49, 0x00, 0x00, 0x00, 0xC3).Pdata(0x1000, 0x1008)
            .Code(0x1050, Enumerable.Repeat((byte)0xFF, 16).ToArray())
            .Analyze();

        Assert.DoesNotContain(image.Functions, f => f.EntryRva == 0x1050);
        Assert.Null(Assert.Single(image.CodePointers).TargetFunctionId);
    }
}
