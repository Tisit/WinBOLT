using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class SafetyGateTests
{
    // mov eax,1 / ret : a clean 6-byte function
    private static readonly byte[] ReturnOne = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

    private static Function Only(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    [Fact]
    public void Clean_function_is_promoted_to_fully_transformable()
    {
        var image = new SyntheticImage().Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006).Analyze();

        Assert.Equal(SafetyStatus.FullyTransformable(), Only(image, 0x1000).SafetyStatus);
    }

    [Fact]
    public void Nothing_is_left_unanalyzed()
    {
        var image = new SyntheticImage().Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006).Export("Tiny", 0x1020).Code(0x1020, 0xC3).Analyze();

        Assert.DoesNotContain(image.Functions, f => f.SafetyStatus.Level == Transformability.Unanalyzed);
    }

    [Fact]
    public void Function_with_an_exception_handler_is_frozen()
    {
        var image = new SyntheticImage().Code(0x1000, ReturnOne).Pdata(0x1000, 0x1006, handlerRva: 0x1100).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
        Assert.StartsWith("handler-data:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Address_taken_function_too_short_for_a_trampoline_is_frozen()
    {
        // Exported "xor eax,eax / ret": 3 bytes, less than a 5-byte jmp.
        var image = new SyntheticImage().Code(0x1000, 0x31, 0xC0, 0xC3).Export("Short", 0x1000).Analyze();
        var f = Only(image, 0x1000);

        Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
        Assert.StartsWith("trampoline-window:", f.SafetyStatus.DowngradeReason);
    }

    [Fact]
    public void Address_taken_function_with_a_branch_target_in_its_first_bytes_is_frozen()
    {
        // 0x1000: xor eax,eax / 0x1002: inc eax / cmp eax,5 / jb 0x1002 / ret  (loop head at +2)
        var image = new SyntheticImage()
            .Code(0x1000, 0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x05, 0x72, 0xF9, 0xC3)
            .Pdata(0x1000, 0x100A)
            .Export("Loop", 0x1000)
            .Analyze();

        Assert.Contains(Only(image, 0x1000).DowngradeReasons, r => r.StartsWith("trampoline-window:") && r.Contains("0x1002"));
    }

    [Fact]
    public void Same_loop_without_an_export_needs_no_trampoline()
    {
        // Same loop, but not exported: no trampoline needed, so the loop head at +2 is fine.
        var image = new SyntheticImage()
            .Code(0x1000, 0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x05, 0x72, 0xF9, 0xC3)
            .Pdata(0x1000, 0x100A)
            .Analyze();

        Assert.Equal(Transformability.FullyTransformable, Only(image, 0x1000).SafetyStatus.Level);
    }
}
