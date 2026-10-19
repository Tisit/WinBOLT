using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

/// <summary>
/// The safety gate's NativeAOT check (DesignDoc R5 item 2) on a synthetic image: managed methods
/// in [0x1000, 0x1030), a native function at 0x1030 and native startup code at 0x1080 that registers
/// the range the way NativeAOT's does.
/// </summary>
public class NativeAotGateTests
{
    // mov eax,1 / ret
    private static readonly byte[] ReturnOne = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

    private const uint ManagedRoot = 0x1000, ParentWithFunclet = 0x1010, Funclet = 0x1020, Native = 0x1030, Startup = 0x1080;

    private static SyntheticImage Build(bool export = true, bool symbols = false, bool registration = false)
    {
        var image = new SyntheticImage()
            .Code(ManagedRoot, ReturnOne).Code(ParentWithFunclet, ReturnOne).Code(Funclet, ReturnOne).Code(Native, ReturnOne)
            // Root, one unwind code: UnwindBlockFlags follows the code unpadded (0 = root, no EH info). A padded read would see the 2 (filter).
            .Code(0x1100, 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00, 0x02)
            // Root with EH info (UBF_FUNC_HAS_EHINFO) and its funclet (kind 1, handler).
            .Code(0x1110, 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00)
            .Code(0x1120, 0x01, 0x00, 0x00, 0x00, 0x01)
            .Code(0x1130, 0x01, 0x00, 0x00, 0x00, 0x00)
            .Pdata(ManagedRoot, ManagedRoot + 6, unwindInfoRva: 0x1100)
            .Pdata(ParentWithFunclet, ParentWithFunclet + 6, unwindInfoRva: 0x1110)
            .Pdata(Funclet, Funclet + 6, unwindInfoRva: 0x1120)
            .Pdata(Native, Native + 6, unwindInfoRva: 0x1130);
        if (export)
        {
            image.Export("DotNetRuntimeDebugHeader", 0x2000); // data, outside .text
        }

        if (symbols)
        {
            image.Symbol("?__managedcode_a@@YAPEAXXZ", ManagedRoot).Symbol("?__managedcode_z@@YAPEAXXZ", Native);
        }

        if (registration)
        {
            image.Code(Startup,
                    0x48, 0x8D, 0x15, 0x79, 0xFF, 0xFF, 0xFF, // lea rdx,[rip-0x87] = 0x1000
                    0x4C, 0x8D, 0x05, 0xA2, 0xFF, 0xFF, 0xFF, // lea r8,[rip-0x5E] = 0x1030
                    0x41, 0x29, 0xD0, // sub r8d,edx
                    0xE8, 0x0A, 0x00, 0x00, 0x00, // call 0x10A0
                    0xC3)
                .Code(0x10A0, 0xC3)
                .Pdata(Startup, Startup + 0x17, unwindInfoRva: 0x1130);
        }

        return image;
    }

    private static Function Only(BinaryImage image, uint entry) => image.Functions.Single(f => f.EntryRva == entry);

    private static void AssertManagedLevels(BinaryImage image)
    {
        Assert.Equal(Transformability.RelocatableOnly, Only(image, ManagedRoot).SafetyStatus.Level);
        Assert.StartsWith("gc-info:", Only(image, ManagedRoot).SafetyStatus.DowngradeReason);
        Assert.Equal(Transformability.Frozen, Only(image, ParentWithFunclet).SafetyStatus.Level);
        Assert.StartsWith("gc-info:", Only(image, ParentWithFunclet).SafetyStatus.DowngradeReason);
        Assert.Equal(Transformability.Frozen, Only(image, Funclet).SafetyStatus.Level);
        Assert.Contains($"parent 0x{ParentWithFunclet:X}", Only(image, Funclet).SafetyStatus.DowngradeReason);
        Assert.Equal(SafetyStatus.FullyTransformable(), Only(image, Native).SafetyStatus);
        Assert.Equal(3, image.NativeAot!.ManagedFunctions);
        Assert.Equal(2, image.NativeAot.FuncletFunctions);
    }

    [Fact]
    public void Managed_range_from_pdb_symbols_downgrades_managed_methods_and_freezes_funclets()
    {
        var image = Build(symbols: true).Analyze();

        Assert.Equal(ManagedRangeSource.PdbSymbols, image.NativeAot!.Source);
        Assert.Equal((ManagedRoot, Native), (image.NativeAot.ManagedStart, image.NativeAot.ManagedEnd));
        AssertManagedLevels(image);
    }

    [Fact]
    public void Managed_range_from_the_registration_call_without_a_pdb()
    {
        var image = Build(registration: true).Analyze();

        Assert.Equal(ManagedRangeSource.RegistrationCall, image.NativeAot!.Source);
        Assert.Equal((ManagedRoot, Native), (image.NativeAot.ManagedStart, image.NativeAot.ManagedEnd));
        Assert.Equal($"RhRegisterOSModule call at 0x{Startup + 17:X}", image.NativeAot.Evidence);
        AssertManagedLevels(image);
    }

    [Fact]
    public void Unknown_managed_range_freezes_every_function()
    {
        var image = Build().Analyze();

        Assert.Equal(ManagedRangeSource.Unknown, image.NativeAot!.Source);
        Assert.All(image.Functions, f =>
        {
            Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level);
            Assert.StartsWith("gc-info:", f.SafetyStatus.DowngradeReason);
        });
    }

    [Fact]
    public void Without_the_export_the_image_is_not_native_aot()
    {
        var image = Build(export: false, symbols: true, registration: true).Analyze();

        Assert.Null(image.NativeAot);
        Assert.DoesNotContain(image.Functions, f => f.DowngradeReasons.Any(r => r.StartsWith("gc-info:")));
    }
}
