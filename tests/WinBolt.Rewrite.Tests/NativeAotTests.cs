using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// NativeAOT images (DesignDoc R5): the gate downgrades managed methods (<c>gc-info</c>) and every
/// rewriter refuses the image. Uses artifacts/aot/aotbench/aotbench.exe (built from
/// artifacts/aot/src/aotbench) when present.
/// </summary>
public class NativeAotTests
{
    private static string? Aotbench()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "aot", "aotbench", "aotbench.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static (BinaryImage Image, byte[] File) Analyze(string path, bool pdb)
    {
        byte[] file = File.ReadAllBytes(path);
        var image = PeImageReader.Read(path, file);
        if (pdb)
        {
            PdbSymbolLoader.Load(image);
        }

        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return (image, file);
    }

    [SkippableFact]
    public void Managed_methods_are_downgraded_with_or_without_the_pdb()
    {
        if (Aotbench() is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (withPdb, _) = Analyze(path, pdb: true);
        var (withoutPdb, _) = Analyze(path, pdb: false);
        if (withPdb.Pdb is null)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.Equal(ManagedRangeSource.PdbSymbols, withPdb.NativeAot!.Source);
        Assert.Equal(ManagedRangeSource.RegistrationCall, withoutPdb.NativeAot!.Source);
        Assert.Equal((withPdb.NativeAot.ManagedStart, withPdb.NativeAot.ManagedEnd), (withoutPdb.NativeAot.ManagedStart, withoutPdb.NativeAot.ManagedEnd));

        foreach (var image in new[] { withPdb, withoutPdb })
        {
            var aot = image.NativeAot!;
            var managed = image.Functions.Where(f => aot.IsManaged(f.EntryRva)).ToList();
            Assert.NotEmpty(managed);
            Assert.All(managed, f =>
            {
                Assert.NotEqual(Transformability.FullyTransformable, f.SafetyStatus.Level);
                Assert.Contains(f.DowngradeReasons, r => r.StartsWith("gc-info:"));
            });

            // Funclets and their parents: UnwindBlockFlags read unpadded is consistent with them (every parent has EH info).
            Assert.InRange(aot.FuncletFunctions, 1, aot.ManagedFunctions / 4);
            Assert.All(managed.Where(f => f.DowngradeReasons.Any(r => r.StartsWith("gc-info: NativeAOT funclet"))),
                f => Assert.Equal(Transformability.Frozen, f.SafetyStatus.Level));

            // Native runtime code after the range is untouched by the check.
            Assert.Contains(image.Functions, f => !aot.IsManaged(f.EntryRva) && f.SafetyStatus.Level == Transformability.FullyTransformable);
        }
    }

    [SkippableTheory]
    [InlineData(RewriteMode.Copy)]
    [InlineData(RewriteMode.Rebuild)]
    public void Append_rewrites_are_refused(RewriteMode mode)
    {
        if (Aotbench() is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path, pdb: false);
        var refused = Assert.Throws<RewriteRefusedException>(() => FunctionRewriter.Rewrite(image, file, null, mode));
        Assert.Contains("NativeAOT", refused.Message);
    }

    [SkippableFact]
    public void Whole_program_rewrite_is_refused()
    {
        if (Aotbench() is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path, pdb: true);
        var refused = Assert.Throws<RewriteRefusedException>(() => WholeProgramRewriter.Rewrite(image, file, null));
        Assert.Contains("NativeAOT", refused.Message);
    }
}
