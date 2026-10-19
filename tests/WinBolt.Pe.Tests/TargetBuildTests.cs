namespace WinBolt.Pe.Tests;

/// <summary>
/// Against the builds tools/targets/Build-Targets.ps1 writes to artifacts/targets/, when present.
/// </summary>
public class TargetBuildTests
{
    private static string? Build(string variant, string file)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", variant, file);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    [SkippableFact]
    public void Cfg_instrumented_objects_alone_do_not_make_an_image_cfg_enabled()
    {
        // The o2 build links CRT objects compiled with /guard:cf, so its load config says
        // CF_INSTRUMENTED, but the image lacks the GUARD_CF characteristic: the loader does not
        // enforce CFG, and a rewrite has no CFG tables to keep valid.
        if (Build("o2", "zopfli.exe") is not { } plain || Build("guardcf", "zopfli.exe") is not { } guarded)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.False(PeImageReader.Read(plain).LoadConfig!.HasCfg);

        var cfg = PeImageReader.Read(guarded).LoadConfig!;
        Assert.True(cfg.HasCfg);
        Assert.NotEmpty(cfg.GuardCfFunctionTable);
    }
}
