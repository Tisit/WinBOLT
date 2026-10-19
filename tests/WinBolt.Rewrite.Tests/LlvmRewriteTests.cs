using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// A rewrite of ripgrep (Rust, LLVM, no PDB): table-relative switch tables are rebuilt and the
/// output runs. Uses artifacts/rg/rg.exe (a copy of the VS Code one) when present.
/// </summary>
public class LlvmRewriteTests
{
    private static string? Rg()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "rg", "rg.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string Search(string exe, string directory)
    {
        var info = new ProcessStartInfo(exe, $"-j1 -uu -c -i \"(test|sqlite3)_[a-z]+\" \"{directory}\"") { RedirectStandardOutput = true };
        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return output;
    }

    [SkippableTheory]
    [InlineData(RewriteMode.Copy)]
    [InlineData(RewriteMode.Rebuild)]
    public void Table_relative_switches_are_rebuilt_verified_and_run(RewriteMode mode)
    {
        if (Rg() is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        byte[] file = File.ReadAllBytes(path);
        var image = PeImageReader.Read(path, file);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        var result = FunctionRewriter.Rewrite(image, file, null, mode);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures.Take(10)));
        Assert.Contains(result.Moved, m => m.Tables.Any(t => t.TableRelative));

        string directory = Path.Combine(Path.GetDirectoryName(path)!, "corpus", "z");
        if (!Directory.Exists(directory))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        string temp = Path.Combine(Path.GetTempPath(), "winbolt-rg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            string output = Path.Combine(temp, "rg.exe");
            File.WriteAllBytes(output, result.Output);
            Assert.Equal(Search(path, directory), Search(output, directory));
        }
        finally
        {
            TempDirectory.Delete(temp);
        }
    }
}
