using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// /guard:ehcont builds (the ehcont variant of cxxehtest and unwindtest): functions holding EH
/// continuation targets move, and the output's GuardEHContinuationTable is rewritten in .wbdata
/// with every original entry plus each moved target's new address (GuardTables). The OS enforces
/// the table only with user-mode shadow stacks (CET hardware), so the run here checks behaviour,
/// the verifier checks the table.
/// </summary>
public class EhContinuationTests
{
    private static string? Build(string name)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", "ehcont", name + ".exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static (int ExitCode, string Output) Run(string exe)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output.Replace("\r\n", "\n"));
    }

    [SkippableTheory]
    [InlineData("cxxehtest", RewriteMode.Copy)]
    [InlineData("cxxehtest", RewriteMode.Rebuild)]
    [InlineData("unwindtest", RewriteMode.Copy)]
    [InlineData("unwindtest", RewriteMode.Rebuild)]
    public void Functions_with_eh_continuations_move_and_the_table_names_their_copies(string name, RewriteMode mode)
    {
        if (Build(name) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        byte[] file = File.ReadAllBytes(path);
        var image = PeImageReader.Read(path, file);
        PdbSymbolLoader.Load(image);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        var continuations = image.LoadConfig!.GuardEhContinuationTable!;
        Assert.NotEmpty(continuations);

        var result = FunctionRewriter.Rewrite(image, file, null, mode);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.DoesNotContain(result.Skipped, s => s.Reason.Contains("continuation"));

        // Every continuation target lies in a moved function, and the output lists both addresses.
        var output = PeImageReader.Read("out.exe", result.Output);
        var table = output.LoadConfig!.GuardEhContinuationTable!;
        foreach (uint t in continuations)
        {
            var moved = result.Moved.Single(m => t >= m.Start && t < m.Start + m.Length);
            Assert.Contains(t, table);
            Assert.Contains(FunctionRewriter.MapMoved(moved, t)!.Value, table);
        }

        Assert.Equal(2 * continuations.Count, table.Count);
        var config = image.DataDirectories.Single(d => d.Name == "LoadConfig");
        ulong tableVa = BinaryPrimitives.ReadUInt64LittleEndian(output.ReadFrom(config.Rva + GuardTables.EhContinuationTableField).Span);
        Assert.Equal(".wbdata", output.FindSection((uint)(tableVa - output.ImageBase))!.Name);

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        string directory = Directory.CreateTempSubdirectory("winbolt-ehcont-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, name + ".exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }

        // Negative control: the original table back in place (moved targets missing) fails verification.
        int at = (int)WholeProgramRewriter.FileOffset(image, config.Rva + GuardTables.EhContinuationTableField)!.Value;
        file.AsSpan(at, 16).CopyTo(result.Output.AsSpan(at));
        var layout = new PeLayout(result.Output);
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(layout.CheckSumOffset), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(layout.CheckSumOffset), PeChecksum.Compute(result.Output, layout.CheckSumOffset));
        var tampered = RewriteVerifier.Verify(image, file, result);
        Assert.False(tampered.Passed);
        Assert.Contains(tampered.Failures, f => f.Contains("GuardEHContinuationTable"));
    }
}
