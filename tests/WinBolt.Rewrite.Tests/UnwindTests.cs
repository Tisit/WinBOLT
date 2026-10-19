using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Exception unwinding through moved and rebuilt frames, at run time: unwindtest
/// (tools/targets/unwindtest) walks its stack with RtlVirtualUnwind and unwinds an SEH exception
/// through a chain of ordinary functions into main's __except.
/// </summary>
public class UnwindTests
{
    private static string? Build(string variant)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", variant, "unwindtest.exe");
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

    private static RewriteResult? Rewrite(string path, RewriteMode mode, out BinaryImage image, out byte[] file)
    {
        file = File.ReadAllBytes(path);
        image = PeImageReader.Read(path, file);
        PdbSymbolLoader.Load(image);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return FunctionRewriter.Rewrite(image, file, null, mode);
    }

    [SkippableTheory]
    [InlineData("o2", RewriteMode.Copy)]
    [InlineData("o2", RewriteMode.Rebuild)]
    [InlineData("guardcf", RewriteMode.Copy)]
    [InlineData("guardcf", RewriteMode.Rebuild)]
    [InlineData("mt", RewriteMode.Copy)]
    [InlineData("mt", RewriteMode.Rebuild)]
    public void Stack_walks_and_exceptions_unwind_through_moved_frames(string variant, RewriteMode mode)
    {
        if (Build(variant) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var result = Rewrite(path, mode, out var image, out var file)!;
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);

        // main (__try/__except) and Guarded (__try/__finally) move with rebased scope tables.
        var seh = result.Moved.Where(m => image.Functions[m.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CSpecific).ToList();
        Assert.True(seh.Count >= 2, $"{seh.Count} SEH functions moved");

        // /MT links __C_specific_handler statically: only the PDB names it.
        Assert.Equal(variant == "mt", seh.Any(m => image.Functions[m.FunctionId].ExceptionHandler!.NamedByPdb));
        Assert.All(seh, m => Assert.NotEqual(image.ExceptionData.First(e => e.BeginAddress == m.Start).UnwindInfoAddress, m.Pdata.First(p => !p.Chained).UnwindInfo));
        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("caught E0000001", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-unwind-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "unwindtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));

            // Negative control: without the copies' exception entries the same program must fail,
            // so the frames being unwound really are the moved ones.
            var broken = result.Output.ToArray();
            DropCopiedExceptionEntries(broken, result);
            File.WriteAllBytes(rewritten, broken);
            Assert.NotEqual(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    [SkippableFact]
    public void Verifier_rejects_a_scope_table_left_pointing_at_the_original()
    {
        if (Build("o2") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var result = Rewrite(path, RewriteMode.Copy, out var image, out var file)!;
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);

        // The first scope entry's BeginAddress in main's copied UNWIND_INFO, set back to the original.
        var main = result.Moved.First(m => image.Functions[m.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CSpecific &&
                                           image.Functions[m.FunctionId].ScopeTable!.Any(e => e.JumpTargetRva != 0));
        var source = image.ExceptionData.First(e => e.BeginAddress == main.Start);
        uint field = main.Pdata.First(p => !p.Chained).UnwindInfo + (source.HandlerDataRva - source.UnwindInfoAddress) + 4;
        var output = PeImageReader.Read("rewritten.exe", result.Output);
        var section = output.FindSection(field)!;
        int offset = (int)(section.FileOffset + (field - section.Rva));
        uint mapped = BinaryPrimitives.ReadUInt32LittleEndian(result.Output.AsSpan(offset));
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(offset), mapped - (main.CopyStart - main.Start));
        int checksum = new PeLayout(result.Output).CheckSumOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(checksum), PeChecksum.Compute(result.Output, checksum));

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.Contains(report.Failures, f => f.Contains("scope entry", StringComparison.Ordinal));
    }

    /// <summary>The exception table is sorted and the copies lie above every original section: cut them off.</summary>
    private static void DropCopiedExceptionEntries(byte[] output, RewriteResult result)
    {
        var image = PeImageReader.Read("broken.exe", output);
        var directory = image.DataDirectories.First(d => d.Name == "Exception");
        int kept = image.ExceptionData.Count(e => e.BeginAddress < result.TextRva);
        int ntHeaders = BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(0x3C));
        int sizeField = ntHeaders + 24 + 112 + 3 * 8 + 4;
        Assert.Equal(directory.Size, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(sizeField)));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(sizeField), (uint)(kept * 12));
    }
}
