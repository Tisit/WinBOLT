using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Functions with <c>__CxxFrameHandler4</c> tables move as byte copies sharing the original
/// tables. cxxehtest (tools/targets/cxxehtest) throws C++ exceptions through them in every way
/// the tables describe: destructors while unwinding, catch and continue, rethrow, throw from a
/// catch. Its output depends only on the program's logic.
/// </summary>
public class CxxEhTests
{
    private static string? Build(string variant)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", variant, "cxxehtest.exe");
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
    [InlineData("o2", RewriteMode.Copy)]
    [InlineData("o2", RewriteMode.Rebuild)]
    [InlineData("guardcf", RewriteMode.Copy)]
    [InlineData("guardcf", RewriteMode.Rebuild)]
    [InlineData("mt", RewriteMode.Copy)]
    [InlineData("mt", RewriteMode.Rebuild)]
    public void Cxx_exceptions_run_through_moved_functions(string variant, RewriteMode mode)
    {
        if (Build(variant) is not { } path)
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

        var result = FunctionRewriter.Rewrite(image, file, null, mode);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // The test's own EH functions moved, as byte copies, catch funclets included.
        var moved = result.Moved.Select(m => image.Functions[m.FunctionId]).Where(f => f.ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler4).ToList();
        Assert.True(moved.Count >= 4, $"{moved.Count} functions with C++ EH tables moved");

        // /MT links __CxxFrameHandler4 statically: only the PDB names it.
        Assert.Equal(variant == "mt", moved.Any(f => f.ExceptionHandler!.NamedByPdb));
        Assert.All(result.Moved.Where(m => image.Functions[m.FunctionId].CxxEh is not null), m => Assert.Null(m.AddressMap));

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("alive 0", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-cxxeh-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "cxxehtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));

            // Negative control: without the copies' exception entries the same program must fail,
            // so the frames the exceptions pass through really are the copies.
            var broken = result.Output.ToArray();
            var output = PeImageReader.Read("broken.exe", broken);
            int kept = output.ExceptionData.Count(e => e.BeginAddress < result.TextRva);
            int ntHeaders = BinaryPrimitives.ReadInt32LittleEndian(broken.AsSpan(0x3C));
            BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(ntHeaders + 24 + 112 + 3 * 8 + 4), (uint)(kept * 12));
            File.WriteAllBytes(rewritten, broken);
            Assert.NotEqual(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }
}
