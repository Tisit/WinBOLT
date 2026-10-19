using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Block layout inside <c>__CxxFrameHandler3</c> functions (Fh3Writer, the /d2FH4- builds): their blocks are
/// reordered (and split) and their IP-to-state map regenerated, instead of moving as byte copies.
/// cxxehtest throws through such functions, including ones with try blocks; if a reordered frame's
/// state map is wrong, a destructor is missed or a handler not found and the output changes.
/// </summary>
public class Fh3LayoutTests
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

    private static (BinaryImage Image, byte[] File) Analyze(string path)
    {
        byte[] file = File.ReadAllBytes(path);
        var image = PeImageReader.Read(path, file);
        PdbSymbolLoader.Load(image);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        foreach (var block in image.Functions.SelectMany(f => f.BasicBlocks))
        {
            block.ExecutionCount ??= 1;
        }

        return (image, file);
    }

    /// <summary>Entry first, the other blocks shuffled, each cold with probability 1/2.</summary>
    private static BlockOrder Shuffled(Function f, int seed)
    {
        var random = new Random(seed ^ (int)f.EntryRva);
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToArray();
        random.Shuffle(others);
        var cold = others.Where(_ => random.Next(2) == 0).ToHashSet();
        return new BlockOrder([entry, .. others.Where(b => !cold.Contains(b))], others.Where(cold.Contains).ToList());
    }

    /// <summary>Every non-entry block that makes a call is cold; forces splitting of the throwing functions.</summary>
    private static BlockOrder CallsCold(BinaryImage image, Function f)
    {
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        bool Calls(BasicBlock b) => Enumerable.Range(b.InstructionStart, b.InstructionCount)
            .Any(i => image.Instructions[i].IsCallNear || image.Instructions[i].FlowControl == Iced.Intel.FlowControl.IndirectCall);
        var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToList();
        return new BlockOrder([entry, .. others.Where(b => !Calls(b))], others.Where(Calls).ToList());
    }

    private static (int ExitCode, string Output) Run(string exe)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output.Replace("\r\n", "\n"));
    }

    private static List<MovedFunction> LaidOutFh3(BinaryImage image, RewriteResult result) =>
        result.Moved.Where(m => m.AddressMap is not null &&
                                image.Functions[m.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler3).ToList();

    [SkippableTheory]
    [InlineData("fh3", 1)]
    [InlineData("fh3", 2)]
    [InlineData("fh3mt", 3)]
    public void Reordered_fh3_functions_unwind_run_destructors_and_catch(string variant, int seed)
    {
        if (Build(variant) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => Shuffled(f, seed), layoutEh: true);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // Real FH3 functions were reordered (rebuilt from their CFG), not moved as byte copies.
        var laidOut = LaidOutFh3(image, result);
        Assert.NotEmpty(laidOut);

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("alive 0", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-fh3-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "cxxehtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>
    /// Splitting a reordered FH3 function into hot and cold parts: the one sorted map covers the hot copy
    /// and every cold segment. Forcing every call-bearing block cold splits the throwing functions, whose
    /// destructors then unwind through the cold part.
    /// </summary>
    [SkippableTheory]
    [InlineData("fh3")]
    [InlineData("fh3mt")]
    public void Split_fh3_functions_unwind_through_cold_segments_and_catch(string variant)
    {
        if (Build(variant) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => CallsCold(image, f), layoutEh: true);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // A reordered FH3 function was actually split (has a cold part).
        Assert.Contains(LaidOutFh3(image, result), m => m.ColdEntries.Count > 0);

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("alive 0", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-fh3split-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "cxxehtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }
}
