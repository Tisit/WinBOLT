using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Block layout inside plain unwind-only <c>__CxxFrameHandler4</c> functions (Fh4Writer): their
/// blocks are reordered and their IP-to-state map regenerated, instead of moving as byte copies.
/// cxxehtest throws through such functions (e.g. Thrower, whose Tracker destructor runs while an
/// exception unwinds); if a reordered frame's state map is wrong, a destructor is missed and the
/// program's alive/destroyed counts change.
/// </summary>
public class Fh4LayoutTests
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

    private static List<MovedFunction> LaidOutFh4(BinaryImage image, RewriteResult result) =>
        result.Moved.Where(m => m.AddressMap is not null &&
                                image.Functions[m.FunctionId].ExceptionHandler?.Kind == ExceptionHandlerKind.CxxFrameHandler4).ToList();

    [SkippableTheory]
    [InlineData("o2", 1)]
    [InlineData("o2", 2)]
    [InlineData("mt", 3)]
    public void Reordered_fh4_functions_unwind_and_run_destructors(string variant, int seed)
    {
        if (Build(variant) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => Shuffled(f, seed), layoutEh: true);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // Real FH4 functions were reordered (rebuilt from their CFG), not moved as byte copies.
        var laidOut = LaidOutFh4(image, result);
        Assert.NotEmpty(laidOut);

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("alive 0", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-fh4-").FullName;
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
    /// Splitting a reordered FH4 function into hot and cold parts: the FuncInfo4 becomes separated
    /// (a map per piece, keyed to the piece's own start). Forcing every call-bearing block cold
    /// splits the throwing functions, whose destructors then unwind through a cold-keyed segment.
    /// </summary>
    [SkippableTheory]
    [InlineData("o2")]
    [InlineData("mt")]
    public void Split_fh4_functions_use_a_separated_funcinfo_and_unwind_correctly(string variant)
    {
        if (Build(variant) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => CallsCold(image, f), layoutEh: true);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // A reordered FH4 function was actually split (has a cold part), so the separated path ran.
        Assert.Contains(LaidOutFh4(image, result), m => m.ColdEntries.Count > 0);

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("alive 0", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-fh4split-").FullName;
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
    /// Negative control: pointing a reordered function's FuncInfo4 back at the original IP-to-state
    /// map (keyed to the original addresses) must be caught, since the states no longer match the
    /// new layout. This exercises the verifier's per-instruction state check.
    /// </summary>
    [SkippableFact]
    public void Verifier_rejects_a_stale_ip_to_state_map()
    {
        if (Build("o2") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        // No cold parts, so the FuncInfo4 is a single (non-separated) map: pointing it at the
        // original map is a clean stale-map case the state check must reject.
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f =>
        {
            var order = Shuffled(f, 4);
            return new BlockOrder([.. order.Hot, .. order.Cold], []);
        }, layoutEh: true);
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);

        var output = PeImageReader.Read("rewritten.exe", result.Output);
        var moved = LaidOutFh4(image, result).First(m => image.Functions[m.FunctionId].BasicBlocks.Count > 3);
        var function = image.Functions[moved.FunctionId];
        uint originalMapRva = CxxEhParser.ReadFh4Layout(image, function.CxxEh!.FuncInfoRva, moved.Start)!.Segments[0].MapRva;

        // The copy's primary UNWIND_INFO -> FuncInfo4 -> its map RVA field, which we point back at the original map.
        uint unwindRva = moved.Pdata.First(p => !p.Chained).UnwindInfo;
        var unwind = output.ReadFrom(unwindRva).Span;
        int trailer = FunctionRewriter.UnwindTrailerOffset(unwind);
        uint funcInfoRva = BinaryPrimitives.ReadUInt32LittleEndian(unwind[(trailer + 4)..]);
        byte header = output.ReadFrom(funcInfoRva).Span[0];
        uint mapField = funcInfoRva + 1 + ((header & Fh4Layout.UnwindMapFlag) != 0 ? 4u : 0u);

        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(FileOffset(output, mapField)), originalMapRva);
        int checksum = new PeLayout(result.Output).CheckSumOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(checksum), PeChecksum.Compute(result.Output, checksum));

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.Contains(report.Failures, f => f.Contains("EH state"));
    }

    private static int FileOffset(BinaryImage image, uint rva)
    {
        var section = image.FindSection(rva)!;
        return (int)(section.FileOffset + (rva - section.Rva));
    }
}
