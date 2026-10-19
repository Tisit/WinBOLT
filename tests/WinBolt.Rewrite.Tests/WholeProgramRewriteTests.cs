using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// DesignDoc §6.2 milestone W2: whole-program function order. The strongest test of fixup-driven
/// relocation is an order no profile would produce: every function reversed or shuffled, so
/// nearly every reference in the image changes; the programs must still behave identically.
/// </summary>
public class WholeProgramRewriteTests
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

    private static (string Path, BinaryImage Image, byte[] File)? Analyze(string variant, string target)
    {
        if (Build(variant, target) is not { } path)
        {
            return null;
        }

        byte[] file = File.ReadAllBytes(path);
        var image = PeImageReader.Read(path, file);
        PdbSymbolLoader.Load(image);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return (path, image, file);
    }

    private static List<SectionContribution> Code(BinaryImage image) =>
        image.SectionContributions.Where(c => image.FindSection(c.Rva) is { IsExecutable: true }).OrderBy(c => c.Rva).ToList();

    private static IReadOnlyList<SectionContribution> Order(BinaryImage image, string how)
    {
        var code = Code(image);
        if (how == "reversed")
        {
            code.Reverse();
            return code;
        }

        var random = new Random(20260928);
        return code.OrderBy(_ => random.Next()).ToList();
    }

    [SkippableFact]
    public void Original_order_is_an_exact_no_op()
    {
        if (Analyze("o2", "zopfli.exe") is not var (_, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var result = WholeProgramRewriter.Rewrite(image, file);

        Assert.True(WholeProgramVerifier.Verify(image, file, result).Passed);
        Assert.All(result.Placed, p => Assert.Equal(0, p.Delta));
        Assert.Equal(0, result.FixupsRewritten);
        // Only the RSDS GUID and the checksum differ.
        var layout = new PeLayout(file);
        var differences = Enumerable.Range(0, file.Length).Where(i => file[i] != result.Output[i]).ToList();
        var guid = image.DebugEntries.First(e => e.Type == DebugDirectoryType.CodeView).PointerToRawData + 4;
        Assert.All(differences, i => Assert.True((i >= guid && i < guid + 16) || (i >= layout.CheckSumOffset && i < layout.CheckSumOffset + 4), $"offset 0x{i:X}"));
    }

    private static (int ExitCode, string Output) Run(string exe, params string[] arguments)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        using var output = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(output);
        process.WaitForExit();
        string text = Convert.ToHexString(output.ToArray());
        if (Path.GetFileName(exe) == "speedtest1.exe")
        {
            // speedtest1 prints timings; its verification hash is the deterministic result.
            text = System.Text.Encoding.UTF8.GetString(output.ToArray()).Split('\n').Select(l => l.Trim())
                .LastOrDefault(l => l.StartsWith("Verification Hash:", StringComparison.Ordinal)) ?? "(no hash)";
        }

        return (process.ExitCode, text);
    }

    [SkippableTheory]
    [InlineData("o2", "zopfli.exe", "reversed")]
    [InlineData("o2", "zopfli.exe", "shuffled")]
    [InlineData("o2", "speedtest1.exe", "shuffled")]
    [InlineData("guardcf", "speedtest1.exe", "shuffled")]
    [InlineData("pgo", "speedtest1.exe", "reversed")]
    [InlineData("o2", "zopflipng.exe", "shuffled")]
    [InlineData("o2", "cxxehtest.exe", "reversed")]
    [InlineData("mt", "cxxehtest.exe", "shuffled")]
    [InlineData("o2", "unwindtest.exe", "shuffled")]
    [InlineData("mt", "unwindtest.exe", "reversed")]
    public void Reordered_program_verifies_and_behaves_identically(string variant, string target, string how)
    {
        if (Analyze(variant, target) is not var (path, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var result = WholeProgramRewriter.Rewrite(image, file, Order(image, how));
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.True(result.Placed.Count(p => p.Delta != 0) > result.Placed.Count / 2);

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, target);
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = target switch
            {
                "zopfli.exe" => ["--i3", "--gzip", "-c", Input(directory, file)],
                "speedtest1.exe" => ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"],
                "zopflipng.exe" => ["-y", Png(path), Path.Combine(directory, "out.png")],
                _ => [],
            };

            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            string? png = target == "zopflipng.exe" ? Convert.ToHexString(File.ReadAllBytes(Path.Combine(directory, "out.png"))) : null;
            Assert.Equal(expected, Run(rewritten, arguments));
            if (png is not null)
            {
                Assert.Equal(png, Convert.ToHexString(File.ReadAllBytes(Path.Combine(directory, "out.png"))));
            }
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    private static string Input(string directory, byte[] file)
    {
        string input = Path.Combine(directory, "input.bin");
        File.WriteAllBytes(input, file.Take(60_000).ToArray());
        return input;
    }

    /// <summary>The zopflipng benchmark input (artifacts/bench, next to artifacts/targets).</summary>
    private static string Png(string exe) =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(exe)!, "..", "..", "bench", "zopflipng-256.png"));

    /// <summary>
    /// The profiled use: C3 order with JCC placement. The padding does not fit in .text, so the
    /// coldest tail spills into .wbcold; the program must still behave identically.
    /// </summary>
    [SkippableTheory]
    [InlineData("zopfli")]
    [InlineData("speedtest1")]
    public void Profiled_order_with_jcc_placement_spills_the_cold_tail_and_behaves_identically(string target)
    {
        if (Analyze("o2", target + ".exe") is not var (path, image, file) ||
            Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "..", "..", $"lbr-{target}.etl")) is not { } trace || !File.Exists(trace))
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        WinBolt.Profile.EtwLbrProfile.Apply(image, trace, target + ".exe");
        var code = Code(image);
        var order = FunctionOrdering.C3(image).Select(o => code.FirstOrDefault(c => o.Function.EntryRva >= c.Rva && o.Function.EntryRva < c.Rva + c.Size))
            .Where(c => c.Size > 0).Distinct().ToList();
        var result = WholeProgramRewriter.Rewrite(image, file, order, jccErratum: true);
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.True(result.Spill.Size > 0);
        Assert.All(order, c => Assert.False(result.InSpill(result.MapSite(c.Rva)), "a hot function spilled"));

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, target + ".exe");
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = target == "zopfli"
                ? ["--i3", "--gzip", "-c", Input(directory, file)]
                : ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            Assert.Equal(expected, Run(rewritten, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    // --- W3: block layout in whole-program mode ---

    private static void MarkAllExecuted(BinaryImage image)
    {
        foreach (var block in image.Functions.SelectMany(f => f.BasicBlocks))
        {
            block.ExecutionCount ??= 1;
        }
    }

    /// <summary>Entry first, the other blocks shuffled, each cold with probability 1/2.</summary>
    private static BlockOrder ShuffledBlocks(Function f, int seed)
    {
        var random = new Random(seed ^ (int)f.EntryRva);
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToArray();
        random.Shuffle(others);
        var cold = others.Where(_ => random.Next(2) == 0).ToHashSet();
        return new BlockOrder([entry, .. others.Where(b => !cold.Contains(b))], others.Where(cold.Contains).ToList());
    }

    /// <summary>Every non-entry block holding a call is cold: frames are unwound from cold code.</summary>
    private static BlockOrder CallsCold(BinaryImage image, Function f)
    {
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        bool Calls(BasicBlock b) => Enumerable.Range(b.InstructionStart, b.InstructionCount).Any(i => image.Instructions[i].IsCallNear ||
                                                                                                        image.Instructions[i].FlowControl == Iced.Intel.FlowControl.IndirectCall);
        var others = f.BasicBlocks.Where(b => b != entry).OrderByDescending(b => b.StartRva).ToList();
        return new BlockOrder([entry, .. others.Where(b => !Calls(b))], others.Where(Calls).Reverse().ToList());
    }

    /// <summary>
    /// Every function executed, every block order shuffled and split, the functions themselves
    /// shuffled: nearly every instruction moves and every call crosses the new layout.
    /// </summary>
    [SkippableTheory]
    [InlineData("o2", "zopfli.exe", 1, false)]
    [InlineData("o2", "zopfli.exe", 2, true)]
    [InlineData("o2", "speedtest1.exe", 3, true)]
    [InlineData("guardcf", "speedtest1.exe", 4, false)]
    [InlineData("o2", "zopflipng.exe", 5, true)]
    public void Shuffled_blocks_and_functions_verify_and_behave_identically(string variant, string target, int seed, bool jccErratum)
    {
        if (Analyze(variant, target) is not var (path, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        MarkAllExecuted(image);
        var result = WholeProgramRewriter.Rewrite(image, file, Order(image, "shuffled"), jccErratum, f => ShuffledBlocks(f, seed));
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.True(result.Rebuilt.Count > image.Functions.Count / 2, $"{result.Rebuilt.Count} of {image.Functions.Count} rebuilt");
        Assert.Contains(result.Rebuilt.Values, r => r.ColdLength > 0);

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, target);
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = target switch
            {
                "zopfli.exe" => ["--i3", "--gzip", "-c", Input(directory, file)],
                "speedtest1.exe" => ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"],
                _ => ["-y", Png(path), Path.Combine(directory, "out.png")],
            };

            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            string? png = target == "zopflipng.exe" ? Convert.ToHexString(File.ReadAllBytes(Path.Combine(directory, "out.png"))) : null;
            Assert.Equal(expected, Run(rewritten, arguments));
            if (png is not null)
            {
                Assert.Equal(png, Convert.ToHexString(File.ReadAllBytes(Path.Combine(directory, "out.png"))));
            }
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    [SkippableTheory]
    [InlineData("o2", false)]
    [InlineData("mt", true)]
    public void Stack_walks_and_exceptions_unwind_through_cold_parts(string variant, bool jccErratum)
    {
        if (Analyze(variant, "unwindtest.exe") is not var (path, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        MarkAllExecuted(image);
        var result = WholeProgramRewriter.Rewrite(image, file, Order(image, "reversed"), jccErratum, f => CallsCold(image, f));
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        // Busy calls from non-entry blocks and is shrink-wrapped: its cold blocks belong to a chained entry.
        Assert.Contains(result.Rebuilt.Values, r => r.Pdata.Count > 1 && r.ColdEntries.Any(c => r.Pdata.Single(p => p.OriginalBegin == c.OriginalBegin).Chained));

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "unwindtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));

            // Negative control: without the cold parts' entries the walk must break.
            var broken = result.Output.ToArray();
            var output = PeImageReader.Read("broken.exe", broken);
            var coldBegins = result.Rebuilt.Values.SelectMany(r => r.ColdEntries).Select(c => c.Begin).ToHashSet();
            var kept = output.ExceptionData.Where(e => !coldBegins.Contains(e.BeginAddress)).ToList();
            int table = WholeProgramRewriter.FileOffset(output, result.Data.Rva)!.Value;
            for (int i = 0; i < kept.Count; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(table + i * 12), kept[i].BeginAddress);
                BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(table + i * 12 + 4), kept[i].EndAddress);
                BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(table + i * 12 + 8), kept[i].UnwindInfoAddress);
            }

            var layout = new PeLayout(broken);
            BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(layout.DataDirectory(PeLayout.ExceptionDirectory) + 4), (uint)kept.Count * 12);
            BinaryPrimitives.WriteUInt32LittleEndian(broken.AsSpan(layout.CheckSumOffset), PeChecksum.Compute(broken, layout.CheckSumOffset));
            File.WriteAllBytes(rewritten, broken);
            Assert.NotEqual(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>
    /// MSVC gives the switch tables after a function's last instruction a chained unwind entry of
    /// their own (SQLite: sqlite3_step, sqlite3_config): no instruction starts it. A rebuilt function
    /// drops that entry; the program must still run, and the new .pdata must not name the tables.
    /// </summary>
    [SkippableTheory]
    [InlineData("o2")]
    [InlineData("ltcg")]
    public void Functions_with_a_table_only_unwind_entry_are_rebuilt(string variant)
    {
        if (Analyze(variant, "speedtest1.exe") is not var (path, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var withTableEntry = image.Functions.Where(f => f.Ranges.Count == 1 && image.ExceptionData.Any(e =>
            e.BeginAddress > f.EntryRva && e.BeginAddress < f.EntryRva + f.EntryRange.Length && BlockRebuilder.IsTableEntry(image, f, e))).ToList();
        Assert.True(withTableEntry.Count >= 3, $"{withTableEntry.Count} functions with a table-only entry");

        MarkAllExecuted(image);
        var result = WholeProgramRewriter.Rewrite(image, file, Order(image, "shuffled"), true, f => ShuffledBlocks(f, 7));
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        var rebuilt = result.Rebuilt.Values.Select(r => r.Function).ToHashSet();
        Assert.All(withTableEntry, f => Assert.Contains(f, rebuilt));

        var output = PeImageReader.Read("rewritten.exe", result.Output);
        foreach (var r in result.Rebuilt.Values.Where(r => withTableEntry.Contains(r.Function)))
        {
            // Nothing in the new table starts past the hot part inside the function's new range but the cold entries.
            Assert.DoesNotContain(output.ExceptionData, e => e.BeginAddress == r.HotStart + r.HotLength);
        }

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "speedtest1.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            Assert.Equal(expected, Run(rewritten, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>
    /// A layout shift moves the same layout by whole cache lines: every rebuilt function keeps its
    /// encoding (all 32-byte decisions are unchanged), only its address moves. Both modes verify
    /// and run identically; a shift that is not a whole cache line is rejected.
    /// </summary>
    [SkippableFact]
    public void Layout_shift_moves_the_same_layout_by_whole_cache_lines()
    {
        if (Analyze("o2", "zopfli.exe") is not var (path, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        MarkAllExecuted(image);
        var order = Order(image, "reversed");
        var plain = WholeProgramRewriter.Rewrite(image, file, order, true, f => ShuffledBlocks(f, 9));
        var shifted = WholeProgramRewriter.Rewrite(image, file, order, true, f => ShuffledBlocks(f, 9), layoutShift: 3 * FunctionRewriter.LayoutShiftUnit);
        Assert.True(WholeProgramVerifier.Verify(image, file, shifted).Passed);
        Assert.All(shifted.Rebuilt, kv => Assert.Equal(plain.Rebuilt[kv.Key].HotLength, kv.Value.HotLength));
        Assert.Equal(plain.Rebuilt.Values.Min(r => r.HotStart) + 3 * FunctionRewriter.LayoutShiftUnit, shifted.Rebuilt.Values.Min(r => r.HotStart));

        var append = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => ShuffledBlocks(f, 9), true, layoutShift: 5 * FunctionRewriter.LayoutShiftUnit);
        Assert.True(RewriteVerifier.Verify(image, file, append).Passed);
        Assert.Throws<ArgumentException>(() => WholeProgramRewriter.Rewrite(image, file, order, layoutShift: 32));

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string[] arguments = ["--i3", "--gzip", "-c", Input(directory, file)];
            var expected = Run(path, arguments);
            foreach (var (name, output) in new[] { ("whole.exe", shifted.Output), ("append.exe", append.Output) })
            {
                string rewritten = Path.Combine(directory, name);
                File.WriteAllBytes(rewritten, output);
                Assert.Equal(expected, Run(rewritten, arguments));
            }
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>The profiled use of W3: C3 order, Stage 6 block layout with splitting, JCC padding.</summary>
    [SkippableTheory]
    [InlineData("zopfli")]
    [InlineData("speedtest1")]
    public void Profiled_block_layout_verifies_and_behaves_identically(string target)
    {
        if (Analyze("o2", target + ".exe") is not var (path, image, file) ||
            Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "..", "..", $"lbr-{target}.etl")) is not { } trace || !File.Exists(trace))
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        WinBolt.Profile.EtwLbrProfile.Apply(image, trace, target + ".exe");
        var code = Code(image);
        var order = FunctionOrdering.C3(image).Select(o => code.FirstOrDefault(c => o.Function.EntryRva >= c.Rva && o.Function.EntryRva < c.Rva + c.Size))
            .Where(c => c.Size > 0).Distinct().ToList();
        var result = WholeProgramRewriter.Rewrite(image, file, order, jccErratum: true, blockOrder: f => BlockLayout.Order(f, true, BlockLayoutAlgorithm.Chains));
        var report = WholeProgramVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.NotEmpty(result.Rebuilt);

        string directory = Directory.CreateTempSubdirectory("winbolt-whole-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, target + ".exe");
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = target == "zopfli"
                ? ["--i3", "--gzip", "-c", Input(directory, file)]
                : ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            Assert.Equal(expected, Run(rewritten, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>A reference the linker resolved, left at its old value: the verifier must catch it.</summary>
    [SkippableFact]
    public void Verifier_rejects_a_fixup_left_at_the_old_address()
    {
        if (Analyze("o2", "speedtest1.exe") is not var (_, image, file))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var result = WholeProgramRewriter.Rewrite(image, file, Order(image, "reversed"));
        var call = image.LinkerFixups.First(f => f.Type == 4 && result.Owner(f.Rva) is { Delta: not 0 } && result.Owner(f.Target) is { Delta: not 0 } &&
                                                 image.ReadFrom(f.Rva - 1).Span[0] == 0xE8);
        uint site = result.MapSite(call.Rva);
        int at = WholeProgramRewriter.FileOffset(image, site)!.Value;
        // The displacement the original call had, at the new site: it no longer reaches the callee.
        BinaryPrimitives.WriteInt32LittleEndian(result.Output.AsSpan(at), BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(WholeProgramRewriter.FileOffset(image, call.Rva)!.Value)));

        var report = WholeProgramVerifier.Verify(image, file, result);

        Assert.False(report.Passed);
        Assert.Contains(report.Failures, f => f.StartsWith($"fixup at 0x{call.Rva:X}"));
    }
}
