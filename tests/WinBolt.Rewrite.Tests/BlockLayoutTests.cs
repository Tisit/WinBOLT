using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Stage 6 step 2: block reordering and hot/cold splitting. Besides the profile-driven layout,
/// forced layouts that no profile would produce (random orders, random cold sets, every block
/// with a call cold) exercise inverted branches, inserted and dropped jumps, and frames whose
/// return addresses lie in cold parts, at run time.
/// </summary>
public class BlockLayoutTests
{
    private static string? Find(params string[] parts)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine([directory.FullName, "artifacts", .. parts]);
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

        return (image, file);
    }

    /// <summary>Entry first, the other blocks shuffled, each cold with probability 1/2 (or none with <paramref name="split"/> off).</summary>
    private static BlockOrder Shuffled(Function f, int seed, bool split = true)
    {
        var random = new Random(seed ^ (int)f.EntryRva);
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToArray();
        random.Shuffle(others);
        var cold = others.Where(_ => split && random.Next(2) == 0).ToHashSet();
        return new BlockOrder([entry, .. others.Where(b => !cold.Contains(b))], others.Where(cold.Contains).ToList());
    }

    /// <summary>Every non-entry block holding a call is cold; the other blocks in reverse order.</summary>
    private static BlockOrder CallsCold(BinaryImage image, Function f)
    {
        var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
        bool Calls(BasicBlock b) => Enumerable.Range(b.InstructionStart, b.InstructionCount).Any(i => image.Instructions[i].IsCallNear || image.Instructions[i].IsCallFar ||
                                                                                                        image.Instructions[i].FlowControl == Iced.Intel.FlowControl.IndirectCall);
        var others = f.BasicBlocks.Where(b => b != entry).OrderByDescending(b => b.StartRva).ToList();
        return new BlockOrder([entry, .. others.Where(b => !Calls(b))], others.Where(Calls).Reverse().ToList());
    }

    private static (int ExitCode, string Output) Run(string exe, params string[] arguments)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output.Replace("\r\n", "\n"));
    }

    private static void AssertLaidOut(BinaryImage image, byte[] file, RewriteResult result)
    {
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.Contains(result.Moved, m => m.ColdEntries.Count > 0);
        Assert.True(result.KeptBlockOrder.Count < result.Moved.Count / 2, $"{result.KeptBlockOrder.Count} of {result.Moved.Count} kept their order");
    }

    [Fact]
    public void Profile_layout_chains_hot_edges_into_fall_throughs_and_splits_unexecuted_blocks()
    {
        // entry -(1000)-> c, entry -(1)-> b; c -> d hot; b and e never executed.
        var f = new Function { Id = 0, Name = "f" };
        f.Ranges.Add(new FunctionRange { StartRva = 0x1000, Length = 0x50, IsEntryRange = true });
        BasicBlock Block(int id, uint at, ulong count)
        {
            var b = new BasicBlock { Id = id, StartRva = at, Length = 0x10, InstructionCount = 1, ExecutionCount = count };
            f.BasicBlocks.Add(b);
            return b;
        }

        var entry = Block(0, 0x1000, 1001);
        var b = Block(1, 0x1010, 1);
        var c = Block(2, 0x1020, 1000);
        var d = Block(3, 0x1030, 1000);
        var e = Block(4, 0x1040, 0);
        void Edge(BasicBlock from, BasicBlock to, EdgeKind kind, ulong count)
        {
            var edge = new Edge { Source = from, Target = to, Kind = kind, ExecutionCount = count };
            from.Successors.Add(edge);
            to.Predecessors.Add(edge);
        }

        Edge(entry, b, EdgeKind.FallThrough, 1);
        Edge(entry, c, EdgeKind.Branch, 1000);
        Edge(c, d, EdgeKind.FallThrough, 1000);
        Edge(d, e, EdgeKind.FallThrough, 0);

        foreach (var algorithm in new[] { BlockLayoutAlgorithm.Chains, BlockLayoutAlgorithm.ExtTsp })
        {
            var order = BlockLayout.Order(f, algorithm: algorithm);
            Assert.Equal([entry, c, d, b], order.Hot);
            Assert.Equal([e], order.Cold);
            Assert.Null(order.Problem(f));
            Assert.Equal([entry, c, d, b, e], BlockLayout.Order(f, split: false, algorithm).Hot);
        }
    }

    [Fact]
    public void Ext_tsp_puts_a_block_between_two_chained_blocks_when_that_scores_more()
    {
        // entry → a (100), a → c (60), a → b (40), b → c (40): greedy chaining takes a → c first
        // and can then only append b; ext-TSP splits [entry a c] to make both of a's successors
        // cheap: a → b falls through and b → c falls through (100 + 40 + 40 beats 100 + 60).
        var f = new Function { Id = 0, Name = "f" };
        f.Ranges.Add(new FunctionRange { StartRva = 0x1000, Length = 0x40, IsEntryRange = true });
        BasicBlock Block(int id, uint at, ulong count)
        {
            var block = new BasicBlock { Id = id, StartRva = at, Length = 0x10, InstructionCount = 1, ExecutionCount = count };
            f.BasicBlocks.Add(block);
            return block;
        }

        var entry = Block(0, 0x1000, 100);
        var a = Block(1, 0x1010, 100);
        var c = Block(2, 0x1020, 100);
        var b = Block(3, 0x1030, 40);
        void Edge(BasicBlock from, BasicBlock to, EdgeKind kind, ulong count)
        {
            var edge = new Edge { Source = from, Target = to, Kind = kind, ExecutionCount = count };
            from.Successors.Add(edge);
            to.Predecessors.Add(edge);
        }

        Edge(entry, a, EdgeKind.FallThrough, 100);
        Edge(a, c, EdgeKind.FallThrough, 60);
        Edge(a, b, EdgeKind.Branch, 40);
        Edge(b, c, EdgeKind.Branch, 40);

        var chains = BlockLayout.Order(f, algorithm: BlockLayoutAlgorithm.Chains).Hot;
        var extTsp = BlockLayout.Order(f, algorithm: BlockLayoutAlgorithm.ExtTsp).Hot;
        Assert.Equal([entry, a, c, b], chains);
        Assert.Equal([entry, a, b, c], extTsp);
        Assert.True(BlockLayout.Score(extTsp) > BlockLayout.Score(chains));
    }

    /// <summary>Without a profile nothing is hot; JCC padding applies to executed blocks only, so treat every block as executed.</summary>
    private static void MarkAllExecuted(BinaryImage image)
    {
        foreach (var block in image.Functions.SelectMany(f => f.BasicBlocks))
        {
            block.ExecutionCount ??= 1;
        }
    }

    [SkippableTheory]
    [InlineData("o2", 1, false)]
    [InlineData("o2", 2, true)]
    [InlineData("guardcf", 3, true)]
    public void Random_layouts_of_zopfli_verify_and_compress_identically(string variant, int seed, bool jccErratum)
    {
        if (Find("targets", variant, "zopfli.exe") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        if (jccErratum)
        {
            MarkAllExecuted(image);
        }

                // Cold code is not padded: the padded variants keep every block hot.
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => Shuffled(f, seed, split: !jccErratum), jccErratum, alignLoops: jccErratum);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.True(result.KeptBlockOrder.Count < result.Moved.Count / 2);
        Assert.Equal(!jccErratum, result.Moved.Any(m => m.ColdEntries.Count > 0));
        if (jccErratum)
        {
            var (branches, before, after, _, _) = LayoutStatistics.JccErratum(image, result);
            Assert.True(before > 0.05 * branches && after < 0.01 * branches, $"{before / branches:P1} of branches on a boundary before, {after / branches:P1} after");
        }

        string directory = Directory.CreateTempSubdirectory("winbolt-blocks-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "zopfli.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, file.Take(60_000).ToArray());
            foreach (string format in new[] { "--gzip", "--deflate" })
            {
                Assert.Equal(Compress(path, format, input), Compress(rewritten, format, input));
            }
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    private static byte[] Compress(string exe, string format, string input)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string arg in new[] { "--i3", format, "-c", input })
        {
            info.ArgumentList.Add(arg);
        }

        using var process = Process.Start(info)!;
        using var output = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(output);
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return output.ToArray();
    }

    [SkippableFact]
    public void Profile_layout_of_zopfli_with_jcc_padding_compresses_identically()
    {
        // Needs the o2 build and an LBR trace of it (tools/profile/Capture-Lbr.ps1), both in artifacts/.
        if (Find("targets", "o2", "zopfli.exe") is not { } path || Find("lbr-zopfli.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (image, file) = Analyze(path);
        EtwLbrProfile.Apply(image, trace, "zopfli.exe");
        var order = FunctionOrdering.C3(image);
        var result = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), RewriteMode.Rebuild, f => BlockLayout.Order(f), jccErratum: true, alignLoops: true);
        AssertLaidOut(image, file, result);
        var (branches, _, onBoundaryAfter, _, _) = LayoutStatistics.JccErratum(image, result);
        Assert.True(onBoundaryAfter < 0.01 * branches);

        string directory = Directory.CreateTempSubdirectory("winbolt-blocks-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "zopfli.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, file.Take(60_000).ToArray());
            Assert.Equal(Compress(path, "--gzip", input), Compress(rewritten, "--gzip", input));

            // Byte copies (function layout only) cannot be padded: their starts are placed to keep
            // executed branches off boundaries. Unplaced copies raise zopfli's exposure.
            var placed = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), jccErratum: true);
            var unplaced = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList());
            Assert.True(RewriteVerifier.Verify(image, file, placed).Passed);
            var (_, before, placedAfter, _, _) = LayoutStatistics.JccErratum(image, placed);
            var (_, _, unplacedAfter, _, _) = LayoutStatistics.JccErratum(image, unplaced);
            Assert.True(placedAfter < before && placedAfter < unplacedAfter / 2, $"{before} before, {unplacedAfter} unplaced, {placedAfter} placed");
            File.WriteAllBytes(rewritten, placed.Output);
            Assert.Equal(Compress(path, "--gzip", input), Compress(rewritten, "--gzip", input));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    [SkippableFact]
    public void Random_layout_of_speedtest1_keeps_its_verification_hash()
    {
        if (Find("targets", "o2", "speedtest1.exe") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => Shuffled(f, 4));
        AssertLaidOut(image, file, result);

        string directory = Directory.CreateTempSubdirectory("winbolt-blocks-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "speedtest1.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            var expected = Run(path, arguments);
            Assert.Equal(0, expected.ExitCode);
            Assert.Equal(Hash(expected.Output), Hash(Run(rewritten, arguments).Output));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }

        static string Hash(string output) => output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("Verification Hash:", StringComparison.Ordinal)) ?? "none";
    }

    [SkippableTheory]
    [InlineData("o2", false)]
    [InlineData("guardcf", false)]
    [InlineData("o2", true)]
    public void Stack_walks_and_exceptions_unwind_through_cold_parts(string variant, bool jccErratum)
    {
        if (Find("targets", variant, "unwindtest.exe") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        if (jccErratum)
        {
            MarkAllExecuted(image);
        }

        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => CallsCold(image, f), jccErratum);
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);
        // The test's own functions are static (no public symbols). Busy calls from non-entry blocks
        // and is shrink-wrapped: its cold blocks belong to a chained entry.
        Assert.True(result.Moved.Any(m => m.Pdata.Count > 1 && m.ColdEntries.Any(c => m.Pdata.Single(p => p.OriginalBegin == c.OriginalBegin).Chained)),
            string.Join("; ", result.KeptBlockOrder.Select(k => $"{k.Function.EntryRva:X}: {k.Reason}")));

        var expected = Run(path);
        Assert.Equal(0, expected.ExitCode);
        Assert.Contains("caught E0000001", expected.Output);

        string directory = Directory.CreateTempSubdirectory("winbolt-unwind-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "unwindtest.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten));

            // Negative control: without the cold parts' entries the walk must break, so frames
            // really are unwound from cold code.
            var broken = result.Output.ToArray();
            DropColdEntries(broken, result);
            File.WriteAllBytes(rewritten, broken);
            Assert.NotEqual(expected, Run(rewritten));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    /// <summary>Cold parts lie above all hot copies and the exception table is sorted: cut their entries off.</summary>
    private static void DropColdEntries(byte[] output, RewriteResult result)
    {
        var image = PeImageReader.Read("broken.exe", output);
        uint firstCold = result.Moved.Where(m => m.ColdLength > 0).Min(m => m.ColdStart);
        int kept = image.ExceptionData.Count(e => e.BeginAddress < firstCold);
        int ntHeaders = BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(0x3C));
        int sizeField = ntHeaders + 24 + 112 + 3 * 8 + 4;
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(sizeField), (uint)(kept * 12));
    }

    [SkippableTheory]
    [InlineData("cold unwind info")]
    [InlineData("inverted branch")]
    [InlineData("padding")]
    [InlineData("prefix")]
    public void Verifier_rejects_a_tampered_layout(string what)
    {
        if (Find("targets", "o2", "zopfli.exe") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var (image, file) = Analyze(path);
        bool padded = what is "padding" or "prefix";
        if (padded)
        {
            MarkAllExecuted(image);
        }

        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Rebuild, f => Shuffled(f, 5, split: !padded), padded);
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);
        var output = PeImageReader.Read("rewritten.exe", result.Output);

        uint rva = 0;
        if (what == "cold unwind info")
        {
            rva = result.Moved.First(m => m.ColdEntries.Count > 0).ColdEntries[0].UnwindInfo + 3; // frame register byte
        }
        else if (what == "padding")
        {
            // A padding NOP that execution runs through (the instruction before it falls through):
            // turned into something else, the code no longer does what the original did.
            foreach (var moved in result.Moved)
            {
                var originals = moved.AddressMap!.Values.ToHashSet();
                var decoder = Iced.Intel.Decoder.Create(64, new Iced.Intel.ByteArrayCodeReader(output.ReadFrom(moved.CopyStart)[..(int)moved.CopyLength].ToArray()));
                decoder.IP = moved.CopyStart;
                Iced.Intel.Instruction previous = default;
                while (decoder.IP < moved.CopyStart + moved.CopyLength && rva == 0)
                {
                    var instruction = decoder.Decode();
                    if (instruction.Mnemonic == Iced.Intel.Mnemonic.Nop && !originals.Contains((uint)instruction.IP) &&
                        previous.FlowControl is Iced.Intel.FlowControl.Next or Iced.Intel.FlowControl.Call or Iced.Intel.FlowControl.ConditionalBranch)
                    {
                        rva = (uint)instruction.IP;
                    }

                    previous = instruction;
                }

                if (rva != 0)
                {
                    break;
                }
            }

            Assert.NotEqual(0u, rva);
            int at = FileOffset(output, rva);
            result.Output[at] = 0xCC ^ 0x01; // int3 after the flip below
        }
        else if (what == "prefix")
        {
            // A CS prefix the padding added to a memory-accessing instruction: as FS it would
            // change the address in 64-bit mode.
            foreach (var moved in result.Moved)
            {
                foreach (var k in image.Functions[moved.FunctionId].BasicBlocks.SelectMany(b => Enumerable.Range(b.InstructionStart, b.InstructionCount)))
                {
                    var x = image.Instructions[k];
                    uint at = moved.Map((uint)x.IP);
                    if (x.SegmentPrefix == Iced.Intel.Register.None && x.Op1Kind == Iced.Intel.OpKind.Memory && Decode(output, at) is { SegmentPrefix: Iced.Intel.Register.CS })
                    {
                        rva = at;
                        break;
                    }
                }

                if (rva != 0)
                {
                    break;
                }
            }

            Assert.NotEqual(0u, rva);
            int prefixAt = FileOffset(output, rva);
            Assert.Equal(0x2E, result.Output[prefixAt]);
            result.Output[prefixAt] = 0x64 ^ 0x01; // FS after the flip below
        }
        else
        {
            // A conditional branch whose condition the layout negated: undo the negation.
            foreach (var moved in result.Moved)
            {
                foreach (var block in image.Functions[moved.FunctionId].BasicBlocks)
                {
                    var last = image.Instructions[block.InstructionStart + block.InstructionCount - 1];
                    if (last.IsJccShortOrNear && Decode(output, moved.Map((uint)last.IP)) is { } now && now.IsJccShortOrNear && now.Mnemonic != last.Mnemonic)
                    {
                        rva = moved.Map((uint)last.IP) + (now.IsJccShort ? 0u : 1u); // the opcode byte holding the condition
                        break;
                    }
                }

                if (rva != 0)
                {
                    break;
                }
            }
        }

        Assert.NotEqual(0u, rva);
        int offset = FileOffset(output, rva);
        result.Output[offset] ^= 0x01; // flips a condition code's lowest bit: its negation
        int checksum = new PeLayout(result.Output).CheckSumOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(checksum), PeChecksum.Compute(result.Output, checksum));

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.DoesNotContain(report.Failures, f => f.Contains("checksum", StringComparison.OrdinalIgnoreCase));
    }

    private static int FileOffset(BinaryImage image, uint rva)
    {
        var section = image.FindSection(rva)!;
        return (int)(section.FileOffset + (rva - section.Rva));
    }

    private static Iced.Intel.Instruction? Decode(BinaryImage image, uint rva)
    {
        var decoder = Iced.Intel.Decoder.Create(64, new Iced.Intel.ByteArrayCodeReader(image.ReadFrom(rva)[..15].ToArray()));
        decoder.IP = rva;
        var instruction = decoder.Decode();
        return instruction.IsInvalid ? null : instruction;
    }

    [SkippableFact]
    public void Profile_layout_of_speedtest1_verifies_and_packs_the_hot_lines()
    {
        // Needs the o2 build and an LBR trace of it (tools/profile/Capture-Lbr.ps1), both in artifacts/.
        if (Find("targets", "o2", "speedtest1.exe") is not { } path || Find("lbr-speedtest1.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (image, file) = Analyze(path);
        EtwLbrProfile.Apply(image, trace, "speedtest1.exe");
        var order = FunctionOrdering.C3(image);
        var result = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), RewriteMode.Rebuild, f => BlockLayout.Order(f));
        AssertLaidOut(image, file, result);

        var copies = result.Moved.ToDictionary(m => m.FunctionId);
        var functionCopies = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList()).Moved.ToDictionary(m => m.FunctionId);
        var before = CodeFootprint.Compute(image, 0.9)[0];
        var functionsOnly = CodeFootprint.Compute(image, (f, b) => functionCopies.TryGetValue(f.Id, out var m) ? m.Map((uint)b.StartRva) : b.StartRva, 0.9)[0];
        var after = CodeFootprint.Compute(image, (f, b) => copies.TryGetValue(f.Id, out var m) ? m.Map((uint)b.StartRva) : b.StartRva, 0.9)[0];
        Assert.True(after.LinesNow * 10 <= functionsOnly.LinesNow * 8,
            $"hot lines: {before.LinesNow} original, {functionsOnly.LinesNow} with function layout, {after.LinesNow} with block layout");

        // Most profiled transfers fall through; ext-TSP, which maximizes exactly that, verifies too and gets at least as many.
        var chains = LayoutStatistics.Measure(image, result);
        Assert.True(chains.FallThroughAfter > 0.75 * chains.Transfers && chains.FallThroughBefore < 0.6 * chains.Transfers,
            $"{chains.FallThroughBefore / chains.Transfers:P1} before, {chains.FallThroughAfter / chains.Transfers:P1} after");
        var extTspResult = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), RewriteMode.Rebuild,
            f => BlockLayout.Order(f, algorithm: BlockLayoutAlgorithm.ExtTsp));
        Assert.True(RewriteVerifier.Verify(image, file, extTspResult).Passed);
        var extTsp = LayoutStatistics.Measure(image, extTspResult);
        Assert.True(extTsp.FallThroughAfter / extTsp.Transfers >= chains.FallThroughAfter / chains.Transfers);

        // JCC erratum padding clears executed branches off 32-byte boundaries.
        var padded = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), RewriteMode.Rebuild, f => BlockLayout.Order(f), jccErratum: true);
        Assert.True(RewriteVerifier.Verify(image, file, padded).Passed);
        var (branches, onBoundaryBefore, onBoundaryAfter, executed, paddingNops) = LayoutStatistics.JccErratum(image, padded);
        Assert.True(onBoundaryBefore > 0.1 * branches && onBoundaryAfter < 0.01 * branches,
            $"{onBoundaryBefore / branches:P1} of executed branches on a boundary before, {onBoundaryAfter / branches:P1} after");

        // Padding goes where it runs least: prefixes, gaps after unconditional jumps, and each
        // function's start offset chosen to need the least.
        Assert.True(paddingNops < 0.01 * executed, $"padding NOPs are {paddingNops / executed:P2} of executed instructions");
    }

    [SkippableFact]
    public void Layout_from_an_instruction_pointer_only_profile_verifies()
    {
        // The estimate of IpProfileBuilder (no branch records) lays blocks out differently from a branch-record
        // profile: layouts of this kind once failed to encode (a tail jump to another copy, made short by iced
        // while it shrank the function, was out of reach in the end; BlockRebuilder.externalBranches).
        if (Find("targets", "o2", "speedtest1.exe") is not { } path || Find("lbr-speedtest1.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (image, file) = Analyze(path);
        var summary = EtwLbrProfile.Apply(image, trace, "speedtest1.exe", ipSamplesOnly: true);
        Assert.Equal(ProfileFidelity.SamplingOnly, summary.Fidelity);
        Assert.Contains("estimates", summary.Binding);
        var order = FunctionOrdering.C3(image);
        var result = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList(), RewriteMode.Rebuild, f => BlockLayout.Order(f), jccErratum: true);
        AssertLaidOut(image, file, result);
    }
}
