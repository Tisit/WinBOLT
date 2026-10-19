using System.Buffers.Binary;
using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// The Stage 4 milestone-1 no-op rewrite against the zopfli builds tools/targets/Build-Targets.ps1
/// writes to artifacts/targets/, when present.
/// </summary>
public class NoOpRewriteTests
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

    private static (BinaryImage Image, byte[] File, RewriteResult Result)? Rewrite(string variant, string target = "zopfli.exe", RewriteMode mode = RewriteMode.Copy)
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

        return (image, file, FunctionRewriter.Rewrite(image, file, null, mode));
    }

    [SkippableTheory]
    [InlineData("o2")]
    [InlineData("guardcf")]
    public void Rewrite_of_zopfli_passes_verification_with_the_fixup_oracle(string variant)
    {
        if (Rewrite(variant) is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.True(report.OracleAvailable);
        Assert.True(result.Moved.Count > image.Functions.Count * 9 / 10);
    }

    [SkippableFact]
    public void Chained_unwind_fragments_are_copied_and_chain_to_the_parent_copy()
    {
        // MSVC splits some zopfli functions into a primary .pdata entry plus nested chained
        // fragments; discovery merges them into one range, so the copy needs every entry.
        if (Rewrite("o2") is not var (image, _, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var chained = result.Moved.Where(m => m.Pdata.Any(p => p.Chained)).ToList();
        Assert.NotEmpty(chained);

        var output = PeImageReader.Read("rewritten.exe", result.Output);
        foreach (var moved in chained)
        {
            int originalEntries = image.ExceptionData.Count(e => e.BeginAddress >= moved.Start && e.BeginAddress < moved.Start + moved.Length);
            Assert.Equal(originalEntries, moved.Pdata.Count);
            foreach (var copy in moved.Pdata.Where(p => p.Chained))
            {
                var entry = output.ExceptionData.Single(e => e.BeginAddress == copy.Begin);
                var parent = image.ExceptionData.Single(e => e.BeginAddress == copy.OriginalBegin).ChainedParent!;
                Assert.Equal(moved.CopyStart + (parent.BeginAddress - moved.Start), entry.ChainedParent!.BeginAddress);
            }
        }
    }

    public static TheoryData<string> Tampering => new() { "rip-relative field", "trampoline", "chained unwind trailer", "branch field", "jump table entry", "table load field" };

    [SkippableTheory]
    [MemberData(nameof(Tampering))]
    public void Verifier_rejects_a_tampered_output(string what)
    {
        bool tables = what is "jump table entry" or "table load field";
        if (Rewrite("o2", tables ? "speedtest1.exe" : "zopfli.exe") is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var output = PeImageReader.Read("rewritten.exe", result.Output);
        uint rva = what switch
        {
            "jump table entry" => result.Moved.SelectMany(m => m.Tables).MaxBy(t => t.EntryCount)!.NewRva + 4,
            "table load field" => result.Patched.First(p => p.Kind == FieldKind.TableAddress).CopySite,
            "rip-relative field" => result.Patched.First(p => p.Kind == FieldKind.RipRelative).CopySite,
            "branch field" => result.Patched.First(p => p.Kind == FieldKind.Branch).CopySite,
            "trampoline" => result.Moved[0].Start + 1,
            _ => ChainedTrailer(output, result),
        };

        int offset = FileOffset(output, rva);
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(offset), BinaryPrimitives.ReadUInt32LittleEndian(result.Output.AsSpan(offset)) + 0x10);
        RefreshChecksum(result.Output);

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.DoesNotContain(report.Failures, f => f.Contains("checksum", StringComparison.OrdinalIgnoreCase));
    }

    [SkippableTheory]
    [InlineData("o2")]
    [InlineData("guardcf")]
    public void Rewrite_of_speedtest1_rebuilds_every_jump_table(string variant)
    {
        // Jump tables sit inside the function's range; the writer rebuilds them in .wbdata and
        // re-points the load, so the interpreter loop (a 187-entry switch) moves too.
        if (Rewrite(variant, "speedtest1.exe") is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        var withTables = image.Functions.Where(f => f.JumpTables.Count > 0 && f.SafetyStatus.Level == Transformability.FullyTransformable).ToList();
        Assert.NotEmpty(withTables);
        Assert.All(withTables, f => Assert.Contains(result.Moved, m => m.Start == f.EntryRva));
        Assert.Contains(result.Moved, m => m.Tables.Any(t => t.EntryCount > 150));

        // The copy reads the rebuilt tables; its stale in-range tables are int3, not entries that
        // a later analysis of the output would decode as code.
        var output = PeImageReader.Read("rewritten.exe", result.Output);
        var inRange = result.Moved.SelectMany(m => m.Tables.Where(t => t.OriginalRva >= m.Start && t.OriginalRva < m.Start + m.Length)
            .Select(t => (Copy: m.CopyStart + (t.OriginalRva - m.Start), t.EntryCount))).ToList();
        Assert.NotEmpty(inRange);
        Assert.All(inRange, t => Assert.All(output.ReadFrom(t.Copy)[..(4 * t.EntryCount)].ToArray(), b => Assert.Equal(0xCC, b)));
    }

    [SkippableFact]
    public void Rewritten_speedtest1_produces_identical_results()
    {
        if (Build("o2", "speedtest1.exe") is not { } original || Rewrite("o2", "speedtest1.exe") is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);
        string directory = Directory.CreateTempSubdirectory("winbolt-rewrite-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "speedtest1.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string[] arguments = ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            string expected = VerificationHash(original, arguments);
            Assert.StartsWith("Verification Hash:", expected);
            Assert.Equal(expected, VerificationHash(rewritten, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    private static string VerificationHash(string exe, string[] arguments)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string arg in arguments)
        {
            info.ArgumentList.Add(arg);
        }

        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("Verification Hash:", StringComparison.Ordinal)) ?? "";
    }

    [SkippableTheory]
    [InlineData("o2")]
    [InlineData("guardcf")]
    public void Rewritten_zopfli_produces_identical_output(string variant)
    {
        if (Build(variant, "zopfli.exe") is not { } original || Rewrite(variant) is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);
        string directory = Directory.CreateTempSubdirectory("winbolt-rewrite-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, "zopfli.exe");
            File.WriteAllBytes(rewritten, result.Output);
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, file.Take(60_000).ToArray());

            foreach (string format in new[] { "--gzip", "--zlib", "--deflate" })
            {
                Assert.Equal(Compress(original, format, input), Compress(rewritten, format, input));
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

    private static uint ChainedTrailer(BinaryImage output, RewriteResult result)
    {
        var copy = result.Moved.SelectMany(m => m.Pdata).First(p => p.Chained);
        return copy.UnwindInfo + (uint)FunctionRewriter.UnwindTrailerOffset(output.ReadFrom(copy.UnwindInfo).Span);
    }

    [SkippableTheory]
    [InlineData("o2", "zopfli.exe")]
    [InlineData("guardcf", "zopfli.exe")]
    [InlineData("o2", "speedtest1.exe")]
    public void Functions_rebuilt_from_their_cfg_pass_verification(string variant, string target)
    {
        if (Rewrite(variant, target, RewriteMode.Rebuild) is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        // Functions whose tables name them as a whole (SEH, C++ EH, interior code pointers) move as
        // byte copies inside a rebuild; everything else is rebuilt.
        Assert.All(result.Moved.Where(m => m.AddressMap is null), m => Assert.True(
            image.Functions[m.FunctionId] is { ExceptionHandler.Kind: ExceptionHandlerKind.CSpecific or ExceptionHandlerKind.CxxFrameHandler4 } or
                { SafetyStatus.Level: Transformability.RelocatableOnly }, $"{m.Name} was copied, not rebuilt"));
        Assert.True(result.Moved.Count(m => m.AddressMap is not null) > result.Moved.Count * 9 / 10);
        Assert.True(result.Moved.Count > image.Functions.Count * 9 / 10);
    }

    [SkippableFact]
    public void Rebuilt_zopfli_and_speedtest1_behave_identically()
    {
        if (Build("o2", "zopfli.exe") is not { } zopfli || Build("o2", "speedtest1.exe") is not { } speedtest ||
            Rewrite("o2", "zopfli.exe", RewriteMode.Rebuild) is not var (zImage, zFile, zResult) ||
            Rewrite("o2", "speedtest1.exe", RewriteMode.Rebuild) is not var (sImage, sFile, sResult))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.True(RewriteVerifier.Verify(zImage, zFile, zResult).Passed);
        Assert.True(RewriteVerifier.Verify(sImage, sFile, sResult).Passed);
        string directory = Directory.CreateTempSubdirectory("winbolt-rebuild-").FullName;
        try
        {
            string rebuiltZopfli = Path.Combine(directory, "zopfli.exe"), rebuiltSpeedtest = Path.Combine(directory, "speedtest1.exe");
            File.WriteAllBytes(rebuiltZopfli, zResult.Output);
            File.WriteAllBytes(rebuiltSpeedtest, sResult.Output);
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, zFile.Take(60_000).ToArray());
            Assert.Equal(Compress(zopfli, "--gzip", input), Compress(rebuiltZopfli, "--gzip", input));

            string[] arguments = ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            Assert.Equal(VerificationHash(speedtest, arguments), VerificationHash(rebuiltSpeedtest, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    [SkippableTheory]
    [InlineData(RewriteMode.Copy)]
    [InlineData(RewriteMode.Rebuild)]
    public void Pgo_builds_move_their_split_functions_and_behave_identically(RewriteMode mode)
    {
        // MSVC PGO splits functions into a hot entry range and cold ranges elsewhere; the entry
        // range moves, the cold ranges stay and branch back into the intact original body.
        if (Build("pgo", "zopfli.exe") is not { } zopfli || Build("pgo", "speedtest1.exe") is not { } speedtest ||
            Rewrite("pgo", "zopfli.exe", mode) is not var (zImage, zFile, zResult) ||
            Rewrite("pgo", "speedtest1.exe", mode) is not var (sImage, sFile, sResult))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        foreach (var (image, file, result) in new[] { (zImage, zFile, zResult), (sImage, sFile, sResult) })
        {
            var report = RewriteVerifier.Verify(image, file, result);
            Assert.True(report.Passed, string.Join("\n", report.Failures));
            Assert.Contains(result.Moved, m => image.Functions[m.FunctionId].Ranges.Count > 1);
        }

        string directory = Directory.CreateTempSubdirectory("winbolt-pgo-").FullName;
        try
        {
            string rewrittenZopfli = Path.Combine(directory, "zopfli.exe"), rewrittenSpeedtest = Path.Combine(directory, "speedtest1.exe");
            File.WriteAllBytes(rewrittenZopfli, zResult.Output);
            File.WriteAllBytes(rewrittenSpeedtest, sResult.Output);
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, zFile.Take(60_000).ToArray());
            Assert.Equal(Compress(zopfli, "--gzip", input), Compress(rewrittenZopfli, "--gzip", input));

            string[] arguments = ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"];
            Assert.Equal(VerificationHash(speedtest, arguments), VerificationHash(rewrittenSpeedtest, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    [SkippableTheory]
    [InlineData("call target")]
    [InlineData("plain instruction byte")]
    public void Verifier_rejects_a_tampered_rebuilt_function(string what)
    {
        if (Rewrite("o2", "zopfli.exe", RewriteMode.Rebuild) is not var (image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        // Pick a rebuilt instruction: a direct call (its rel32 at +1), or an address-independent one.
        var output = PeImageReader.Read("rewritten.exe", result.Output);
        uint rva = 0;
        foreach (var moved in result.Moved)
        {
            var function = image.Functions[moved.FunctionId];
            var instructions = function.BasicBlocks.SelectMany(b => Enumerable.Range(b.InstructionStart, b.InstructionCount)).Select(i => image.Instructions[i]);
            var pick = what == "call target"
                ? instructions.FirstOrDefault(i => i.IsCallNear)
                : instructions.FirstOrDefault(i => i.Mnemonic == Iced.Intel.Mnemonic.Mov && !i.IsIPRelativeMemoryOperand && i.Op1Kind == Iced.Intel.OpKind.Register);
            if (pick.Length > 0)
            {
                rva = moved.Map((uint)pick.IP) + (what == "call target" ? 1u : (uint)pick.Length - 1);
                break;
            }
        }

        Assert.NotEqual(0u, rva);
        int offset = FileOffset(output, rva);
        result.Output[offset] ^= 0x08;
        RefreshChecksum(result.Output);

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.DoesNotContain(report.Failures, f => f.Contains("checksum", StringComparison.OrdinalIgnoreCase));
    }

    private static int FileOffset(BinaryImage image, uint rva)
    {
        var section = image.FindSection(rva)!;
        return (int)(section.FileOffset + (rva - section.Rva));
    }

    private static void RefreshChecksum(byte[] file)
    {
        int offset = new PeLayout(file).CheckSumOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(offset), PeChecksum.Compute(file, offset));
    }
}
