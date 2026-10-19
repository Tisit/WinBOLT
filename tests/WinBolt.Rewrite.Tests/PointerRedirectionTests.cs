using System.Buffers.Binary;
using System.Diagnostics;
using Iced.Intel;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Pointer redirection (<see cref="PointerRedirection"/>): the one-value proof on a synthetic
/// image, then on the targets: identical behaviour, and a verifier that catches a pointer left
/// at the original.
/// </summary>
public class PointerRedirectionTests
{
    private const ulong ImageBase = 0x140000000;

    // .text 0x1000: lea rax,[rip+F] (decoded); F at 0x1080 and G at 0x1090 (ret each).
    // .rdata 0x2000: a relocated pointer to G.
    private static BinaryImage Synthetic(Action<byte[], byte[], BinaryImage>? customize = null, ushort dllCharacteristics = 0x40)
    {
        var text = Enumerable.Repeat((byte)0xCC, 0x100).ToArray();
        byte[] lea = [0x48, 0x8D, 0x05, 0x79, 0x00, 0x00, 0x00];
        lea.CopyTo(text, 0);
        text[0x80] = 0xC3;
        text[0x90] = 0xC3;
        var rdata = new byte[0x40];
        BinaryPrimitives.WriteUInt64LittleEndian(rdata, ImageBase + 0x1090);

        var image = new BinaryImage
        {
            FilePath = "synthetic.dll", ImageBase = ImageBase, SizeOfImage = 0x3000, TimeDateStamp = 0, Checksum = 0,
            DllCharacteristics = dllCharacteristics,
        };
        image.Relocations.Add(new Relocation { Rva = 0x2000, Type = RelocationType.Dir64 });
        customize?.Invoke(text, rdata, image);
        image.Sections.Add(new Section { Name = ".text", Rva = 0x1000, VirtualSize = 0x100, RawSize = 0x100, FileOffset = 0x400, Characteristics = 0x60000020, Data = text });
        image.Sections.Add(new Section { Name = ".rdata", Rva = 0x2000, VirtualSize = 0x40, RawSize = 0x200, FileOffset = 0x600, Characteristics = 0x40000040, Data = rdata });

        var decoder = Decoder.Create(64, new ByteArrayCodeReader(lea));
        decoder.IP = 0x1000;
        image.Instructions.Add(decoder.Decode());
        return image;
    }

    private static readonly Dictionary<uint, uint> CopyOf = new() { [0x1080] = 0x5000, [0x1090] = 0x5010 };

    [Fact]
    public void Lea_and_relocated_pointers_are_redirected()
    {
        var plan = PointerRedirection.Plan(Synthetic(), CopyOf);

        Assert.Null(plan.Refused);
        Assert.Equal(CopyOf, plan.Targets);
        Assert.Equal([new PointerSite(0x1000, true, 0x1080), new PointerSite(0x2000, false, 0x1090)], plan.Sites);
    }

    [Fact]
    public void An_rva_of_the_function_in_data_excludes_it()
    {
        var plan = PointerRedirection.Plan(Synthetic((_, rdata, _) => BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan(0x10), 0x1090)), CopyOf);

        Assert.Equal("RVA in data", plan.Excluded[0x1090]);
        Assert.DoesNotContain(plan.Sites, s => s.Target == 0x1090);
        Assert.Contains(0x1080u, plan.Targets.Keys);
    }

    [Theory]
    [InlineData(2, false)] // the word is an unwind code: not a pointer
    [InlineData(0, true)] // no codes: the word after the header is data and may be an RVA
    public void Unwind_codes_that_look_like_an_rva_do_not_exclude_it(byte codeCount, bool excluded)
    {
        // UNWIND_INFO at 0x2010 (version 1, no handler) whose 32-bit word at 0x2014 equals G's RVA.
        var plan = PointerRedirection.Plan(Synthetic((_, rdata, image) =>
        {
            new byte[] { 0x01, 0x00, codeCount, 0x00 }.CopyTo(rdata, 0x10);
            BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan(0x14), 0x1090);
            image.ExceptionData.Add(new ExceptionInfo { BeginAddress = 0x1090, EndAddress = 0x1091, UnwindInfoAddress = 0x2010 });
        }), CopyOf);

        Assert.Equal(excluded, plan.Excluded.ContainsKey(0x1090));
        Assert.Equal(!excluded, plan.Targets.ContainsKey(0x1090));
    }

    [Fact]
    public void A_possible_rip_relative_reference_in_undecoded_code_excludes_it()
    {
        // mov eax,[rip+F] at 0x1040, which the analysis did not decode.
        var plan = PointerRedirection.Plan(Synthetic((text, _, _) => new byte[] { 0x8B, 0x05, 0x3A, 0x00, 0x00, 0x00 }.CopyTo(text, 0x40)), CopyOf);

        Assert.Equal("possible RIP-relative reference in undecoded code", plan.Excluded[0x1080]);
        Assert.DoesNotContain(plan.Sites, s => s.Target == 0x1080);
    }

    [Fact]
    public void An_exported_function_keeps_its_address()
    {
        var plan = PointerRedirection.Plan(Synthetic((_, _, image) => image.Exports.Add(new ExportedSymbol("F", 1, 0x1080, null))), CopyOf);

        Assert.Equal("exported", plan.Excluded[0x1080]);
    }

    [Fact]
    public void An_image_without_dynamic_base_is_refused()
    {
        var plan = PointerRedirection.Plan(Synthetic(dllCharacteristics: 0), CopyOf);

        Assert.NotNull(plan.Refused);
        Assert.Empty(plan.Sites);
    }

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

    private static (string Path, BinaryImage Image, byte[] File, RewriteResult Result)? Rewrite(string variant, string target, RewriteMode mode)
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

        return (path, image, file, FunctionRewriter.Rewrite(image, file, null, mode, redirectPointers: true));
    }

    private static (int ExitCode, string Output) Run(string exe, params string[] arguments)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        string output = process.StandardOutput.ReadToEnd().Replace("\r\n", "\n");
        process.WaitForExit();

        // speedtest1 prints timings; its verification hash is the deterministic result.
        string? hash = output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("Verification Hash:", StringComparison.Ordinal));
        return (process.ExitCode, hash ?? output);
    }

    [SkippableTheory]
    [InlineData("o2", "speedtest1.exe", RewriteMode.Copy)]
    [InlineData("o2", "speedtest1.exe", RewriteMode.Rebuild)]
    [InlineData("o2", "cxxehtest.exe", RewriteMode.Copy)]
    [InlineData("mt", "cxxehtest.exe", RewriteMode.Copy)]
    [InlineData("mt", "unwindtest.exe", RewriteMode.Rebuild)]
    public void Redirected_output_verifies_and_behaves_identically(string variant, string target, RewriteMode mode)
    {
        if (Rewrite(variant, target, mode) is not var (path, image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        Assert.NotEmpty(result.Redirection!.Targets);
        Assert.Contains(result.Redirected, r => !r.IsLea && !r.InCopy);
        Assert.Contains(result.Redirected, r => r.IsLea);
        // Entries too short for a trampoline move too, once every pointer to them is redirected.
        Assert.Contains(result.Moved, m => !m.HasTrampoline);

        string[] arguments = target == "speedtest1.exe" ? ["--memdb", "--verify", "--size", "2", "--testset", "main,cte,rtree,orm,fp,json,star,app"] : [];
        var expected = Run(path, arguments);
        Assert.Equal(0, expected.ExitCode);

        string directory = Directory.CreateTempSubdirectory("winbolt-redirect-").FullName;
        try
        {
            string rewritten = Path.Combine(directory, target);
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Run(rewritten, arguments));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    public static TheoryData<string> Missed => new() { "relocated value", "lea in original code", "lea in a copy", "pointer to a function without a trampoline" };

    /// <summary>A pointer put back to the original address breaks the one-value rule: the verifier must say so.</summary>
    [SkippableTheory]
    [MemberData(nameof(Missed))]
    public void Verifier_rejects_a_pointer_left_at_the_original(string what)
    {
        if (Rewrite("o2", "speedtest1.exe", RewriteMode.Copy) is not var (_, image, file, result))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var output = PeImageReader.Read("rewritten.exe", result.Output);
        var field = what switch
        {
            "relocated value" => result.Redirected.First(r => !r.IsLea && !r.InCopy),
            "lea in original code" => result.Redirected.First(r => r.IsLea && !r.InCopy),
            "pointer to a function without a trampoline" => result.Redirected.First(r => !r.InCopy && result.Moved.Any(m => !m.HasTrampoline && m.Start == r.Target)),
            _ => result.Redirected.First(r => r.IsLea && r.InCopy),
        };

        var section = output.FindSection(field.Site)!;
        int at = (int)(section.FileOffset + (field.Site - section.Rva));
        if (field.IsLea)
        {
            var decoder = Decoder.Create(64, new ByteArrayCodeReader(result.Output.AsSpan(at, 15).ToArray()));
            decoder.IP = field.Site;
            var lea = decoder.Decode();
            int displacement = decoder.GetConstantOffsets(lea).DisplacementOffset;
            BinaryPrimitives.WriteInt32LittleEndian(result.Output.AsSpan(at + displacement), (int)(field.Target - (field.Site + (uint)lea.Length)));
        }
        else
        {
            BinaryPrimitives.WriteUInt64LittleEndian(result.Output.AsSpan(at), image.ImageBase + field.Target);
        }

        int checksum = new PeLayout(result.Output).CheckSumOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(result.Output.AsSpan(checksum), PeChecksum.Compute(result.Output, checksum));

        var report = RewriteVerifier.Verify(image, file, result);
        Assert.False(report.Passed);
        Assert.Contains(report.Failures, f => f.Contains("one value") || f.Contains("redirected") || f.Contains("RIP-relative") || f.Contains("reach the copy"));
    }
}
