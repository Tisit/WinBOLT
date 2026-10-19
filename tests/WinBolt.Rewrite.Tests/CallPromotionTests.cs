using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Indirect call promotion (CallPromotion, BlockRebuilder.Encode's promotions) on zopfli, whose
/// hot indirect calls are its LZ77 callbacks: the promoted build compresses identically, a build
/// promoting every site to a wrong target still does (the guard falls back to the original call),
/// and a sequence comparing against the wrong value fails verification.
/// </summary>
public class CallPromotionTests
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

    private static byte[] Compress(string exe, string input)
    {
        var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string arg in new[] { "--i3", "--gzip", "-c", input })
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
    public void Promoted_calls_compress_identically_and_a_wrong_target_falls_back_to_the_indirect_call()
    {
        if (Find("targets", "o2", "zopfli.exe") is not { } path || Find("lbr-zopfli.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (image, file) = Analyze(path);
        EtwLbrProfile.Apply(image, trace, "zopfli.exe");
        var order = FunctionOrdering.C3(image).Select(o => o.Function.EntryRva).ToList();
        var plan = CallPromotion.Plan(image);
        Assert.NotEmpty(plan);

        var result = FunctionRewriter.Rewrite(image, file, order, RewriteMode.Rebuild, f => BlockLayout.Order(f), jccErratum: true, promoteCalls: plan);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));
        var promoted = result.Moved.SelectMany(m => m.PromotedCalls).ToList();
        Assert.Equal(plan.Count, promoted.Count);

        // Every site promoted to another function: each guard fails, the original call runs.
        var entries = image.Functions.Where(f => f.Name is not null).Select(f => f.EntryRva).Order().ToList();
        var wrong = plan.ToDictionary(kv => kv.Key, kv => entries.First(e => e != kv.Value && image.Functions.Single(f => f.EntryRva == e).EntryRange is var r && (kv.Key < r.StartRva || kv.Key >= r.StartRva + r.Length)));
        var misguided = FunctionRewriter.Rewrite(image, file, order, RewriteMode.Rebuild, f => BlockLayout.Order(f), promoteCalls: wrong);
        var misguidedReport = RewriteVerifier.Verify(image, file, misguided);
        Assert.True(misguidedReport.Passed, string.Join("\n", misguidedReport.Failures));
        Assert.Equal(wrong.Count, misguided.Moved.Sum(m => m.PromotedCalls.Count));

        string directory = Directory.CreateTempSubdirectory("winbolt-icp-").FullName;
        try
        {
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, file.Take(60_000).ToArray());
            byte[] expected = Compress(path, input);
            string rewritten = Path.Combine(directory, "zopfli.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(expected, Compress(rewritten, input));
            File.WriteAllBytes(rewritten, misguided.Output);
            Assert.Equal(expected, Compress(rewritten, input));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }

        // Negative control: the compare value one off fails verification.
        var (site, _) = promoted[0];
        var moved = result.Moved.Single(m => m.PromotedCalls.ContainsKey(site));
        var output = PeImageReader.Read("out.exe", result.Output);
        var text = output.Sections.Single(s => s.Name == ".wbtext");
        int lea = (int)(text.FileOffset + (moved.Map(site) - text.Rva));
        Assert.Equal(0x8D, result.Output[lea + 1]); // REX lea r1x,[rip+disp32]: displacement at +3
        result.Output[lea + 3]++;
        var tampered = RewriteVerifier.Verify(image, file, result);
        Assert.Contains(tampered.Failures, f => f.Contains("promoted call"));
    }
}
