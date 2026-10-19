using System.Diagnostics;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// Stale profiles (StaleProfile.Transfer): a trace of the o2 zopfli build carried over to the same
/// build reproduces the profile exactly, and carried over to a modified build
/// (artifacts/targets-mod: ZopfliFindLongestMatch, the hottest function, counts its calls in a
/// volatile, see DesignDoc "Step 28") drives a verified layout that compresses identically.
/// </summary>
public class StaleProfileTests
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

    [SkippableFact]
    public void A_profile_carried_over_to_the_same_build_is_the_same_profile()
    {
        if (Find("targets", "o2", "zopfli.exe") is not { } path || Find("lbr-zopfli.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (fresh, _) = Analyze(path);
        EtwLbrProfile.Apply(fresh, trace, "zopfli.exe");
        var (copy, _) = Analyze(path);
        var transfer = StaleProfile.Transfer(fresh, copy);

        Assert.Equal(1.0, transfer.WeightTransferred);
        Assert.Equal(1.0, transfer.EdgesTransferred);
        for (int i = 0; i < fresh.Functions.Count; i++)
        {
            var a = fresh.Functions[i].BasicBlocks;
            var b = copy.Functions[i].BasicBlocks;
            Assert.Equal(a.Select(x => x.ExecutionCount), b.Select(x => x.ExecutionCount));
            Assert.Equal(a.SelectMany(x => x.Successors).Select(e => e.ExecutionCount), b.SelectMany(x => x.Successors).Select(e => e.ExecutionCount));
        }

        Assert.Equal(fresh.ProfileSummary!.CallCounts.OrderBy(kv => kv.Key), copy.ProfileSummary!.CallCounts.OrderBy(kv => kv.Key));
        Assert.Equal(fresh.ProfileSummary.IndirectTargets.Keys.Order(), copy.ProfileSummary.IndirectTargets.Keys.Order());
    }

    [SkippableFact]
    public void A_profile_of_the_previous_build_lays_out_the_modified_one()
    {
        if (Find("targets", "o2", "zopfli.exe") is not { } old || Find("targets-mod", "o2", "zopfli.exe") is not { } path ||
            Find("lbr-zopfli.etl") is not { } trace)
        {
throw new SkipException("LBR trace not captured (tools/profile/Capture-*.ps1)");
        }

        var (profiled, _) = Analyze(old);
        EtwLbrProfile.Apply(profiled, trace, "zopfli.exe");
        var (image, file) = Analyze(path);
        Assert.Throws<ProfileBindingException>(() => EtwLbrProfile.Apply(Analyze(path).Image, trace, "zopfli.exe"));

        var transfer = StaleProfile.Transfer(profiled, image);
        Assert.True(transfer.WeightTransferred > 0.95, $"{transfer}");
        var hottest = image.Functions.Single(f => f.Name == "ZopfliFindLongestMatch");
        Assert.True(hottest.BasicBlocks.Count(b => b.ExecutionCount > 0) > hottest.BasicBlocks.Count / 2);

        var order = FunctionOrdering.C3(image).Select(o => o.Function.EntryRva).ToList();
        var result = FunctionRewriter.Rewrite(image, file, order, RewriteMode.Rebuild, f => BlockLayout.Order(f), jccErratum: true);
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        string directory = Directory.CreateTempSubdirectory("winbolt-stale-").FullName;
        try
        {
            string input = Path.Combine(directory, "input.bin");
            File.WriteAllBytes(input, file.Take(60_000).ToArray());
            string rewritten = Path.Combine(directory, "zopfli.exe");
            File.WriteAllBytes(rewritten, result.Output);
            Assert.Equal(Compress(path, input), Compress(rewritten, input));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
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
}
