using WinBolt.Core.Ir;
using WinBolt.Core.Measurement;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;
using WinBolt.Pdb;
using WinBolt.Pe;
using WinBolt.Profile;

namespace WinBolt.Rewrite.Tests;

/// <summary>Stage 5: C3 function ordering, the layout rewrite, and the benchmark statistics.</summary>
public class LayoutTests
{
    /// <summary>A function of one block: <paramref name="executions"/> runs of <paramref name="instructions"/> instructions.</summary>
    private static Function AddFunction(BinaryImage image, uint entry, uint size, ulong executions, int instructions = 10)
    {
        var f = new Function { Id = image.Functions.Count, Name = $"f{image.Functions.Count}" };
        f.Ranges.Add(new FunctionRange { StartRva = entry, Length = size, IsEntryRange = true });
        f.BasicBlocks.Add(new BasicBlock { Id = 0, StartRva = entry, Length = size, InstructionCount = instructions, ExecutionCount = executions });
        image.Functions.Add(f);
        return f;
    }

    private static void AddCall(BinaryImage image, Function caller, Function callee, uint site, long count)
    {
        image.CallSites.Add(new CallSite(caller.Id, site, CallKind.Call, callee.EntryRva, callee.Id));
        image.ProfileSummary!.CallCounts[site] = count;
    }

    private static BinaryImage NewImage() => new()
    {
        FilePath = "synthetic.exe",
        ImageBase = 0x140000000,
        SizeOfImage = 0x100000,
        TimeDateStamp = 0,
        Checksum = 0,
        ProfileSummary = new ProfileSummary(),
    };

    [Fact]
    public void C3_appends_hot_callees_to_their_hottest_callers_and_leaves_unexecuted_code_out()
    {
        var image = NewImage();
        var caller = AddFunction(image, 0x1000, 100, 200);       // density 20
        var hot = AddFunction(image, 0x5000, 100, 1000);         // density 100, called mostly by caller
        var other = AddFunction(image, 0x9000, 100, 500);        // density 50
        var coldCaller = AddFunction(image, 0xA000, 3000, 3);    // density 0.01: too cold to pull 'other' in
        var never = AddFunction(image, 0xC000, 100, 0);
        AddCall(image, caller, hot, 0x1010, 1000);
        AddCall(image, coldCaller, hot, 0xA010, 10);
        AddCall(image, coldCaller, other, 0xA020, 500);

        var order = FunctionOrdering.C3(image);

        Assert.Equal([caller, hot, other, coldCaller], order.Select(o => o.Function));
        Assert.Equal(order[0].Cluster, order[1].Cluster);
        Assert.NotEqual(order[2].Cluster, order[3].Cluster);
        Assert.DoesNotContain(order, o => o.Function == never);
    }

    [Fact]
    public void C3_does_not_merge_clusters_past_a_page()
    {
        var image = NewImage();
        var caller = AddFunction(image, 0x1000, 3000, 3000);
        var callee = AddFunction(image, 0x5000, 2000, 2000);
        AddCall(image, caller, callee, 0x1010, 1000);

        var order = FunctionOrdering.C3(image);

        Assert.Equal(2, order.Select(o => o.Cluster).Distinct().Count());
    }

    [Fact]
    public void Identical_timings_are_no_change_and_a_clear_shift_beyond_the_noise_floor_is_a_verdict()
    {
        var random = new Random(7);
        var baseline = Enumerable.Range(0, 30).Select(_ => 1.0 + random.NextDouble() * 0.01).ToArray();
        var copy = baseline.Select(t => t * (1 + (random.NextDouble() - 0.5) * 0.004)).ToArray();
        var faster = baseline.Select(t => t * 0.95).ToArray();
        var same = baseline.ToArray();

        var noise = BenchmarkStatistics.Compare(baseline, copy);
        Assert.True(noise.Low <= 1 && noise.High >= 1);
        Assert.Equal(Verdict.Faster, BenchmarkStatistics.Judge(BenchmarkStatistics.Compare(baseline, faster), noise));
        Assert.Equal(Verdict.NoChange, BenchmarkStatistics.Judge(BenchmarkStatistics.Compare(baseline, same), noise));

        // A shift inside the noise floor's interval is not claimed even when its own interval excludes 1.
        var wide = new Comparison(1.0, 0.97, 1.03);
        Assert.Equal(Verdict.NoChange, BenchmarkStatistics.Judge(new Comparison(0.99, 0.985, 0.995), wide));
    }

    [SkippableFact]
    public void C3_layout_of_speedtest1_verifies_and_halves_the_hot_page_footprint()
    {
        // Needs the o2 build and an LBR trace of it (tools/profile/Capture-Lbr.ps1), both in artifacts/.
        string? exe = null, trace = null;
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            exe ??= Path.Combine(directory.FullName, "artifacts", "targets", "o2", "speedtest1.exe") is var e && File.Exists(e) ? e : null;
            trace ??= Path.Combine(directory.FullName, "artifacts", "lbr-speedtest1.etl") is var t && File.Exists(t) ? t : null;
        }

        if (exe is null || trace is null)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        byte[] file = File.ReadAllBytes(exe);
        var image = PeImageReader.Read(exe, file);
        PdbSymbolLoader.Load(image);
        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        EtwLbrProfile.Apply(image, trace, "speedtest1.exe");
        var order = FunctionOrdering.C3(image);
        var result = FunctionRewriter.Rewrite(image, file, order.Select(o => o.Function.EntryRva).ToList());
        var report = RewriteVerifier.Verify(image, file, result);
        Assert.True(report.Passed, string.Join("\n", report.Failures));

        // Moved in exactly the layout order.
        var rank = order.Select((o, i) => (o.Function.EntryRva, i)).ToDictionary(x => x.EntryRva, x => x.i);
        Assert.Equal(result.Moved.Select(m => rank[m.Start]).Order(), result.Moved.Select(m => rank[m.Start]));
        Assert.True(result.Moved.Zip(result.Moved.Skip(1)).All(p => p.First.CopyStart < p.Second.CopyStart));

        var copies = result.Moved.ToDictionary(m => m.FunctionId);
        var before = CodeFootprint.Compute(image, 0.9)[0];
        var after = CodeFootprint.Compute(image, (f, b) => copies.TryGetValue(f.Id, out var m) ? m.CopyStart + (b.StartRva - m.Start) : b.StartRva, 0.9)[0];
        Assert.True(after.PagesNow * 10 <= before.PagesNow * 6, $"{before.PagesNow} pages before, {after.PagesNow} after");
    }
}
