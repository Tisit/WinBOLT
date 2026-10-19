using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// The residency map read off an append-mode output (<see cref="ResidencyMap"/>) and the
/// classification of synthetic trace records against it (<see cref="ResidencyAnalysis"/>).
/// </summary>
public class ResidencyTests
{
    private static (BinaryImage Input, RewriteResult Result, ResidencyMap Map)? Rewritten(string variant, string target)
    {
        string? path = null;
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null && path is null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", variant, target);
            path = File.Exists(candidate) ? candidate : null;
        }

        if (path is null)
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

        var result = FunctionRewriter.Rewrite(image, file, null, RewriteMode.Copy);
        var output = PeImageReader.Read(path, result.Output);
        return (image, result, ResidencyMap.Build(image, output));
    }

    [SkippableFact]
    public void The_map_finds_exactly_the_moved_functions_and_their_copies()
    {
        if (Rewritten("o2", "zopfli.exe") is not var (_, result, map))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var expected = result.Moved.Where(m => m.HasTrampoline).ToDictionary(m => m.Start, m => m.CopyStart);
        var found = map.Moved.Where(m => m.HasTrampoline).ToDictionary(m => m.Start, m => m.CopyEntry!.Value);
        Assert.NotEmpty(expected);
        Assert.Equal(expected.OrderBy(p => p.Key), found.OrderBy(p => p.Key));
        Assert.Equal(result.Moved.Count, map.Moved.Count);
    }

    [SkippableFact]
    public void Records_are_classified_by_place_and_source()
    {
        if (Rewritten("o2", "zopfli.exe") is not var (input, result, map))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        // A direct call in a moved caller's original body to another moved function: in the
        // output it still names the original entry, so it lands on the trampoline.
        var movedEntries = map.Moved.Where(m => m.HasTrampoline).ToDictionary(m => m.Start);
        var moved = map.Moved.Where(m => m.HasTrampoline && m.Length > 16).ToDictionary(m => m.Function.Id);
        var site = input.CallSites.First(c => c.Kind == CallKind.Call && c.TargetRva is { } t && movedEntries.ContainsKey(t) &&
                                              moved.TryGetValue(c.CallerId, out var caller) && c.SiteRva >= caller.Start + 5);
        var callee = movedEntries[site.TargetRva!.Value];
        var body = moved.Values.First(m => m.Function.ExceptionHandler is null);

        var analysis = new ResidencyAnalysis(map);
        analysis.AddBranch(site.SiteRva, callee.Start);
        analysis.AddBranch(null, body.Start + body.Length - 1);
        analysis.AddBranch(body.Start + 8, body.Start + 9); // inside the body: not an entry
        analysis.AddIpSample(body.CopyEntry!.Value);
        analysis.AddIpSample(body.Start + 1);
        analysis.AddIpSample(body.Start + 8);

        Assert.Equal(CodePlace.Trampoline, map.Locate(callee.Start).Place);
        Assert.Equal(CodePlace.OriginalBody, map.Locate(site.SiteRva).Place);
        Assert.Equal(CodePlace.Optimized, map.Locate(body.CopyEntry!.Value).Place);
        Assert.Equal(CodePlace.Outside, map.Locate(null).Place);
        Assert.Equal("direct call", map.BranchKind(site.SiteRva));

        var hits = analysis.TrampolineHits[callee.Function];
        Assert.Equal(1, hits[(CodePlace.OriginalBody, "direct call")]);
        var entry = Assert.Single(analysis.BodyEntries);
        Assert.Equal((body.Function, (uint?)null, CodePlace.Outside, body.Start + body.Length - 1, 1L), (entry.Function, entry.From, entry.Place, entry.To, entry.Count));
        Assert.StartsWith("UNEXPLAINED", ResidencyAnalysis.Explain(entry.Function, entry.Place, entry.Kind));
        Assert.Equal(3, analysis.IpSamples);

        string report = analysis.Format(null);
        Assert.Contains(callee.Function.DisplayName, report);
        Assert.Contains("Original bodies of moved functions still executing: 1 functions", report);
    }

    [SkippableFact]
    public void An_unrewritten_image_has_nothing_moved()
    {
        if (Rewritten("o2", "zopfli.exe") is not var (input, _, _))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var map = ResidencyMap.Build(input, input);
        Assert.Empty(map.Moved);
        Assert.Equal(CodePlace.Unmoved, map.Locate(input.Functions[0].EntryRva).Place);
    }
}
