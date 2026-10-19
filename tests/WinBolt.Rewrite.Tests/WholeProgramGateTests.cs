using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// DesignDoc §6.2 milestone W1: the whole-program gate passes on our targets (linked with
/// /DEBUGTYPE:CV,FIXUP) and refuses when the records are absent or incomplete.
/// </summary>
public class WholeProgramGateTests
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

    private static BinaryImage? Analyze(string variant, string target, bool withPdb = true)
    {
        if (Build(variant, target) is not { } path)
        {
            return null;
        }

        var image = PeImageReader.Read(path);
        if (withPdb)
        {
            PdbSymbolLoader.Load(image);
        }

        var context = new PassContext();
        foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
        {
            pass.Run(image, context);
        }

        return image;
    }

    [SkippableTheory]
    [InlineData("o2", "zopfli.exe")]
    [InlineData("o2", "speedtest1.exe")]
    [InlineData("o2", "zopflipng.exe")]
    [InlineData("o2", "cxxehtest.exe")]
    [InlineData("guardcf", "speedtest1.exe")]
    [InlineData("mt", "unwindtest.exe")]
    public void Targets_linked_with_fixups_pass(string variant, string target)
    {
        if (Analyze(variant, target) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = WholeProgramGate.Check(image);

        Assert.True(report.Passed, string.Join("\n", report.Checks.Where(c => !c.Passed).Select(c => $"{c.Name}: {c.Detail}")));
        Assert.NotEmpty(image.SectionContributions);
    }

    [SkippableFact]
    public void Image_without_fixup_records_is_refused()
    {
        if (Analyze("o2", "zopfli.exe", withPdb: false) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var report = WholeProgramGate.Check(image);

        Assert.False(report.Passed);
        Assert.Equal("records present", Assert.Single(report.Checks).Name);
    }

    public static TheoryData<string> Removed => new() { "call", "rip-relative", "relocation", "jump table entry", "pdata" };

    /// <summary>One fixup record removed: the gate must notice the reference it no longer explains.</summary>
    [SkippableTheory]
    [MemberData(nameof(Removed))]
    public void A_missing_fixup_record_is_refused(string what)
    {
        if (Analyze("o2", "speedtest1.exe") is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var text = image.Sections.First(s => s.IsExecutable);
        var entries = image.ExceptionData.Select(e => e.BeginAddress).ToHashSet();
        var tableEntries = image.Functions.SelectMany(f => f.JumpTables).Select(t => (uint)t.Rva).ToHashSet();
        var pdata = image.DataDirectories.First(d => d.Name == "Exception");
        var relocations = image.Relocations.Select(r => r.Rva).ToHashSet();
        LinkerFixup victim = what switch
        {
            "call" => image.LinkerFixups.First(f => f.Type == 4 && text.Contains(f.Rva) && image.ReadFrom(f.Rva - 1).Span[0] == 0xE8),
            "rip-relative" => image.LinkerFixups.First(f => f.Type == 4 && text.Contains(f.Rva) && image.FindSection(f.Target) is { IsExecutable: false }),
            "relocation" => image.LinkerFixups.First(f => f.Type == 1 && relocations.Contains(f.Rva)),
            "jump table entry" => image.LinkerFixups.First(f => tableEntries.Contains(f.Rva)),
            _ => image.LinkerFixups.First(f => f.Rva >= pdata.Rva && f.Rva < pdata.Rva + pdata.Size),
        };
        Assert.True(image.LinkerFixups.Remove(victim));

        var report = WholeProgramGate.Check(image);

        string expected = what switch
        {
            "relocation" => "relocations agree",
            "pdata" => "exception structures fixed up",
            _ => "decoding agrees with the fixups",
        };
        Assert.False(report.Passed);
        Assert.False(report.Checks.Single(c => c.Name == expected).Passed, $"removed the {what} fixup at 0x{victim.Rva:X}");
    }
}
