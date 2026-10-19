using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Pe.Tests;

public class FunctionDiscoveryTests
{
    public static TheoryData<string> SystemBinaries => new()
    {
        @"C:\Windows\System32\notepad.exe",
        @"C:\Windows\System32\ntdll.dll",
        @"C:\Windows\System32\kernel32.dll",
        @"C:\Windows\System32\sqlncli11.dll", // BBT-rewritten; absent on many machines
    };

    private static BinaryImage? Discover(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var image = PeImageReader.Read(path);
        new FunctionDiscoveryPass().Run(image, new PassContext());
        return image;
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Every_executable_byte_is_accounted_for_exactly_once(string path)
    {
        if (Discover(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var spans = image.Functions
            .SelectMany(f => f.Ranges.Select(r => ((uint)r.StartRva, r.Length)))
            .Concat(image.UnclaimedCode.Select(u => (u.Rva, u.Length)))
            .OrderBy(s => s.Item1)
            .ToList();

        for (int i = 1; i < spans.Count; i++)
        {
            Assert.True(spans[i - 1].Item1 + spans[i - 1].Item2 <= spans[i].Item1,
                $"0x{spans[i - 1].Item1:X}+0x{spans[i - 1].Item2:X} overlaps 0x{spans[i].Item1:X}");
        }

        long executable = image.Sections.Where(s => s.IsExecutable).Sum(s => (long)s.MappedSize);
        Assert.Equal(executable, spans.Sum(s => (long)s.Item2));
    }

    [SkippableTheory]
    [MemberData(nameof(SystemBinaries))]
    public void Every_unchained_pdata_entry_is_a_function_entry(string path)
    {
        if (Discover(path) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var entries = image.Functions.Select(f => f.EntryRva).ToHashSet();
        Assert.All(image.ExceptionData.Where(e => !e.IsChained), e => Assert.Contains(e.BeginAddress, entries));
        Assert.All(image.Functions, f => Assert.Single(f.Ranges, r => r.IsEntryRange));
    }

    [SkippableFact]
    public void Ntdll_exports_resolve_to_named_functions()
    {
        if (Discover(@"C:\Windows\System32\ntdll.dll") is not { } image)
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        Assert.Contains(image.Exports, e => e.Name == "NtClose");
        var ntClose = image.Functions.Single(f => f.Name == "NtClose");

        Assert.True(ntClose.DiscoveredBy.HasFlag(DiscoverySource.Export));

        // Leaf exports have no .pdata entry; only the export table finds them.
        Assert.Contains(image.Functions, f =>
            f.DiscoveredBy.HasFlag(DiscoverySource.Export) && !f.DiscoveredBy.HasFlag(DiscoverySource.Pdata) && f.Name is not null);
    }

    [SkippableFact]
    public void Forwarded_exports_have_no_rva()
    {
        if (!File.Exists(@"C:\Windows\System32\kernel32.dll"))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(@"C:\Windows\System32\kernel32.dll");

        Assert.Contains(image.Exports, e => e.IsForwarder && e.Forwarder!.Contains('.'));
        Assert.All(image.Exports.Where(e => e.IsForwarder), e => Assert.Equal(0u, e.Rva));
    }
}
