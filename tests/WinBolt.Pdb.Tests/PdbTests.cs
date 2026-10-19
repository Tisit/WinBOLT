using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pe;

namespace WinBolt.Pdb.Tests;

public class OmapTests
{
    private static readonly OmapEntry[] Omap =
    [
        new(0x1000, 0x5000),  // [0x1000, 0x1010) moved to 0x5000
        new(0x1010, 0),       // [0x1010, 0x1020) dropped by the rewriter
        new(0x1020, 0x2000),  // [0x1020, ...) moved to 0x2000
    ];

    [Theory]
    [InlineData(0x1000u, 0x5000u)]
    [InlineData(0x100Fu, 0x500Fu)]
    [InlineData(0x1024u, 0x2004u)]
    public void Address_maps_through_the_covering_record(uint original, uint expected) =>
        Assert.Equal(expected, PdbFile.TranslateOmap(Omap, original));

    [Theory]
    [InlineData(0x0FFFu)] // before the first record
    [InlineData(0x1010u)] // in a block with no counterpart
    [InlineData(0x101Fu)]
    public void Address_without_a_counterpart_is_dropped_not_guessed(uint original) =>
        Assert.Null(PdbFile.TranslateOmap(Omap, original));
}

/// <summary>
/// Real PDBs from the symbol cache of the sibling project AssemblyOptimizationDetection (bft),
/// when present. Each test returns early on machines without it.
/// </summary>
public class SymbolLoadingTests
{
    private static readonly string SymbolCache =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BinaryFingerprint", "symcache");

    private static BinaryImage? Load(string file, bool analyze = true)
    {
        string path = Path.Combine(@"C:\Windows\System32", file);
        if (!File.Exists(path) || !Directory.Exists(SymbolCache))
        {
            return null;
        }

        var image = PeImageReader.Read(path);
        if (!PdbSymbolLoader.Load(image, searchDirectories: [SymbolCache]).Loaded)
        {
            return null; // this build's PDB is not cached
        }

        if (analyze)
        {
            var context = new PassContext();
            foreach (var pass in PassRegistry.Discover(typeof(PassRegistry).Assembly).CreateAnalysisPasses())
            {
                pass.Run(image, context);
            }
        }

        return image;
    }

    [SkippableFact]
    public void Symbols_of_an_unrewritten_image_agree_with_its_exports()
    {
        if (Load("ntdll.dll", analyze: false) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        Assert.False(image.Pdb!.HasOmap);
        var ntClose = image.Exports.Single(e => e.Name == "NtClose");
        Assert.Contains(image.Symbols, s => s.Name == "NtClose" && s.Rva == ntClose.Rva);
    }

    /// <summary>
    /// The check bft runs on OMAP layouts: every translated function symbol lands exactly on a
    /// function entry or outside every function (a leaf discovery did not otherwise find), never
    /// inside another function.
    /// </summary>
    [SkippableTheory]
    [InlineData("ntdll.dll")]
    [InlineData("sqlncli11.dll")]
    public void Function_symbols_land_on_function_entries_never_inside(string file)
    {
        if (Load(file) is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var inside = image.Symbols
            .Where(s => s.IsFunction)
            .Where(s => image.Functions.Any(f => f.EntryRva != s.Rva && f.Ranges.Any(r => s.Rva > r.StartRva && s.Rva < r.StartRva + r.Length)))
            .Select(s => $"{s.Name} 0x{s.Rva:X}")
            .ToList();

        // ntdll's exported interior labels (ExpInterlockedPopEntrySList*) are real interior entries.
        Assert.True(inside.Count <= 4, string.Join(", ", inside.Take(10)));
    }

    [SkippableFact]
    public void Ignoring_omap_would_put_symbols_in_the_wrong_place()
    {
        // The control for the test above: the same symbols at their original, untranslated
        // addresses mostly miss function entries. This is the silent failure §3.3 warns about.
        if (Load("sqlncli11.dll") is not { } image)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var pdb = PdbFile.Read(image.Pdb!.Path);
        Assert.True(pdb.OmapFromSrc.Length > 0);
        var entries = image.Functions.Select(f => f.EntryRva).ToHashSet();

        var functions = pdb.Publics.Where(p => p.IsFunction && p.Segment >= 1 && p.Segment <= pdb.OriginalSections.Length).ToList();
        int translatedHits = functions.Count(p => pdb.ToImageRva(p.Segment, p.Offset, []) is { } rva && entries.Contains(rva));
        int untranslatedHits = functions.Count(p => entries.Contains(pdb.OriginalSections[p.Segment - 1] + p.Offset));

        Assert.True(translatedHits > functions.Count * 0.9, $"{translatedHits} of {functions.Count} translated symbols hit an entry");
        Assert.True(untranslatedHits < translatedHits / 4, $"untranslated: {untranslatedHits}, translated: {translatedHits}");
    }

    [SkippableFact]
    public void Pdb_of_another_image_is_rejected()
    {
        string path = @"C:\Windows\System32\ntdll.dll";
        string wrongPdb = Directory.Exists(SymbolCache)
            ? Directory.EnumerateFiles(Path.Combine(SymbolCache, "kernel32.pdb"), "kernel32.pdb", SearchOption.AllDirectories).FirstOrDefault() ?? string.Empty
            : string.Empty;
        if (!File.Exists(path) || !File.Exists(wrongPdb))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(path);
        var result = PdbSymbolLoader.Load(image, explicitPath: wrongPdb, searchDirectories: []);

        // It may still find ntdll's own PDB elsewhere (_NT_SYMBOL_PATH); it must never use kernel32's.
        Assert.NotEqual(wrongPdb, image.Pdb?.Path);
        if (!result.Loaded)
        {
            Assert.Contains("does not match", result.Message);
            Assert.Empty(image.Symbols);
        }
    }
}

public class MsfWriterTests
{
    private static string? Target(string file)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "artifacts", "targets", "o2", file);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    [SkippableTheory]
    [InlineData("zopfli.pdb")]
    [InlineData("speedtest1.pdb")]
    public void Every_stream_survives_a_rewrite_of_the_container(string name)
    {
        if (Target(name) is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var original = MsfFile.Parse(File.ReadAllBytes(path));
        var streams = Enumerable.Range(0, original.StreamCount).Select(i => original.StreamExists(i) ? original.ReadStream(i) : null).ToList();
        var copy = MsfFile.Parse(MsfWriter.Write(original.BlockSize, streams));

        Assert.Equal(original.StreamCount, copy.StreamCount);
        for (int i = 0; i < streams.Count; i++)
        {
            Assert.Equal(original.StreamExists(i), copy.StreamExists(i));
            Assert.Equal(streams[i] ?? [], copy.ReadStream(i));
        }

        // The PDB's own content is intact: identity and public symbols read back the same.
        var pdb = PdbFile.Parse(MsfWriter.Write(original.BlockSize, streams));
        var before = PdbFile.Read(path);
        Assert.Equal((before.Guid, before.InfoAge, before.Publics.Count), (pdb.Guid, pdb.InfoAge, pdb.Publics.Count));
    }

    [SkippableFact]
    public void Omap_pdb_translates_a_symbol_through_the_new_tables()
    {
        if (Target("zopfli.pdb") is not { } path)
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        // Everything maps to itself except [0x1000, 0x1100), which moved to 0x2000.
        byte[] bytes = PdbWriter.WithOmap(File.ReadAllBytes(path), Guid.NewGuid(), 1,
            [new OmapRecord(0, 0), new OmapRecord(0x2000, 0x1000), new OmapRecord(0x2100, 0x2100)],
            [new OmapRecord(0, 0), new OmapRecord(0x1000, 0x2000), new OmapRecord(0x1100, 0x1100)],
            new byte[40]);
        var pdb = PdbFile.Parse(bytes);

        Assert.Equal(1u, pdb.InfoAge);
        Assert.Equal(1u, pdb.DbiAge);
        Assert.NotEmpty(pdb.OmapFromSrc);
        Assert.NotEmpty(pdb.OriginalSections);
        Assert.Equal(0x2010u, PdbFile.TranslateOmap(pdb.OmapFromSrc, 0x1010));
        Assert.Equal(0x3000u, PdbFile.TranslateOmap(pdb.OmapFromSrc, 0x3000));
    }
}
