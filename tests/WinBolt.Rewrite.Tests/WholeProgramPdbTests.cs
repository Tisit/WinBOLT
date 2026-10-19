using System.Runtime.InteropServices;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// DesignDoc §6.2 milestone W4: the rewritten image's PDB, with OMAP. WinBolt's own loader and
/// Microsoft's dbghelp must both find every function at its new address, and name an
/// instruction inside a rebuilt function by its original offset.
/// </summary>
public class WholeProgramPdbTests
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

    /// <summary>zopfli, every function executed and its blocks shuffled and split, the functions reversed; output and PDB in a temp directory.</summary>
    private static (BinaryImage Image, WholeProgramResult Result, string Exe, string Pdb, string Directory)? Rewrite()
    {
        if (Build("o2", "zopfli.exe") is not { } path)
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

        foreach (var block in image.Functions.SelectMany(f => f.BasicBlocks))
        {
            block.ExecutionCount ??= 1;
        }

        var code = image.SectionContributions.Where(c => image.FindSection(c.Rva) is { IsExecutable: true }).OrderByDescending(c => c.Rva).ToList();
        string directory = Directory.CreateTempSubdirectory("winbolt-pdb-").FullName;
        string exe = Path.Combine(directory, "zopfli-w4.exe"), pdb = Path.Combine(directory, "zopfli-w4.pdb");
        var result = WholeProgramRewriter.Rewrite(image, file, code, jccErratum: true, blockOrder: f =>
        {
            var random = new Random((int)f.EntryRva);
            var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
            var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToArray();
            random.Shuffle(others);
            var cold = others.Where(_ => random.Next(2) == 0).ToHashSet();
            return new BlockOrder([entry, .. others.Where(b => !cold.Contains(b))], others.Where(cold.Contains).ToList());
        }, pdbPath: pdb);
        Assert.True(WholeProgramVerifier.Verify(image, file, result).Passed);

        var (toSource, fromSource) = WholeProgramOmap.Build(image, result);
        File.WriteAllBytes(pdb, PdbWriter.WithOmap(File.ReadAllBytes(image.Pdb!.Path), result.PdbGuid!.Value, result.PdbAge,
            toSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(), fromSource.Select(r => new OmapRecord(r.Rva, r.RvaTo)).ToList(),
            WholeProgramOmap.SectionHeaders(result.Output)));
        File.WriteAllBytes(exe, result.Output);
        return (image, result, exe, pdb, directory);
    }

    [SkippableFact]
    public void WinBolt_finds_every_function_symbol_at_its_new_address()
    {
        if (Rewrite() is not var (image, result, exe, pdb, directory))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        try
        {
            var output = PeImageReader.Read(exe);
            Assert.True(PdbSymbolLoader.Load(output, pdb).Loaded);
            Assert.True(output.Pdb!.HasOmap);
            var expected = image.Symbols.Where(s => s.IsFunction).GroupBy(s => s.Name).Where(g => g.Count() == 1).Select(g => g.Single()).ToList();
            var actual = output.Symbols.Where(s => s.IsFunction).ToLookup(s => s.Name, s => s.Rva);
            Assert.NotEmpty(expected);
            Assert.All(expected, s => Assert.Contains(result.MapSite(s.Rva), actual[s.Name]));
        }
        finally
        {
            TempDirectory.Delete(directory);
        }
    }

    // --- dbghelp ---

    private const uint SymoptUndname = 0x2, SymoptLoadLines = 0x10, SymoptFailCriticalErrors = 0x200;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SymbolInfo
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        public ulong Reserved0, Reserved1;
        public uint Index, Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value, Address;
        public uint Register, Scope, Tag, NameLen, MaxNameLen;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Name;
    }

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymInitializeW")]
    private static extern bool SymInitialize(IntPtr process, string? searchPath, bool invadeProcess);

    [DllImport("dbghelp.dll")]
    private static extern uint SymSetOptions(uint options);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymLoadModuleExW")]
    private static extern ulong SymLoadModuleEx(IntPtr process, IntPtr file, string imageName, string? moduleName, ulong baseOfDll, uint dllSize, IntPtr data, uint flags);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymFromNameW")]
    private static extern bool SymFromName(IntPtr process, string name, ref SymbolInfo symbol);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymFromAddrW")]
    private static extern bool SymFromAddr(IntPtr process, ulong address, out ulong displacement, ref SymbolInfo symbol);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool SymCleanup(IntPtr process);

    private static SymbolInfo NewSymbol() => new() { SizeOfStruct = 88, MaxNameLen = 1024, Name = string.Empty };

    [SkippableFact]
    public void Dbghelp_names_new_addresses_through_the_omap()
    {
        if (Rewrite() is not var (image, result, exe, _, directory))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var process = new IntPtr(0x5742_0000 + Environment.CurrentManagedThreadId); // a handle that is not a real process
        const ulong Base = 0x1_4000_0000;
        try
        {
            SymSetOptions(SymoptUndname | SymoptLoadLines | SymoptFailCriticalErrors);
            Assert.True(SymInitialize(process, directory, false), $"SymInitialize: {Marshal.GetLastWin32Error()}");
            Assert.NotEqual(0ul, SymLoadModuleEx(process, IntPtr.Zero, exe, null, Base, (uint)PeImageReader.Read(exe).SizeOfImage, IntPtr.Zero, 0));

            // By name: every rebuilt function's entry is its hot part's start.
            int checkedNames = 0;
            // Import thunks (jmp [__imp_x], 6 bytes) share their name with the import: dbghelp looks in the imported module.
            // Decorated C++ names are stored undecorated (SYMOPT_UNDNAME): only C names are compared.
            foreach (var r in result.Rebuilt.Values.Where(r => r.Function.Name is { } name && !name.StartsWith('?') && r.Function.EntryRange.Length > 8 &&
                                                               image.Symbols.Count(s => s.Name == r.Function.Name) == 1))
            {
                var symbol = NewSymbol();
                Assert.True(SymFromName(process, r.Function.Name!, ref symbol), $"{r.Function.Name}: {Marshal.GetLastWin32Error()}");
                Assert.Equal(Base + r.HotStart, symbol.Address);
                checkedNames++;
            }

            Assert.True(checkedNames > 10, $"{checkedNames} named rebuilt functions");

            // By address: an instruction deep in a rebuilt function, hot or cold, is named by the
            // function and its original offset (OMAP_TO_SRC per instruction).
            int checkedAddresses = 0;
            foreach (var r in result.Rebuilt.Values.Where(r => r.Function.Name is { } name && !name.StartsWith('?') && r.ColdLength > 0).Take(20))
            {
                foreach (var x in BlockRebuilder.Instructions(image, r.Function).Where((_, i) => i % 7 == 3))
                {
                    if (!r.AddressMap.TryGetValue((uint)x.IP, out uint at) || (x.IsJmpShortOrNear && r.AddressMap.GetValueOrDefault((uint)x.NearBranchTarget) == at))
                    {
                        continue; // dropped jmp: its address is its target's
                    }

                    var symbol = NewSymbol();
                    Assert.True(SymFromAddr(process, Base + at, out ulong displacement, ref symbol), $"0x{at:X}: {Marshal.GetLastWin32Error()}");
                    Assert.Equal(r.Function.Name, symbol.Name);
                    Assert.Equal(x.IP - r.Function.EntryRva, displacement);
                    checkedAddresses++;
                }
            }

            Assert.True(checkedAddresses > 50, $"{checkedAddresses} addresses checked");
        }
        finally
        {
            SymCleanup(process);
            TempDirectory.Delete(directory);
        }
    }
}
