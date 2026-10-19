using System.Runtime.InteropServices;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Pdb;
using WinBolt.Pe;

namespace WinBolt.Rewrite.Tests;

/// <summary>
/// DesignDoc Step 21: the PDB of an append-mode rewrite (AppendPdb). WinBolt's own loader and Microsoft's
/// dbghelp must name every function at its copy (by name) and every address inside a copy, hot or cold, by
/// the function and its original offset (by address); only the CodeView record and the checksum change
/// after verification.
/// </summary>
public class AppendPdbTests
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

    private static (BinaryImage Image, byte[] File, RewriteResult Result, string Exe, string Pdb, string Directory)? Rewrite(RewriteMode mode)
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

        // Rebuild mode: every function's blocks shuffled and split, so hot and cold parts are both mapped.
        Func<Function, BlockOrder?>? order = mode == RewriteMode.Rebuild ? f =>
        {
            var random = new Random((int)f.EntryRva);
            var entry = f.BasicBlocks.Single(b => b.StartRva == f.EntryRva);
            var others = f.BasicBlocks.Where(b => b != entry).OrderBy(b => b.StartRva).ToArray();
            random.Shuffle(others);
            var cold = others.Where(_ => random.Next(2) == 0).ToHashSet();
            return new BlockOrder([entry, .. others.Where(b => !cold.Contains(b))], others.Where(cold.Contains).ToList());
        } : null;
        var result = FunctionRewriter.Rewrite(image, file, null, mode, order);
        Assert.True(RewriteVerifier.Verify(image, file, result).Passed);

        string directory = Directory.CreateTempSubdirectory("winbolt-apdb-").FullName;
        string exe = Path.Combine(directory, "zopfli-a.exe"), pdb = Path.Combine(directory, "zopfli-a.pdb");
        var verified = result.Output.ToArray();
        var (guid, age) = AppendPdb.Retire(image, result, pdb);
        File.WriteAllBytes(pdb, AppendPdb.Write(image, result, File.ReadAllBytes(image.Pdb!.Path), guid, age));
        File.WriteAllBytes(exe, result.Output);

        // After verification only the CodeView record and the checksum may change.
        var layout = new PeLayout(verified);
        var cv = image.DebugEntries.Single(e => e.Type == DebugDirectoryType.CodeView);
        var changed = Enumerable.Range(0, verified.Length).Where(i => verified[i] != result.Output[i]).ToList();
        Assert.NotEmpty(changed);
        Assert.All(changed, i => Assert.True((i >= cv.PointerToRawData && i < cv.PointerToRawData + cv.SizeOfData) ||
                                             (i >= layout.CheckSumOffset && i < layout.CheckSumOffset + 4), $"byte 0x{i:X} changed"));
        return (image, file, result, exe, pdb, directory);
    }

    [SkippableTheory]
    [InlineData(RewriteMode.Copy)]
    [InlineData(RewriteMode.Rebuild)]
    public void WinBolt_finds_every_function_symbol_at_its_copy(RewriteMode mode)
    {
        if (Rewrite(mode) is not var (image, _, result, exe, pdb, directory))
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
            Assert.All(expected, s => Assert.Contains(AppendPdb.NewAddress(result, s.Rva), actual[s.Name]));
            Assert.Contains(expected, s => AppendPdb.NewAddress(result, s.Rva) != s.Rva);
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

    [SkippableTheory]
    [InlineData(RewriteMode.Copy)]
    [InlineData(RewriteMode.Rebuild)]
    public void Dbghelp_names_copies_and_originals_through_the_omap(RewriteMode mode)
    {
        if (Rewrite(mode) is not var (image, _, result, exe, _, directory))
        {
throw new SkipException("build artifacts missing (run tools/targets/Build-Targets.ps1)");
        }

        var process = new IntPtr(0x5743_0000 + Environment.CurrentManagedThreadId); // a handle that is not a real process
        const ulong Base = 0x1_4000_0000;
        try
        {
            SymSetOptions(SymoptUndname | SymoptLoadLines | SymoptFailCriticalErrors);
            Assert.True(SymInitialize(process, directory, false), $"SymInitialize: {Marshal.GetLastWin32Error()}");
            Assert.NotEqual(0ul, SymLoadModuleEx(process, IntPtr.Zero, exe, null, Base, (uint)PeImageReader.Read(exe).SizeOfImage, IntPtr.Zero, 0));

            // By name: the symbol's original address, translated, is its copy's start.
            int names = 0, addresses = 0;
            foreach (var m in result.Moved.Where(m => image.Functions[m.FunctionId].Name is { } n && !n.StartsWith('?') && m.Length > 8 &&
                                                      image.Symbols.Count(s => s.Name == image.Functions[m.FunctionId].Name) == 1))
            {
                var function = image.Functions[m.FunctionId];
                var symbol = NewSymbol();
                Assert.True(SymFromName(process, function.Name!, ref symbol), $"{function.Name}: {Marshal.GetLastWin32Error()}");
                Assert.Equal(Base + m.CopyStart, symbol.Address);
                names++;

                // By address, in the copy: the function and the original offset of the instruction.
                foreach (var x in BlockRebuilder.Instructions(image, function).Where((_, i) => i % 5 == 2))
                {
                    uint at = m.AddressMap is null ? m.CopyStart + ((uint)x.IP - m.Start) : m.AddressMap.GetValueOrDefault((uint)x.IP);
                    if (at == 0 || (m.AddressMap is not null && x.IsJmpShortOrNear && m.AddressMap.GetValueOrDefault((uint)x.NearBranchTarget) == at))
                    {
                        continue; // unmapped, or a dropped jmp whose address is its target's
                    }

                    var byAddress = NewSymbol();
                    Assert.True(SymFromAddr(process, Base + at, out ulong displacement, ref byAddress), $"0x{at:X}: {Marshal.GetLastWin32Error()}");
                    Assert.Equal(function.Name, byAddress.Name);
                    Assert.Equal(x.IP - function.EntryRva, displacement);
                    addresses++;
                }

                // By address, at the original entry (the trampoline): still named.
                var original = NewSymbol();
                Assert.True(SymFromAddr(process, Base + m.Start, out ulong zero, ref original));
                Assert.Equal(function.Name, original.Name);
                Assert.Equal(0ul, zero);
            }

            Assert.True(names > 10 && addresses > 50, $"{names} names, {addresses} addresses checked");
        }
        finally
        {
            SymCleanup(process);
            TempDirectory.Delete(directory);
        }
    }
}
