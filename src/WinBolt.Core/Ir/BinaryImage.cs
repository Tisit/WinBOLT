namespace WinBolt.Core.Ir;

/// <summary>
/// Root IR node (§5). Everything downstream — analysis, optimization, validation, and the
/// writer — operates on this and never on raw bytes directly.
/// </summary>
public sealed class BinaryImage
{
    public required string FilePath { get; init; }

    public required ulong ImageBase { get; init; }

    public required uint SizeOfImage { get; init; }

    public required uint TimeDateStamp { get; init; }

    public required uint Checksum { get; init; }

    /// <summary>IMAGE_OPTIONAL_HEADER64.DllCharacteristics (ASLR, NX, GUARD_CF, ...): the loader's view of the image.</summary>
    public ushort DllCharacteristics { get; init; }

    /// <summary>AddressOfEntryPoint; 0 when the image has none (common for resource-only DLLs).</summary>
    public uint EntryPointRva { get; init; }

    public List<ExportedSymbol> Exports { get; } = [];

    public List<ImportedSymbol> Imports { get; } = [];

    /// <summary>The CodeView (RSDS) record naming the matching PDB; null when the image has none.</summary>
    public CodeViewInfo? CodeView { get; set; }

    /// <summary>PDB symbols in image RVAs; empty when no matching PDB was loaded.</summary>
    public List<Symbol> Symbols { get; } = [];

    /// <summary>Linker fixup records from the PDB, when it has them and the image was not rewritten (no OMAP).</summary>
    public List<LinkerFixup> LinkerFixups { get; } = [];

    /// <summary>Section contributions from the PDB in image RVAs, sorted; empty without a PDB or when the image was rewritten (OMAP).</summary>
    public List<SectionContribution> SectionContributions { get; } = [];

    /// <summary>The PDB that supplied <see cref="Symbols"/>; null when none was loaded.</summary>
    public PdbInfo? Pdb { get; set; }

    /// <summary>Identified language-specific handlers, keyed by handler RVA.</summary>
    public Dictionary<uint, ExceptionHandlerInfo> ExceptionHandlers { get; } = [];

    /// <summary>
    /// Parsed SEH scope tables keyed by the BeginAddress of the .pdata entry that owns them. Raw:
    /// validated against function ranges only once functions exist (CFG construction).
    /// </summary>
    public Dictionary<uint, List<ScopeEntry>> ScopeTables { get; } = [];

    /// <summary>Parsed C++ EH tables keyed by the BeginAddress of the .pdata entry that owns them.</summary>
    public Dictionary<uint, CxxEhInfo> CxxEhTables { get; } = [];

    /// <summary>Non-empty data directories (§5.4: address-bearing structures), excluding Security, whose "RVA" is a file offset.</summary>
    public List<DataDirectory> DataDirectories { get; } = [];

    /// <summary>TLS callback RVAs (§5.2: a code-address table the loader calls through).</summary>
    public List<uint> TlsCallbacks { get; } = [];

    /// <summary>Executable-section spans no function claims, filled by function discovery.</summary>
    public List<UnclaimedRange> UnclaimedCode { get; } = [];

    /// <summary>Backing store for every decoded instruction in the image (§5.3).</summary>
    public InstructionStore Instructions { get; } = new();

    public List<Section> Sections { get; } = [];

    public List<Function> Functions { get; } = [];

    /// <summary>Call graph edges, filled by CFG construction.</summary>
    public List<CallSite> CallSites { get; } = [];

    /// <summary>Code addresses loaded by <c>lea [rip+X]</c> in reachable code, filled by CFG construction.</summary>
    public List<CodePointer> CodePointers { get; } = [];

    public List<Relocation> Relocations { get; } = [];

    public List<ExceptionInfo> ExceptionData { get; } = [];

    public LoadConfigTables? LoadConfig { get; set; }

    /// <summary>Set when a runtime profile was applied (Stage 2); per-function data is on <see cref="Function.Profile"/>.</summary>
    public WinBolt.Core.Profile.ProfileSummary? ProfileSummary { get; set; }

    /// <summary>Set by the safety gate when the image is .NET NativeAOT; null otherwise.</summary>
    public NativeAotInfo? NativeAot { get; set; }

    public List<DebugDirectoryEntry> DebugEntries { get; } = [];

    /// <summary>Decoded POGO debug entry; null when the image has none (non-LTCG build).</summary>
    public PogoInfo? Pogo { get; set; }

    public Dictionary<string, string> Metadata { get; } = [];

    public Section? FindSection(uint rva) => Sections.FirstOrDefault(s => s.Contains(rva));

    /// <summary>
    /// File-backed bytes from <paramref name="rva"/> to the end of its section's data. Empty when
    /// the RVA is unmapped or lies in zero-fill.
    /// </summary>
    public ReadOnlyMemory<byte> ReadFrom(uint rva)
    {
        if (FindSection(rva) is not { } section || rva - section.Rva >= section.Data.Length)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return section.Data[(int)(rva - section.Rva)..];
    }
}
