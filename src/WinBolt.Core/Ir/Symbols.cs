namespace WinBolt.Core.Ir;

/// <summary>RSDS CodeView debug record: identifies the one PDB that matches this image.</summary>
public sealed record CodeViewInfo(Guid Guid, uint Age, string PdbPath);

/// <summary>A symbol, already translated to an RVA in this image (§3.3: through OMAP when present).</summary>
public sealed record Symbol(string Name, uint Rva, bool IsFunction);

/// <summary>
/// One reference the linker resolved (PDB fixup debug info, /DEBUGTYPE:FIXUP). A validation
/// oracle for images built with it (DesignDoc Stage 4); third-party binaries lack it.
/// </summary>
public readonly record struct LinkerFixup(ushort Type, uint Rva, uint Target);

/// <summary>
/// One section contribution from the PDB (DBI section contribution substream), in image RVAs: an
/// object file's piece of a section, the unit a linker places. Without disassembly, only whole
/// contributions may move, as the linker's <c>/ORDER</c> would move them (DesignDoc §6.2).
/// </summary>
/// <param name="Module">Index of the contributing module (object file) in the DBI module list.</param>
public readonly record struct SectionContribution(uint Rva, uint Size, uint Characteristics, int Module);

/// <summary>Which PDB supplied <see cref="BinaryImage.Symbols"/>, and how its addresses were mapped.</summary>
/// <param name="HasOmap">Addresses went through OMAP_FROM_SRC: the image was rewritten after linking.</param>
/// <param name="DroppedSymbols">Public symbols with no counterpart in this image (OMAP maps them to nothing).</param>
public sealed record PdbInfo(string Path, bool HasOmap, int PublicSymbols, int DroppedSymbols);
