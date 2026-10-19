namespace WinBolt.Core.Ir;

/// <summary>
/// One IMAGE_DEBUG_DIRECTORY entry. The debug directory is one of the address-bearing
/// structures in §5.4, and its entry types are the main input to layout provenance
/// (Stage 1).
/// </summary>
public sealed record DebugDirectoryEntry(uint Type, uint SizeOfData, uint AddressOfRawData, uint PointerToRawData)
{
    public string TypeName => DebugDirectoryType.Name(Type);
}

/// <summary>IMAGE_DEBUG_TYPE_* values, including the undocumented ones layout provenance relies on.</summary>
public static class DebugDirectoryType
{
    public const uint Coff = 1;
    public const uint CodeView = 2;
    public const uint Fpo = 3;
    public const uint Misc = 4;
    public const uint Exception = 5;
    public const uint Fixup = 6;
    public const uint OmapToSrc = 7;
    public const uint OmapFromSrc = 8;
    public const uint Borland = 9;

    /// <summary>
    /// Undocumented. Empirically present on exactly the post-link-rewritten images in a scan
    /// of 4,289 Microsoft binaries with PDBs (DesignDoc.md Stage 1, layout provenance).
    /// </summary>
    public const uint Reserved10 = 10;

    public const uint Clsid = 11;
    public const uint VcFeature = 12;
    public const uint Pogo = 13;
    public const uint Iltcg = 14;
    public const uint Mpx = 15;
    public const uint Repro = 16;
    public const uint EmbeddedPortablePdb = 17;
    public const uint PdbChecksum = 19;
    public const uint ExDllCharacteristics = 20;

    public static string Name(uint type) => type switch
    {
        Coff => "COFF",
        CodeView => "CodeView",
        Fpo => "FPO",
        Misc => "Misc",
        Exception => "Exception",
        Fixup => "Fixup",
        OmapToSrc => "OMAP_TO_SRC",
        OmapFromSrc => "OMAP_FROM_SRC",
        Borland => "Borland",
        Reserved10 => "Reserved10",
        Clsid => "CLSID",
        VcFeature => "VC_FEATURE",
        Pogo => "POGO",
        Iltcg => "ILTCG",
        Mpx => "MPX",
        Repro => "Repro",
        EmbeddedPortablePdb => "EmbeddedPortablePdb",
        PdbChecksum => "PdbChecksum",
        ExDllCharacteristics => "ExDllCharacteristics",
        _ => $"Unknown({type})",
    };
}
