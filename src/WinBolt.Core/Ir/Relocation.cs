namespace WinBolt.Core.Ir;

/// <summary>
/// IMAGE_REL_BASED_* base relocation types actually encountered in PE32+ images.
/// </summary>
public enum RelocationType
{
    Absolute, // padding entry, no-op
    Dir64,    // 8-byte absolute address fixup — the common x64 case
    HighLow,  // 4-byte absolute address fixup — legacy, rare in x64 images
}

/// <summary>
/// One entry from the base relocation table (.reloc). §5.4: every relocation whose target
/// moved needs its RVA updated, and relocations pointing into moved code need their site
/// RVAs updated.
/// </summary>
public sealed class Relocation
{
    public required uint Rva { get; init; }

    public required RelocationType Type { get; init; }
}
