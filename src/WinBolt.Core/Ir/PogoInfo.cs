namespace WinBolt.Core.Ir;

/// <summary>One section contribution listed by the POGO debug entry.</summary>
public sealed record PogoContribution(uint Rva, uint Size, string Name);

/// <summary>
/// Decoded IMAGE_DEBUG_TYPE_POGO payload. The linker writes it for LTCG and PGO builds; the
/// signature says which kind of build produced the layout (Stage 1, layout provenance).
/// </summary>
public sealed record PogoInfo(uint RawSignature, IReadOnlyList<PogoContribution> Contributions)
{
    // The signature is stored so that reading it little-endian yields these values.
    public const uint SignatureLtcg = 0x4C544347; // "LTCG": LTCG, no profile
    public const uint SignaturePgi = 0x50474900;  // "PGI": instrumented build
    public const uint SignaturePgo = 0x50474F00;  // "PGO": optimized with profile (older toolsets)
    public const uint SignaturePgu = 0x50475500;  // "PGU": optimized using profile

    public string Signature => RawSignature switch
    {
        SignatureLtcg => "LTCG",
        SignaturePgi => "PGI",
        SignaturePgo => "PGO",
        SignaturePgu => "PGU",
        _ => $"0x{RawSignature:X8}",
    };

    /// <summary>True when the image was built using a training profile.</summary>
    public bool IsProfileOptimized => RawSignature is SignaturePgu or SignaturePgo;

    /// <summary>Contributions whose name marks a profile-ordered layout bucket (<c>.text$lp…</c>, <c>…_pri…</c>).</summary>
    public int ProfileOrderedGroups => Contributions.Count(c => IsProfileOrderedGroup(c.Name));

    /// <summary>Contributions that hold cold code split away from its function (<c>.text$x</c>, <c>.text$z…</c>).</summary>
    public int ColdGroups => Contributions.Count(c => IsColdGroup(c.Name));

    // e.g. ".text$lp00kernelbase.dll!20_pri7"
    public static bool IsProfileOrderedGroup(string name) =>
        name.Contains("$lp", StringComparison.Ordinal) || name.Contains("_pri", StringComparison.Ordinal);

    public static bool IsColdGroup(string name) =>
        name.Equals(".text$x", StringComparison.Ordinal) || name.StartsWith(".text$z", StringComparison.Ordinal);
}
