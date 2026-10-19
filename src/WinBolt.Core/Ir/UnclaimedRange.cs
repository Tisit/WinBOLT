namespace WinBolt.Core.Ir;

public enum UnclaimedKind
{
    /// <summary>int3 / nop / zero bytes between functions.</summary>
    Padding,

    /// <summary>Executable bytes no discovery source attributed to a function (Stage 1: "unclaimed code").</summary>
    Unattributed,

    /// <summary>A chained .pdata fragment whose chain is invalid (§5.1). Never moved (§5.5).</summary>
    InvalidChainFragment,

    /// <summary>
    /// Data known to be data, placed in an executable section: what the PE headers describe
    /// (import/IAT, export, debug, load config, TLS …, as older toolsets merge .rdata into .text),
    /// and recovered jump tables, which MSVC places after the function that uses them.
    /// </summary>
    KnownData,
}

/// <summary>A span of an executable section that belongs to no <see cref="Function"/>.</summary>
public sealed record UnclaimedRange(uint Rva, uint Length, UnclaimedKind Kind);
