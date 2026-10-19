namespace WinBolt.Core.Ir;

/// <summary>
/// See §5.2. Entry encoding varies by toolchain and drives recovery difficulty
/// independently of relocation availability.
/// </summary>
public enum JumpTableEncoding
{
    /// <summary>MSVC PE: 4-byte offset relative to __ImageBase. Carries no relocations.</summary>
    ImageRelativeOffset32,

    /// <summary>LLVM (clang-cl/lld): signed 4-byte offset relative to <see cref="JumpTable.BaseRva"/> (usually the table itself), loaded with <c>movsxd</c>.</summary>
    TableRelativeOffset32,

    /// <summary>GCC/Clang non-PIC, or Delphi: 8-byte absolute pointer. Carries relocations.</summary>
    AbsolutePointer64,

    /// <summary>MSVC two-level form: byte-sized index table feeding a dword table.</summary>
    TwoLevelMsvc,
}

/// <summary>
/// A recovered table of code addresses (§5.2). Failure to recover a table downgrades the
/// owning function's <see cref="SafetyStatus"/> rather than leaving an unsound CFG.
/// A writer must rewrite every entry when a target moves.
/// </summary>
public sealed class JumpTable
{
    /// <summary>The indirect jump that dispatches through the table.</summary>
    public required ulong SiteRva { get; init; }

    /// <summary>The table of code addresses (the dword table for <see cref="JumpTableEncoding.TwoLevelMsvc"/>).</summary>
    public required ulong Rva { get; init; }

    public required JumpTableEncoding Encoding { get; init; }

    /// <summary>
    /// The index has no bound check on the code's paths (a switch over an enum the compiler knows
    /// is in range: LLVM's default-less switch), so <see cref="EntryCount"/> comes from the data:
    /// entries up to the first one that does not target the function, or the next data object the
    /// function references. Entries beyond the real table can only add edges to code addresses.
    /// </summary>
    public bool ExtentInferred { get; init; }

    /// <summary>The address <see cref="JumpTableEncoding.TableRelativeOffset32"/> entries are relative to; 0 otherwise.</summary>
    public ulong BaseRva { get; init; }

    /// <summary>Number of entries in the table at <see cref="Rva"/>.</summary>
    public required int EntryCount { get; init; }

    /// <summary>Target of each entry, in table order (duplicates kept: cases can share a target).</summary>
    public List<ulong> TargetRvas { get; } = [];

    /// <summary>Set only for <see cref="JumpTableEncoding.TwoLevelMsvc"/>.</summary>
    public ulong? IndexTableRva { get; init; }

    /// <summary>Number of byte entries in the index table; 0 without one.</summary>
    public int IndexEntryCount { get; init; }

    /// <summary>
    /// The instruction that loads an entry from the table at <see cref="Rva"/>; its 32-bit
    /// displacement is the table's RVA. A writer that moves the table rewrites that field.
    /// </summary>
    public ulong? LoadRva { get; init; }

    /// <summary>
    /// <see cref="JumpTableEncoding.TableRelativeOffset32"/>: every <c>lea reg,[rip+BaseRva]</c> that
    /// loads the base on some path into the dispatch (there is no table address in the load itself;
    /// <see cref="LoadRva"/> is the first of them). A writer that moves the table re-points them all.
    /// </summary>
    public IReadOnlyList<ulong> BaseSites { get; init; } = [];

    /// <summary>The instructions whose 32-bit field names the table: the load, or for the table-relative form the base <c>lea</c>s.</summary>
    public IEnumerable<ulong> FieldSites => Encoding == JumpTableEncoding.TableRelativeOffset32 ? BaseSites : LoadRva is { } load ? [load] : [];

    /// <summary>The instruction that loads from the index table (two-level form only).</summary>
    public ulong? IndexLoadRva { get; init; }
}
