namespace WinBolt.Core.Ir;

/// <summary>Evidence a function start was found through. A function may have several.</summary>
[Flags]
public enum DiscoverySource
{
    None = 0,

    /// <summary>Unchained RUNTIME_FUNCTION entry: the primary mechanism on x64 (Stage 1).</summary>
    Pdata = 1 << 0,
    Export = 1 << 1,
    EntryPoint = 1 << 2,
    TlsCallback = 1 << 3,

    /// <summary>GuardCFFunctionTable: authoritative address-taken list (§5.4).</summary>
    CfgTarget = 1 << 4,

    /// <summary>Target of a direct call in already-discovered code.</summary>
    CallTarget = 1 << 5,

    /// <summary>Target of a direct jump leaving already-discovered code (tail call).</summary>
    JumpTarget = 1 << 6,

    /// <summary>Absolute pointer into code found through a base relocation.</summary>
    RelocationTarget = 1 << 7,

    /// <summary>
    /// Named by exception data: a language-specific handler named by .pdata unwind info, a
    /// filter or termination-handler funclet named by an SEH scope table, or an unwind or catch
    /// funclet or destructor named by a C++ EH table.
    /// </summary>
    ExceptionTable = 1 << 8,

    /// <summary>Address loaded by <c>lea reg,[rip+X]</c> in code: address-taken (§6.1).</summary>
    CodePointer = 1 << 9,

    /// <summary>Function public symbol from a matching PDB (§3.3).</summary>
    Symbol = 1 << 10,

    /// <summary>
    /// Target of a direct jmp that is the first instruction of a function with .pdata or entry-asserting
    /// evidence (a thunk, or a rewriter's trampoline): control arrives there with the caller's frame
    /// untouched, so the target is entered as a function.
    /// </summary>
    EntryJump = 1 << 11,
}

/// <summary>
/// A logical function, possibly spanning several discontiguous <see cref="FunctionRange"/>
/// (§5.1). The range, not the function, is the unit of movement (Stage 4).
/// </summary>
public sealed class Function
{
    public required int Id { get; init; }

    /// <summary>Symbol name when known (PDB or export table); null for unattributed code.</summary>
    public string? Name { get; set; }

    /// <summary>The name, or <c>sub_&lt;entry RVA&gt;</c> for unattributed code.</summary>
    public string DisplayName => Name ?? $"sub_{EntryRva:X}";

    public DiscoverySource DiscoveredBy { get; set; }

    /// <summary>Ranges in ascending RVA order. Each is a maximal contiguous span; exactly one is the entry range.</summary>
    public List<FunctionRange> Ranges { get; } = [];

    public List<BasicBlock> BasicBlocks { get; } = [];

    public List<JumpTable> JumpTables { get; } = [];

    /// <summary>The language-specific handler of the function's primary .pdata entry, if any.</summary>
    public ExceptionHandlerInfo? ExceptionHandler { get; set; }

    /// <summary>The validated SEH scope table, for <see cref="ExceptionHandlerKind.CSpecific"/> handlers.</summary>
    public List<ScopeEntry>? ScopeTable { get; set; }

    /// <summary>The parsed C++ EH table, for <c>__CxxFrameHandler3/4</c> handlers.</summary>
    public CxxEhInfo? CxxEh { get; set; }

    public SafetyStatus SafetyStatus { get; set; } = SafetyStatus.Unanalyzed;

    /// <summary>
    /// Every downgrade reason recorded, in order, including ones that did not lower the level.
    /// <see cref="SafetyStatus"/> keeps only the first reason at the most restrictive level; this
    /// list answers "what would it take to free this function?".
    /// </summary>
    public List<string> DowngradeReasons { get; } = [];

    public ProfileInfo? Profile { get; set; }

    public FunctionRange EntryRange => Ranges.Single(r => r.IsEntryRange);

    /// <summary>Logical entry point. The entry range always starts at it.</summary>
    public uint EntryRva => (uint)EntryRange.StartRva;

    public uint TotalLength => (uint)Ranges.Sum(r => (long)r.Length);

    /// <summary>
    /// The blocks inside the entry range. A function split by PGO or BBT has further ranges (its
    /// cold code elsewhere); moving the function moves only these.
    /// </summary>
    public IEnumerable<BasicBlock> EntryBlocks
    {
        get
        {
            var entry = EntryRange;
            return BasicBlocks.Where(b => b.StartRva >= entry.StartRva && b.StartRva < entry.StartRva + entry.Length);
        }
    }

    /// <summary>
    /// Lowers <see cref="SafetyStatus"/> to <paramref name="level"/> if that is more restrictive
    /// than the current level; never raises it (§5.5: downgrades are one-way and carry a reason).
    /// </summary>
    public void Downgrade(Transformability level, string reason)
    {
        DowngradeReasons.Add(reason);
        if (Restrictiveness(level) > Restrictiveness(SafetyStatus.Level))
        {
            SafetyStatus = new SafetyStatus(level, reason);
        }
    }

    private static int Restrictiveness(Transformability level) => level switch
    {
        Transformability.Unanalyzed => 0,
        Transformability.FullyTransformable => 1,
        Transformability.RelocatableOnly => 2,
        Transformability.Frozen => 3,
        _ => 3,
    };
}
