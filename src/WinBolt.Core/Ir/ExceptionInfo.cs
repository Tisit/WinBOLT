namespace WinBolt.Core.Ir;

/// <summary>
/// One RUNTIME_FUNCTION entry from .pdata. The exception directory must remain sorted in
/// ascending order of <see cref="BeginAddress"/> (§5.4) — RtlLookupFunctionEntry
/// binary-searches it at runtime, so reordering functions requires re-sorting .pdata, not
/// merely rewriting RVAs in place.
/// </summary>
public sealed class ExceptionInfo
{
    public required uint BeginAddress { get; init; }

    public required uint EndAddress { get; init; }

    public required uint UnwindInfoAddress { get; init; }

    /// <summary>
    /// True when the unwind info has UNW_FLAG_CHAININFO, or <see cref="UnwindInfoAddress"/>
    /// has its low bit set (the indirect form, which points at the parent RUNTIME_FUNCTION
    /// directly) (§5.1).
    /// </summary>
    public bool IsChained { get; init; }

    /// <summary>
    /// The immediate parent entry. Null on a chained entry means the chain is invalid (the
    /// parent is not a .pdata entry or could not be read), which §5.5 treats as unattributed code.
    /// </summary>
    public ExceptionInfo? ChainedParent { get; set; }

    /// <summary>
    /// UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER: the entry names a language-specific handler whose
    /// handler data (C++ FuncInfo, SEH scope table, GS cookie info) may hold code RVAs (§5.2).
    /// </summary>
    public bool HasHandler => HandlerRva != 0;

    /// <summary>RVA of the language-specific handler; 0 when there is none.</summary>
    public uint HandlerRva { get; init; }

    /// <summary>RVA of the handler data that follows the handler RVA; 0 when there is no handler.</summary>
    public uint HandlerDataRva { get; init; }
}
