namespace WinBolt.Core.Ir;

/// <summary>
/// Which language-specific exception handler a .pdata entry names. The kind decides how its
/// handler data is laid out, and so whether the code addresses in it are known (§5.2).
/// </summary>
public enum ExceptionHandlerKind
{
    /// <summary>Not identified. Its handler data may hold code RVAs in an unknown layout.</summary>
    Unknown,

    /// <summary>
    /// <c>__GSHandlerCheck</c>: stack cookie check only. Its handler data is a frame-relative
    /// cookie offset and holds no code addresses.
    /// </summary>
    GsCookieCheck,

    /// <summary><c>__C_specific_handler</c> (SEH <c>__try</c>): handler data is a SCOPE_TABLE.</summary>
    CSpecific,

    /// <summary><c>__CxxFrameHandler3</c>: handler data is the RVA of a FuncInfo.</summary>
    CxxFrameHandler3,

    /// <summary><c>__CxxFrameHandler4</c>: handler data is the RVA of a compressed FuncInfo4.</summary>
    CxxFrameHandler4,
}

/// <summary>
/// An identified handler. <see cref="Evidence"/> says how it was identified; <see cref="NamedByPdb"/>
/// marks a statically linked handler known only from its public symbol in the matching PDB;
/// <see cref="InferredFromData"/> one known only because the handler data of every function using it
/// parses as the kind's table and its addresses check out against those functions.
/// </summary>
public sealed record ExceptionHandlerInfo(uint HandlerRva, ExceptionHandlerKind Kind, string? Name, string Evidence, bool NamedByPdb = false, bool InferredFromData = false);

/// <summary>
/// One SCOPE_TABLE record for <c>__C_specific_handler</c>. <see cref="HandlerRva"/> is a filter
/// function, or 1 (EXCEPTION_EXECUTE_HANDLER) for <c>__except(1)</c>. <see cref="JumpTargetRva"/> is
/// the <c>__except</c> block inside the function; 0 marks a <c>__finally</c>, and then
/// <see cref="HandlerRva"/> is the termination handler funclet.
/// </summary>
public sealed record ScopeEntry(uint BeginRva, uint EndRva, uint HandlerRva, uint JumpTargetRva)
{
    public bool IsFinally => JumpTargetRva == 0;

    /// <summary>The filter or termination handler funclet, when there is one.</summary>
    public uint? FuncletRva => HandlerRva > 1 ? HandlerRva : null;
}
