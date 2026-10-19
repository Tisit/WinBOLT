namespace WinBolt.Core.Ir;

public enum CallKind
{
    /// <summary>Direct near call.</summary>
    Call,

    /// <summary>Unconditional direct jump leaving the function: a tail call.</summary>
    TailJump,

    /// <summary>Conditional direct jump leaving the function.</summary>
    ConditionalTailJump,

    /// <summary>Call through a register or memory; target unknown until indirect-target analysis (§5.2).</summary>
    IndirectCall,

    /// <summary><c>jmp [rip+x]</c>: an import thunk or tail call through a pointer.</summary>
    IndirectTailJump,
}

/// <summary>
/// One edge of the call graph (Stage 1 deliverable). <see cref="CalleeId"/> is set when the
/// target is a known function's entry; a target inside a function, in unattributed code, or
/// unknown (indirect) leaves it null. <see cref="PointerRva"/> is the pointer an indirect
/// <c>call/jmp [rip+X]</c> reads: an IAT slot names the import it calls.
/// </summary>
public sealed record CallSite(int CallerId, uint SiteRva, CallKind Kind, uint? TargetRva, int? CalleeId, uint? PointerRva = null);
