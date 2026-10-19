namespace WinBolt.Core.Ir;

/// <summary>
/// A code address materialized by <c>lea reg,[rip+X]</c> in reachable code. x64 takes function
/// addresses this way without any relocation, so outside a <c>/guard:cf</c> image this is the
/// main evidence that a function is address-taken (§6.1), and the only evidence that an
/// interior code address escapes (computed jumps, FH3 catch continuations).
/// A writer must re-point <see cref="SiteRva"/> when <see cref="TargetRva"/> moves.
/// </summary>
/// <param name="FunctionId">Function containing the <c>lea</c>.</param>
/// <param name="TargetFunctionId">Function whose range contains the target; null if none.</param>
/// <param name="IsEntry">The target is <see cref="TargetFunctionId"/>'s entry point.</param>
public sealed record CodePointer(int FunctionId, uint SiteRva, uint TargetRva, int? TargetFunctionId, bool IsEntry);
