namespace WinBolt.Core.Ir;

/// <summary>
/// One contiguous range of a (possibly discontiguous) function. See §5.1: functions
/// backed by <c>UNW_FLAG_CHAININFO</c>-chained <c>RUNTIME_FUNCTION</c> entries, or already
/// hot/cold split by MSVC PGO, are the normal case rather than an edge case.
/// </summary>
public sealed class FunctionRange
{
    public required ulong StartRva { get; init; }

    public required uint Length { get; set; }

    /// <summary>True for the range containing the function's logical entry point.</summary>
    public required bool IsEntryRange { get; init; }
}
