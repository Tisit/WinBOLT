namespace WinBolt.Core.Ir;

/// <summary>
/// A basic block within a <see cref="Function"/>. Instructions are not stored here as
/// objects; <see cref="InstructionStart"/>/<see cref="InstructionCount"/> index into the
/// owning <see cref="BinaryImage"/>'s <see cref="InstructionStore"/> (§5.3).
/// </summary>
public sealed class BasicBlock
{
    public required int Id { get; init; }

    public required ulong StartRva { get; init; }

    /// <summary>Size in bytes: from <see cref="StartRva"/> to the end of the last instruction.</summary>
    public uint Length { get; set; }

    public int InstructionStart { get; set; }

    public int InstructionCount { get; set; }

    /// <summary>
    /// Profiled executions, derived from edge counts: the larger of the incoming and outgoing
    /// totals (an entry block has no counted predecessors, an exit block no successors). Null
    /// without an edge-accurate profile. Relative, not absolute: LBR is sampled.
    /// </summary>
    public ulong? ExecutionCount { get; set; }

    public List<Edge> Successors { get; } = [];

    public List<Edge> Predecessors { get; } = [];

    /// <summary>
    /// Control can enter the block other than by falling through from the code before it: a
    /// branch, a table dispatch, an exception handler, or a root with no known predecessor. A
    /// block that starts only because a leader rule split the code (after a conditional branch,
    /// at an unwind entry start) is not.
    /// </summary>
    public bool IsBranchTarget => Predecessors.Count == 0 || Predecessors.Any(e => e.Kind != EdgeKind.FallThrough);
}
