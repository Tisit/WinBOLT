namespace WinBolt.Core.Ir;

public enum EdgeKind
{
    FallThrough,
    Branch,
    Call,
    Return,

    /// <summary>Target enumerated via jump-table or other code-address-table recovery (§5.2).</summary>
    IndirectBranch,

    ExceptionHandler,
}

/// <summary>
/// A CFG edge. <see cref="ExecutionCount"/> is measured by Stage 2 edge-accurate (branch record)
/// profiling. A sampling-only profile has none to measure: <see cref="Profile.IpProfileBuilder"/> fills
/// in an estimate and says so (<see cref="Passes.ProfileFidelity.SamplingOnly"/>).
/// </summary>
public sealed class Edge
{
    public required BasicBlock Source { get; init; }

    public required BasicBlock Target { get; init; }

    public required EdgeKind Kind { get; init; }

    public ulong? ExecutionCount { get; set; }
}
