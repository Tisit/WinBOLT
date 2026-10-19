namespace WinBolt.Core.Ir;

/// <summary>
/// One export table entry. Exports are named entry points available without a PDB, and an
/// export's RVA must be updated if its target moves (§5.4). Forwarders have no RVA in this
/// image (<see cref="Rva"/> is 0).
/// </summary>
public sealed record ExportedSymbol(string? Name, uint Ordinal, uint Rva, string? Forwarder)
{
    public bool IsForwarder => Forwarder is not null;
}
