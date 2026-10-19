namespace WinBolt.Core.Ir;

/// <summary>
/// Code addresses held by one C++ EH FuncInfo (<c>__CxxFrameHandler3</c>) or FuncInfo4
/// (<c>__CxxFrameHandler4</c>), §5.2. These are the addresses a writer must rewrite when code
/// moves, and the only references to unwind and catch funclets.
/// </summary>
/// <param name="FuncInfoRva">Where the FuncInfo lives (the handler data holds this RVA).</param>
/// <param name="Version">3 or 4.</param>
/// <param name="FuncletRvas">
/// Entries called by the EH runtime: unwind-action funclets, destructors named by FH4 unwind
/// entries, and catch-handler funclets.
/// </param>
/// <param name="ContinuationRvas">FH4 catch continuations: where the parent resumes after a catch.</param>
/// <param name="IpStateRvas">
/// Absolute addresses of IP-to-state map entries (FH4 offsets are resolved against the function
/// start). Block reordering must regenerate these; moving the function as a unit rebases them.
/// </param>
/// <param name="Problem">Why parsing stopped, or null when every table was read.</param>
public sealed record CxxEhInfo(
    uint FuncInfoRva,
    int Version,
    IReadOnlyList<uint> FuncletRvas,
    IReadOnlyList<uint> ContinuationRvas,
    IReadOnlyList<uint> IpStateRvas,
    string? Problem)
{
    /// <summary>
    /// FH4 header: the function is split into separated segments (PGO/BBT), whose IP-to-state
    /// maps are keyed by absolute segment RVAs.
    /// </summary>
    public bool IsSeparated { get; init; }

    /// <summary>FH4 header: this FuncInfo belongs to a catch funclet (it carries dispFrame).</summary>
    public bool IsCatch { get; init; }

    /// <summary>FH4 header: the function has a try block map (catch handlers and continuations).</summary>
    public bool HasTryBlocks { get; init; }
}

/// <summary>
/// The parts of an FH4 FuncInfo4 a writer regenerates: its header byte, the unwind and try block
/// map RVAs (0 when absent), and each segment's IP-to-state map as absolute RVAs with states
/// (-1 = no state). A function that is not separated has one segment, starting at its entry.
/// </summary>
public sealed record Fh4Layout(byte Header, uint UnwindMapRva, uint TryBlockMapRva, IReadOnlyList<Fh4Segment> Segments)
{
    public const byte IsCatchFlag = 0x01, IsSeparatedFlag = 0x02, BbtFlag = 0x04, UnwindMapFlag = 0x08, TryBlockMapFlag = 0x10;

    /// <summary>
    /// The state of <paramref name="ip"/> under <paramref name="map"/>, as __CxxFrameHandler4
    /// reads it: the last entry at or below the IP, else -1.
    /// </summary>
    public static int StateAt(IReadOnlyList<(uint Rva, int State)> map, uint ip)
    {
        int state = -1;
        foreach (var (rva, entryState) in map)
        {
            if (ip < rva)
            {
                break;
            }

            state = entryState;
        }

        return state;
    }
}

/// <summary>One FH4 IP-to-state map, keyed by the start its offsets are relative to.</summary>
public sealed record Fh4Segment(uint Start, uint MapRva, IReadOnlyList<(uint Rva, int State)> Map);
