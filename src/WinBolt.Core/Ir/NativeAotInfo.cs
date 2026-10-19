namespace WinBolt.Core.Ir;

/// <summary>Where <see cref="NativeAotInfo"/>'s managed-code range came from.</summary>
public enum ManagedRangeSource
{
    /// <summary><c>__managedcode_a</c> / <c>__managedcode_z</c> from a matching PDB.</summary>
    PdbSymbols,

    /// <summary>The two <c>lea</c>s native startup code passes to <c>RhRegisterOSModule</c>.</summary>
    RegistrationCall,

    /// <summary>Not found: every .pdata function is treated as possibly managed.</summary>
    Unknown,
}

/// <summary>
/// A .NET NativeAOT image (DesignDoc R5, "NativeAOT survey"), recognized by its
/// <c>DotNetRuntimeDebugHeader</c> export. Managed methods' UNWIND_INFO is followed by runtime data
/// (UnwindBlockFlags, EH-info and associated-data RVAs, GC info) keyed by offsets from the method
/// start, the runtime registers one managed-code range, and funclets sit at fixed offsets from their
/// parent: no rewriter may touch such an image.
/// </summary>
/// <param name="ManagedStart">Start of the registered managed-code range; 0 when <see cref="Source"/> is Unknown.</param>
/// <param name="ManagedEnd">End (exclusive) of the range; 0 when <see cref="Source"/> is Unknown.</param>
/// <param name="Evidence">Where the range came from, for reports.</param>
public sealed record NativeAotInfo(ManagedRangeSource Source, uint ManagedStart, uint ManagedEnd, string Evidence)
{
    /// <summary>Functions downgraded as (possibly) managed.</summary>
    public int ManagedFunctions { get; set; }

    /// <summary>Managed functions that are funclets (UnwindBlockFlags kind handler or filter) or parents of one.</summary>
    public int FuncletFunctions { get; set; }

    /// <summary>True when <paramref name="rva"/> may be managed code.</summary>
    public bool IsManaged(uint rva) => Source == ManagedRangeSource.Unknown || (rva >= ManagedStart && rva < ManagedEnd);
}
