using WinBolt.Core.Arch;

namespace WinBolt.Core.Passes;

/// <summary>Shared, per-run state and configuration handed to every pass.</summary>
public sealed class PassContext
{
    public IReadOnlyDictionary<string, string> Options { get; init; } = new Dictionary<string, string>();

    /// <summary>Instruction decoding boundary (§3.2); x64 is the only implementation.</summary>
    public IArchitecture Architecture { get; init; } = new X64Architecture();
}
