using Iced.Intel;

namespace WinBolt.Core.Arch;

/// <summary>
/// Instruction and register abstraction boundary (§3.2). x64 is the only implementation,
/// but the boundary is established now: retrofitting it through code that assumed x64
/// everywhere would be far more expensive than maintaining this thin interface.
/// </summary>
public interface IArchitecture
{
    string Name { get; }

    int BitWidth { get; }

    /// <summary>Creates a decoder over <paramref name="code"/>, whose first byte is at <paramref name="startRva"/>.</summary>
    IInstructionDecoder CreateDecoder(ReadOnlyMemory<byte> code, ulong startRva);
}

/// <summary>Sequential instruction decoder over a code buffer.</summary>
public interface IInstructionDecoder
{
    /// <summary>Decodes the next instruction. Returns false when the buffer is exhausted.</summary>
    bool TryDecodeNext(out Instruction instruction);
}
