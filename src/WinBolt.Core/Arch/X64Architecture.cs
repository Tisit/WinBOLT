using System.Runtime.InteropServices;
using Iced.Intel;

namespace WinBolt.Core.Arch;

/// <summary>The only <see cref="IArchitecture"/> implementation (§3.2, §3.3 — built on iced).</summary>
public sealed class X64Architecture : IArchitecture
{
    public string Name => "x64";

    public int BitWidth => 64;

    public IInstructionDecoder CreateDecoder(ReadOnlyMemory<byte> code, ulong startRva) =>
        new X64InstructionDecoder(code, startRva);
}

internal sealed class X64InstructionDecoder : IInstructionDecoder
{
    private readonly Decoder _decoder;
    private readonly ulong _endRva;

    public X64InstructionDecoder(ReadOnlyMemory<byte> code, ulong startRva)
    {
        // Wrap the caller's array rather than copying: discovery creates one decoder per
        // range, and a copy of the rest of the section each time would be quadratic.
        var reader = MemoryMarshal.TryGetArray(code, out var segment)
            ? new ByteArrayCodeReader(segment)
            : new ByteArrayCodeReader(code.ToArray());
        _decoder = Decoder.Create(64, reader, DecoderOptions.None);
        _decoder.IP = startRva;
        _endRva = startRva + (ulong)code.Length;
    }

    public bool TryDecodeNext(out Instruction instruction)
    {
        if (_decoder.IP >= _endRva)
        {
            instruction = default;
            return false;
        }

        instruction = _decoder.Decode();
        return true;
    }
}
