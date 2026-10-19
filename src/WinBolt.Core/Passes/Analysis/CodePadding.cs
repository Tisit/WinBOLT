using Iced.Intel;
using WinBolt.Core.Arch;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>Recognizes alignment filler between and inside functions.</summary>
internal static class CodePadding
{
    public static bool IsPaddingByte(byte b) => b is 0xCC or 0x90 or 0x00;

    /// <summary>
    /// True when <paramref name="bytes"/> is entirely int3 / nop / zero bytes, or decodes
    /// entirely as nops and int3 (multi-byte nops from clang and some MSVC alignment).
    /// </summary>
    public static bool IsPadding(IArchitecture architecture, ReadOnlySpan<byte> bytes, uint rva)
    {
        bool allPaddingBytes = true;
        foreach (byte b in bytes)
        {
            if (!IsPaddingByte(b))
            {
                allPaddingBytes = false;
                break;
            }
        }

        if (allPaddingBytes)
        {
            return true;
        }

        var decoder = architecture.CreateDecoder(bytes.ToArray(), rva);
        int decoded = 0;
        while (decoder.TryDecodeNext(out var instruction))
        {
            if (instruction.IsInvalid || instruction.Mnemonic is not (Mnemonic.Nop or Mnemonic.Int3))
            {
                return false;
            }

            decoded += instruction.Length;
        }

        return decoded == bytes.Length;
    }
}
