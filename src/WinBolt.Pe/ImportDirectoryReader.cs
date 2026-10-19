using System.Buffers.Binary;
using System.Text;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Parses IMAGE_IMPORT_DESCRIPTOR entries and their 64-bit thunks. Names come from the
/// OriginalFirstThunk (lookup table) when present, since the IAT itself may be pre-bound.
/// </summary>
internal static class ImportDirectoryReader
{
    private const int DescriptorSize = 20;
    private const ulong OrdinalFlag = 0x8000000000000000;

    // Bounds work on corrupt tables; real images stay far below these.
    private const int MaxDescriptors = 4096;
    private const int MaxThunksPerDll = 1 << 16;

    public static List<ImportedSymbol> Read(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory)
    {
        var imports = new List<ImportedSymbol>();
        if (directory.Rva == 0 || directory.Size == 0)
        {
            return imports;
        }

        for (int d = 0; d < MaxDescriptors; d++)
        {
            uint descriptorRva = directory.Rva + (uint)(d * DescriptorSize);
            if (!rvaMapper.TryToFileOffset(descriptorRva, out var o) || o + DescriptorSize > image.Length)
            {
                break;
            }

            uint lookupTable = ReadU32(image, o);
            uint nameRva = ReadU32(image, o + 12);
            uint firstThunk = ReadU32(image, o + 16);
            if (nameRva == 0 && firstThunk == 0)
            {
                break; // null terminator descriptor
            }

            string dll = ReadAsciiZ(image, rvaMapper, nameRva) ?? string.Empty;
            uint namesFrom = lookupTable != 0 ? lookupTable : firstThunk;
            for (int i = 0; i < MaxThunksPerDll; i++)
            {
                if (!rvaMapper.TryToFileOffset(namesFrom + (uint)(i * 8), out var t) || t + 8 > image.Length)
                {
                    break;
                }

                ulong thunk = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)t, 8));
                if (thunk == 0)
                {
                    break;
                }

                uint slot = firstThunk + (uint)(i * 8);
                imports.Add((thunk & OrdinalFlag) != 0
                    ? new ImportedSymbol(dll, null, (ushort)thunk, slot)
                    : new ImportedSymbol(dll, ReadAsciiZ(image, rvaMapper, (uint)thunk + 2), null, slot)); // skip the u16 hint
            }
        }

        return imports;
    }

    private static string? ReadAsciiZ(byte[] image, RvaMapper rvaMapper, uint rva)
    {
        if (!rvaMapper.TryToFileOffset(rva, out var offset) || offset >= image.Length)
        {
            return null;
        }

        var span = image.AsSpan((int)offset);
        int length = span.IndexOf((byte)0);
        return length < 0 ? null : Encoding.ASCII.GetString(span[..length]);
    }

    private static uint ReadU32(byte[] image, uint offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)offset, 4));
}
