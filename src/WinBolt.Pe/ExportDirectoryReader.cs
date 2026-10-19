using System.Buffers.Binary;
using System.Text;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Parses IMAGE_EXPORT_DIRECTORY. An export whose RVA falls inside the export directory itself
/// is a forwarder string ("DLL.Function"), not code.
/// </summary>
internal static class ExportDirectoryReader
{
    private const int OffsetBase = 16;
    private const int OffsetNumberOfFunctions = 20;
    private const int OffsetNumberOfNames = 24;
    private const int OffsetAddressOfFunctions = 28;
    private const int OffsetAddressOfNames = 32;
    private const int OffsetAddressOfNameOrdinals = 36;
    private const int DirectorySize = 40;

    // Far above any real export count; bounds work on a corrupt header.
    private const uint MaxEntries = 1 << 20;

    public static List<ExportedSymbol> Read(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory)
    {
        var exports = new List<ExportedSymbol>();
        if (directory.Rva == 0 || directory.Size == 0 ||
            !rvaMapper.TryToFileOffset(directory.Rva, out var dirOffset) || dirOffset + DirectorySize > image.Length)
        {
            return exports;
        }

        uint ordinalBase = ReadU32(image, dirOffset + OffsetBase);
        uint functionCount = ReadU32(image, dirOffset + OffsetNumberOfFunctions);
        uint nameCount = ReadU32(image, dirOffset + OffsetNumberOfNames);
        if (functionCount > MaxEntries || nameCount > MaxEntries)
        {
            return exports;
        }

        if (!TryReadU32Array(image, rvaMapper, ReadU32(image, dirOffset + OffsetAddressOfFunctions), functionCount, out var functions))
        {
            return exports;
        }

        // Names are optional; an unreadable name table degrades to ordinal-only exports.
        var names = new string?[functionCount];
        if (TryReadU32Array(image, rvaMapper, ReadU32(image, dirOffset + OffsetAddressOfNames), nameCount, out var nameRvas) &&
            rvaMapper.TryToFileOffset(ReadU32(image, dirOffset + OffsetAddressOfNameOrdinals), out var ordinalsOffset) &&
            ordinalsOffset + (long)nameCount * 2 <= image.Length)
        {
            for (int i = 0; i < nameCount; i++)
            {
                ushort index = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)ordinalsOffset + i * 2, 2));
                if (index < functionCount)
                {
                    names[index] ??= ReadAsciiZ(image, rvaMapper, nameRvas[i]);
                }
            }
        }

        for (uint i = 0; i < functionCount; i++)
        {
            uint rva = functions[i];
            if (rva == 0)
            {
                continue; // unused ordinal slot
            }

            bool isForwarder = rva >= directory.Rva && rva - directory.Rva < directory.Size;
            exports.Add(isForwarder
                ? new ExportedSymbol(names[i], ordinalBase + i, 0, ReadAsciiZ(image, rvaMapper, rva) ?? string.Empty)
                : new ExportedSymbol(names[i], ordinalBase + i, rva, null));
        }

        return exports;
    }

    private static bool TryReadU32Array(byte[] image, RvaMapper rvaMapper, uint rva, uint count, out uint[] values)
    {
        values = new uint[count];
        if (count == 0)
        {
            return true;
        }

        if (!rvaMapper.TryToFileOffset(rva, out var offset) || offset + (long)count * 4 > image.Length)
        {
            return false;
        }

        for (int i = 0; i < count; i++)
        {
            values[i] = ReadU32(image, offset + (uint)i * 4);
        }

        return true;
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
