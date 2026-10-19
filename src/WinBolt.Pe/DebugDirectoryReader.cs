using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Parses the debug directory (an array of 28-byte IMAGE_DEBUG_DIRECTORY entries) and
/// decodes the POGO entry when present. Input to layout provenance (Stage 1).
/// </summary>
internal static class DebugDirectoryReader
{
    private const int EntrySize = 28;

    public static (List<DebugDirectoryEntry> Entries, PogoInfo? Pogo, CodeViewInfo? CodeView) Read(
        byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory)
    {
        var entries = new List<DebugDirectoryEntry>();
        if (directory.Rva == 0 || directory.Size == 0 || !rvaMapper.TryToFileOffset(directory.Rva, out var baseOffset))
        {
            return (entries, null, null);
        }

        PogoInfo? pogo = null;
        CodeViewInfo? codeView = null;
        int count = (int)(directory.Size / EntrySize);
        for (int i = 0; i < count; i++)
        {
            long o = baseOffset + (long)i * EntrySize;
            if (o + EntrySize > image.Length)
            {
                break;
            }

            var span = image.AsSpan((int)o, EntrySize);
            var entry = new DebugDirectoryEntry(
                Type: BinaryPrimitives.ReadUInt32LittleEndian(span[12..]),
                SizeOfData: BinaryPrimitives.ReadUInt32LittleEndian(span[16..]),
                AddressOfRawData: BinaryPrimitives.ReadUInt32LittleEndian(span[20..]),
                PointerToRawData: BinaryPrimitives.ReadUInt32LittleEndian(span[24..]));
            entries.Add(entry);

            // PointerToRawData is a file offset; debug data need not be mapped at all.
            if (entry.Type == DebugDirectoryType.Pogo && pogo is null &&
                entry.PointerToRawData > 0 && (long)entry.PointerToRawData + entry.SizeOfData <= image.Length)
            {
                pogo = PogoParser.Parse(image.AsSpan((int)entry.PointerToRawData, (int)entry.SizeOfData));
            }

            if (entry.Type == DebugDirectoryType.CodeView && codeView is null &&
                entry.PointerToRawData > 0 && (long)entry.PointerToRawData + entry.SizeOfData <= image.Length)
            {
                codeView = ParseRsds(image.AsSpan((int)entry.PointerToRawData, (int)entry.SizeOfData));
            }
        }

        return (entries, pogo, codeView);
    }

    /// <summary>"RSDS", GUID, u32 age, NUL-terminated UTF-8 PDB path. Older NB10 records carry no GUID.</summary>
    private static CodeViewInfo? ParseRsds(ReadOnlySpan<byte> data)
    {
        if (data.Length < 25 || !data[..4].SequenceEqual("RSDS"u8))
        {
            return null;
        }

        var pathBytes = data[24..];
        int nul = pathBytes.IndexOf((byte)0);
        return new CodeViewInfo(
            new Guid(data.Slice(4, 16)),
            BinaryPrimitives.ReadUInt32LittleEndian(data[20..]),
            System.Text.Encoding.UTF8.GetString(nul < 0 ? pathBytes : pathBytes[..nul]));
    }
}
