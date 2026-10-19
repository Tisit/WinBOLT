using System.Buffers.Binary;
using System.Text;

namespace WinBolt.Rewrite;

/// <summary>
/// The header fields the writer edits, located in a PE32+ file. Offsets follow
/// IMAGE_NT_HEADERS64; the reader (WinBolt.Pe) has already validated the image.
/// </summary>
internal sealed class PeLayout
{
    public const int SectionHeaderSize = 40;
    public const int ExceptionDirectory = (int)WinBolt.Pe.DataDirectoryIndex.Exception;
    public const int SecurityDirectory = (int)WinBolt.Pe.DataDirectoryIndex.Security;
    public const int BaseRelocationDirectory = (int)WinBolt.Pe.DataDirectoryIndex.BaseRelocation;

    public int NtHeaders { get; }

    public int NumberOfSectionsOffset => NtHeaders + 4 + 2;

    public int OptionalHeader => NtHeaders + 24;

    public int SizeOfCodeOffset => OptionalHeader + 4;

    public int SizeOfImageOffset => OptionalHeader + 56;

    public int SizeOfHeadersOffset => OptionalHeader + 60;

    public int CheckSumOffset => OptionalHeader + 64;

    public int SectionTable { get; }

    public int NumberOfSections { get; }

    public uint SectionAlignment { get; }

    public uint FileAlignment { get; }

    public uint SizeOfHeaders { get; }

    public PeLayout(byte[] file)
    {
        NtHeaders = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(NumberOfSectionsOffset));
        int sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(NtHeaders + 4 + 16));
        SectionTable = OptionalHeader + sizeOfOptionalHeader;
        SectionAlignment = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(OptionalHeader + 32));
        FileAlignment = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(OptionalHeader + 36));
        SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(SizeOfHeadersOffset));
    }

    public int DataDirectory(int index) => OptionalHeader + 112 + index * 8;

    public static uint Align(uint value, uint alignment) => (value + alignment - 1) / alignment * alignment;

    /// <summary>Writes an IMAGE_SECTION_HEADER.</summary>
    public static void WriteSectionHeader(Span<byte> header, string name, uint virtualSize, uint virtualAddress, uint rawSize, uint rawPointer, uint characteristics)
    {
        header.Clear();
        Encoding.ASCII.GetBytes(name).CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], virtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], virtualAddress);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], rawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], rawPointer);
        BinaryPrimitives.WriteUInt32LittleEndian(header[36..], characteristics);
    }
}

/// <summary>The PE image checksum (as computed by imagehlp's CheckSumMappedFile).</summary>
internal static class PeChecksum
{
    public static uint Compute(ReadOnlySpan<byte> file, int checksumOffset)
    {
        ulong sum = 0;
        for (int i = 0; i + 1 < file.Length; i += 2)
        {
            if (i == checksumOffset || i == checksumOffset + 2)
            {
                continue; // the checksum field itself counts as zero
            }

            sum += BinaryPrimitives.ReadUInt16LittleEndian(file[i..]);
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        if (file.Length % 2 == 1)
        {
            sum += file[^1];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint)sum + (uint)file.Length;
    }
}
