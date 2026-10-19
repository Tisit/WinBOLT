using System.Buffers.Binary;
using System.Text;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Purpose-built PE32+ reader (§3.3). <c>System.Reflection.PortableExecutable.PEReader</c>
/// is deliberately not used as the production path here: it targets managed images and
/// does not expose the load config directory, .pdata/.xdata, CFGuard tables, or the base
/// relocation table, all of which this project depends on.
/// </summary>
public static class PeImageReader
{
    private const ushort DosSignature = 0x5A4D; // "MZ"
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const ushort ImageFileMachineAmd64 = 0x8664;
    private const ushort Pe32PlusMagic = 0x20B;

    public static BinaryImage Read(string filePath)
    {
        // A full in-memory read is the baseline; System.IO.Pipelines is flagged
        // in §3.3 as an optional future improvement for bulk I/O on very large images.
        byte[] bytes = File.ReadAllBytes(filePath);
        return Parse(filePath, bytes);
    }

    /// <summary>Parses an image already in memory, e.g. a rewritten image before it is written out.</summary>
    public static BinaryImage Read(string filePath, byte[] bytes) => Parse(filePath, bytes);

    private static BinaryImage Parse(string filePath, byte[] bytes)
    {
        if (bytes.Length < 0x40 || ReadU16(bytes, 0) != DosSignature)
        {
            throw new PeFormatException("Missing DOS 'MZ' signature.");
        }

        int peHeaderOffset = ReadI32(bytes, 0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 4 > bytes.Length)
        {
            throw new PeFormatException("Invalid e_lfanew.");
        }

        if (ReadU32(bytes, peHeaderOffset) != PeSignature)
        {
            throw new PeFormatException("Missing PE signature.");
        }

        int fileHeaderOffset = peHeaderOffset + 4;
        ushort machine = ReadU16(bytes, fileHeaderOffset + 0);
        ushort numberOfSections = ReadU16(bytes, fileHeaderOffset + 2);
        uint timeDateStamp = ReadU32(bytes, fileHeaderOffset + 4);
        ushort sizeOfOptionalHeader = ReadU16(bytes, fileHeaderOffset + 16);

        if (machine != ImageFileMachineAmd64)
        {
            throw new PeFormatException(
                $"Unsupported machine type 0x{machine:X4}; only x64 (PE32+) is in scope for release 1.0 (§2.2, §3.2).");
        }

        int optionalHeaderOffset = fileHeaderOffset + 20;
        ushort magic = ReadU16(bytes, optionalHeaderOffset);
        if (magic != Pe32PlusMagic)
        {
            throw new PeFormatException("Not a PE32+ (x64) image; PE32 (x86) is out of scope (§2.2).");
        }

        uint entryPointRva = ReadU32(bytes, optionalHeaderOffset + 16);
        uint checksum = ReadU32(bytes, optionalHeaderOffset + 64);
        ushort dllCharacteristics = ReadU16(bytes, optionalHeaderOffset + 70);
        ulong imageBase = ReadU64(bytes, optionalHeaderOffset + 24);
        uint sizeOfImage = ReadU32(bytes, optionalHeaderOffset + 56);
        ushort numberOfRvaAndSizes = ReadU16(bytes, optionalHeaderOffset + 108);

        int dataDirectoryOffset = optionalHeaderOffset + 112;
        var dataDirectories = new (uint Rva, uint Size)[16];
        for (int i = 0; i < 16 && i < numberOfRvaAndSizes; i++)
        {
            int o = dataDirectoryOffset + i * 8;
            if (o + 8 > bytes.Length)
            {
                break;
            }

            dataDirectories[i] = (ReadU32(bytes, o), ReadU32(bytes, o + 4));
        }

        int sectionHeaderOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        var sections = new List<Section>(numberOfSections);
        for (int i = 0; i < numberOfSections; i++)
        {
            int o = sectionHeaderOffset + i * 40;
            if (o + 40 > bytes.Length)
            {
                throw new PeFormatException("Section table extends past end of file.");
            }

            uint virtualSize = ReadU32(bytes, o + 8);
            uint rawSize = ReadU32(bytes, o + 16);
            uint fileOffset = ReadU32(bytes, o + 20);
            sections.Add(new Section
            {
                Name = ReadSectionName(bytes, o),
                VirtualSize = virtualSize,
                Rva = ReadU32(bytes, o + 12),
                RawSize = rawSize,
                FileOffset = fileOffset,
                Characteristics = ReadU32(bytes, o + 36),
                Data = SectionData(bytes, fileOffset, rawSize, virtualSize),
            });
        }

        var image = new BinaryImage
        {
            FilePath = filePath,
            ImageBase = imageBase,
            SizeOfImage = sizeOfImage,
            TimeDateStamp = timeDateStamp,
            Checksum = checksum,
            EntryPointRva = entryPointRva,
            DllCharacteristics = dllCharacteristics,
        };

        image.Sections.AddRange(sections);

        for (int i = 0; i < dataDirectories.Length; i++)
        {
            var (rva, size) = dataDirectories[i];
            if (rva != 0 && size != 0 && i != (int)DataDirectoryIndex.Security)
            {
                image.DataDirectories.Add(new DataDirectory(((DataDirectoryIndex)i).ToString(), rva, size));
            }
        }

        var rvaMapper = new RvaMapper(sections);

        image.ExceptionData.AddRange(
            ExceptionDirectoryReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.Exception]));

        image.Relocations.AddRange(
            BaseRelocationReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.BaseRelocation]));

        image.LoadConfig =
            LoadConfigReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.LoadConfig], imageBase, dllCharacteristics);

        var (debugEntries, pogo, codeView) =
            DebugDirectoryReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.Debug]);
        image.DebugEntries.AddRange(debugEntries);
        image.Pogo = pogo;
        image.CodeView = codeView;

        image.Exports.AddRange(
            ExportDirectoryReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.Export]));

        image.Imports.AddRange(
            ImportDirectoryReader.Read(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.Import]));

        image.TlsCallbacks.AddRange(
            TlsDirectoryReader.ReadCallbacks(bytes, rvaMapper, dataDirectories[(int)DataDirectoryIndex.Tls], imageBase));

        return image;
    }

    /// <summary>
    /// The file-backed part of a section. Raw data is file-aligned and may run past the
    /// mapped size; those trailing bytes are not loaded, so they are cut off here.
    /// </summary>
    private static ReadOnlyMemory<byte> SectionData(byte[] bytes, uint fileOffset, uint rawSize, uint virtualSize)
    {
        if (rawSize == 0 || fileOffset >= bytes.Length)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        long length = Math.Min(rawSize, (long)bytes.Length - fileOffset);
        if (virtualSize != 0)
        {
            length = Math.Min(length, virtualSize);
        }

        return bytes.AsMemory((int)fileOffset, (int)length);
    }

    private static string ReadSectionName(byte[] bytes, int offset)
    {
        int length = 0;
        while (length < 8 && bytes[offset + length] != 0)
        {
            length++;
        }

        return Encoding.ASCII.GetString(bytes, offset, length);
    }

    private static ushort ReadU16(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));

    private static uint ReadU32(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));

    private static ulong ReadU64(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));

    private static int ReadI32(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
}
