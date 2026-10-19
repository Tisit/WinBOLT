using System.Buffers.Binary;
using System.Text;

namespace WinBolt.Pdb;

/// <summary>One OMAP record: [Rva, next record's Rva) maps to RvaTo + (address - Rva); RvaTo = 0 has no counterpart.</summary>
internal readonly record struct OmapEntry(uint Rva, uint RvaTo);

/// <summary>
/// One linker fixup record (DBI debug stream "Fixup", present with /DEBUGTYPE:FIXUP or
/// /PROFILE). The layout is not officially documented; it is 12 bytes: u16 type, u16 flags,
/// u32 site RVA, u32 target RVA. Type meanings are established against the image, not assumed.
/// </summary>
internal readonly record struct FixupRecord(ushort Type, ushort Flags, uint Rva, uint Target);

/// <summary>A DBI section contribution as stored: <see cref="Section"/> is 1-based, like a public symbol's segment.</summary>
internal readonly record struct ContributionRecord(ushort Section, uint Offset, uint Size, uint Characteristics, ushort Module);

/// <summary>A public symbol as stored: <see cref="Segment"/> is a 1-based index into the PDB's section table.</summary>
internal readonly record struct PublicSymbol(string Name, ushort Segment, uint Offset, bool IsFunction);

/// <summary>
/// The parts of a PDB WinBolt uses: identity, public symbols, and what maps the linker's
/// layout to the image's (§3.3). Layouts follow https://llvm.org/docs/PDB/ (PdbStream,
/// DbiStream, PublicStream). Adapted from the sibling project AssemblyOptimizationDetection.
/// </summary>
internal sealed class PdbFile
{
    private const int PdbInfoStream = 1;
    private const int DbiStream = 3;
    private const int DbiHeaderSize = 64;
    private const ushort NilStream = 0xFFFF;
    private const ushort SPub32 = 0x110E;
    private const uint PublicFunctionFlag = 0x2;

    // Index of each u16 stream number in the DBI optional debug header.
    private const int FixupSlot = 2;
    private const int OmapFromSrcSlot = 4;
    private const int SectionHdrSlot = 5;
    private const int SectionHdrOrigSlot = 10;

    // Section contribution substream versions (llvm/DebugInfo/PDB/Native/RawConstants.h).
    private const uint SectionContribVer60 = 0xeffe0000 + 19970605;
    private const uint SectionContribV2 = 0xeffe0000 + 20140516;

    public required Guid Guid { get; init; }

    /// <summary>Age from the PDB info stream.</summary>
    public required uint InfoAge { get; init; }

    /// <summary>Age from the DBI header; the RSDS record's age matches one of the two.</summary>
    public required uint DbiAge { get; init; }

    public required IReadOnlyList<PublicSymbol> Publics { get; init; }

    /// <summary>Original → image addresses. Empty unless a post-link rewriter ran.</summary>
    public required OmapEntry[] OmapFromSrc { get; init; }

    /// <summary>Section contributions in the linker's layout; empty when the substream is absent or of an unknown version.</summary>
    public required ContributionRecord[] Contributions { get; init; }

    /// <summary>Linker fixup records; empty unless the image was linked with fixup debug info.</summary>
    public required FixupRecord[] Fixups { get; init; }

    /// <summary>Virtual addresses of the final section table (DBI SectionHdr stream); may be empty.</summary>
    public required uint[] Sections { get; init; }

    /// <summary>Virtual addresses of the pre-rewrite section table (SectionHdrOrig); empty without OMAP.</summary>
    public required uint[] OriginalSections { get; init; }

    public static PdbFile Read(string path) => Parse(File.ReadAllBytes(path));

    /// <summary>A PDB is untrusted input: any structural inconsistency surfaces as <see cref="PdbFormatException"/>.</summary>
    public static PdbFile Parse(byte[] bytes)
    {
        try
        {
            return ParseCore(bytes);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException or OutOfMemoryException)
        {
            throw new PdbFormatException($"Malformed PDB: {ex.Message}");
        }
    }

    private static PdbFile ParseCore(byte[] bytes)
    {
        var msf = MsfFile.Parse(bytes);

        var info = msf.ReadStream(PdbInfoStream);
        if (info.Length < 28)
        {
            throw new PdbFormatException("PDB info stream is missing or truncated.");
        }

        var dbi = msf.ReadStream(DbiStream);
        if (dbi.Length < DbiHeaderSize)
        {
            throw new PdbFormatException("PDB has no DBI stream.");
        }

        var header = dbi.AsSpan();
        uint dbiAge = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        ushort symbolRecordStream = BinaryPrimitives.ReadUInt16LittleEndian(header[20..]);
        int modInfoSize = ReadI32(header, 24), secContrSize = ReadI32(header, 28), secMapSize = ReadI32(header, 32);
        int srcInfoSize = ReadI32(header, 36), typeServerMapSize = ReadI32(header, 40);
        int optionalDebugHeaderSize = ReadI32(header, 48), ecSize = ReadI32(header, 52);

        // The optional debug header comes after every other substream.
        long debugOffset = (long)DbiHeaderSize + modInfoSize + secContrSize + secMapSize + srcInfoSize + typeServerMapSize + ecSize;
        var debugStreams = new Dictionary<int, int>();
        if (debugOffset >= 0 && debugOffset + optionalDebugHeaderSize <= dbi.Length)
        {
            var slots = header.Slice((int)debugOffset, optionalDebugHeaderSize);
            for (int i = 0; i + 2 <= slots.Length; i += 2)
            {
                ushort stream = BinaryPrimitives.ReadUInt16LittleEndian(slots[i..]);
                if (stream != NilStream && msf.StreamExists(stream))
                {
                    debugStreams[i / 2] = stream;
                }
            }
        }

        byte[] Slot(int slot) => debugStreams.TryGetValue(slot, out int s) ? msf.ReadStream(s) : [];

        return new PdbFile
        {
            Guid = new Guid(info.AsSpan(12, 16)),
            InfoAge = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(8)),
            DbiAge = dbiAge,
            Publics = symbolRecordStream == NilStream ? [] : ReadPublics(msf.ReadStream(symbolRecordStream)),
            OmapFromSrc = ReadOmap(Slot(OmapFromSrcSlot)),
            Fixups = ReadFixups(Slot(FixupSlot)),
            Contributions = DbiHeaderSize + (long)modInfoSize + secContrSize <= dbi.Length && secContrSize >= 4
                ? ReadContributions(header.Slice(DbiHeaderSize + modInfoSize, secContrSize))
                : [],
            Sections = ReadSectionAddresses(Slot(SectionHdrSlot)),
            OriginalSections = ReadSectionAddresses(Slot(SectionHdrOrigSlot)),
        };
    }

    /// <summary>
    /// Image RVA of a PDB address, or null when it has no counterpart in the image. With OMAP,
    /// segments index the pre-rewrite section table and the result goes through
    /// OMAP_FROM_SRC (§3.3). Without it, segments index the final section table.
    /// </summary>
    public uint? ToImageRva(ushort segment, uint offset, IReadOnlyList<uint> imageSections)
    {
        bool rewritten = OmapFromSrc.Length > 0;
        IReadOnlyList<uint> table = rewritten ? OriginalSections : Sections.Length > 0 ? Sections : imageSections;
        if (segment < 1 || segment > table.Count)
        {
            return null;
        }

        uint rva = table[segment - 1] + offset;
        return rewritten ? TranslateOmap(OmapFromSrc, rva) : rva;
    }

    /// <summary>The record covering <paramref name="rva"/> is the last one starting at or below it.</summary>
    internal static uint? TranslateOmap(OmapEntry[] omap, uint rva)
    {
        int lo = 0, hi = omap.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (omap[mid].Rva <= rva)
            {
                found = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return found < 0 || omap[found].RvaTo == 0 ? null : omap[found].RvaTo + (rva - omap[found].Rva);
    }

    /// <summary>
    /// SectionContribEntry: u16 section, u16 pad, i32 offset, i32 size, u32 characteristics,
    /// u16 module, u16 pad, u32 data CRC, u32 reloc CRC (28 bytes); V2 appends u32 COFF section index.
    /// </summary>
    private static ContributionRecord[] ReadContributions(ReadOnlySpan<byte> data)
    {
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(data);
        int size = version switch { SectionContribVer60 => 28, SectionContribV2 => 32, _ => 0 };
        if (size == 0)
        {
            return [];
        }

        var entries = new ContributionRecord[(data.Length - 4) / size];
        for (int i = 0; i < entries.Length; i++)
        {
            var entry = data.Slice(4 + i * size, size);
            entries[i] = new ContributionRecord(
                BinaryPrimitives.ReadUInt16LittleEndian(entry),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[12..]),
                BinaryPrimitives.ReadUInt16LittleEndian(entry[16..]));
        }

        return entries;
    }

    private static FixupRecord[] ReadFixups(byte[] data)
    {
        var fixups = new FixupRecord[data.Length / 12];
        for (int i = 0; i < fixups.Length; i++)
        {
            var record = data.AsSpan(i * 12, 12);
            fixups[i] = new FixupRecord(
                BinaryPrimitives.ReadUInt16LittleEndian(record),
                BinaryPrimitives.ReadUInt16LittleEndian(record[2..]),
                BinaryPrimitives.ReadUInt32LittleEndian(record[4..]),
                BinaryPrimitives.ReadUInt32LittleEndian(record[8..]));
        }

        return fixups;
    }

    private static OmapEntry[] ReadOmap(byte[] data)
    {
        var entries = new OmapEntry[data.Length / 8];
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i] = new OmapEntry(
                BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i * 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i * 8 + 4)));
        }

        return entries;
    }

    /// <summary>IMAGE_SECTION_HEADER array, 40 bytes each; only VirtualAddress (offset 12) is needed.</summary>
    private static uint[] ReadSectionAddresses(byte[] data)
    {
        var addresses = new uint[data.Length / 40];
        for (int i = 0; i < addresses.Length; i++)
        {
            addresses[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i * 40 + 12));
        }

        return addresses;
    }

    /// <summary>S_PUB32 records in the symbol record stream: u32 flags, u32 offset, u16 segment, name.</summary>
    private static List<PublicSymbol> ReadPublics(byte[] data)
    {
        var publics = new List<PublicSymbol>();
        var span = data.AsSpan();
        for (int position = 0; position + 4 <= span.Length;)
        {
            int length = BinaryPrimitives.ReadUInt16LittleEndian(span[position..]);
            ushort kind = BinaryPrimitives.ReadUInt16LittleEndian(span[(position + 2)..]);
            if (length < 2 || position + 2 + length > span.Length)
            {
                break;
            }

            if (kind == SPub32 && length >= 12)
            {
                var record = span.Slice(position + 4, length - 2);
                var name = record[10..];
                int nul = name.IndexOf((byte)0);
                publics.Add(new PublicSymbol(
                    Encoding.UTF8.GetString(nul < 0 ? name : name[..nul]),
                    BinaryPrimitives.ReadUInt16LittleEndian(record[8..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(record[4..]),
                    (BinaryPrimitives.ReadUInt32LittleEndian(record) & PublicFunctionFlag) != 0));
            }

            position += 2 + length;
        }

        return publics;
    }

    private static int ReadI32(ReadOnlySpan<byte> span, int offset) => BinaryPrimitives.ReadInt32LittleEndian(span[offset..]);
}
