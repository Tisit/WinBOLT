using System.Buffers.Binary;

namespace WinBolt.Pdb;

/// <summary>One OMAP record for <see cref="PdbWriter.WithOmap"/>: [Rva, next record's Rva) maps to RvaTo + offset; RvaTo 0 has no counterpart.</summary>
public readonly record struct OmapRecord(uint Rva, uint RvaTo);

/// <summary>
/// Writes the PDB of a rewritten image the way Microsoft's post-link rewriter does (DesignDoc
/// §3.3, §6.2 milestone W4): every stream of the original PDB unchanged, plus OMAP_TO_SRC
/// (new → original addresses), OMAP_FROM_SRC (original → new) and the new section table, with
/// the original section table kept as SectionHdrOrig. Symbols keep their original addresses;
/// debuggers translate them through the OMAP. The PDB gets the image's new GUID and age.
/// </summary>
public static class PdbWriter
{
    private const int PdbInfoStream = 1;
    private const int DbiStream = 3;
    private const int DbiHeaderSize = 64;
    private const int OmapToSrcSlot = 3;
    private const int OmapFromSrcSlot = 4;
    private const int SectionHdrSlot = 5;
    private const int SectionHdrOrigSlot = 10;
    private const int DebugSlots = 11;
    private const ushort NilStream = 0xFFFF;

    /// <param name="sectionHeaders">The rewritten image's IMAGE_SECTION_HEADERs (40 bytes each).</param>
    /// <exception cref="PdbFormatException">The PDB is malformed, or already has OMAP.</exception>
    public static byte[] WithOmap(byte[] pdb, Guid guid, uint age, IReadOnlyList<OmapRecord> toSource, IReadOnlyList<OmapRecord> fromSource, byte[] sectionHeaders)
    {
        var msf = MsfFile.Parse(pdb);
        var streams = new List<byte[]?>();
        for (int i = 0; i < msf.StreamCount; i++)
        {
            streams.Add(msf.StreamExists(i) ? msf.ReadStream(i) : null);
        }

        // Stream 0 is the previous transaction's stream directory: its block numbers mean nothing
        // in a newly laid out file (Microsoft's reader rejects a PDB whose old directory names
        // blocks now in use), so it is written empty, as lld does.
        streams[0] = [];

        var info = streams[PdbInfoStream]!.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(8), age);
        guid.TryWriteBytes(info.AsSpan(12, 16));
        streams[PdbInfoStream] = info;

        var dbi = streams[DbiStream] ?? throw new PdbFormatException("PDB has no DBI stream.");
        var header = dbi.AsSpan();
        int modInfoSize = BinaryPrimitives.ReadInt32LittleEndian(header[24..]), secContrSize = BinaryPrimitives.ReadInt32LittleEndian(header[28..]);
        int secMapSize = BinaryPrimitives.ReadInt32LittleEndian(header[32..]), srcInfoSize = BinaryPrimitives.ReadInt32LittleEndian(header[36..]);
        int typeServerMapSize = BinaryPrimitives.ReadInt32LittleEndian(header[40..]), optionalSize = BinaryPrimitives.ReadInt32LittleEndian(header[48..]);
        int ecSize = BinaryPrimitives.ReadInt32LittleEndian(header[52..]);
        int debugOffset = DbiHeaderSize + modInfoSize + secContrSize + secMapSize + srcInfoSize + typeServerMapSize + ecSize;
        if (debugOffset + optionalSize != dbi.Length)
        {
            throw new PdbFormatException("the DBI optional debug header is not the stream's last substream");
        }

        var slots = new ushort[Math.Max(DebugSlots, optionalSize / 2)];
        Array.Fill(slots, NilStream);
        for (int i = 0; i < optionalSize / 2; i++)
        {
            slots[i] = BinaryPrimitives.ReadUInt16LittleEndian(header[(debugOffset + i * 2)..]);
        }

        if (slots[OmapToSrcSlot] != NilStream || slots[OmapFromSrcSlot] != NilStream)
        {
            throw new PdbFormatException("the PDB already has OMAP: the image was rewritten before");
        }

        ushort Add(byte[] stream)
        {
            streams.Add(stream);
            return (ushort)(streams.Count - 1);
        }

        slots[SectionHdrOrigSlot] = slots[SectionHdrSlot];
        slots[SectionHdrSlot] = Add(sectionHeaders);
        slots[OmapToSrcSlot] = Add(Omap(toSource));
        slots[OmapFromSrcSlot] = Add(Omap(fromSource));

        var newDbi = new byte[debugOffset + slots.Length * 2];
        dbi.AsSpan(0, debugOffset).CopyTo(newDbi);
        BinaryPrimitives.WriteUInt32LittleEndian(newDbi.AsSpan(8), age);
        BinaryPrimitives.WriteInt32LittleEndian(newDbi.AsSpan(48), slots.Length * 2);
        for (int i = 0; i < slots.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(newDbi.AsSpan(debugOffset + i * 2), slots[i]);
        }

        streams[DbiStream] = newDbi;
        return MsfWriter.Write(msf.BlockSize, streams);
    }

    private static byte[] Omap(IReadOnlyList<OmapRecord> records)
    {
        var bytes = new byte[records.Count * 8];
        for (int i = 0; i < records.Count; i++)
        {
            if (i > 0 && records[i].Rva <= records[i - 1].Rva)
            {
                throw new ArgumentException($"OMAP records must ascend (0x{records[i].Rva:X} after 0x{records[i - 1].Rva:X})");
            }

            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * 8), records[i].Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * 8 + 4), records[i].RvaTo);
        }

        return bytes;
    }
}
