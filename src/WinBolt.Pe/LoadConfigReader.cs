using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Parses the load config directory / CFGuard tables (§5.4). Field offsets follow
/// IMAGE_LOAD_CONFIG_DIRECTORY64. The struct has grown across SDK versions, so every
/// optional field is gated on the directory's own <c>Size</c> against that field's offset
/// — an older binary's directory may legitimately be shorter than the fields below, and
/// that must degrade cleanly rather than read garbage or throw.
/// </summary>
internal static class LoadConfigReader
{
    private const int OffsetSize = 0x00;
    private const int OffsetGuardCfFunctionTable = 0x80;
    private const int OffsetGuardCfFunctionCount = 0x88;
    private const int OffsetGuardFlags = 0x90;
    private const int OffsetGuardAddressTakenIatEntryTable = 0xA0;
    private const int OffsetGuardAddressTakenIatEntryCount = 0xA8;
    private const int OffsetGuardLongJumpTargetTable = 0xB0;
    private const int OffsetGuardLongJumpTargetCount = 0xB8;
    private const int OffsetGuardEhContinuationTable = 0x108;
    private const int OffsetGuardEhContinuationCount = 0x110;

    private const uint GuardCfInstrumented = 0x00000100;
    private const ushort DllCharacteristicsGuardCf = 0x4000; // IMAGE_DLLCHARACTERISTICS_GUARD_CF
    private const uint GuardCfFunctionTableSizeMask = 0xF0000000;
    private const int GuardCfFunctionTableSizeShift = 28;
    private const uint GuardXfgEnabled = 0x00800000;

    /// <param name="dllCharacteristics">
    /// The optional header's DllCharacteristics. CFG is enforced only when its GUARD_CF bit is
    /// set: a load config can carry CF_INSTRUMENTED just because some linked objects (the
    /// static CRT, typically) were compiled with /guard:cf, in an image the loader does not
    /// treat as CFG-enabled.
    /// </param>
    public static LoadConfigTables? Read(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory, ulong imageBase, ushort dllCharacteristics)
    {
        if (directory.Rva == 0 || directory.Size == 0)
        {
            return null;
        }

        if (!rvaMapper.TryToFileOffset(directory.Rva, out var baseOffset))
        {
            return null;
        }

        if (baseOffset + 4 > image.Length)
        {
            return null;
        }

        uint size = ReadU32(image, baseOffset, OffsetSize);
        if (size < 0x94) // smaller than the pre-CFGuard-era struct; nothing to recover
        {
            return new LoadConfigTables { HasCfg = false };
        }

        uint guardFlags = HasField(size, OffsetGuardFlags) ? ReadU32(image, baseOffset, OffsetGuardFlags) : 0;
        bool instrumented = (guardFlags & GuardCfInstrumented) != 0;
        bool hasCfg = instrumented && (dllCharacteristics & DllCharacteristicsGuardCf) != 0;

        var tables = new LoadConfigTables
        {
            HasCfg = hasCfg,
            HasXfg = hasCfg && (guardFlags & GuardXfgEnabled) != 0,
        };

        // Read the function table whenever one is present: even unenforced, it lists
        // address-taken functions the compiler knew about.
        if (instrumented && HasField(size, OffsetGuardCfFunctionCount))
        {
            int entryStride = 4 + (int)((guardFlags & GuardCfFunctionTableSizeMask) >> GuardCfFunctionTableSizeShift);
            ReadRvaTable(
                image, rvaMapper, imageBase,
                ReadU64(image, baseOffset, OffsetGuardCfFunctionTable),
                ReadU64(image, baseOffset, OffsetGuardCfFunctionCount),
                entryStride, tables.GuardCfFunctionTable);
        }

        if (HasField(size, OffsetGuardAddressTakenIatEntryCount))
        {
            ReadRvaTable(
                image, rvaMapper, imageBase,
                ReadU64(image, baseOffset, OffsetGuardAddressTakenIatEntryTable),
                ReadU64(image, baseOffset, OffsetGuardAddressTakenIatEntryCount),
                4, tables.GuardAddressTakenIatEntryTable);
        }

        if (HasField(size, OffsetGuardLongJumpTargetCount))
        {
            ReadRvaTable(
                image, rvaMapper, imageBase,
                ReadU64(image, baseOffset, OffsetGuardLongJumpTargetTable),
                ReadU64(image, baseOffset, OffsetGuardLongJumpTargetCount),
                4, tables.GuardLongJumpTargetTable);
        }

        if (HasField(size, OffsetGuardEhContinuationCount))
        {
            ulong ehTableVa = ReadU64(image, baseOffset, OffsetGuardEhContinuationTable);
            if (ehTableVa != 0)
            {
                var ehContinuationTable = new List<uint>();
                ReadRvaTable(
                    image, rvaMapper, imageBase,
                    ehTableVa,
                    ReadU64(image, baseOffset, OffsetGuardEhContinuationCount),
                    4, ehContinuationTable);
                tables.GuardEhContinuationTable = ehContinuationTable;
            }
        }

        return tables;
    }

    /// <summary>Conservative check: true only if the directory is large enough to fully contain an 8-byte field starting at <paramref name="fieldOffset"/>.</summary>
    private static bool HasField(uint directorySize, int fieldOffset) =>
        directorySize >= fieldOffset + 8;

    /// <summary>
    /// GuardCFFunctionTable and its siblings store an absolute VA (ImageBase + RVA) to the
    /// table's own location. The RVAs inside the table are plain, unrelocated RVAs — that
    /// is precisely why MSVC picked this encoding for switch tables too (§5.2).
    /// </summary>
    private static void ReadRvaTable(
        byte[] image, RvaMapper rvaMapper, ulong imageBase,
        ulong tableVa, ulong count, int entryStride, List<uint> destination)
    {
        if (tableVa == 0 || count == 0 || tableVa < imageBase)
        {
            return;
        }

        uint tableRva = (uint)(tableVa - imageBase);
        if (!rvaMapper.TryToFileOffset(tableRva, out var fileOffset))
        {
            return;
        }

        for (ulong i = 0; i < count; i++)
        {
            long entryOffset = fileOffset + (long)i * entryStride;
            if (entryOffset + 4 > image.Length)
            {
                break;
            }

            destination.Add(BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)entryOffset, 4)));
        }
    }

    private static uint ReadU32(byte[] image, uint baseOffset, int fieldOffset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)baseOffset + fieldOffset, 4));

    private static ulong ReadU64(byte[] image, uint baseOffset, int fieldOffset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)baseOffset + fieldOffset, 8));
}
