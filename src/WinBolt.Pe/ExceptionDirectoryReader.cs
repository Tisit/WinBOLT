using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Parses .pdata (the RUNTIME_FUNCTION table) and follows UNW_FLAG_CHAININFO links to
/// parent entries (§5.1) by reading each entry's UNWIND_INFO header directly.
/// </summary>
internal static class ExceptionDirectoryReader
{
    private const int RuntimeFunctionSize = 12;
    private const uint UnwFlagChainInfo = 0x4;

    public static List<ExceptionInfo> Read(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory)
    {
        var entries = new List<ExceptionInfo>();
        if (directory.Rva == 0 || directory.Size == 0)
        {
            return entries;
        }

        if (!rvaMapper.TryToFileOffset(directory.Rva, out var fileOffset))
        {
            return entries;
        }

        int count = (int)(directory.Size / RuntimeFunctionSize);
        var byBegin = new Dictionary<uint, ExceptionInfo>(count);

        for (int i = 0; i < count; i++)
        {
            int o = (int)fileOffset + i * RuntimeFunctionSize;
            if (o + RuntimeFunctionSize > image.Length)
            {
                break;
            }

            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(o, 4));
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(o + 4, 4));
            uint unwindInfoAddress = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(o + 8, 4));

            bool isChained = IsIndirect(unwindInfoAddress) || TryReadChainFlag(image, rvaMapper, unwindInfoAddress);
            uint handlerRva = 0;
            if (!isChained)
            {
                TryReadHandler(image, rvaMapper, unwindInfoAddress, out handlerRva);
            }

            var info = new ExceptionInfo
            {
                BeginAddress = begin,
                EndAddress = end,
                UnwindInfoAddress = unwindInfoAddress,
                IsChained = isChained,
                HandlerRva = handlerRva,
                HandlerDataRva = handlerRva != 0 ? unwindInfoAddress + (uint)TrailerOffset(image, rvaMapper, unwindInfoAddress) + 4 : 0,
            };

            entries.Add(info);

            // Multiple RUNTIME_FUNCTION entries legitimately share a BeginAddress under
            // some COMDAT-folding scenarios; last one wins for chain-parent lookup, which
            // is an acceptable approximation.
            byBegin[begin] = info;
        }

        foreach (var info in entries)
        {
            if (!info.IsChained)
            {
                continue;
            }

            if (TryReadChainedParentBegin(image, rvaMapper, info.UnwindInfoAddress, out var parentBegin) &&
                byBegin.TryGetValue(parentBegin, out var parent))
            {
                info.ChainedParent = parent;
            }
        }

        return entries;
    }

    /// <summary>
    /// Indirect form: when the low bit of UnwindData is set, the field is the RVA of another
    /// RUNTIME_FUNCTION (the parent) rather than of an UNWIND_INFO. Post-link rewriters such
    /// as BBT use it; reading it as UNWIND_INFO yields garbage flags.
    /// </summary>
    private static bool IsIndirect(uint unwindData) => (unwindData & 1) != 0;

    private const uint UnwFlagHandlerMask = 0x3; // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER

    /// <summary>The UNW_FLAG_* bits of an UNWIND_INFO's first byte (the low three bits are the version).</summary>
    private static uint Flags(byte versionAndFlags) => (uint)(versionAndFlags >> 3) & 0x1F;

    /// <summary>
    /// Offset from the UNWIND_INFO start to what follows the unwind codes: the handler RVA, or
    /// (with UNW_FLAG_CHAININFO) the parent RUNTIME_FUNCTION. Codes are padded to an even count.
    /// </summary>
    private static int TrailerOffset(byte[] image, RvaMapper rvaMapper, uint unwindInfoRva)
    {
        if (!rvaMapper.TryToFileOffset(unwindInfoRva, out var fileOffset) || fileOffset + 4 > image.Length)
        {
            return -1;
        }

        byte countOfCodes = image[fileOffset + 2];
        return 4 + ((countOfCodes + 1) & ~1) * 2;
    }

    private static bool TryReadHandler(byte[] image, RvaMapper rvaMapper, uint unwindInfoRva, out uint handlerRva)
    {
        handlerRva = 0;
        if (!rvaMapper.TryToFileOffset(unwindInfoRva, out var fileOffset) || fileOffset >= image.Length)
        {
            return false;
        }

        uint flags = Flags(image[fileOffset]);
        int trailer = TrailerOffset(image, rvaMapper, unwindInfoRva);
        if ((flags & UnwFlagHandlerMask) == 0 || trailer < 0 || fileOffset + trailer + 4 > image.Length)
        {
            return false;
        }

        handlerRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)(fileOffset + trailer), 4));
        return handlerRva != 0;
    }

    private static bool TryReadChainFlag(byte[] image, RvaMapper rvaMapper, uint unwindInfoRva)
    {
        if (!rvaMapper.TryToFileOffset(unwindInfoRva, out var fileOffset) || fileOffset >= image.Length)
        {
            return false;
        }

        return (Flags(image[fileOffset]) & UnwFlagChainInfo) != 0;
    }

    /// <summary>
    /// UNWIND_INFO layout: 4-byte header (VersionAndFlags, SizeOfProlog, CountOfCodes,
    /// FrameRegisterAndOffset), then CountOfCodes UNWIND_CODE entries (2 bytes each,
    /// padded to a 4-byte boundary), then — because UNW_FLAG_CHAININFO is set — the
    /// parent's RUNTIME_FUNCTION triple in place of an exception handler RVA.
    /// </summary>
    private static bool TryReadChainedParentBegin(byte[] image, RvaMapper rvaMapper, uint unwindInfoRva, out uint parentBeginAddress)
    {
        parentBeginAddress = 0;

        if (IsIndirect(unwindInfoRva))
        {
            if (!rvaMapper.TryToFileOffset(unwindInfoRva & ~1u, out var parentOffset) || parentOffset + 4 > image.Length)
            {
                return false;
            }

            parentBeginAddress = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)parentOffset, 4));
            return true;
        }

        int trailer = TrailerOffset(image, rvaMapper, unwindInfoRva);
        if (trailer < 0 || !rvaMapper.TryToFileOffset(unwindInfoRva, out var fileOffset))
        {
            return false;
        }

        long chainOffset = fileOffset + trailer;

        if (chainOffset + 4 > image.Length)
        {
            return false;
        }

        parentBeginAddress = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)chainOffset, 4));
        return true;
    }
}
