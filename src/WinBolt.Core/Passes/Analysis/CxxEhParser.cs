using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes.Analysis;

/// <summary>
/// Reads the code addresses out of MSVC x64 C++ EH tables (§5.2). Only what matters for code
/// motion is kept: funclet and destructor entries, catch continuations, and IP-to-state map
/// addresses. States, type descriptors and frame offsets are skipped.
/// <para>
/// Nothing here is trusted on its own: CFG construction and the safety gate check every
/// address against the functions discovery found. A misread table shows up as addresses that
/// do not fit and freezes the function, rather than proceeding.
/// </para>
/// </summary>
public static class CxxEhParser
{
    // Real tables are far smaller; these bound work on corrupt data.
    private const uint MaxEntries = 1 << 16;

    /// <summary>
    /// FuncInfo (FH3), fixed layout: magic (low 29 bits: 0x19930520..22), maxState,
    /// dispUnwindMap, nTryBlocks, dispTryBlockMap, nIPMapEntries, dispIPToStateMap, ...
    /// UnwindMapEntry { toState, action } 8 bytes; TryBlockMapEntry { tryLow, tryHigh, catchHigh,
    /// nCatches, dispHandlerArray } 20 bytes; HandlerType { adjectives, dispType, dispCatchObj,
    /// dispOfHandler, dispFrame } 20 bytes; IptoStateMapEntry { Ip, State } 8 bytes. All disp*
    /// are image RVAs.
    /// </summary>
    public static CxxEhInfo ParseFh3(BinaryImage image, uint funcInfoRva)
    {
        var funclets = new List<uint>();
        var ipStates = new List<uint>();
        try
        {
            uint magic = U32(image, funcInfoRva) & 0x1FFFFFFF;
            if (magic is < 0x19930520 or > 0x19930522)
            {
                return new CxxEhInfo(funcInfoRva, 3, funclets, [], ipStates, $"bad FuncInfo magic 0x{magic:X}");
            }

            uint maxState = Count(U32(image, funcInfoRva + 4));
            uint unwindMap = U32(image, funcInfoRva + 8);
            uint tryBlocks = Count(U32(image, funcInfoRva + 12));
            uint tryBlockMap = U32(image, funcInfoRva + 16);
            uint ipEntries = Count(U32(image, funcInfoRva + 20));
            uint ipMap = U32(image, funcInfoRva + 24);

            for (uint i = 0; i < maxState; i++)
            {
                AddNonZero(funclets, U32(image, unwindMap + i * 8 + 4));
            }

            for (uint i = 0; i < tryBlocks; i++)
            {
                uint entry = tryBlockMap + i * 20;
                uint catches = Count(U32(image, entry + 12));
                uint handlers = U32(image, entry + 16);
                for (uint j = 0; j < catches; j++)
                {
                    AddNonZero(funclets, U32(image, handlers + j * 20 + 12));
                }
            }

            for (uint i = 0; i < ipEntries; i++)
            {
                ipStates.Add(U32(image, ipMap + i * 8));
            }

            return new CxxEhInfo(funcInfoRva, 3, funclets, [], ipStates, null);
        }
        catch (TableException ex)
        {
            return new CxxEhInfo(funcInfoRva, 3, funclets, [], ipStates, ex.Message);
        }
    }

    /// <summary>
    /// FuncInfo4 (FH4), compressed. Header byte: isCatch 0x01, isSeparated 0x02, BBT 0x04,
    /// UnwindMap 0x08, TryBlockMap 0x10. Then [bbtFlags: uint] [dispUnwindMap: int]
    /// [dispTryBlockMap: int] dispIPtoStateMap: int [dispFrame: uint, catch funclets only].
    /// IP-to-state entries and non-RVA continuations are offsets from the function start
    /// (<paramref name="functionStart"/>, or each separated piece's own start).
    /// </summary>
    public static CxxEhInfo ParseFh4(BinaryImage image, uint funcInfoRva, uint functionStart)
    {
        var funclets = new List<uint>();
        var continuations = new List<uint>();
        var ipStates = new List<uint>();
        try
        {
            var info = new Reader(image, funcInfoRva);
            byte header = info.Byte();
            bool isSeparated = (header & 0x02) != 0;
            if ((header & 0x04) != 0)
            {
                info.Unsigned(); // BBT flags
            }

            uint unwindMap = (header & 0x08) != 0 ? info.Int() : 0;
            uint tryBlockMap = (header & 0x10) != 0 ? info.Int() : 0;
            uint ipMap = info.Int();

            if (unwindMap != 0)
            {
                ReadUnwindMap4(new Reader(image, unwindMap), funclets);
            }

            if (tryBlockMap != 0)
            {
                ReadTryBlockMap4(image, new Reader(image, tryBlockMap), functionStart, funclets, continuations);
            }

            if (isSeparated)
            {
                var separated = new Reader(image, ipMap);
                uint pieces = Count(separated.Unsigned());
                for (uint i = 0; i < pieces; i++)
                {
                    uint pieceStart = separated.Int();
                    ReadIpMap4(new Reader(image, separated.Int()), pieceStart, ipStates);
                }
            }
            else
            {
                ReadIpMap4(new Reader(image, ipMap), functionStart, ipStates);
            }

            return new CxxEhInfo(funcInfoRva, 4, funclets, continuations, ipStates, null)
            {
                IsSeparated = isSeparated, IsCatch = (header & 0x01) != 0, HasTryBlocks = tryBlockMap != 0,
            };
        }
        catch (TableException ex)
        {
            return new CxxEhInfo(funcInfoRva, 4, funclets, continuations, ipStates, ex.Message);
        }
    }

    /// <summary>
    /// Count, then entries: uint (nextOffset &lt;&lt; 2 | type). Types 1 and 2 (destructor on an
    /// object / a pointer to one) carry action: int (the destructor's RVA) and object: uint;
    /// type 3 carries action: int (an unwind funclet's RVA); type 0 carries nothing.
    /// </summary>
    private static void ReadUnwindMap4(Reader map, List<uint> funclets)
    {
        uint entries = Count(map.Unsigned());
        for (uint i = 0; i < entries; i++)
        {
            uint type = map.Unsigned() & 3;
            if (type is 1 or 2)
            {
                AddNonZero(funclets, map.Int());
                map.Unsigned();
            }
            else if (type == 3)
            {
                AddNonZero(funclets, map.Int());
            }
        }
    }

    /// <summary>
    /// Count, then { tryLow, tryHigh, catchHigh: uint; dispHandlerArray: int }. Each handler
    /// array: count, then { header: byte; [adjectives: uint] [dispType: int] [dispCatchObj: uint]
    /// dispOfHandler: int; 0-2 continuations }. Header: adjectives 0x01, dispType 0x02,
    /// dispCatchObj 0x04, contIsRVA 0x08, continuation count in bits 4-5.
    /// </summary>
    private static void ReadTryBlockMap4(BinaryImage image, Reader map, uint functionStart, List<uint> funclets, List<uint> continuations)
    {
        uint tryBlocks = Count(map.Unsigned());
        for (uint i = 0; i < tryBlocks; i++)
        {
            map.Unsigned();
            map.Unsigned();
            map.Unsigned();
            var handlers = new Reader(image, map.Int());
            uint count = Count(handlers.Unsigned());
            for (uint j = 0; j < count; j++)
            {
                byte header = handlers.Byte();
                if ((header & 0x01) != 0)
                {
                    handlers.Unsigned();
                }

                if ((header & 0x02) != 0)
                {
                    handlers.Int();
                }

                if ((header & 0x04) != 0)
                {
                    handlers.Unsigned();
                }

                AddNonZero(funclets, handlers.Int());

                int continuationCount = (header >> 4) & 3;
                for (int c = 0; c < continuationCount; c++)
                {
                    continuations.Add((header & 0x08) != 0 ? handlers.Int() : functionStart + handlers.Unsigned());
                }
            }
        }
    }

    /// <summary>
    /// An FH4 FuncInfo4's header, map RVAs and IP-to-state maps with states (see <see cref="Fh4Layout"/>),
    /// or null if it does not decode. <paramref name="functionStart"/> keys a function that is not separated.
    /// </summary>
    public static Fh4Layout? ReadFh4Layout(BinaryImage image, uint funcInfoRva, uint functionStart)
    {
        try
        {
            var info = new Reader(image, funcInfoRva);
            byte header = info.Byte();
            if ((header & Fh4Layout.BbtFlag) != 0)
            {
                info.Unsigned();
            }

            uint unwindMap = (header & Fh4Layout.UnwindMapFlag) != 0 ? info.Int() : 0;
            uint tryBlockMap = (header & Fh4Layout.TryBlockMapFlag) != 0 ? info.Int() : 0;
            uint ipMap = info.Int();
            var segments = new List<Fh4Segment>();
            if ((header & Fh4Layout.IsSeparatedFlag) != 0)
            {
                var separated = new Reader(image, ipMap);
                uint pieces = Count(separated.Unsigned());
                for (uint i = 0; i < pieces; i++)
                {
                    uint start = separated.Int();
                    uint map = separated.Int();
                    segments.Add(new Fh4Segment(start, map, ReadStateMap4(new Reader(image, map), start)));
                }
            }
            else
            {
                segments.Add(new Fh4Segment(functionStart, ipMap, ReadStateMap4(new Reader(image, ipMap), functionStart)));
            }

            return new Fh4Layout(header, unwindMap, tryBlockMap, segments);
        }
        catch (TableException)
        {
            return null;
        }
    }

    private static List<(uint Rva, int State)> ReadStateMap4(Reader map, uint start)
    {
        var entries = new List<(uint, int)>();
        uint count = Count(map.Unsigned());
        uint ip = start;
        for (uint i = 0; i < count; i++)
        {
            ip += map.Unsigned();
            entries.Add((ip, (int)map.Unsigned() - 1));
        }

        return entries;
    }

    /// <summary>Count, then { ipDelta: uint; state + 1: uint }, with IPs accumulating from <paramref name="start"/>.</summary>
    private static void ReadIpMap4(Reader map, uint start, List<uint> ipStates)
    {
        uint entries = Count(map.Unsigned());
        uint ip = start;
        for (uint i = 0; i < entries; i++)
        {
            ip += map.Unsigned();
            map.Unsigned();
            ipStates.Add(ip);
        }
    }

    private static void AddNonZero(List<uint> list, uint rva)
    {
        if (rva != 0)
        {
            list.Add(rva);
        }
    }

    /// <summary>
    /// The catch handler funclets of an FH3 FuncInfo (<c>dispOfHandler</c> of every HandlerType of every
    /// try block). The runtime recognizes a running catch funclet by its unwind entry's BeginAddress
    /// being one of these RVAs, so such a funclet cannot move. Empty when the table does not parse.
    /// </summary>
    public static IReadOnlyList<uint> Fh3CatchHandlers(BinaryImage image, uint funcInfoRva)
    {
        var handlers = new List<uint>();
        try
        {
            uint tryBlocks = Count(U32(image, funcInfoRva + 12));
            uint tryBlockMap = U32(image, funcInfoRva + 16);
            for (uint i = 0; i < tryBlocks; i++)
            {
                uint entry = tryBlockMap + i * 20;
                uint catches = Count(U32(image, entry + 12));
                uint array = U32(image, entry + 16);
                for (uint j = 0; j < catches; j++)
                {
                    handlers.Add(U32(image, array + j * 20 + 12));
                }
            }
        }
        catch (TableException)
        {
            // handled by the caller through CxxEhInfo.Problem
        }

        return handlers;
    }

    private static uint Count(uint value) =>
        value <= MaxEntries ? value : throw new TableException($"implausible entry count {value}");

    private static uint U32(BinaryImage image, uint rva)
    {
        var data = image.ReadFrom(rva).Span;
        return data.Length >= 4
            ? BinaryPrimitives.ReadUInt32LittleEndian(data)
            : throw new TableException($"table at 0x{rva:X} is outside the image's file-backed data");
    }

    private sealed class TableException(string message) : Exception(message);

    /// <summary>Sequential reader for FH4's compressed encoding.</summary>
    private sealed class Reader(BinaryImage image, uint rva)
    {
        private readonly ReadOnlyMemory<byte> _data = image.ReadFrom(rva);
        private int _position;

        public byte Byte() => Take(1)[0];

        public uint Int() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

        /// <summary>
        /// The low bits of the first byte give the length: xxxxxxx0 = 1 byte, xxxxxx01 = 2,
        /// xxxxx011 = 3, xxxx0111 = 4, xxxx1111 = 5 (value in the next 4 bytes). For 1-4 bytes the
        /// value is the little-endian bytes shifted right by the length.
        /// </summary>
        public uint Unsigned()
        {
            if (_position >= _data.Length)
            {
                throw Overrun();
            }

            byte first = _data.Span[_position];
            int length = (first & 1) == 0 ? 1 : (first & 3) == 1 ? 2 : (first & 7) == 3 ? 3 : (first & 15) == 7 ? 4 : 5;
            var bytes = Take(length);
            if (length == 5)
            {
                return BinaryPrimitives.ReadUInt32LittleEndian(bytes[1..]);
            }

            uint value = 0;
            for (int i = length - 1; i >= 0; i--)
            {
                value = (value << 8) | bytes[i];
            }

            return value >> length;
        }

        private ReadOnlySpan<byte> Take(int count)
        {
            if (_position + count > _data.Length)
            {
                throw Overrun();
            }

            var span = _data.Span.Slice(_position, count);
            _position += count;
            return span;
        }

        private TableException Overrun() => new($"compressed table at 0x{rva:X} runs past the image's file-backed data");
    }
}
