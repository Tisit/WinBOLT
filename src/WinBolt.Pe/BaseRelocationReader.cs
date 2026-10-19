using System.Buffers.Binary;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>Parses .reloc: a sequence of IMAGE_BASE_RELOCATION blocks, each a 4K page RVA plus 2-byte (type:4, offset:12) entries.</summary>
internal static class BaseRelocationReader
{
    private const int TypeAbsolute = 0; // padding entry, no address
    private const int TypeHighLow = 3;
    private const int TypeDir64 = 10;

    public static List<Relocation> Read(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory)
    {
        var relocations = new List<Relocation>();
        if (directory.Rva == 0 || directory.Size == 0)
        {
            return relocations;
        }

        if (!rvaMapper.TryToFileOffset(directory.Rva, out var blockOffset))
        {
            return relocations;
        }

        uint remaining = directory.Size;

        while (remaining >= 8 && blockOffset + 8 <= image.Length)
        {
            uint pageRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)blockOffset, 4));
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)blockOffset + 4, 4));

            if (blockSize < 8 || blockSize > remaining || blockOffset + blockSize > image.Length)
            {
                break; // malformed block; stop rather than read out of bounds
            }

            int entryCount = (int)(blockSize - 8) / 2;
            for (int i = 0; i < entryCount; i++)
            {
                int entryOffset = (int)blockOffset + 8 + i * 2;
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(entryOffset, 2));
                int type = entry >> 12;
                int pageOffset = entry & 0xFFF;

                RelocationType? relocationType = type switch
                {
                    TypeAbsolute => RelocationType.Absolute,
                    TypeHighLow => RelocationType.HighLow,
                    TypeDir64 => RelocationType.Dir64,
                    _ => null,
                };

                if (relocationType is null or RelocationType.Absolute)
                {
                    continue;
                }

                relocations.Add(new Relocation
                {
                    Rva = pageRva + (uint)pageOffset,
                    Type = relocationType.Value,
                });
            }

            blockOffset += blockSize;
            remaining -= blockSize;
        }

        return relocations;
    }
}
