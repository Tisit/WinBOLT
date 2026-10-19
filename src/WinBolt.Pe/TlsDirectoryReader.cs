using System.Buffers.Binary;

namespace WinBolt.Pe;

/// <summary>
/// Reads the TLS callback array from IMAGE_TLS_DIRECTORY64: AddressOfCallBacks is a VA of a
/// null-terminated array of callback VAs (§5.2).
/// </summary>
internal static class TlsDirectoryReader
{
    private const int OffsetAddressOfCallBacks = 24;

    // Loader-called array; real images have a handful. Bounds a missing terminator.
    private const int MaxCallbacks = 4096;

    public static List<uint> ReadCallbacks(byte[] image, RvaMapper rvaMapper, (uint Rva, uint Size) directory, ulong imageBase)
    {
        var callbacks = new List<uint>();
        if (directory.Rva == 0 || directory.Size < OffsetAddressOfCallBacks + 8 ||
            !rvaMapper.TryToFileOffset(directory.Rva, out var dirOffset) || dirOffset + OffsetAddressOfCallBacks + 8 > image.Length)
        {
            return callbacks;
        }

        ulong arrayVa = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)dirOffset + OffsetAddressOfCallBacks, 8));
        if (arrayVa < imageBase || !rvaMapper.TryToFileOffset((uint)(arrayVa - imageBase), out var arrayOffset))
        {
            return callbacks;
        }

        for (int i = 0; i < MaxCallbacks && arrayOffset + (i + 1) * 8L <= image.Length; i++)
        {
            ulong va = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)arrayOffset + i * 8, 8));
            if (va == 0)
            {
                break;
            }

            if (va >= imageBase && va - imageBase <= uint.MaxValue)
            {
                callbacks.Add((uint)(va - imageBase));
            }
        }

        return callbacks;
    }
}
