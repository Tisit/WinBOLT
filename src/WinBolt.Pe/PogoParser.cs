using System.Buffers.Binary;
using System.Text;
using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>
/// Decodes the undocumented IMAGE_DEBUG_TYPE_POGO payload: a 4-byte signature followed by
/// <c>{ u32 rva; u32 size; char name[]; }</c> records, each padded to a 4-byte boundary.
/// </summary>
public static class PogoParser
{
    public static PogoInfo Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            return new PogoInfo(0, []);
        }

        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(data);
        var contributions = new List<PogoContribution>();
        int pos = 4;
        while (pos + 9 <= data.Length)
        {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(data[pos..]);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(data[(pos + 4)..]);
            int nameStart = pos + 8;
            int nul = data[nameStart..].IndexOf((byte)0);
            if (nul < 0)
            {
                break;
            }

            contributions.Add(new PogoContribution(rva, size, Encoding.ASCII.GetString(data.Slice(nameStart, nul))));
            pos = (nameStart + nul + 1 + 3) & ~3;
        }

        return new PogoInfo(signature, contributions);
    }
}
