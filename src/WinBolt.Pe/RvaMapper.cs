using WinBolt.Core.Ir;

namespace WinBolt.Pe;

/// <summary>Maps RVAs to file offsets using the section table.</summary>
public sealed class RvaMapper
{
    private readonly IReadOnlyList<Section> _sections;

    public RvaMapper(IReadOnlyList<Section> sections) => _sections = sections;

    public bool TryToFileOffset(uint rva, out uint fileOffset)
    {
        foreach (var section in _sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.Rva && rva < section.Rva + span)
            {
                fileOffset = section.FileOffset + (rva - section.Rva);
                return true;
            }
        }

        fileOffset = 0;
        return false;
    }

    public uint ToFileOffset(uint rva)
    {
        if (!TryToFileOffset(rva, out var fileOffset))
        {
            throw new PeFormatException($"RVA 0x{rva:X} does not map to any section.");
        }

        return fileOffset;
    }
}
