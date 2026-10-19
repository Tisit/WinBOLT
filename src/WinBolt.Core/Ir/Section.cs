namespace WinBolt.Core.Ir;

public sealed class Section
{
    public required string Name { get; init; }

    public required uint Rva { get; init; }

    public required uint VirtualSize { get; init; }

    public required uint RawSize { get; init; }

    public required uint FileOffset { get; init; }

    /// <summary>Raw IMAGE_SECTION_HEADER.Characteristics flags.</summary>
    public required uint Characteristics { get; init; }

    /// <summary>
    /// File-backed contents, <c>min(RawSize, VirtualSize)</c> bytes (all of <c>RawSize</c> when
    /// <c>VirtualSize</c> is 0). Bytes past this up to <see cref="VirtualSize"/> are zero-fill.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; init; }

    public bool IsExecutable => (Characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE

    /// <summary>Mapped extent: the loader maps <see cref="VirtualSize"/> bytes (or <see cref="RawSize"/> when it is 0).</summary>
    public uint MappedSize => VirtualSize != 0 ? VirtualSize : RawSize;

    public bool Contains(uint rva) => rva >= Rva && rva - Rva < MappedSize;
}
