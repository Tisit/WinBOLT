using System.Buffers.Binary;
using System.Text;

namespace WinBolt.Pdb;

/// <summary>
/// Reader for the MSF 7.0 ("big MSF") container that holds every modern PDB
/// (https://llvm.org/docs/PDB/MsfFile.html). Adapted from the sibling project
/// AssemblyOptimizationDetection, whose reader is cross-checked against llvm-pdbutil.
/// A PDB is untrusted input: every block reference is bounds-checked.
/// </summary>
internal sealed class MsfFile
{
    internal static readonly byte[] Magic = Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00\r\n\x1a" + "DS\0\0\0");
    internal const uint NilStreamSize = 0xFFFFFFFF;

    private readonly byte[] _data;
    private readonly int _blockSize;
    private readonly uint[] _streamSizes;
    private readonly uint[][] _streamBlocks;

    private MsfFile(byte[] data, int blockSize, uint[] streamSizes, uint[][] streamBlocks)
    {
        _data = data;
        _blockSize = blockSize;
        _streamSizes = streamSizes;
        _streamBlocks = streamBlocks;
    }

    public static MsfFile Parse(byte[] data)
    {
        if (data.Length < 56 || !data.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new PdbFormatException("Not an MSF 7.0 PDB (2.00-format PDBs are not supported).");
        }

        var span = data.AsSpan();
        int blockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[32..]);
        uint directoryBytes = BinaryPrimitives.ReadUInt32LittleEndian(span[44..]);
        uint blockMapAddress = BinaryPrimitives.ReadUInt32LittleEndian(span[52..]);
        if (blockSize is not (512 or 1024 or 2048 or 4096 or 8192 or 16384 or 32768))
        {
            throw new PdbFormatException($"Unexpected MSF block size {blockSize}.");
        }

        // The block map lists the blocks that make up the stream directory.
        int directoryBlockCount = (int)((directoryBytes + blockSize - 1) / blockSize);
        long mapOffset = (long)blockMapAddress * blockSize;
        if (mapOffset + directoryBlockCount * 4L > data.Length)
        {
            throw new PdbFormatException("MSF block map lies outside the file.");
        }

        var directoryBlocks = new uint[directoryBlockCount];
        for (int i = 0; i < directoryBlockCount; i++)
        {
            directoryBlocks[i] = BinaryPrimitives.ReadUInt32LittleEndian(span[(int)(mapOffset + i * 4)..]);
        }

        var directory = Gather(data, blockSize, directoryBlocks, directoryBytes).AsSpan();
        if (directory.Length < 4)
        {
            throw new PdbFormatException("MSF stream directory is empty.");
        }

        int streamCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(directory);
        if (streamCount < 0 || 4 + streamCount * 4L > directory.Length)
        {
            throw new PdbFormatException("MSF stream directory is truncated.");
        }

        var sizes = new uint[streamCount];
        for (int i = 0; i < streamCount; i++)
        {
            sizes[i] = BinaryPrimitives.ReadUInt32LittleEndian(directory[(4 + i * 4)..]);
        }

        int position = 4 + streamCount * 4;
        var blocks = new uint[streamCount][];
        for (int i = 0; i < streamCount; i++)
        {
            uint size = sizes[i] == NilStreamSize ? 0 : sizes[i];
            int count = (int)((size + blockSize - 1) / blockSize);
            if (position + count * 4L > directory.Length)
            {
                throw new PdbFormatException("MSF stream directory is truncated.");
            }

            blocks[i] = new uint[count];
            for (int b = 0; b < count; b++, position += 4)
            {
                blocks[i][b] = BinaryPrimitives.ReadUInt32LittleEndian(directory[position..]);
            }
        }

        return new MsfFile(data, blockSize, sizes, blocks);
    }

    public int BlockSize => _blockSize;

    public int StreamCount => _streamSizes.Length;

    public bool StreamExists(int index) =>
        index >= 0 && index < _streamSizes.Length && _streamSizes[index] != NilStreamSize;

    /// <summary>The stream's bytes; empty for a nil or missing stream.</summary>
    public byte[] ReadStream(int index) =>
        StreamExists(index) ? Gather(_data, _blockSize, _streamBlocks[index], _streamSizes[index]) : [];

    private static byte[] Gather(byte[] data, int blockSize, uint[] blocks, uint size)
    {
        // A stream cannot be larger than the file that holds it; the size field is untrusted.
        if (size > data.Length)
        {
            throw new PdbFormatException($"MSF stream of {size:N0} bytes is larger than the file.");
        }

        var result = new byte[size];
        int written = 0;
        foreach (uint block in blocks)
        {
            int count = Math.Min(blockSize, (int)size - written);
            long offset = (long)block * blockSize;
            if (offset + count > data.Length)
            {
                throw new PdbFormatException($"MSF block {block} lies outside the file.");
            }

            Buffer.BlockCopy(data, (int)offset, result, written, count);
            written += count;
        }

        return result;
    }
}

/// <summary>
/// Writes an MSF 7.0 container: block 0 the superblock, blocks 1 and 2 (and every 1/2 + k * block
/// size) the free page maps, then the streams, the stream directory and the block map.
/// </summary>
internal static class MsfWriter
{
    /// <param name="streams">Stream contents by index; null for a nil stream.</param>
    public static byte[] Write(int blockSize, IReadOnlyList<byte[]?> streams)
    {
        int next = 3;
        int Allocate()
        {
            while (next % blockSize is 1 or 2)
            {
                next++; // free page map blocks of later intervals
            }

            return next++;
        }

        var streamBlocks = streams.Select(stream => Enumerable.Range(0, stream is null ? 0 : (stream.Length + blockSize - 1) / blockSize).Select(_ => Allocate()).ToArray()).ToList();

        var directory = new List<byte>();
        directory.AddRange(BitConverter.GetBytes((uint)streams.Count));
        foreach (var stream in streams)
        {
            directory.AddRange(BitConverter.GetBytes(stream is null ? MsfFile.NilStreamSize : (uint)stream.Length));
        }

        foreach (var blocks in streamBlocks)
        {
            foreach (int block in blocks)
            {
                directory.AddRange(BitConverter.GetBytes((uint)block));
            }
        }

        var directoryBlocks = Enumerable.Range(0, (directory.Count + blockSize - 1) / blockSize).Select(_ => Allocate()).ToArray();
        if (directoryBlocks.Length * 4 > blockSize)
        {
            throw new PdbFormatException("the stream directory does not fit one block map block");
        }

        int blockMap = Allocate();
        int numBlocks = next;
        var file = new byte[(long)numBlocks * blockSize];

        void Put(byte[] data, int[] blocks)
        {
            for (int i = 0; i < blocks.Length; i++)
            {
                int count = Math.Min(blockSize, data.Length - i * blockSize);
                Buffer.BlockCopy(data, i * blockSize, file, blocks[i] * blockSize, count);
            }
        }

        for (int i = 0; i < streams.Count; i++)
        {
            if (streams[i] is { } stream)
            {
                Put(stream, streamBlocks[i]);
            }
        }

        Put(directory.ToArray(), directoryBlocks);
        for (int i = 0; i < directoryBlocks.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(blockMap * blockSize + i * 4), (uint)directoryBlocks[i]);
        }

        // Free page map: a bit per block, set when free. Every block of the file is in use; the
        // bits past its end are free. Its bytes are spread over blocks 1, 1 + blockSize, ...
        int bitmapBytes = ((numBlocks + 7) / 8 + blockSize - 1) / blockSize * blockSize;
        var bitmap = new byte[bitmapBytes];
        for (int b = numBlocks; b < bitmapBytes * 8; b++)
        {
            bitmap[b / 8] |= (byte)(1 << (b % 8));
        }

        for (int k = 0; k * blockSize < bitmapBytes; k++)
        {
            foreach (int fpm in new[] { 1 + k * blockSize, 2 + k * blockSize })
            {
                if (fpm < numBlocks)
                {
                    Buffer.BlockCopy(bitmap, k * blockSize, file, fpm * blockSize, blockSize);
                }
            }
        }

        MsfFile.Magic.CopyTo(file, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(32), (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(36), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(40), (uint)numBlocks);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(44), (uint)directory.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(52), (uint)blockMap);
        return file;
    }
}

public sealed class PdbFormatException(string message) : Exception(message);
