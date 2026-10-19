using WinBolt.Core.Ir;

namespace WinBolt.Core.Profile;

/// <summary>Every basic block of an image in address order, with the function that owns it, for lookup by RVA.</summary>
internal sealed class BlockIndex
{
    private readonly uint[] _starts;

    public BlockIndex(BinaryImage image)
    {
        Blocks = image.Functions
            .SelectMany(f => f.BasicBlocks.Select(b => (Function: f, Block: b)))
            .OrderBy(x => x.Block.StartRva)
            .ToArray();
        _starts = Blocks.Select(x => (uint)x.Block.StartRva).ToArray();
    }

    public (Function Function, BasicBlock Block)[] Blocks { get; }

    /// <summary>The block containing <paramref name="rva"/>, or null when it lies in no block.</summary>
    public (Function Function, BasicBlock Block)? Find(uint rva)
    {
        int i = Array.BinarySearch(_starts, rva);
        if (i < 0)
        {
            i = ~i - 1;
        }

        return i >= 0 && rva < Blocks[i].Block.StartRva + Blocks[i].Block.Length ? Blocks[i] : null;
    }
}
