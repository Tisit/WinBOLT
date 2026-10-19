using Iced.Intel;
using WinBolt.Core.Ir;

namespace WinBolt.Core.Tests;

public class InstructionStoreTests
{
    [Fact]
    public void Add_ReturnsSequentialIds()
    {
        var store = new InstructionStore();

        int id0 = store.Add(default);
        int id1 = store.Add(default);

        Assert.Equal(0, id0);
        Assert.Equal(1, id1);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void Add_GrowsPastInitialCapacity()
    {
        var store = new InstructionStore();

        for (int i = 0; i < 1000; i++)
        {
            store.Add(default);
        }

        Assert.Equal(1000, store.Count);
    }

    [Fact]
    public void Indexer_OutOfRange_Throws()
    {
        var store = new InstructionStore();
        store.Add(default);

        Assert.Throws<ArgumentOutOfRangeException>(() => store[5]);
    }

    [Fact]
    public void Slice_ReturnsRequestedRange()
    {
        var store = new InstructionStore();
        var decoder = Decoder.Create(64, new ByteArrayCodeReader([0xC3, 0x90, 0xC3])); // ret, nop, ret
        decoder.IP = 0x1000;

        while (decoder.IP < 0x1000 + 3)
        {
            store.Add(decoder.Decode());
        }

        var slice = store.Slice(0, 3);
        Assert.Equal(3, slice.Length);
        Assert.Equal(Mnemonic.Ret, slice[0].Mnemonic);
        Assert.Equal(Mnemonic.Nop, slice[1].Mnemonic);
        Assert.Equal(Mnemonic.Ret, slice[2].Mnemonic);
    }
}
