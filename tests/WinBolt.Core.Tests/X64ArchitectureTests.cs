using Iced.Intel;
using WinBolt.Core.Arch;

namespace WinBolt.Core.Tests;

public class X64ArchitectureTests
{
    [Fact]
    public void CreateDecoder_DecodesKnownByteSequence()
    {
        var arch = new X64Architecture();
        byte[] code = [0x90, 0xC3]; // nop; ret
        var decoder = arch.CreateDecoder(code, 0x1000);

        Assert.True(decoder.TryDecodeNext(out var first));
        Assert.Equal(Mnemonic.Nop, first.Mnemonic);
        Assert.Equal(0x1000UL, first.IP);

        Assert.True(decoder.TryDecodeNext(out var second));
        Assert.Equal(Mnemonic.Ret, second.Mnemonic);
        Assert.Equal(0x1001UL, second.IP);

        Assert.False(decoder.TryDecodeNext(out _));
    }

    [Fact]
    public void Name_IsX64()
    {
        var arch = new X64Architecture();
        Assert.Equal("x64", arch.Name);
        Assert.Equal(64, arch.BitWidth);
    }
}
