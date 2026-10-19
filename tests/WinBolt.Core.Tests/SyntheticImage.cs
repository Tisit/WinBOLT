using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Passes.Analysis;

namespace WinBolt.Core.Tests;

/// <summary>A one-section image built from hand-assembled bytes, for pass tests.</summary>
internal sealed class SyntheticImage
{
    public const ulong ImageBase = 0x140000000;
    public const uint TextRva = 0x1000;
    private const int TextSize = 0x200;

    private readonly byte[] _text = Enumerable.Repeat((byte)0xCC, TextSize).ToArray();

    public BinaryImage Image { get; } = new()
    {
        FilePath = "synthetic.dll",
        ImageBase = ImageBase,
        SizeOfImage = 0x3000,
        TimeDateStamp = 0,
        Checksum = 0,
    };

    public SyntheticImage Code(uint rva, params byte[] bytes)
    {
        bytes.CopyTo(_text, (int)(rva - TextRva));
        return this;
    }

    public SyntheticImage Pdata(uint begin, uint end, uint handlerRva = 0, uint handlerDataRva = 0, uint unwindInfoRva = 0)
    {
        Image.ExceptionData.Add(new ExceptionInfo
        {
            BeginAddress = begin,
            EndAddress = end,
            UnwindInfoAddress = unwindInfoRva,
            HandlerRva = handlerRva,
            HandlerDataRva = handlerDataRva,
        });
        return this;
    }

    /// <summary>Writes little-endian u32 values, e.g. a scope table.</summary>
    public SyntheticImage Data(uint rva, params uint[] values) =>
        Code(rva, values.SelectMany(BitConverter.GetBytes).ToArray());

    public SyntheticImage Import(string name, uint iatSlotRva)
    {
        Image.Imports.Add(new ImportedSymbol("vcruntime140.dll", name, null, iatSlotRva));
        return this;
    }

    public SyntheticImage Export(string name, uint rva)
    {
        Image.Exports.Add(new ExportedSymbol(name, (uint)Image.Exports.Count + 1, rva, null));
        return this;
    }

    /// <summary>A function public symbol, as the PDB loader supplies it.</summary>
    public SyntheticImage Symbol(string name, uint rva)
    {
        Image.Symbols.Add(new Symbol(name, rva, IsFunction: true));
        return this;
    }

    /// <summary>Adds the .text section without running any pass.</summary>
    public BinaryImage Build()
    {
        Image.Sections.Add(new Section
        {
            Name = ".text", Rva = TextRva, VirtualSize = TextSize, RawSize = TextSize, FileOffset = 0x400,
            Characteristics = 0x60000020, Data = _text,
        });
        return Image;
    }

    /// <summary>Runs handler identification, discovery, CFG construction and, unless disabled, the safety gate.</summary>
    public BinaryImage Analyze(bool safetyGate = true)
    {
        Build();
        var context = new PassContext();
        new ExceptionHandlerPass().Run(Image, context);
        new FunctionDiscoveryPass().Run(Image, context);
        new CfgConstructionPass().Run(Image, context);
        if (safetyGate)
        {
            new SafetyGatePass().Run(Image, context);
        }

        return Image;
    }
}
