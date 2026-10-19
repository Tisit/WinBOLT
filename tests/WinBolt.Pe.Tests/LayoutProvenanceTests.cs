using System.Buffers.Binary;
using System.Text;
using WinBolt.Core.Analysis;
using WinBolt.Core.Ir;

namespace WinBolt.Pe.Tests;

public class LayoutProvenanceTests
{
    [Fact]
    public void PogoParser_reads_signature_and_padded_records()
    {
        var bytes = new List<byte>();
        void U32(uint v)
        {
            var b = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(b, v);
            bytes.AddRange(b);
        }

        void Record(uint rva, uint size, string name)
        {
            U32(rva);
            U32(size);
            bytes.AddRange(Encoding.ASCII.GetBytes(name));
            bytes.Add(0);
            while (bytes.Count % 4 != 0)
            {
                bytes.Add(0);
            }
        }

        U32(PogoInfo.SignaturePgu);
        Record(0x1000, 0x200, ".text$lp00app.exe!20_pri7");
        Record(0x1200, 0x40, ".text$mn");
        Record(0x1240, 0x10, ".text$x");

        var pogo = PogoParser.Parse(bytes.ToArray());

        Assert.Equal("PGU", pogo.Signature);
        Assert.True(pogo.IsProfileOptimized);
        Assert.Equal([".text$lp00app.exe!20_pri7", ".text$mn", ".text$x"], pogo.Contributions.Select(c => c.Name));
        Assert.Equal(0x1240u, pogo.Contributions[2].Rva);
        Assert.Equal(1, pogo.ProfileOrderedGroups);
        Assert.Equal(1, pogo.ColdGroups);
    }

    [Fact]
    public void PogoParser_tolerates_truncated_payload()
    {
        Assert.Empty(PogoParser.Parse([0x00, 0x55, 0x47]).Contributions);
    }

    [SkippableFact]
    public void Ntdll_is_compiler_pgo_with_far_fragments()
    {
        // Confirmed by the AssemblyOptimizationDetection project's scan of System32.
        const string path = @"C:\Windows\System32\ntdll.dll";
        if (!File.Exists(path))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(path);
        var provenance = LayoutProvenanceClassifier.Classify(image);

        Assert.NotNull(image.Pogo);
        Assert.Equal(LayoutOrigin.CompilerPgo, provenance.Origin);
        Assert.True(provenance.Chains.FarFragments > 0);
    }

    [SkippableFact]
    public void Sqlncli11_is_post_link_rewritten()
    {
        // The one BBT-rewritten binary that scan found in System32; not on every machine.
        const string path = @"C:\Windows\System32\sqlncli11.dll";
        if (!File.Exists(path))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(path);
        var provenance = LayoutProvenanceClassifier.Classify(image);

        Assert.Contains(image.DebugEntries, e => e.Type == DebugDirectoryType.Reserved10);
        Assert.Contains(provenance.Origin, new[] { LayoutOrigin.PostLinkRewrite, LayoutOrigin.LikelyPostLinkRewrite });

        // BBT writes indirect chains (UnwindData low bit set). Misreading them as UNWIND_INFO
        // once produced hundreds of spurious invalid chains here.
        Assert.Contains(image.ExceptionData, e => (e.UnwindInfoAddress & 1) != 0);
        Assert.Equal(0, provenance.Chains.InvalidChains);
    }
}
