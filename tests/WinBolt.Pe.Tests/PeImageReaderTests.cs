using WinBolt.Pe;

namespace WinBolt.Pe.Tests;

public class PeImageReaderTests
{
    // A real, always-present system binary is a cheap and realistic fixture for Stage 1
    // structural parsing (synthetic PE generation is a separate, larger test-corpus
    // concern — see DesignDoc.md §10).
    private const string SystemBinaryPath = @"C:\Windows\System32\notepad.exe";

    [SkippableFact]
    public void Read_SystemBinary_ParsesHeadersAndSections()
    {
        if (!File.Exists(SystemBinaryPath))
        {
throw new SkipException("environment without this path; nothing to verify here");
        }

        var image = PeImageReader.Read(SystemBinaryPath);

        Assert.NotEmpty(image.Sections);
        Assert.Contains(image.Sections, s => s.Name == ".text" && s.IsExecutable);
        Assert.True(image.ImageBase > 0);
        Assert.True(image.SizeOfImage > 0);
    }

    [SkippableFact]
    public void Read_SystemBinary_ParsesExceptionDirectory()
    {
        if (!File.Exists(SystemBinaryPath))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(SystemBinaryPath);

        // x64 requires unwind data for every non-leaf function (§Stage 1), so a
        // non-trivial x64 executable must have a non-empty .pdata.
        Assert.NotEmpty(image.ExceptionData);
        Assert.All(image.ExceptionData, e => Assert.True(e.EndAddress >= e.BeginAddress));
    }

    [SkippableFact]
    public void Read_SystemBinary_ExceptionDirectoryIsSortedByBeginAddress()
    {
        if (!File.Exists(SystemBinaryPath))
        {
throw new SkipException("Windows system binary or PDB not available on this machine");
        }

        var image = PeImageReader.Read(SystemBinaryPath);

        // §5.4: RtlLookupFunctionEntry binary-searches .pdata, so the loader requires it
        // sorted ascending by BeginAddress on disk.
        for (int i = 1; i < image.ExceptionData.Count; i++)
        {
            Assert.True(image.ExceptionData[i].BeginAddress >= image.ExceptionData[i - 1].BeginAddress);
        }
    }

    [Fact]
    public void Read_NonPeFile_ThrowsPeFormatException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, [0x00, 0x01, 0x02, 0x03]);
            Assert.Throws<PeFormatException>(() => PeImageReader.Read(tempFile));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
