namespace WinBolt.Core.Ir;

/// <summary>One IMAGE_OPTIONAL_HEADER64.DataDirectory entry, by name (Export, Import, Iat, …).</summary>
public sealed record DataDirectory(string Name, uint Rva, uint Size);
