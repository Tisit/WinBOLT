namespace WinBolt.Core.Ir;

/// <summary>
/// One import, identified by its IAT slot. Code reaches it through <c>call/jmp [rip+slot]</c>, so
/// the slot RVA is what names an import thunk (e.g. an exception handler that is
/// <c>jmp [__imp___C_specific_handler]</c>).
/// </summary>
public sealed record ImportedSymbol(string Dll, string? Name, ushort? Ordinal, uint IatSlotRva);
