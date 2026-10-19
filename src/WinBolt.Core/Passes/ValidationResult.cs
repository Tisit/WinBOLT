namespace WinBolt.Core.Passes;

public sealed class ValidationResult
{
    public required bool Success { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = [];

    public static ValidationResult Ok() => new() { Success = true };

    public static ValidationResult Fail(params string[] errors) =>
        new() { Success = false, Errors = errors };
}
