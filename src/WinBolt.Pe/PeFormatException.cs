namespace WinBolt.Pe;

public sealed class PeFormatException : Exception
{
    public PeFormatException(string message) : base(message)
    {
    }
}
