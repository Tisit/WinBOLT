namespace WinBolt.Rewrite.Tests;

internal static class TempDirectory
{
    /// <summary>
    /// Removes a test's temporary directory. A negative control that crashed may still be held
    /// open by Windows Error Reporting for a moment; a directory that stays locked is left behind.
    /// </summary>
    public static void Delete(string directory)
    {
        for (int attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                Directory.Delete(directory, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(250);
            }
        }
    }
}
