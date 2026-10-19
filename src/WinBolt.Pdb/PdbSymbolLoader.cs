using WinBolt.Core.Ir;

namespace WinBolt.Pdb;

/// <summary>Outcome of looking for and loading a PDB. <see cref="Message"/> says what was tried or found.</summary>
public sealed record PdbLoadResult(bool Loaded, string Message);

/// <summary>
/// Finds the PDB matching an image and loads its public symbols into
/// <see cref="BinaryImage.Symbols"/>, translated to image RVAs (§3.3). The PDB is optional:
/// stripped binaries are an explicit target, so every failure is a message, not an exception.
/// Only a PDB whose GUID and age match the image's CodeView record is used; a stale PDB would
/// name the wrong code.
/// </summary>
public static class PdbSymbolLoader
{
    /// <param name="explicitPath">A PDB path given by the user, tried first.</param>
    /// <param name="searchDirectories">
    /// Directories to search, flat (<c>dir/name.pdb</c>) or symbol-store layout
    /// (<c>dir/name.pdb/GUIDAGE/name.pdb</c>). The local directories named by
    /// <c>_NT_SYMBOL_PATH</c> are added automatically.
    /// </param>
    public static PdbLoadResult Load(BinaryImage image, string? explicitPath = null, IEnumerable<string>? searchDirectories = null)
    {
        if (image.CodeView is not { } codeView)
        {
            return new PdbLoadResult(false, "the image has no RSDS CodeView record naming a PDB");
        }

        var rejected = new List<string>();
        foreach (string candidate in Candidates(image, codeView, explicitPath, searchDirectories ?? []))
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            PdbFile pdb;
            try
            {
                pdb = PdbFile.Read(candidate);
            }
            catch (Exception ex) when (ex is PdbFormatException or IOException or UnauthorizedAccessException)
            {
                rejected.Add($"{candidate}: {ex.Message}");
                continue;
            }

            if (pdb.Guid != codeView.Guid || (pdb.InfoAge != codeView.Age && pdb.DbiAge != codeView.Age))
            {
                rejected.Add($"{candidate}: GUID/age {pdb.Guid:N}/{pdb.InfoAge} does not match the image's {codeView.Guid:N}/{codeView.Age}");
                continue;
            }

            Resolve(image, pdb, candidate);
            return new PdbLoadResult(true, candidate);
        }

        return new PdbLoadResult(false, rejected.Count > 0
            ? "no matching PDB; rejected " + string.Join("; ", rejected)
            : $"no PDB found for {Path.GetFileName(codeView.PdbPath)}");
    }

    private static void Resolve(BinaryImage image, PdbFile pdb, string path)
    {
        var imageSections = image.Sections.Select(s => s.Rva).ToList();
        int dropped = 0;
        foreach (var symbol in pdb.Publics)
        {
            if (pdb.ToImageRva(symbol.Segment, symbol.Offset, imageSections) is { } rva)
            {
                image.Symbols.Add(new Symbol(symbol.Name, rva, symbol.IsFunction));
            }
            else
            {
                dropped++;
            }
        }

        // Fixups describe the linker's layout: usable only when no post-link rewrite moved code.
        if (pdb.OmapFromSrc.Length == 0)
        {
            foreach (var fixup in pdb.Fixups)
            {
                image.LinkerFixups.Add(new LinkerFixup(fixup.Type, fixup.Rva, fixup.Target));
            }

            foreach (var contribution in pdb.Contributions.Where(c => c.Size > 0))
            {
                if (pdb.ToImageRva(contribution.Section, contribution.Offset, imageSections) is { } rva)
                {
                    image.SectionContributions.Add(new SectionContribution(rva, contribution.Size, contribution.Characteristics, contribution.Module));
                }
            }

            image.SectionContributions.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        }

        image.Pdb = new PdbInfo(path, pdb.OmapFromSrc.Length > 0, pdb.Publics.Count, dropped);
    }

    private static IEnumerable<string> Candidates(BinaryImage image, CodeViewInfo codeView, string? explicitPath, IEnumerable<string> searchDirectories)
    {
        string name = Path.GetFileName(codeView.PdbPath.Replace('\\', Path.DirectorySeparatorChar));
        string key = codeView.Guid.ToString("N").ToUpperInvariant() + codeView.Age.ToString("X");

        if (explicitPath is not null)
        {
            yield return explicitPath;
        }

        if (Path.GetDirectoryName(Path.GetFullPath(image.FilePath)) is { } imageDirectory)
        {
            yield return Path.Combine(imageDirectory, name);
        }

        // The RSDS path comes from the (untrusted) image: a UNC path would make analysis open a network share.
        if (!codeView.PdbPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            yield return codeView.PdbPath;
        }

        foreach (string directory in searchDirectories.Concat(SymbolPathDirectories()))
        {
            yield return Path.Combine(directory, name, key, name);
            yield return Path.Combine(directory, name);
        }
    }

    /// <summary>
    /// Local directories in <c>_NT_SYMBOL_PATH</c>: plain entries, and the cache directory of
    /// <c>srv*cache*url</c> and <c>cache*dir</c> entries. Nothing is downloaded.
    /// </summary>
    private static IEnumerable<string> SymbolPathDirectories()
    {
        string? symbolPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
        if (string.IsNullOrWhiteSpace(symbolPath))
        {
            yield break;
        }

        foreach (string entry in symbolPath.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split('*');
            if (parts[0].Equals("srv", StringComparison.OrdinalIgnoreCase) || parts[0].Equals("cache", StringComparison.OrdinalIgnoreCase))
            {
                if (parts.Length > 1 && !parts[1].Contains("://", StringComparison.Ordinal) && parts[1].Length > 0)
                {
                    yield return parts[1];
                }
            }
            else if (!entry.Contains("://", StringComparison.Ordinal))
            {
                yield return entry;
            }
        }
    }
}
