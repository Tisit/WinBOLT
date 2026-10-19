using System.Net;
using System.Text;
using WinBolt.Core.Ir;
using WinBolt.Core.Passes;
using WinBolt.Core.Profile;

/// <summary>
/// Self-contained HTML rendering of the analysis (DesignDoc §12: HTML report). Rendering is a
/// writer concern; the reports themselves stay plain text. With a profile it adds the Stage 2
/// views: a page heat map of each executable section and a hot-path view of the hottest
/// functions.
/// </summary>
internal static class HtmlReport
{
    private const int PagesPerRow = 128;
    private const int Cell = 7;
    private const int HotFunctions = 6;

    public static void Write(string path, BinaryImage image, IEnumerable<Report> reports)
    {
        var html = new StringBuilder();
        html.Append("""
            <!DOCTYPE html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>WinBolt report</title>
            <style>
            :root { --bg:#ffffff; --fg:#1d1d1f; --muted:#6e6e73; --panel:#f5f5f7; --line:#d2d2d7; --cold:#e8e8ed; --bar:#c2410c; }
            @media (prefers-color-scheme: dark) { :root { --bg:#161618; --fg:#ececf0; --muted:#9a9aa2; --panel:#1f1f23; --line:#3a3a40; --cold:#2a2a30; --bar:#fb923c; } }
            body { background:var(--bg); color:var(--fg); font:14px/1.5 system-ui, sans-serif; margin:0 auto; max-width:1100px; padding:24px 16px; }
            h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:28px 0 8px; } h3 { font-size:14px; margin:16px 0 6px; }
            .muted { color:var(--muted); }
            pre { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:12px; overflow-x:auto; font:12px/1.45 ui-monospace, Consolas, monospace; }
            svg rect.cold { fill:var(--cold); }
            table { border-collapse:collapse; font:12px ui-monospace, Consolas, monospace; }
            td { padding:1px 8px 1px 0; white-space:nowrap; }
            .bar { height:9px; background:var(--bar); border-radius:2px; }
            .scroll { overflow-x:auto; }
            .legend { display:flex; gap:6px; align-items:center; font-size:12px; }
            </style></head><body>
            """);
        html.Append($"<h1>WinBolt report</h1><div class=\"muted\">{Encode(image.FilePath)}</div>");

        if (image.ProfileSummary is not null)
        {
            WriteHeatMap(html, image);
            WriteHotPaths(html, image);
        }

        foreach (var report in reports)
        {
            html.Append($"<h2>{Encode(report.Title)} <span class=\"muted\">(confidence: {report.Confidence})</span></h2>");
            html.Append($"<pre>{Encode(report.Body.TrimEnd())}</pre>");
        }

        html.Append("</body></html>\n");
        File.WriteAllText(path, html.ToString());
    }

    /// <summary>One cell per 4 KB page, coloured by profiled executed bytes (count × bytes), log scale.</summary>
    private static void WriteHeatMap(StringBuilder html, BinaryImage image)
    {
        var heat = new Dictionary<ulong, double>();
        var hottest = new Dictionary<ulong, (string Name, double Weight)>();
        foreach (var function in image.Functions)
        {
            foreach (var block in function.BasicBlocks.Where(b => b.ExecutionCount > 0))
            {
                for (ulong address = block.StartRva; address < block.StartRva + block.Length;)
                {
                    ulong page = address / CodeFootprint.PageSize;
                    ulong pageEnd = (page + 1) * CodeFootprint.PageSize;
                    ulong bytes = Math.Min(pageEnd, block.StartRva + block.Length) - address;
                    double weight = (double)block.ExecutionCount!.Value * bytes;
                    heat[page] = heat.GetValueOrDefault(page) + weight;
                    if (weight > hottest.GetValueOrDefault(page).Weight)
                    {
                        hottest[page] = (function.DisplayName, weight);
                    }

                    address += bytes;
                }
            }
        }

        if (heat.Count == 0)
        {
            return;
        }

        double max = Math.Log10(heat.Values.Max() + 1);
        html.Append("<h2>Code heat map</h2>");
        html.Append($"<div class=\"muted\">Each cell is a 4 KB page, {PagesPerRow} pages per row; colour is profiled executed bytes (log scale). " +
                    $"{heat.Count} pages executed. Hover for the page's hottest function.</div>");
        foreach (var section in image.Sections.Where(s => s.IsExecutable))
        {
            ulong first = section.Rva / CodeFootprint.PageSize;
            int pages = (int)((section.MappedSize + CodeFootprint.PageSize - 1) / CodeFootprint.PageSize);
            int rows = (pages + PagesPerRow - 1) / PagesPerRow;
            html.Append($"<h3>{Encode(section.Name)} <span class=\"muted\">0x{section.Rva:X}, {pages} pages</span></h3>");
            // Scales down with the page: the viewBox keeps cells square at any width.
            html.Append($"<svg viewBox=\"0 0 {PagesPerRow * (Cell + 1)} {rows * (Cell + 1)}\" width=\"100%\" style=\"max-width:{PagesPerRow * (Cell + 1)}px\" role=\"img\" aria-label=\"page heat map of {Encode(section.Name)}\">");
            for (int i = 0; i < pages; i++)
            {
                ulong page = first + (ulong)i;
                int x = i % PagesPerRow * (Cell + 1), y = i / PagesPerRow * (Cell + 1);
                if (heat.TryGetValue(page, out double weight))
                {
                    double t = Math.Log10(weight + 1) / max;
                    var (name, _) = hottest[page];
                    html.Append($"<rect x=\"{x}\" y=\"{y}\" width=\"{Cell}\" height=\"{Cell}\" fill=\"{Heat(t)}\"><title>0x{page * CodeFootprint.PageSize:X}: {Encode(name)} ({weight:N0})</title></rect>");
                }
                else
                {
                    html.Append($"<rect class=\"cold\" x=\"{x}\" y=\"{y}\" width=\"{Cell}\" height=\"{Cell}\"/>");
                }
            }

            html.Append("</svg>");
        }

        html.Append($"<div class=\"legend\"><span class=\"muted\">cold</span>{string.Concat(Enumerable.Range(0, 6).Select(i => $"<svg width=\"14\" height=\"10\"><rect width=\"14\" height=\"10\" fill=\"{Heat(i / 5.0)}\"/></svg>"))}<span class=\"muted\">hot</span></div>");
    }

    /// <summary>The hottest functions' blocks in address order, with execution bars: where the hot path runs.</summary>
    private static void WriteHotPaths(StringBuilder html, BinaryImage image)
    {
        var functions = image.Functions
            .Where(f => f.BasicBlocks.Any(b => b.ExecutionCount > 0))
            .OrderByDescending(f => f.BasicBlocks.Sum(b => (double)(b.ExecutionCount ?? 0) * b.Length))
            .Take(HotFunctions)
            .ToList();
        if (functions.Count == 0)
        {
            return;
        }

        html.Append("<h2>Hot paths</h2><div class=\"muted\">Blocks of the hottest functions in address order; bars are profiled executions.</div>");
        foreach (var function in functions)
        {
            double top = function.BasicBlocks.Max(b => (double)(b.ExecutionCount ?? 0));
            html.Append($"<h3>{Encode(function.DisplayName)} <span class=\"muted\">{function.SafetyStatus.Level}</span></h3><div class=\"scroll\"><table>");
            foreach (var block in function.BasicBlocks.OrderBy(b => b.StartRva))
            {
                double count = block.ExecutionCount ?? 0;
                int width = count == 0 ? 0 : Math.Max(1, (int)(300 * count / top));
                string successors = string.Join(" ", block.Successors.Select(e => $"{(e.Kind == EdgeKind.FallThrough ? "↓" : "→")}{e.Target.StartRva:X}:{e.ExecutionCount ?? 0}"));
                html.Append($"<tr><td>0x{block.StartRva:X}</td><td class=\"muted\">{block.Length,4} B</td><td>{count:N0}</td>" +
                            $"<td><div class=\"bar\" style=\"width:{width}px\"></div></td><td class=\"muted\">{Encode(successors)}</td></tr>");
            }

            html.Append("</table></div>");
        }
    }

    /// <summary>Yellow to deep red: the same order in light and dark themes.</summary>
    private static string Heat(double t)
    {
        t = Math.Clamp(t, 0, 1);
        int r = (int)(253 - 90 * t), g = (int)(224 - 194 * t), b = (int)(71 - 41 * t);
        return $"#{r:X2}{g:X2}{b:X2}";
    }

    private static string Encode(string text) => WebUtility.HtmlEncode(text);
}
