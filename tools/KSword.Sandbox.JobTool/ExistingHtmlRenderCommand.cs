using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Reporting;

internal static partial class ProgramMain
{
    /// <summary>
    /// Re-renders only the three HTML views from an existing report.json. This
    /// path never imports events, opens the sample, or invokes a VM provider.
    /// Existing HTML is backed up before atomic replacement so an operator can
    /// inspect the previous view if the renderer changes.
    /// </summary>
    private static int RenderExistingHtml(JobToolOptions options)
    {
        var suppliedRoot = GetOption(options, "job-root", string.Empty);
        if (string.IsNullOrWhiteSpace(suppliedRoot) || !GetBool(options, "replace-html"))
        {
            throw new ArgumentException("render-existing-html requires --job-root <existing job directory> --replace-html; only HTML files are replaced.");
        }

        var jobRoot = Path.GetFullPath(suppliedRoot);
        if (!Directory.Exists(jobRoot)) throw new DirectoryNotFoundException(jobRoot);
        EnsureNoReparseAncestorForHtml(jobRoot);
        var reportPath = Path.Combine(jobRoot, "report.json");
        if (!File.Exists(reportPath)) throw new FileNotFoundException("Existing report.json is required.", reportPath);
        EnsureNoReparseAncestorForHtml(reportPath);
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(reportPath), JsonOptions)
            ?? throw new InvalidOperationException("Existing report.json did not contain an analysis report.");
        if (report.JobId == Guid.Empty) throw new InvalidOperationException("Existing report has no job ID.");
        if (report.Sample is null) throw new InvalidOperationException("Existing report has no sample identity.");
        // Renderer can fall back to parsing the submitted PE when static PE
        // metadata is absent. This command promises HTML-only work, so refuse
        // if that executable is present on the host instead of opening it.
        if (!string.IsNullOrWhiteSpace(report.Sample.FullPath) && File.Exists(report.Sample.FullPath))
        {
            throw new InvalidOperationException("HTML-only refresh refuses an existing submitted sample path; remove it from the host before retrying.");
        }

        var indexPath = Path.Combine(jobRoot, HostArtifactIndexBuilder.IndexFileName);
        if (File.Exists(indexPath)) EnsureNoReparseAncestorForHtml(indexPath);
        var index = new HostArtifactIndexBuilder().TryReadIndex(jobRoot);
        if (index is not null && index.JobId != report.JobId)
        {
            throw new InvalidOperationException("Existing artifact-index.json job ID differs from report.json.");
        }

        var renderer = new HtmlReportRenderer();
        var english = renderer.RenderEnglish(report, index?.Artifacts, index?.Collections);
        var chinese = renderer.LocalizeChineseFromEnglish(english, report);
        var documents = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["report.en.html"] = english,
            ["report.zh.html"] = chinese,
            ["report.html"] = chinese
        };
        var backupStamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + Guid.NewGuid().ToString("N")[..8];
        var backupPaths = new List<string>();
        var pending = new List<(string Temporary, string Target)>();

        try
        {
            foreach (var (name, html) in documents)
            {
                var target = Path.Combine(jobRoot, name);
                EnsureNoReparseAncestorForHtml(target);
                var temporary = Path.Combine(jobRoot, name + ".tmp-" + backupStamp);
                File.WriteAllText(temporary, html, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                pending.Add((temporary, target));
            }

            foreach (var (_, target) in pending)
            {
                if (!File.Exists(target)) continue;
                var backup = target + ".before-timeline-" + backupStamp + ".bak";
                File.Copy(target, backup, overwrite: false);
                backupPaths.Add(backup);
            }

            foreach (var (temporary, target) in pending)
            {
                File.Move(temporary, target, overwrite: true);
            }
        }
        finally
        {
            foreach (var (temporary, _) in pending)
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        var result = new
        {
            report.JobId,
            source = reportPath,
            reportHtml = Path.Combine(jobRoot, "report.html"),
            reportHtmlZh = Path.Combine(jobRoot, "report.zh.html"),
            reportHtmlEn = Path.Combine(jobRoot, "report.en.html"),
            backups = backupPaths,
            eventCount = report.Events.Count,
            findingCount = report.Findings.Count,
            vmAction = "none",
            sampleExecuted = false,
            reportJsonChanged = false
        };
        if (GetBool(options, "json")) WriteJson(result);
        else Console.WriteLine($"HTML views refreshed from existing report.json. Job={report.JobId:D}; events={report.Events.Count}; VM action=none; sample executed=false.\n{result.reportHtmlZh}");
        return 0;
    }

    private static void EnsureNoReparseAncestorForHtml(string path)
    {
        var cursor = Path.GetFullPath(path);
        while (!string.IsNullOrWhiteSpace(cursor))
        {
            if ((File.Exists(cursor) || Directory.Exists(cursor)) &&
                (File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException($"HTML source or destination contains a reparse point: {cursor}");
            }

            var parent = Path.GetDirectoryName(cursor);
            if (string.IsNullOrWhiteSpace(parent) || parent == cursor) break;
            cursor = parent;
        }
    }
}
