using System.Text.Json;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Pipeline;
using KSword.Sandbox.Core.Reporting;

namespace KSword.Sandbox.Core.Pipeline.Stages;

/// <summary>
/// Persists report artifacts for a pipeline-generated report.
/// Inputs are pipeline context and runtime paths; processing writes JSON and
/// HTML when a report exists; the stage returns after files are flushed.
/// </summary>
public sealed class ReportArtifactStage : IAnalysisPipelineStage
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly HostArtifactIndexBuilder artifactIndexBuilder = new();
    private readonly HtmlReportRenderer renderer = new();

    public string StageId => "report.artifacts.write";

    public string Title => "Write report artifacts";

    /// <inheritdoc />
    public Task ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default)
    {
        if (context.Report is null)
        {
            return Task.CompletedTask;
        }

        var jobRoot = Path.Combine(context.Config.Paths.RuntimeRoot, "jobs", context.JobId.ToString("N"));
        Directory.CreateDirectory(jobRoot);
        File.WriteAllText(Path.Combine(jobRoot, "report.json"), JsonSerializer.Serialize(context.Report, JsonOptions));
        var currentIndex = artifactIndexBuilder.Build(context.JobId, jobRoot, context.Config.ArtifactCollection);
        File.WriteAllText(Path.Combine(jobRoot, "report.html"), renderer.RenderChinese(context.Report, currentIndex.Artifacts));
        foreach (var document in renderer.RenderBilingualReports(context.Report, currentIndex.Artifacts))
        {
            File.WriteAllText(Path.Combine(jobRoot, document.FileName), document.Html);
        }

        artifactIndexBuilder.WriteIndex(context.JobId, jobRoot, context.Config.ArtifactCollection);
        return Task.CompletedTask;
    }
}
