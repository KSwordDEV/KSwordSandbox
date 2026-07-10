using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the static R0 file minifilter telemetry contract without loading a
/// driver. Inputs are repository paths from SmokeTestContext; processing reads
/// source, ABI, and documentation files for required operation and evidence
/// markers; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class R0FileMonitorContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.file-monitor.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fileFilter = ReadRepositoryText(context, "driver", "KSword.Sandbox.Driver", "src", "Producers", "File", "FileFilter.c");
        var driverAbi = ReadRepositoryText(context, "driver", "KSword.Sandbox.Driver", "include", "KSwordSandboxDriverIoctl.h");
        var contractDoc = ReadRepositoryText(context, "docs", "r0-file-monitor.md");

        RequireContains(fileFilter, "IRP_MJ_CREATE", "File minifilter should register create telemetry.");
        RequireContains(fileFilter, "IRP_MJ_READ", "File minifilter should register read telemetry.");
        RequireContains(fileFilter, "IRP_MJ_WRITE", "File minifilter should register write telemetry.");
        RequireContains(fileFilter, "IRP_MJ_SET_INFORMATION", "File minifilter should register set-information telemetry.");
        RequireContains(fileFilter, "IRP_MJ_CLEANUP", "File minifilter should register cleanup telemetry.");
        RequireContains(fileFilter, "IRP_MJ_CLOSE", "File minifilter should register close telemetry.");
        RequireContains(fileFilter, "KswSandboxFileOperationRead", "Read operations should have a stable public operation value.");
        RequireContains(fileFilter, "KswSandboxFileOperationRename", "Rename set-information classes should map to rename telemetry.");
        RequireContains(fileFilter, "KswSandboxFileOperationDelete", "Disposition set-information classes should map to delete telemetry.");
        RequireContains(fileFilter, "KswSandboxFileOperationSetInformation", "Other set-information classes should remain visible.");
        RequireContains(fileFilter, "FLT_FILE_NAME_NORMALIZED", "File paths should prefer FltMgr-normalized names.");
        RequireContains(fileFilter, "FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP", "File paths should have a safe cache-only normalized lookup fallback.");
        RequireContains(fileFilter, "KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED", "Path truncation should be flagged.");
        RequireContains(fileFilter, "KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED", "Normalized path provenance should be flagged.");
        RequireContains(fileFilter, "KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK", "Fallback path provenance should be flagged.");
        RequireContains(fileFilter, "KswShouldSuppressFilePayload", "Sandbox self-path events should be filtered before queueing.");
        RequireContains(fileFilter, "\\KSwordSandbox\\incoming\\", "Self-path policy should deliberately document/keep incoming paths observable.");
        RequireContains(fileFilter, "KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT", "Post callbacks should expose final status.");
        RequireContains(fileFilter, "KswPushEvent", "File telemetry should still flow through the common READ_EVENTS ring.");

        RequireContains(driverAbi, "KswSandboxFileOperationRead = 7", "Public ABI should append a read operation without renumbering existing values.");
        RequireContains(driverAbi, "KswSandboxFileOperationRename = 8", "Public ABI should append a rename operation without renumbering existing values.");
        RequireContains(driverAbi, "KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED", "Public ABI should define the normalized-path flag.");
        RequireContains(driverAbi, "KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK", "Public ABI should define the fallback-path flag.");

        RequireContains(contractDoc, "IRP_MJ_CREATE", "R0 file monitor doc should list create coverage.");
        RequireContains(contractDoc, "IRP_MJ_READ", "R0 file monitor doc should list read coverage.");
        RequireContains(contractDoc, "IRP_MJ_WRITE", "R0 file monitor doc should list write coverage.");
        RequireContains(contractDoc, "IRP_MJ_SET_INFORMATION", "R0 file monitor doc should list set-information coverage.");
        RequireContains(contractDoc, "IRP_MJ_CLEANUP", "R0 file monitor doc should list cleanup coverage.");
        RequireContains(contractDoc, "IRP_MJ_CLOSE", "R0 file monitor doc should list close coverage.");
        RequireContains(contractDoc, "pathNormalized", "R0 file monitor doc should define normalized path evidence.");
        RequireContains(contractDoc, "pathTruncated", "R0 file monitor doc should define truncated path evidence.");
        RequireContains(contractDoc, "dropEvidenceKind", "R0 file monitor doc should design drop-file evidence fields.");
        RequireContains(contractDoc, "dropConfidence", "R0 file monitor doc should design drop-file confidence fields.");
        RequireContains(contractDoc, "firstSeenSequence", "R0 file monitor doc should preserve event sequence evidence for drops.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 file minifilter telemetry source, ABI, and documentation contracts are present."
        });
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are the smoke context and relative path segments; processing joins
    /// the path under RepositoryRoot and reads the file; the method returns the
    /// complete file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires that a text block contains a literal value.
    /// Inputs are text, expected literal, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
