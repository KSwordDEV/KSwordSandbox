using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Optionally captures best-effort minidumps for the launched sample process
/// and its visible descendants.
/// Inputs are after-start/after-run probe phases, root process ID, and an
/// explicit CLI opt-in flag; processing delegates to a platform capture
/// implementation and reuses the low-privilege process snapshot provider;
/// CollectAsync returns memory_dump.captured, memory_dump.skipped, and
/// memory_dump.sweep events.
/// </summary>
internal sealed class MemoryDumpProbe : IGuestProbe
{
    private const string ReasonTaxonomy = "guest-artifact.memory-dump.reason.v1";
    private const string CoverageTaxonomy = "guest-artifact.memory-dump.coverage.v1";
    private const string ArtifactSelectorVersion = "artifact-selectors-v1";

    private readonly IProcessMemoryDumpCapture dumpCapture;
    private readonly IProcessSnapshotProvider snapshotProvider;
    private readonly HashSet<int> capturedProcessIds = [];
    private readonly Dictionary<int, CapturedMemoryDumpArtifact> capturedArtifactsByProcessId = [];
    private int? rememberedRootProcessId;

    public MemoryDumpProbe()
        : this(new WindowsMiniDumpCapture(), new ProcessSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a memory dump probe with an injectable capture implementation.
    /// The input is a dump capture service, processing stores it for future
    /// phases, and the constructor returns no value.
    /// </summary>
    public MemoryDumpProbe(IProcessMemoryDumpCapture dumpCapture)
        : this(dumpCapture, new ProcessSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a memory dump probe with injectable capture and process snapshot
    /// providers. Inputs are services used by the probe; processing stores
    /// them for future phases; the constructor returns no value.
    /// </summary>
    public MemoryDumpProbe(
        IProcessMemoryDumpCapture dumpCapture,
        IProcessSnapshotProvider snapshotProvider)
    {
        this.dumpCapture = dumpCapture;
        this.snapshotProvider = snapshotProvider;
    }

    public string ProbeId => "memory-dump";

    /// <summary>
    /// Captures opt-in minidumps while the sample process is running and after
    /// the run has produced descendants.
    /// Inputs are phase, guest context, and cancellation token; processing skips
    /// by default, captures the root process at AfterStart as a safety net, and
    /// sweeps the visible root/child process tree at Cleanup/AfterRun; the
    /// method returns diagnostic events for enabled attempts.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!context.CaptureMemoryDump)
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateDisabledEvent(context)]
                : [];
        }

        var phaseLabel = ToPhaseLabel(phase);
        if (context.RootProcessId is not null)
        {
            rememberedRootProcessId = context.RootProcessId.Value;
        }

        return phase switch
        {
            ProbePhase.AfterStart => await CaptureRootSafetyNetAsync(context, phaseLabel, cancellationToken).ConfigureAwait(false),
            ProbePhase.Cleanup => await CaptureVisibleProcessTreeAsync(context, phaseLabel, cancellationToken).ConfigureAwait(false),
            ProbePhase.AfterRun => await CaptureVisibleProcessTreeAsync(context, phaseLabel, cancellationToken).ConfigureAwait(false),
            _ => []
        };
    }

    /// <summary>
    /// Captures the root process once while it is most likely still alive.
    /// Inputs are context, phase label, and cancellation token; processing
    /// writes one root dump or a non-fatal skipped event; the method returns
    /// memory dump events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CaptureRootSafetyNetAsync(
        GuestProbeContext context,
        string phaseLabel,
        CancellationToken cancellationToken)
    {
        if (rememberedRootProcessId is null)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Sample root process ID is not available for memory dump capture.",
                        processId: null,
                        diagnosticStage: "root-process"),
                    phaseLabel,
                    target: null,
                    rootProcessId: null,
                    duplicate: false)
            ];
        }

        var target = new MemoryDumpTarget(
            rememberedRootProcessId.Value,
            ParentProcessId: context.RootParentProcessId,
            ProcessName: context.RootProcessName ?? SampleProcessName(context.SamplePath) ?? "root",
            Path: context.RootProcessPath ?? context.SamplePath,
            Depth: 0,
            Lineage: rememberedRootProcessId.Value.ToString(CultureInfo.InvariantCulture),
            IsRoot: true,
            StartTimeUtc: context.RootProcessStartTimeUtc,
            SessionId: null,
            ThreadCount: null,
            BasePriority: null,
            SnapshotKey: string.Empty,
            RootVisibleInSnapshot: true,
            SelectionSource: "after-start-root-safety-net");
        return [await CaptureTargetAsync(context, phaseLabel, target, rememberedRootProcessId.Value, cancellationToken).ConfigureAwait(false)];
    }

    /// <summary>
    /// Captures root plus visible descendants at a final or pre-kill sweep.
    /// Inputs are context, phase label, and cancellation token; processing
    /// snapshots processes, walks the root child tree, skips already captured
    /// PIDs, and writes a summary event; the method returns sweep events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CaptureVisibleProcessTreeAsync(
        GuestProbeContext context,
        string phaseLabel,
        CancellationToken cancellationToken)
    {
        var rootProcessId = context.RootProcessId ?? rememberedRootProcessId;
        if (rootProcessId is null)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Sample root process ID is not available for final memory dump sweep.",
                        processId: null,
                        diagnosticStage: "root-process-final"),
                    phaseLabel,
                    target: null,
                    rootProcessId: null,
                    duplicate: false)
            ];
        }

        Dictionary<int, ProcessTreeSnapshot> snapshot;
        try
        {
            snapshot = snapshotProvider.Capture(cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or UnauthorizedAccessException)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Process tree snapshot failed before final memory dump sweep.",
                        rootProcessId.Value,
                        ex.GetType().FullName ?? ex.GetType().Name,
                        diagnosticStage: "process-tree-snapshot"),
                    phaseLabel,
                    target: null,
                    rootProcessId: rootProcessId.Value,
                    duplicate: false)
            ];
        }

        var events = new List<SandboxEvent>();
        var rootPidReuseSkipped = false;
        if (TryGetRootPidReuseSnapshot(snapshot, context, rootProcessId.Value, out var pidReuseSnapshot))
        {
            events.Add(CreateRootPidReuseSkippedEvent(phaseLabel, rootProcessId.Value, pidReuseSnapshot));
            rootPidReuseSkipped = true;
        }

        var targets = BuildVisibleDumpTargets(snapshot, context, rootProcessId.Value);
        var alreadyCaptured = 0;
        var attempted = 0;
        var captured = 0;
        var skipped = 0;
        var rootTargetCount = targets.Count(static target => target.IsRoot);
        var childTargetCount = targets.Count(static target => !target.IsRoot);
        var rootAttempted = 0;
        var childAttempted = 0;
        var rootCaptured = 0;
        var childCaptured = 0;
        var rootSkipped = 0;
        var childSkipped = 0;
        var rootAlreadyCaptured = 0;
        var childAlreadyCaptured = 0;
        var directChildTargetCount = targets.Count(static target => !target.IsRoot && target.Depth == 1);
        var deeperDescendantTargetCount = targets.Count(static target => !target.IsRoot && target.Depth > 1);
        var directChildAttempted = 0;
        var deeperDescendantAttempted = 0;
        var directChildCaptured = 0;
        var deeperDescendantCaptured = 0;
        var directChildSkipped = 0;
        var deeperDescendantSkipped = 0;
        var directChildAlreadyCaptured = 0;
        var deeperDescendantAlreadyCaptured = 0;

        foreach (var target in targets.OrderBy(target => target.Depth).ThenBy(target => target.ProcessId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (capturedProcessIds.Contains(target.ProcessId))
            {
                alreadyCaptured++;
                if (target.IsRoot)
                {
                    rootAlreadyCaptured++;
                }
                else
                {
                    childAlreadyCaptured++;
                    if (target.Depth == 1)
                    {
                        directChildAlreadyCaptured++;
                    }
                    else
                    {
                        deeperDescendantAlreadyCaptured++;
                    }
                }

                events.Add(CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Process memory dump was already captured earlier in this run.",
                        target.ProcessId,
                        diagnosticStage: "duplicate"),
                    phaseLabel,
                    target,
                    rootProcessId.Value,
                    duplicate: true));
                continue;
            }

            attempted++;
            if (target.IsRoot)
            {
                rootAttempted++;
            }
            else
            {
                childAttempted++;
                if (target.Depth == 1)
                {
                    directChildAttempted++;
                }
                else
                {
                    deeperDescendantAttempted++;
                }
            }

            var evt = await CaptureTargetAsync(context, phaseLabel, target, rootProcessId.Value, cancellationToken).ConfigureAwait(false);
            if (string.Equals(evt.EventType, "memory_dump.captured", StringComparison.OrdinalIgnoreCase))
            {
                captured++;
                if (target.IsRoot)
                {
                    rootCaptured++;
                }
                else
                {
                    childCaptured++;
                    if (target.Depth == 1)
                    {
                        directChildCaptured++;
                    }
                    else
                    {
                        deeperDescendantCaptured++;
                    }
                }
            }
            else
            {
                skipped++;
                if (target.IsRoot)
                {
                    rootSkipped++;
                }
                else
                {
                    childSkipped++;
                    if (target.Depth == 1)
                    {
                        directChildSkipped++;
                    }
                    else
                    {
                        deeperDescendantSkipped++;
                    }
                }
            }

            events.Add(evt);
        }

        if (targets.Count == 0)
        {
            events.Add(CreateSkippedEvent(
                MemoryDumpCaptureResult.Skipped(
                    "No visible root or child processes were available for final memory dump sweep.",
                    rootProcessId.Value,
                    diagnosticStage: "process-tree-empty"),
                phaseLabel,
                target: null,
                rootProcessId: rootProcessId.Value,
                duplicate: false));
        }

        var sweepEvent = CreateSweepEvent(
            phaseLabel,
            rootProcessId.Value,
            targets.Count,
            attempted,
            captured,
            skipped,
            alreadyCaptured,
            rootTargetCount,
            childTargetCount,
            rootAttempted,
            childAttempted,
            rootCaptured,
            childCaptured,
            rootSkipped,
            childSkipped,
            rootAlreadyCaptured,
            childAlreadyCaptured,
            directChildTargetCount,
            deeperDescendantTargetCount,
            directChildAttempted,
            deeperDescendantAttempted,
            directChildCaptured,
            deeperDescendantCaptured,
            directChildSkipped,
            deeperDescendantSkipped,
            directChildAlreadyCaptured,
            deeperDescendantAlreadyCaptured,
            rootPidReuseSkipped);
        AddMemoryDumpSweepArtifactSelectors(sweepEvent, events);
        events.Add(sweepEvent);
        return events;
    }

    /// <summary>
    /// Captures one target process and converts the result into an event.
    /// Inputs are context, phase, target metadata, root PID, and cancellation;
    /// processing delegates to the dump capture service and stores tree
    /// metadata; the method returns one SandboxEvent.
    /// </summary>
    private async Task<SandboxEvent> CaptureTargetAsync(
        GuestProbeContext context,
        string phaseLabel,
        MemoryDumpTarget target,
        int rootProcessId,
        CancellationToken cancellationToken)
    {
        var duplicate = capturedProcessIds.Contains(target.ProcessId);
        var result = duplicate
            ? MemoryDumpCaptureResult.Skipped(
                "Process memory dump was already captured earlier in this run.",
                target.ProcessId,
                diagnosticStage: "duplicate")
            : await dumpCapture.CaptureAsync(context.OutputDirectory, target.ProcessId, phaseLabel, cancellationToken).ConfigureAwait(false);
        var evt = result.Captured
            ? CreateCapturedEvent(result, phaseLabel, target, rootProcessId, context.OutputDirectory)
            : CreateSkippedEvent(result, phaseLabel, target, rootProcessId, duplicate);
        if (result.Captured && result.ProcessId is not null)
        {
            capturedProcessIds.Add(result.ProcessId.Value);
            RememberCapturedArtifact(result.ProcessId.Value, evt);
        }
        else if (duplicate && target is not null)
        {
            AddCapturedArtifactReference(evt, target.ProcessId);
        }

        return evt;
    }

    /// <summary>
    /// Creates a memory_dump.captured event with process-tree metadata.
    /// </summary>
    private SandboxEvent CreateCapturedEvent(
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId,
        string outputDirectory)
    {
        var evt = CreateBaseEvent("memory_dump.captured", result, phaseLabel, target, rootProcessId);
        evt.Data["captureState"] = "captured";
        evt.Data["status"] = "captured";
        evt.Data["childProcessDumpTarget"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["artifactAttemptEvent"] = "true";
        evt.Data["targetDumpOutcome"] = "captured";
        evt.Data["childProcessDumpOutcome"] = target is null || target.IsRoot ? "not-child-target" : "captured";
        evt.Data["childProcessArtifactEvent"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["nonfatal"] = "false";
        evt.Data["artifactEvent"] = "true";
        evt.Data["summaryRow"] = "false";
        evt.Data["reportRowKind"] = "memory-dump-artifact";
        evt.Data["eventSemanticClass"] = "artifact-memory-dump";
        evt.Data["semanticEventCategory"] = "artifact-evidence";
        evt.Data["semanticEventTags"] = "artifact,memory-dump,captured,nonbehavior";
        evt.Data["artifactSemanticType"] = "memory-dump";
        evt.Data["behaviorCounted"] = "false";
        evt.Data["nonbehavior"] = "true";
        evt.Data["reason"] = "memoryDumpCaptured";
        evt.Data["reasonCode"] = "memoryDumpCaptured";
        evt.Data["reasonCategory"] = "captured";
        evt.Data["reasonTaxonomy"] = ReasonTaxonomy;
        evt.Data["reasonTaxonomyVersion"] = "v1";
        evt.Data["artifactSelectorVersion"] = ArtifactSelectorVersion;
        evt.Data["artifactIntegrityState"] = "pending-hash";
        evt.Data["zhMessage"] = "内存转储已采集为可下载证据文件。";
        evt.Data["zhHint"] = "内存转储可能包含敏感内容；请使用 artifactRelativePath 下载，并用 sizeBytes/sha256 校验完整性。";
        if (result.SizeBytes is not null)
        {
            evt.Data["sizeBytes"] = result.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = result.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["sizeBytesStatus"] = "computed";
        }

        if (!string.IsNullOrWhiteSpace(result.Path))
        {
            var artifactPath = ResolveArtifactRelativePath(outputDirectory, result.Path);
            evt.Data["relativePath"] = artifactPath.DisplayPath;
            evt.Data["memoryDumpPath"] = result.Path;
            evt.Data["dumpPath"] = result.Path;
            evt.Data["memoryDumpRelativePath"] = artifactPath.DisplayPath;
            evt.Data["dumpRelativePath"] = artifactPath.DisplayPath;
            evt.Data["artifactFullPath"] = result.Path;
            if (artifactPath.IsOutputRelative)
            {
                AddOptionalData(evt, "artifactRelativePath", artifactPath.DisplayPath);
                AddOptionalData(evt, "artifactSelector", artifactPath.DisplayPath);
                AddOptionalData(evt, "stableArtifactSelector", artifactPath.DisplayPath);
                AddOptionalData(evt, "canonicalArtifactSelector", artifactPath.DisplayPath);
                AddOptionalData(evt, "downloadSelector", artifactPath.DisplayPath);
                AddOptionalData(evt, "artifactSafeLink", BuildSafeLink(artifactPath.DisplayPath));
                evt.Data["artifactSelectorKind"] = "safe-output-relative-path";
                evt.Data["artifactSelectionReason"] = target is null ? "memory-dump-captured" : $"memory-dump-{evt.Data["targetProcessRole"]}";
            }

            evt.Data["artifactRelativePathStatus"] = artifactPath.Status;
            AddArtifactFileEvidence(evt, result.Path);
        }
        else
        {
            evt.Data["artifactRelativePathStatus"] = "missing";
            evt.Data["sizeBytesStatus"] = "missing";
            evt.Data["sha256Status"] = "missing";
        }

        return evt;
    }

    /// <summary>
    /// Creates a memory_dump.skipped event with process-tree metadata.
    /// </summary>
    private SandboxEvent CreateSkippedEvent(
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId,
        bool duplicate)
    {
        var evt = CreateBaseEvent("memory_dump.skipped", result, phaseLabel, target, rootProcessId);
        evt.Data["captureState"] = "skipped";
        evt.Data["status"] = "skipped";
        evt.Data["nonfatal"] = "true";
        evt.Data["artifactEvent"] = "false";
        evt.Data["summaryRow"] = "false";
        evt.Data["reportRowKind"] = duplicate ? "memory-dump-artifact-reference" : "memory-dump-diagnostic";
        evt.Data["eventSemanticClass"] = duplicate ? "artifact-memory-dump-reference" : "artifact-memory-dump-diagnostic";
        evt.Data["semanticEventCategory"] = "artifact-evidence";
        evt.Data["semanticEventTags"] = duplicate ? "artifact,memory-dump,duplicate-reference,nonbehavior" : "artifact,memory-dump,skipped,nonbehavior";
        evt.Data["artifactSemanticType"] = "memory-dump";
        evt.Data["behaviorCounted"] = "false";
        evt.Data["nonbehavior"] = "true";
        evt.Data["collectionHealth"] = "true";
        evt.Data["artifactExists"] = "false";
        evt.Data["artifactIntegrityState"] = "skipped";
        evt.Data["artifactRelativePathStatus"] = duplicate ? "already-captured" : "not-created";
        evt.Data["artifactAttemptEvent"] = "true";
        evt.Data["artifactDiagnosticEvent"] = "true";
        evt.Data["sizeBytesStatus"] = "not-created";
        evt.Data["sha256Status"] = "not-created";
        evt.Data["duplicate"] = duplicate.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["alreadyCaptured"] = duplicate.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["childProcessDumpTarget"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["targetDumpOutcome"] = duplicate ? "already-captured" : "skipped";
        evt.Data["childProcessDumpOutcome"] = target is null || target.IsRoot ? "not-child-target" : duplicate ? "already-captured" : "skipped";
        evt.Data["childProcessArtifactEvent"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        if (duplicate)
        {
            evt.Data["artifactReferenceEvent"] = "true";
            evt.Data["artifactSelectorState"] = "references-existing-capture";
            evt.Data["zhHint"] = "该进程的内存转储已在本次运行中采集过；请使用 existingArtifactSelector/artifactRelativePath 下载已存在的转储，并用 sizeBytes/sha256 校验完整性。";
        }

        AddOptionalData(evt, "reason", result.Reason);
        evt.Data["reasonCode"] = MemoryDumpReasonCode(result, duplicate);
        evt.Data["reasonCategory"] = MemoryDumpReasonCategory(result, duplicate);
        evt.Data["reasonTaxonomy"] = ReasonTaxonomy;
        evt.Data["reasonTaxonomyVersion"] = "v1";
        evt.Data["zhReason"] = MemoryDumpReasonZhReason(result, duplicate);
        AddOptionalData(evt, "zhMessage", "内存转储采集被跳过；该事件说明证据缺口，不会中断整体分析。");
        AddOptionalData(evt, "zhHint", MemoryDumpReasonZhHint(result.Reason, result.DiagnosticStage, duplicate));
        AddOptionalData(evt, "exceptionType", result.ExceptionType);
        AddOptionalData(evt, "diagnosticStage", result.DiagnosticStage);
        if (IsExitedBeforeDump(result.Reason, result.DiagnosticStage))
        {
            evt.Data["processExited"] = "true";
            evt.Data["exitMissing"] = "true";
            evt.Data["exitedBeforeDump"] = "true";
        }

        if (result.Win32Error is not null)
        {
            evt.Data["win32Error"] = result.Win32Error.Value.ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Creates base event fields shared by captured/skipped dump attempts.
    /// </summary>
    private static SandboxEvent CreateBaseEvent(
        string eventType,
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = result.Path,
            ProcessId = result.ProcessId,
            ProcessName = target?.ProcessName,
            ParentProcessId = target?.ParentProcessId,
            CommandLine = target?.Path,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--memory-dump/--memory-dumps",
                ["sensitiveArtifact"] = "true",
                ["sensitiveArtifactReason"] = "process-memory-dump",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-sensitive-memory-dump",
                ["childProcessDumpEnabled"] = "true",
                ["childProcessDumpMode"] = "visible-root-tree",
                ["dumpType"] = result.DumpType,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["expectedRelativePath"] = "memory-dumps/*.dmp",
                ["dumpTargetSelectionMode"] = "root-plus-visible-descendants",
                ["descendantProcessDumpEnabled"] = "true",
                ["rootProcessIdStatus"] = rootProcessId is null ? "unavailable" : "available",
                ["treeLineageStatus"] = rootProcessId is null ? "unavailable" : "stable",
                ["artifactIntegrityState"] = "pending"
            }
        };

        if (result.ProcessId is not null)
        {
            evt.Data["processId"] = result.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (rootProcessId is not null)
        {
            evt.Data["rootProcessId"] = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data.TryAdd("treeLineage", rootProcessId.Value.ToString(CultureInfo.InvariantCulture));
            evt.Data.TryAdd("treeDepth", "0");
            evt.Data.TryAdd("processRole", "sample-root-context");
        }

        if (target is not null)
        {
            var targetRole = target.IsRoot ? "root" : target.Depth == 1 ? "direct-child" : "descendant";
            evt.Data["processRole"] = targetRole;
            evt.Data["treeDepth"] = target.Depth.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeLineage"] = target.Lineage;
            evt.Data["treeLineageStatus"] = string.IsNullOrWhiteSpace(target.Lineage) ? "unavailable" : "stable";
            evt.Data["rootProcessDumpTarget"] = target.IsRoot.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["childProcessDumpTarget"] = (!target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["descendantProcessDumpTarget"] = (!target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["directChildProcessDumpTarget"] = (!target.IsRoot && target.Depth == 1).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["deeperDescendantProcessDumpTarget"] = (!target.IsRoot && target.Depth > 1).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["memoryDumpCoverageRole"] = targetRole;
            evt.Data["childProcessScope"] = target.IsRoot ? "root-only" : target.Depth == 1 ? "direct-child" : "deeper-descendant";
            evt.Data["childProcessScopeSummary"] = target.IsRoot
                ? "target=root"
                : $"target={targetRole};depth={target.Depth.ToString(CultureInfo.InvariantCulture)};lineage={target.Lineage}";
            evt.Data["targetProcessId"] = target.ProcessId.ToString(CultureInfo.InvariantCulture);
            evt.Data["targetProcessName"] = target.ProcessName;
            evt.Data["targetSelectionSource"] = target.SelectionSource;
            evt.Data["targetTreeDepth"] = target.Depth.ToString(CultureInfo.InvariantCulture);
            evt.Data["targetTreeLineage"] = target.Lineage;
            evt.Data["targetProcessRole"] = targetRole;
            evt.Data["rootAncestorProcessId"] = rootProcessId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
            evt.Data["rootVisibleInSnapshot"] = target.RootVisibleInSnapshot.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["isRootProcess"] = target.IsRoot.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["isChildProcess"] = (!target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["isDescendantOfRoot"] = (!target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["isDirectChildOfRoot"] = (!target.IsRoot && target.Depth == 1).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["lineageIncludesRoot"] = (!string.IsNullOrWhiteSpace(target.Lineage) &&
                rootProcessId is not null &&
                LineageContainsPid(target.Lineage, rootProcessId.Value)).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            if (target.StartTimeUtc is not null)
            {
                evt.Data["targetProcessStartTimeUtc"] = target.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            }

            if (target.SessionId is not null)
            {
                evt.Data["targetSessionId"] = target.SessionId.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (target.ThreadCount is not null)
            {
                evt.Data["targetThreadCount"] = target.ThreadCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (target.BasePriority is not null)
            {
                evt.Data["targetBasePriority"] = target.BasePriority.Value.ToString(CultureInfo.InvariantCulture);
            }

            evt.Data["dumpTargetKey"] = string.IsNullOrWhiteSpace(target.SnapshotKey)
                ? target.ProcessId.ToString(CultureInfo.InvariantCulture)
                : target.SnapshotKey;
            evt.Data["duplicateKeyMode"] = "pid";
            evt.Data["pidReuseGuarded"] = string.IsNullOrWhiteSpace(target.SnapshotKey) ? "false" : "snapshot-key-recorded";
            AddOptionalData(evt, "processName", target.ProcessName);
            AddOptionalData(evt, "targetProcessPath", target.Path);
            AddOptionalData(evt, "processPath", target.Path);
            AddOptionalData(evt, "snapshotKey", target.SnapshotKey);
            if (target.ParentProcessId is not null)
            {
                evt.Data["parentProcessId"] = target.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
                evt.Data["targetParentProcessId"] = target.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
            }
        }
        else
        {
            evt.Data["rootProcessDumpTarget"] = rootProcessId is not null ? "true" : "false";
            evt.Data["childProcessDumpTarget"] = "false";
            evt.Data["descendantProcessDumpTarget"] = "false";
            evt.Data["memoryDumpCoverageRole"] = rootProcessId is null ? "unknown" : "root-context";
            evt.Data["rootVisibleInSnapshot"] = "unknown";
            evt.Data["lineageIncludesRoot"] = rootProcessId is not null ? "true" : "false";
        }

        return evt;
    }

    /// <summary>
    /// Creates a memory_dump.sweep summary event for final tree capture.
    /// </summary>
    private static SandboxEvent CreateSweepEvent(
        string phaseLabel,
        int rootProcessId,
        int visibleTargetCount,
        int attemptedCount,
        int capturedCount,
        int skippedCount,
        int alreadyCapturedCount,
        int rootTargetCount,
        int childTargetCount,
        int rootAttemptedCount,
        int childAttemptedCount,
        int rootCapturedCount,
        int childCapturedCount,
        int rootSkippedCount,
        int childSkippedCount,
        int rootAlreadyCapturedCount,
        int childAlreadyCapturedCount,
        int directChildTargetCount,
        int deeperDescendantTargetCount,
        int directChildAttemptedCount,
        int deeperDescendantAttemptedCount,
        int directChildCapturedCount,
        int deeperDescendantCapturedCount,
        int directChildSkippedCount,
        int deeperDescendantSkippedCount,
        int directChildAlreadyCapturedCount,
        int deeperDescendantAlreadyCapturedCount,
        bool rootPidReuseSkipped)
    {
        return new SandboxEvent
        {
            EventType = "memory_dump.sweep",
            Source = "guest",
            ProcessId = rootProcessId,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--memory-dump/--memory-dumps",
                ["sensitiveArtifact"] = "true",
                ["sensitiveArtifactReason"] = "process-memory-dump",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-sensitive-memory-dump",
                ["childProcessDumpEnabled"] = "true",
                ["childProcessDumpMode"] = "visible-root-tree",
                ["captureState"] = "summary",
                ["status"] = "summary",
                ["summaryEvent"] = "true",
                ["summaryRow"] = "true",
                ["reportRowKind"] = "memory-dump-sweep-summary",
                ["eventSemanticClass"] = "artifact-memory-dump-summary",
                ["semanticEventCategory"] = "artifact-evidence",
                ["semanticEventTags"] = "artifact,memory-dump,sweep,summary,nonbehavior",
                ["artifactSemanticType"] = "memory-dump",
                ["nonfatal"] = "false",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["reason"] = "memoryDumpSweepCompleted",
                ["reasonCode"] = "memoryDumpSweepCompleted",
                ["reasonCategory"] = "summary",
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["coverageTaxonomy"] = CoverageTaxonomy,
                ["coverageTaxonomyVersion"] = "v1",
                ["dumpType"] = MemoryDumpCaptureResult.MiniDumpTypeName,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["expectedRelativePath"] = "memory-dumps/*.dmp",
                ["artifactRelativePathStatus"] = "not-applicable-summary",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "not-applicable-summary",
                ["sizeBytesStatus"] = "not-applicable-summary",
                ["sha256Status"] = "not-applicable-summary",
                ["dumpTargetSelectionMode"] = "root-plus-visible-descendants",
                ["descendantProcessDumpEnabled"] = "true",
                ["rootProcessId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processRole"] = "root",
                ["treeDepth"] = "0",
                ["treeLineage"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["rootProcessIdStatus"] = "available",
                ["treeLineageStatus"] = "stable",
                ["visibleTargetCount"] = visibleTargetCount.ToString(CultureInfo.InvariantCulture),
                ["attemptedCount"] = attemptedCount.ToString(CultureInfo.InvariantCulture),
                ["capturedCount"] = capturedCount.ToString(CultureInfo.InvariantCulture),
                ["skippedCount"] = skippedCount.ToString(CultureInfo.InvariantCulture),
                ["alreadyCapturedCount"] = alreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootTargetCount"] = rootTargetCount.ToString(CultureInfo.InvariantCulture),
                ["childTargetCount"] = childTargetCount.ToString(CultureInfo.InvariantCulture),
                ["descendantTargetCount"] = childTargetCount.ToString(CultureInfo.InvariantCulture),
                ["directChildTargetCount"] = directChildTargetCount.ToString(CultureInfo.InvariantCulture),
                ["deeperDescendantTargetCount"] = deeperDescendantTargetCount.ToString(CultureInfo.InvariantCulture),
                ["rootAttemptedCount"] = rootAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["childAttemptedCount"] = childAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["descendantAttemptedCount"] = childAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["directChildAttemptedCount"] = directChildAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["deeperDescendantAttemptedCount"] = deeperDescendantAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["rootCapturedCount"] = rootCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["childCapturedCount"] = childCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["descendantCapturedCount"] = childCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["directChildCapturedCount"] = directChildCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["deeperDescendantCapturedCount"] = deeperDescendantCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootSkippedCount"] = rootSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["childSkippedCount"] = childSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["descendantSkippedCount"] = childSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["directChildSkippedCount"] = directChildSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["deeperDescendantSkippedCount"] = deeperDescendantSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["rootAlreadyCapturedCount"] = rootAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["childAlreadyCapturedCount"] = childAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["descendantAlreadyCapturedCount"] = childAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["directChildAlreadyCapturedCount"] = directChildAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["deeperDescendantAlreadyCapturedCount"] = deeperDescendantAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootPidReuseSkipped"] = rootPidReuseSkipped.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["rootPidReuseSkippedCount"] = (rootPidReuseSkipped ? 1 : 0).ToString(CultureInfo.InvariantCulture),
                ["rootProcessCoverageState"] = DetermineDumpCoverageState(rootTargetCount, rootAttemptedCount, rootCapturedCount, rootSkippedCount, rootAlreadyCapturedCount),
                ["childProcessCoverageState"] = DetermineDumpCoverageState(childTargetCount, childAttemptedCount, childCapturedCount, childSkippedCount, childAlreadyCapturedCount),
                ["directChildCoverageState"] = DetermineDumpCoverageState(directChildTargetCount, directChildAttemptedCount, directChildCapturedCount, directChildSkippedCount, directChildAlreadyCapturedCount),
                ["deeperDescendantCoverageState"] = DetermineDumpCoverageState(deeperDescendantTargetCount, deeperDescendantAttemptedCount, deeperDescendantCapturedCount, deeperDescendantSkippedCount, deeperDescendantAlreadyCapturedCount),
                ["memoryDumpCoverageState"] = DetermineDumpCoverageState(visibleTargetCount, attemptedCount, capturedCount, skippedCount, alreadyCapturedCount),
                ["rootDescendantCoverageState"] = DetermineRootDescendantCoverageState(rootTargetCount, childTargetCount, rootCapturedCount, childCapturedCount, rootAlreadyCapturedCount, childAlreadyCapturedCount),
                ["descendantCoverageCompleteness"] = DetermineDescendantCoverageCompleteness(childTargetCount, directChildTargetCount, deeperDescendantTargetCount, childCapturedCount, childAlreadyCapturedCount, directChildCapturedCount, directChildAlreadyCapturedCount, deeperDescendantCapturedCount, deeperDescendantAlreadyCapturedCount),
                ["childProcessScopeSummary"] = BuildChildProcessScopeSummary(childTargetCount, directChildTargetCount, deeperDescendantTargetCount, childAttemptedCount, childCapturedCount, childSkippedCount, childAlreadyCapturedCount),
                ["zhMessage"] = "内存转储 sweep 已完成并记录根/子进程覆盖情况。",
                ["zhHint"] = "内存转储为显式 opt-in；启用后会尽力覆盖可见根进程树中的子进程。请结合 rootProcessId/treeLineage、capturedCount、skippedCount 和 alreadyCapturedCount 判断覆盖面。"
            }
        };
    }

    /// <summary>
    /// Creates a single disabled event for the opt-in memory-dump lane.
    /// </summary>
    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = new SandboxEvent
        {
            EventType = "memory_dump.disabled",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "before-start",
                ["capturePhase"] = "before-start",
                ["captureEnabled"] = "false",
                ["captureRequested"] = "false",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--memory-dump/--memory-dumps",
                ["sensitiveArtifact"] = "true",
                ["sensitiveArtifactReason"] = "process-memory-dump",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-sensitive-memory-dump",
                ["childProcessDumpEnabled"] = "false",
                ["childProcessDumpMode"] = "disabled-until-memory-dump-requested",
                ["descendantProcessDumpEnabled"] = "false",
                ["dumpTargetSelectionMode"] = "disabled-until-memory-dump-requested",
                ["reason"] = "memoryDumpNotRequested",
                ["reasonCode"] = "memoryDumpNotRequested",
                ["reasonCategory"] = "disabled",
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhMessage"] = "内存转储采集未启用。",
                ["zhHint"] = "未启用 --memory-dump/--memory-dumps，Guest Agent 不会生成进程 minidump。",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["summaryRow"] = "true",
                ["reportRowKind"] = "memory-dump-disabled",
                ["eventSemanticClass"] = "artifact-memory-dump-disabled",
                ["semanticEventCategory"] = "artifact-evidence",
                ["semanticEventTags"] = "artifact,memory-dump,disabled,nonbehavior",
                ["artifactSemanticType"] = "memory-dump",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["dumpType"] = MemoryDumpCaptureResult.MiniDumpTypeName,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "memory-dumps/*.dmp",
                ["artifactRelativePathStatus"] = "disabled",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "disabled",
                ["rootProcessIdStatus"] = context.RootProcessId is null ? "unavailable-before-sample-start" : "available",
                ["treeLineageStatus"] = context.RootProcessId is null ? "unavailable-before-sample-start" : "stable",
                ["sizeBytesStatus"] = "disabled",
                ["sha256Status"] = "disabled",
                ["artifactHashStatus"] = "disabled",
                ["zhReason"] = "未请求内存转储。",
                ["samplePath"] = context.SamplePath
            }
        };

        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeDepth"] = "0";
            evt.Data["treeLineage"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddOptionalData(evt, "processName", evt.ProcessName);
        return evt;
    }

    private static string MemoryDumpReasonZhHint(string? reason, string? diagnosticStage, bool duplicate)
    {
        if (duplicate)
        {
            return "同一进程已在本次运行中采集过转储，重复目标被跳过。";
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            return string.Empty;
        }

        if (reason.Contains("only implemented on Windows", StringComparison.OrdinalIgnoreCase))
        {
            return "内存转储当前仅支持 Windows guest；非 Windows 环境会记录 skipped。";
        }

        if (reason.Contains("root process ID is not available", StringComparison.OrdinalIgnoreCase))
        {
            return "样本根进程 ID 不可用，无法定位要转储的进程。";
        }

        if (reason.Contains("exited before memory dump", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-state", StringComparison.OrdinalIgnoreCase))
        {
            return "目标进程在转储前已经退出；可尝试延长样本运行时间或更早启用 after-start 转储。";
        }

        if (reason.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-lookup", StringComparison.OrdinalIgnoreCase))
        {
            return "无法通过 PID 找到目标进程；它可能已经退出或权限不可见。";
        }

        if (string.Equals(diagnosticStage, "MiniDumpWriteDump", StringComparison.OrdinalIgnoreCase))
        {
            return "MiniDumpWriteDump 调用失败；请检查进程权限、位数匹配、DbgHelp 可用性和输出路径。";
        }

        if (string.Equals(diagnosticStage, "pid-reuse", StringComparison.OrdinalIgnoreCase))
        {
            return "检测到 root PID 可能已被其他进程复用；为避免误采无关进程，root dump 会跳过，但仍会尝试可见子孙进程。";
        }

        return "请结合 diagnosticStage、exceptionType/message 和 win32Error 判断是权限、进程状态、DbgHelp 还是输出路径问题。";
    }

    private static string MemoryDumpReasonCode(MemoryDumpCaptureResult result, bool duplicate)
    {
        if (duplicate)
        {
            return "duplicate";
        }

        if (result.Reason?.Contains("only implemented on Windows", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "notWindows";
        }

        if (result.Reason?.Contains("root process ID is not available", StringComparison.OrdinalIgnoreCase) == true)
        {
            return string.Equals(result.DiagnosticStage, "root-process-final", StringComparison.OrdinalIgnoreCase)
                ? "rootProcessIdUnavailableFinal"
                : "rootProcessIdUnavailable";
        }

        return result.DiagnosticStage switch
        {
            "process-state" => "processExitedBeforeDump",
            "process-lookup" => "processNotFound",
            "process-tree-empty" => "noVisibleProcessTargets",
            "process-tree-snapshot" => "processTreeSnapshotFailed",
            "MiniDumpWriteDump" => "miniDumpWriteDumpFailed",
            "pid-reuse" => "pidReuseGuard",
            "platform-check" => "notWindows",
            "capture" => "captureFailed",
            _ => "memoryDumpSkipped"
        };
    }

    private static string MemoryDumpReasonCategory(MemoryDumpCaptureResult result, bool duplicate)
    {
        if (duplicate)
        {
            return "duplicate";
        }

        return MemoryDumpReasonCode(result, duplicate) switch
        {
            "notWindows" => "platform",
            "rootProcessIdUnavailable" or "rootProcessIdUnavailableFinal" or "noVisibleProcessTargets" or "processTreeSnapshotFailed" => "process-tree",
            "processExitedBeforeDump" or "processNotFound" => "process-state",
            "miniDumpWriteDumpFailed" => "minidump-api",
            "pidReuseGuard" => "pid-reuse",
            "captureFailed" => "capture-io",
            _ => "unknown"
        };
    }

    private static string MemoryDumpReasonZhReason(MemoryDumpCaptureResult result, bool duplicate)
    {
        return MemoryDumpReasonCode(result, duplicate) switch
        {
            "duplicate" => "目标进程已采集过。",
            "notWindows" => "非 Windows guest。",
            "rootProcessIdUnavailable" => "样本根进程 ID 不可用。",
            "rootProcessIdUnavailableFinal" => "最终 sweep 时样本根进程 ID 不可用。",
            "processExitedBeforeDump" => "目标进程已退出。",
            "processNotFound" => "无法找到目标进程。",
            "noVisibleProcessTargets" => "没有可见的转储目标。",
            "processTreeSnapshotFailed" => "进程树快照失败。",
            "miniDumpWriteDumpFailed" => "MiniDumpWriteDump 失败。",
            "pidReuseGuard" => "检测到 PID 复用保护。",
            "captureFailed" => "转储捕获失败。",
            _ => "内存转储采集被跳过。"
        };
    }

    /// <summary>
    /// Summarizes root/child minidump coverage for report cards without
    /// requiring the host to recompute per-target attempt counters.
    /// </summary>
    private static string DetermineDumpCoverageState(
        int targetCount,
        int attemptedCount,
        int capturedCount,
        int skippedCount,
        int alreadyCapturedCount)
    {
        if (targetCount == 0)
        {
            return "no-visible-targets";
        }

        if (capturedCount + alreadyCapturedCount >= targetCount && skippedCount == 0)
        {
            return "covered";
        }

        if (capturedCount > 0 || alreadyCapturedCount > 0)
        {
            return "partial";
        }

        if (attemptedCount > 0 && skippedCount == attemptedCount)
        {
            return "all-skipped";
        }

        return "unknown";
    }

    private static string DetermineRootDescendantCoverageState(
        int rootTargetCount,
        int childTargetCount,
        int rootCapturedCount,
        int childCapturedCount,
        int rootAlreadyCapturedCount,
        int childAlreadyCapturedCount)
    {
        var rootCovered = rootTargetCount == 0 || rootCapturedCount + rootAlreadyCapturedCount >= rootTargetCount;
        var descendantsCovered = childTargetCount == 0 || childCapturedCount + childAlreadyCapturedCount >= childTargetCount;
        if (rootCovered && descendantsCovered)
        {
            return childTargetCount == 0 ? "root-covered-no-visible-descendants" : "root-and-descendants-covered";
        }

        if (rootCovered)
        {
            return "root-covered-descendants-partial";
        }

        if (descendantsCovered)
        {
            return "root-missing-descendants-covered";
        }

        return "partial-root-and-descendants";
    }

    private static string DetermineDescendantCoverageCompleteness(
        int descendantTargetCount,
        int directChildTargetCount,
        int deeperDescendantTargetCount,
        int descendantCapturedCount,
        int descendantAlreadyCapturedCount,
        int directChildCapturedCount,
        int directChildAlreadyCapturedCount,
        int deeperDescendantCapturedCount,
        int deeperDescendantAlreadyCapturedCount)
    {
        if (descendantTargetCount == 0)
        {
            return "no-visible-descendants";
        }

        var directChildrenCovered = directChildTargetCount == 0 ||
            directChildCapturedCount + directChildAlreadyCapturedCount >= directChildTargetCount;
        var deeperDescendantsCovered = deeperDescendantTargetCount == 0 ||
            deeperDescendantCapturedCount + deeperDescendantAlreadyCapturedCount >= deeperDescendantTargetCount;
        if (directChildrenCovered && deeperDescendantsCovered)
        {
            return deeperDescendantTargetCount == 0
                ? "direct-children-covered-no-deeper-descendants"
                : "all-descendant-depths-covered";
        }

        if (descendantCapturedCount + descendantAlreadyCapturedCount > 0)
        {
            return directChildrenCovered ? "direct-children-covered-deeper-descendants-partial" : "partial-descendant-depths";
        }

        return "descendants-not-covered";
    }

    private static string BuildChildProcessScopeSummary(
        int childTargetCount,
        int directChildTargetCount,
        int deeperDescendantTargetCount,
        int childAttemptedCount,
        int childCapturedCount,
        int childSkippedCount,
        int childAlreadyCapturedCount)
    {
        return string.Join(
            ";",
            [
                $"mode=visible-root-tree",
                $"children={childTargetCount.ToString(CultureInfo.InvariantCulture)}",
                $"direct={directChildTargetCount.ToString(CultureInfo.InvariantCulture)}",
                $"deeper={deeperDescendantTargetCount.ToString(CultureInfo.InvariantCulture)}",
                $"attempted={childAttemptedCount.ToString(CultureInfo.InvariantCulture)}",
                $"captured={childCapturedCount.ToString(CultureInfo.InvariantCulture)}",
                $"skipped={childSkippedCount.ToString(CultureInfo.InvariantCulture)}",
                $"alreadyCaptured={childAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture)}"
            ]);
    }

    /// <summary>
    /// Adds stable first/last/largest selectors to the memory dump sweep row,
    /// including already-captured duplicate references, so report generators can
    /// resolve root/child dump artifacts from the summary alone.
    /// </summary>
    private static void AddMemoryDumpSweepArtifactSelectors(SandboxEvent sweepEvent, IReadOnlyList<SandboxEvent> attemptEvents)
    {
        var artifacts = attemptEvents
            .Where(static evt =>
                string.Equals(evt.EventType, "memory_dump.captured", StringComparison.OrdinalIgnoreCase) ||
                (string.Equals(evt.EventType, "memory_dump.skipped", StringComparison.OrdinalIgnoreCase) &&
                 evt.Data.TryGetValue("artifactSelectorState", out var selectorState) &&
                 string.Equals(selectorState, "references-existing-capture", StringComparison.OrdinalIgnoreCase)))
            .Select(static evt => new MemoryDumpArtifactSummary(
                FirstData(evt, "artifactRelativePath", "relativePath", "memoryDumpRelativePath", "dumpRelativePath"),
                ParseLong(FirstData(evt, "artifactSizeBytes", "sizeBytes")),
                FirstData(evt, "artifactSha256", "sha256", "existingArtifactSha256"),
                FirstData(evt, "targetProcessId", "processId"),
                FirstData(evt, "targetProcessRole", "processRole"),
                FirstData(evt, "targetTreeLineage", "treeLineage")))
            .Where(static artifact => !string.IsNullOrWhiteSpace(artifact.RelativePath))
            .GroupBy(static artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .ToList();

        if (artifacts.Count == 0)
        {
            sweepEvent.Data["artifactSelectorState"] = "none-captured";
            return;
        }

        sweepEvent.Data["artifactSelectorState"] = "available";
        sweepEvent.Data["artifactSelectorMode"] = "sweep-event-order-and-size";
        sweepEvent.Data["selectorArtifactCount"] = artifacts.Count.ToString(CultureInfo.InvariantCulture);
        AddMemoryDumpArtifactSelector(sweepEvent.Data, "first", artifacts.First(), "first-sweep-artifact");
        AddMemoryDumpArtifactSelector(sweepEvent.Data, "last", artifacts.Last(), "last-sweep-artifact");
        AddMemoryDumpArtifactSelector(
            sweepEvent.Data,
            "largest",
            artifacts
                .OrderByDescending(static artifact => artifact.SizeBytes)
                .ThenBy(static artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                .First(),
            "largest-size-bytes");
    }

    private static void AddMemoryDumpArtifactSelector(
        Dictionary<string, string> data,
        string prefix,
        MemoryDumpArtifactSummary artifact,
        string selectionReason)
    {
        var titlePrefix = char.ToUpperInvariant(prefix[0]) + prefix[1..];
        data[MemoryDumpArtifactSelectorKey(prefix)] = artifact.RelativePath;
        data[$"{prefix}ArtifactRelativePath"] = artifact.RelativePath;
        data[$"{prefix}ArtifactSafeLink"] = BuildSafeLink(artifact.RelativePath);
        data[$"{prefix}ArtifactSizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactSha256", artifact.Sha256);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactProcessId", artifact.ProcessId);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactProcessRole", artifact.ProcessRole);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactTreeLineage", artifact.TreeLineage);
        data[$"{prefix}ArtifactSelectionReason"] = selectionReason;
        data[$"has{titlePrefix}ArtifactSelector"] = "true";
    }

    private static string MemoryDumpArtifactSelectorKey(string prefix)
    {
        return prefix switch
        {
            "first" => "firstArtifactSelector",
            "last" => "lastArtifactSelector",
            "largest" => "largestArtifactSelector",
            _ => $"{prefix}ArtifactSelector"
        };
    }

    private static bool IsExitedBeforeDump(string? reason, string? diagnosticStage)
    {
        return (!string.IsNullOrWhiteSpace(reason) &&
                reason.Contains("exited before memory dump", StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(diagnosticStage, "process-state", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-lookup", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Creates an explicit skipped row when the original root PID now appears
    /// to belong to a different process, preventing unrelated dumps after PID
    /// reuse while keeping descendant targeting evidence understandable.
    /// </summary>
    private SandboxEvent CreateRootPidReuseSkippedEvent(
        string phaseLabel,
        int rootProcessId,
        ProcessTreeSnapshot visiblePidSnapshot)
    {
        var evt = CreateSkippedEvent(
            MemoryDumpCaptureResult.Skipped(
                "Visible process with the sample root PID did not match the original root process start time; root dump skipped to avoid dumping an unrelated process.",
                rootProcessId,
                diagnosticStage: "pid-reuse"),
            phaseLabel,
            target: null,
            rootProcessId: rootProcessId,
            duplicate: false);
        evt.Data["pidReuseSuspected"] = "true";
        evt.Data["rootProcessDumpTarget"] = "false";
        evt.Data["memoryDumpCoverageRole"] = "root-pid-reuse";
        evt.Data["rootVisibleInSnapshot"] = "false";
        evt.Data["reasonCode"] = "pidReuseGuard";
        evt.Data["reasonCategory"] = "pid-reuse";
        evt.Data["zhReason"] = "检测到 PID 复用保护。";
        evt.Data["visiblePidSnapshotKey"] = visiblePidSnapshot.Key;
        evt.Data["visiblePidProcessId"] = visiblePidSnapshot.ProcessId.ToString(CultureInfo.InvariantCulture);
        evt.Data["visiblePidProcessName"] = visiblePidSnapshot.ProcessName;
        AddOptionalData(evt, "visiblePidImagePath", visiblePidSnapshot.Path);
        AddOptionalData(evt, "visiblePidCommandLine", visiblePidSnapshot.CommandLine);
        if (visiblePidSnapshot.StartTimeUtc is not null)
        {
            evt.Data["visiblePidStartTimeUtc"] = visiblePidSnapshot.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        evt.Data["zhHint"] = "检测到 root PID 可能已复用；为避免转储无关进程，已跳过该 PID 的 root dump，但仍会尝试可见的 root 子孙进程。";
        return evt;
    }

    /// <summary>
    /// Remembers the first captured artifact for a PID so later duplicate
    /// sweep rows can still expose stable selectors, size, and hash metadata.
    /// </summary>
    private void RememberCapturedArtifact(int processId, SandboxEvent capturedEvent)
    {
        if (!capturedEvent.Data.TryGetValue("artifactRelativePath", out var relativePath) ||
            string.IsNullOrWhiteSpace(relativePath))
        {
            return;
        }

        capturedArtifactsByProcessId.TryAdd(
            processId,
            new CapturedMemoryDumpArtifact(
                relativePath,
                FirstData(capturedEvent, "artifactSelector", "artifactRelativePath"),
                FirstData(capturedEvent, "downloadSelector", "artifactRelativePath"),
                FirstData(capturedEvent, "artifactSafeLink"),
                FirstData(capturedEvent, "sizeBytes", "artifactSizeBytes"),
                FirstData(capturedEvent, "sha256", "artifactSha256"),
                FirstData(capturedEvent, "artifactHashStatus", "hashStatus"),
                FirstData(capturedEvent, "artifactIntegrityState"),
                FirstData(capturedEvent, "targetProcessRole", "processRole"),
                FirstData(capturedEvent, "targetTreeLineage", "treeLineage")));
    }

    /// <summary>
    /// Adds a download reference to duplicate memory_dump.skipped rows. The
    /// skipped row remains non-behavior collection evidence, but reports can
    /// resolve the already-captured root/child dump by selector without reading
    /// previous events.
    /// </summary>
    private void AddCapturedArtifactReference(SandboxEvent evt, int processId)
    {
        if (!capturedArtifactsByProcessId.TryGetValue(processId, out var artifact))
        {
            evt.Data.TryAdd("artifactSelectorState", "already-captured-reference-missing");
            evt.Data.TryAdd("existingArtifactSelectorStatus", "missing");
            return;
        }

        evt.Data["artifactExists"] = "true";
        evt.Data["artifactRelativePath"] = artifact.RelativePath;
        evt.Data["relativePath"] = artifact.RelativePath;
        evt.Data["memoryDumpRelativePath"] = artifact.RelativePath;
        evt.Data["dumpRelativePath"] = artifact.RelativePath;
        evt.Data["artifactSelector"] = artifact.Selector;
        evt.Data["downloadSelector"] = artifact.DownloadSelector;
        evt.Data["existingArtifactRelativePath"] = artifact.RelativePath;
        evt.Data["existingArtifactSelector"] = artifact.Selector;
        evt.Data["existingDownloadSelector"] = artifact.DownloadSelector;
        evt.Data["artifactSelectorKind"] = "safe-output-relative-path";
        evt.Data["artifactSelectorVersion"] = ArtifactSelectorVersion;
        evt.Data["artifactRelativePathStatus"] = "already-captured";
        evt.Data["artifactSelectorState"] = "references-existing-capture";
        evt.Data["existingArtifactSelectorStatus"] = "available";
        evt.Data["artifactSelectionReason"] = "already-captured-duplicate-pid";
        AddOptionalData(evt, "artifactSafeLink", artifact.SafeLink);
        AddOptionalData(evt, "existingArtifactSafeLink", artifact.SafeLink);
        AddOptionalData(evt, "sizeBytes", artifact.SizeBytes);
        AddOptionalData(evt, "artifactSizeBytes", artifact.SizeBytes);
        AddOptionalData(evt, "sha256", artifact.Sha256);
        AddOptionalData(evt, "artifactSha256", artifact.Sha256);
        AddOptionalData(evt, "existingArtifactSha256", artifact.Sha256);
        AddOptionalData(evt, "artifactHashStatus", artifact.HashStatus);
        AddOptionalData(evt, "hashStatus", artifact.HashStatus);
        AddOptionalData(evt, "artifactIntegrityState", artifact.IntegrityState);
        AddOptionalData(evt, "referencedArtifactProcessRole", artifact.ProcessRole);
        AddOptionalData(evt, "referencedArtifactTreeLineage", artifact.TreeLineage);
        evt.Data["sizeBytesStatus"] = string.IsNullOrWhiteSpace(artifact.SizeBytes) ? "missing" : "computed";
        evt.Data["sha256Status"] = string.IsNullOrWhiteSpace(artifact.Sha256) ? "missing" : "computed";
    }

    /// <summary>
    /// Builds final dump targets from the visible root process tree.
    /// Inputs are a process snapshot and root PID; processing walks children by
    /// parent PID even when the root has already exited; the method returns
    /// deterministic root/child targets.
    /// </summary>
    private static IReadOnlyList<MemoryDumpTarget> BuildVisibleDumpTargets(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        GuestProbeContext context,
        int rootProcessId)
    {
        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());
        var targets = new List<MemoryDumpTarget>();
        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth, string Lineage, bool IsRoot, string SelectionSource)>();
        var visited = new HashSet<int>();
        var rootVisible = snapshot.TryGetValue(rootProcessId, out var root) && IsSameRootProcess(root, context);
        if (rootVisible && root is not null)
        {
            queue.Enqueue((root, 0, root.ProcessId.ToString(CultureInfo.InvariantCulture), true, "visible-root"));
        }
        else if (childrenByParent.TryGetValue(rootProcessId, out var orphanedChildren))
        {
            foreach (var child in orphanedChildren)
            {
                queue.Enqueue((child, 1, $"{rootProcessId.ToString(CultureInfo.InvariantCulture)}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}", false, "visible-orphaned-descendant"));
            }
        }

        while (queue.Count > 0)
        {
            var (process, depth, lineage, isRoot, selectionSource) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            targets.Add(new MemoryDumpTarget(
                process.ProcessId,
                process.ParentProcessId,
                process.ProcessName,
                process.Path,
                depth,
                lineage,
                isRoot,
                process.StartTimeUtc,
                process.SessionId,
                process.ThreadCount,
                process.BasePriority,
                process.Key,
                rootVisible,
                selectionSource));

            if (!childrenByParent.TryGetValue(process.ProcessId, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                var childDepth = depth + 1;
                var childSelectionSource = childDepth == 1
                    ? "visible-direct-child"
                    : selectionSource.Contains("orphaned", StringComparison.OrdinalIgnoreCase)
                        ? "visible-orphaned-deeper-descendant"
                        : "visible-deeper-descendant";
                queue.Enqueue((child, childDepth, $"{lineage}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}", false, childSelectionSource));
            }
        }

        return targets;
    }

    private static bool TryGetRootPidReuseSnapshot(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        GuestProbeContext context,
        int rootProcessId,
        out ProcessTreeSnapshot visiblePidSnapshot)
    {
        if (snapshot.TryGetValue(rootProcessId, out visiblePidSnapshot!) &&
            !IsSameRootProcess(visiblePidSnapshot, context))
        {
            return true;
        }

        visiblePidSnapshot = null!;
        return false;
    }

    private static bool IsSameRootProcess(ProcessTreeSnapshot process, GuestProbeContext context)
    {
        if (context.RootProcessStartTimeUtc is null || process.StartTimeUtc is null)
        {
            return true;
        }

        var delta = process.StartTimeUtc.Value - context.RootProcessStartTimeUtc.Value;
        return Math.Abs(delta.TotalSeconds) <= 1;
    }

    private static bool LineageContainsPid(string lineage, int pid)
    {
        foreach (var token in lineage.Split('>', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var currentPid) &&
                currentPid == pid)
            {
                return true;
            }
        }

        return false;
    }

    private static string FirstData(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string BuildSafeLink(string relativePath)
    {
        return string.Join(
            "/",
            relativePath
                .Replace('\\', '/')
                .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
    }

    private static long ParseLong(string value)
    {
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;
    }

    private static void AddDataIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private static void AddOptionalData(SandboxEvent evt, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evt.Data[key] = value;
        }
    }

    /// <summary>
    /// Reads a display process name for root sample dump attempts.
    /// </summary>
    private static string? SampleProcessName(string samplePath)
    {
        try
        {
            return string.IsNullOrWhiteSpace(samplePath) ? null : Path.GetFileName(samplePath);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Converts probe phases to stable artifact labels.
    /// Inputs are enum values; processing maps known phases; the method returns
    /// a lowercase label for filenames and event data.
    /// </summary>
    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }

    /// <summary>
    /// Computes a display relative path and a machine-readable artifact path
    /// status without treating outside-output paths as downloadable artifacts.
    /// </summary>
    private static MemoryDumpArtifactPath ResolveArtifactRelativePath(string outputDirectory, string path)
    {
        try
        {
            var outputRoot = Path.GetFullPath(outputDirectory);
            var fullPath = Path.GetFullPath(path);
            var outputRootWithSeparator = Path.EndsInDirectorySeparator(outputRoot)
                ? outputRoot
                : outputRoot + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(outputRootWithSeparator, StringComparison.OrdinalIgnoreCase))
            {
                var relativePath = Path.GetRelativePath(outputRoot, fullPath).Replace('\\', '/');
                return new MemoryDumpArtifactPath(relativePath, IsOutputRelative: true, Status: "captured");
            }

            var directory = Path.GetDirectoryName(fullPath);
            var displayPath = string.IsNullOrWhiteSpace(directory)
                ? Path.GetFileName(fullPath)
                : Path.Combine(Path.GetFileName(directory), Path.GetFileName(fullPath)).Replace('\\', '/');
            return new MemoryDumpArtifactPath(displayPath, IsOutputRelative: false, Status: "outside-output-root");
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new MemoryDumpArtifactPath(path, IsOutputRelative: false, Status: "invalid-or-unresolved");
        }
    }

    /// <summary>
    /// Adds event-level file size/hash metadata for captured minidumps.
    /// Inputs are an event and dump path; processing reads the file best-effort
    /// with sharing flags; failures are retained as diagnostics.
    /// </summary>
    private static void AddArtifactFileEvidence(SandboxEvent evt, string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                evt.Data["hashStatus"] = "missing";
                evt.Data["artifactHashStatus"] = "missing";
                evt.Data["artifactExists"] = "false";
                evt.Data["artifactIntegrityState"] = "missing";
                evt.Data["sizeBytesStatus"] = "missing";
                evt.Data["sha256Status"] = "missing";
                return;
            }

            evt.Data["artifactExists"] = "true";
            evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactLastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["sha256"] = sha256;
            evt.Data["artifactSha256"] = sha256;
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["hashStatus"] = "computed";
            evt.Data["artifactHashAlgorithm"] = "sha256";
            evt.Data["artifactHashStatus"] = "computed";
            evt.Data["artifactIntegrityState"] = "verified";
            evt.Data["sizeBytesStatus"] = "computed";
            evt.Data["sha256Status"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["hashStatus"] = "failed";
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactIntegrityState"] = "hash-failed";
            evt.Data["sha256Status"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
    }

    private sealed record MemoryDumpTarget(
        int ProcessId,
        int? ParentProcessId,
        string ProcessName,
        string? Path,
        int Depth,
        string Lineage,
        bool IsRoot,
        DateTime? StartTimeUtc,
        int? SessionId,
        int? ThreadCount,
        int? BasePriority,
        string? SnapshotKey,
        bool RootVisibleInSnapshot,
        string SelectionSource);

    private sealed record MemoryDumpArtifactPath(
        string DisplayPath,
        bool IsOutputRelative,
        string Status);

    private sealed record CapturedMemoryDumpArtifact(
        string RelativePath,
        string Selector,
        string DownloadSelector,
        string SafeLink,
        string SizeBytes,
        string Sha256,
        string HashStatus,
        string IntegrityState,
        string ProcessRole,
        string TreeLineage);

    private sealed record MemoryDumpArtifactSummary(
        string RelativePath,
        long SizeBytes,
        string Sha256,
        string ProcessId,
        string ProcessRole,
        string TreeLineage);
}

/// <summary>
/// Defines a process memory dump capture implementation.
/// Inputs are output directory, target PID, phase label, and cancellation token;
/// processing writes or skips a dump artifact; CaptureAsync returns capture
/// metadata for event emission.
/// </summary>
internal interface IProcessMemoryDumpCapture
{
    Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures a Windows MiniDumpNormal file for a target process.
/// Inputs are output directory, PID, and phase; processing uses DbgHelp
/// MiniDumpWriteDump and writes memory-dumps/*.dmp; CaptureAsync returns
/// success metadata or a skipped result when capture is unavailable.
/// </summary>
internal sealed class WindowsMiniDumpCapture : IProcessMemoryDumpCapture
{
    private const string DumpDirectoryName = "memory-dumps";

    /// <summary>
    /// Captures a process minidump if the platform and access rights permit it.
    /// Inputs are output directory, target process ID, phase, and cancellation
    /// token; processing writes one .dmp file; the method returns capture
    /// metadata or a skipped diagnostic.
    /// </summary>
    public Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Memory dump capture is only implemented on Windows.",
                processId,
                diagnosticStage: "platform-check"));
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                    "Sample process exited before memory dump capture.",
                    processId,
                    diagnosticStage: "process-state"));
            }

            var dumpDirectory = Path.Combine(outputDirectory, DumpDirectoryName);
            Directory.CreateDirectory(dumpDirectory);
            var safePhase = phase.Replace(' ', '-');
            var path = Path.Combine(dumpDirectory, $"{safePhase}-pid{processId}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.dmp");
            var sizeBytes = WriteMiniDump(process, path, cancellationToken);
            return Task.FromResult(MemoryDumpCaptureResult.Success(path, processId, MiniDumpType.MiniDumpNormal.ToString(), sizeBytes));
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Sample process was not found for memory dump capture.",
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "process-lookup"));
        }
        catch (MemoryDumpCaptureException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Stage,
                ex.Win32Error));
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException or DllNotFoundException or EntryPointNotFoundException)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "capture"));
        }
    }

    /// <summary>
    /// Writes the minidump file through DbgHelp.
    /// Inputs are a target process, output path, and cancellation token;
    /// processing creates the dump file and removes partial output on failure;
    /// the method returns the final byte length.
    /// </summary>
    private static long WriteMiniDump(Process process, string path, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096);
            cancellationToken.ThrowIfCancellationRequested();
            if (!MiniDumpWriteDump(
                    process.Handle,
                    process.Id,
                    stream.SafeFileHandle.DangerousGetHandle(),
                    MiniDumpType.MiniDumpNormal,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw MemoryDumpCaptureException.ForLastPInvokeError(
                    "MiniDumpWriteDump",
                    "MiniDumpWriteDump failed while capturing the sample process.");
            }

            stream.Flush(flushToDisk: true);
            return stream.Length;
        }
        catch
        {
            TryDeleteFile(path);
            throw;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Preserve the original capture failure as the diagnostic event.
        }
    }

    [DllImport("dbghelp.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int processId,
        IntPtr hFile,
        MiniDumpType dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [Flags]
    private enum MiniDumpType
    {
        MiniDumpNormal = 0x00000000
    }
}

/// <summary>
/// Carries memory dump capture failure diagnostics from the platform-specific
/// implementation. Inputs are a capture stage, message, and Win32 error code;
/// processing is immutable exception storage; records are converted into
/// memory_dump.skipped event Data.
/// </summary>
internal sealed class MemoryDumpCaptureException : InvalidOperationException
{
    public MemoryDumpCaptureException(string stage, string message, int win32Error)
        : base(message)
    {
        Stage = stage;
        Win32Error = win32Error;
    }

    public string Stage { get; }

    public int Win32Error { get; }

    /// <summary>
    /// Creates a memory dump exception using the last P/Invoke error code.
    /// Inputs are capture stage and message; processing reads the thread-local
    /// P/Invoke error; the method returns a MemoryDumpCaptureException.
    /// </summary>
    public static MemoryDumpCaptureException ForLastPInvokeError(string stage, string message)
    {
        return new MemoryDumpCaptureException(stage, message, Marshal.GetLastPInvokeError());
    }
}

/// <summary>
/// Describes the result of one memory dump attempt.
/// Inputs are capture outcome details; processing is immutable storage; records
/// are returned by IProcessMemoryDumpCapture and converted into SandboxEvent
/// data.
/// </summary>
internal sealed record MemoryDumpCaptureResult(
    bool Captured,
    string? Path,
    int? ProcessId,
    string DumpType,
    long? SizeBytes,
    string? Reason,
    string? ExceptionType,
    string? DiagnosticStage,
    int? Win32Error)
{
    /// <summary>
    /// Creates a successful memory dump result.
    /// Inputs are artifact path, process ID, dump type, and byte length;
    /// processing stores success metadata; the method returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Success(string path, int processId, string dumpType, long sizeBytes)
    {
        return new MemoryDumpCaptureResult(true, path, processId, dumpType, sizeBytes, null, null, null, null);
    }

    /// <summary>
    /// Creates a skipped memory dump result.
    /// Inputs are skip reason, process ID, optional exception type, diagnostic
    /// stage, and Win32 error; processing stores diagnostic metadata; the method
    /// returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Skipped(
        string reason,
        int? processId,
        string? exceptionType = null,
        string? diagnosticStage = null,
        int? win32Error = null)
    {
        return new MemoryDumpCaptureResult(false, null, processId, MiniDumpTypeName, null, reason, exceptionType, diagnosticStage, win32Error);
    }

    public const string MiniDumpTypeName = "MiniDumpNormal";
}
