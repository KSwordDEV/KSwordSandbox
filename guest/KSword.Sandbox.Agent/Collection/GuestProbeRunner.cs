using System.Diagnostics;
using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Runs a set of guest probes and converts probe failures into events.
/// Inputs are probe instances, a phase, and run context; processing calls each
/// probe in order; methods return collected or diagnostic SandboxEvent records.
/// </summary>
internal sealed class GuestProbeRunner
{
    private static readonly TimeSpan DefaultProbeTimeout = TimeSpan.FromSeconds(10);
    private readonly IReadOnlyList<IGuestProbe> probes;
    private readonly TimeSpan probeTimeout;

    /// <summary>
    /// Creates a probe runner.
    /// The input is a probe sequence, processing snapshots it, and the
    /// constructor returns no value.
    /// </summary>
    public GuestProbeRunner(IEnumerable<IGuestProbe> probes, TimeSpan? probeTimeout = null)
    {
        this.probes = probes.ToList();
        this.probeTimeout = probeTimeout.GetValueOrDefault(DefaultProbeTimeout);
        if (this.probeTimeout <= TimeSpan.Zero)
        {
            this.probeTimeout = DefaultProbeTimeout;
        }
    }

    /// <summary>
    /// Runs every configured probe for one phase.
    /// Inputs are phase, shared run context, and cancellation token; processing
    /// catches probe exceptions; the method returns collected events.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        var events = new List<SandboxEvent>();
        var completedCount = 0;
        var failedCount = 0;
        var timedOutCount = 0;
        foreach (var probe in probes)
        {
            var elapsed = Stopwatch.StartNew();
            try
            {
                var probeEvents = await CollectProbeWithTimeoutAsync(probe, phase, context, cancellationToken).ConfigureAwait(false);
                elapsed.Stop();
                events.AddRange(probeEvents);
                events.Add(CreateProbeSummaryEvent(
                    probe,
                    phase,
                    context,
                    status: "completed",
                    reason: "probeCompleted",
                    elapsed.Elapsed,
                    emittedEventCount: probeEvents.Count,
                    probeTimeout,
                    exception: null));
                completedCount++;
            }
            catch (ProbeTimeoutException)
            {
                elapsed.Stop();
                var timeoutEvent = CreateProbeTimeoutEvent(probe, phase, context, elapsed.Elapsed);
                events.Add(timeoutEvent);
                events.Add(CreateProbeSummaryEvent(
                    probe,
                    phase,
                    context,
                    status: "timeout",
                    reason: "probeTimeout",
                    elapsed.Elapsed,
                    emittedEventCount: 1,
                    probeTimeout,
                    exception: null));
                timedOutCount++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException ex)
            {
                elapsed.Stop();
                var failureEvent = CreateProbeFailureEvent("probe.canceled", probe, phase, context, elapsed.Elapsed, ex);
                events.Add(failureEvent);
                events.Add(CreateProbeSummaryEvent(
                    probe,
                    phase,
                    context,
                    status: "canceled",
                    reason: "probeCanceled",
                    elapsed.Elapsed,
                    emittedEventCount: 1,
                    probeTimeout,
                    exception: ex));
                failedCount++;
            }
            catch (Exception ex)
            {
                elapsed.Stop();
                var failureEvent = CreateProbeFailureEvent("probe.failed", probe, phase, context, elapsed.Elapsed, ex);
                events.Add(failureEvent);
                events.Add(CreateProbeSummaryEvent(
                    probe,
                    phase,
                    context,
                    status: "failed",
                    reason: "probeFailed",
                    elapsed.Elapsed,
                    emittedEventCount: 1,
                    probeTimeout,
                    exception: ex));
                failedCount++;
            }
        }

        events.Add(CreateProbePhaseSummaryEvent(
            phase,
            context,
            completedCount,
            failedCount,
            timedOutCount,
            events.Count));
        return events;
    }

    /// <summary>
    /// Runs one probe and races it against the configured timeout.
    /// Inputs are probe, phase, context, and caller cancellation token;
    /// processing links cancellation and observes timed-out tasks in the
    /// background; the method returns probe events or throws a diagnostic
    /// exception consumed by CollectAsync.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CollectProbeWithTimeoutAsync(
        IGuestProbe probe,
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource();
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        var probeTask = probe.CollectAsync(phase, context, linkedCts.Token);
        var timeoutTask = Task.Delay(probeTimeout, cancellationToken);

        if (await Task.WhenAny(probeTask, timeoutTask).ConfigureAwait(false) == probeTask)
        {
            return await probeTask.ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await timeoutCts.CancelAsync().ConfigureAwait(false);
        _ = ObserveTimedOutProbeAsync(probeTask);
        throw new ProbeTimeoutException();
    }

    /// <summary>
    /// Observes a timed-out probe task so late exceptions do not surface as
    /// unobserved task failures. The input is a task left running after timeout;
    /// processing awaits and suppresses its outcome; the method returns no
    /// value to the caller.
    /// </summary>
    private static async Task ObserveTimedOutProbeAsync(Task<IReadOnlyList<SandboxEvent>> probeTask)
    {
        try
        {
            _ = await probeTask.ConfigureAwait(false);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Creates a normalized probe timeout event.
    /// Inputs are probe identity, phase, and elapsed duration; processing adds
    /// bounded timeout metadata; the method returns a SandboxEvent.
    /// </summary>
    private SandboxEvent CreateProbeTimeoutEvent(
        IGuestProbe probe,
        ProbePhase phase,
        GuestProbeContext context,
        TimeSpan elapsed)
    {
        var evt = new SandboxEvent
        {
            EventType = "probe.timeout",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["probeId"] = probe.ProbeId,
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["nonfatal"] = "true",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["reason"] = "probeTimeout",
                ["zhMessage"] = "Guest 探针超时；该探针结果会标记为 failed，但不会中断整体采集。",
                ["zhHint"] = "请结合 probeId、phase、timeoutMilliseconds 判断是否需要调大探针超时或降低该采集项依赖的系统调用成本。",
                ["timeoutMilliseconds"] = probeTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["elapsedMilliseconds"] = elapsed.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)
            }
        };
        AddProbeRunContextData(evt, context);
        AddProbeCollectionData(evt, probe, context);
        return evt;
    }

    /// <summary>
    /// Creates a normalized probe failure event.
    /// Inputs are event type, probe, phase, elapsed time, and exception;
    /// processing copies exception details and timing metadata; the method
    /// returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateProbeFailureEvent(
        string eventType,
        IGuestProbe probe,
        ProbePhase phase,
        GuestProbeContext context,
        TimeSpan elapsed,
        Exception exception)
    {
        var reason = string.Equals(eventType, "probe.canceled", StringComparison.OrdinalIgnoreCase)
            ? "probeCanceled"
            : "probeFailed";
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["probeId"] = probe.ProbeId,
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["nonfatal"] = "true",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["reason"] = reason,
                ["elapsedMilliseconds"] = elapsed.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message,
                ["zhMessage"] = string.Equals(reason, "probeCanceled", StringComparison.OrdinalIgnoreCase)
                    ? "Guest 探针被取消；该事件用于说明采集不完整，不代表样本行为。"
                    : "Guest 探针执行失败；该事件用于说明采集不完整，不代表样本行为。",
                ["zhHint"] = "请查看 probeId、phase、exceptionType/message 以及 collectionName 来定位受影响的证据通道。"
            }
        };
        AddProbeRunContextData(evt, context);
        AddProbeCollectionData(evt, probe, context);
        return evt;
    }

    /// <summary>
    /// Creates a per-probe collection summary event. Inputs are probe identity,
    /// phase, elapsed time, emitted-event count, and optional exception;
    /// processing stores a compact health row consumed by live telemetry and
    /// reports; the method returns a non-behavior SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateProbeSummaryEvent(
        IGuestProbe probe,
        ProbePhase phase,
        GuestProbeContext context,
        string status,
        string reason,
        TimeSpan elapsed,
        int emittedEventCount,
        TimeSpan probeTimeout,
        Exception? exception)
    {
        var evt = new SandboxEvent
        {
            EventType = "probe.summary",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["probeId"] = probe.ProbeId,
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureState"] = status,
                ["status"] = status,
                ["reason"] = reason,
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["emittedEventCount"] = emittedEventCount.ToString(CultureInfo.InvariantCulture),
                ["elapsedMilliseconds"] = elapsed.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["timeoutMilliseconds"] = probeTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["zhMessage"] = ProbeSummaryZhMessage(status),
                ["zhHint"] = "这是采集通道健康摘要，不代表样本恶意行为；用于解释某个探针是否执行、是否超时、输出了多少事件。"
            }
        };

        if (exception is not null)
        {
            evt.Data["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name;
            evt.Data["message"] = exception.Message;
        }

        AddProbeRunContextData(evt, context);
        AddProbeCollectionData(evt, probe, context);
        return evt;
    }

    /// <summary>
    /// Creates a phase-level probe summary after all probes complete.
    /// </summary>
    private SandboxEvent CreateProbePhaseSummaryEvent(
        ProbePhase phase,
        GuestProbeContext context,
        int completedCount,
        int failedCount,
        int timedOutCount,
        int emittedEventCount)
    {
        var evt = new SandboxEvent
        {
            EventType = "probe.phase.summary",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureState"] = failedCount == 0 && timedOutCount == 0 ? "completed" : "partial",
                ["status"] = failedCount == 0 && timedOutCount == 0 ? "completed" : "partial",
                ["reason"] = failedCount == 0 && timedOutCount == 0 ? "allProbesCompleted" : "oneOrMoreProbesIncomplete",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["probeCount"] = probes.Count.ToString(CultureInfo.InvariantCulture),
                ["completedProbeCount"] = completedCount.ToString(CultureInfo.InvariantCulture),
                ["failedProbeCount"] = failedCount.ToString(CultureInfo.InvariantCulture),
                ["timedOutProbeCount"] = timedOutCount.ToString(CultureInfo.InvariantCulture),
                ["emittedEventCount"] = emittedEventCount.ToString(CultureInfo.InvariantCulture),
                ["samplePath"] = context.SamplePath,
                ["workingDirectory"] = context.WorkingDirectory,
                ["outputDirectory"] = context.OutputDirectory,
                ["zhMessage"] = failedCount == 0 && timedOutCount == 0
                    ? "该阶段 Guest 探针已执行完成。"
                    : "该阶段 Guest 探针部分失败或超时；整体分析仍继续。",
                ["zhHint"] = "请查看同阶段 probe.summary/probe.timeout/probe.failed 事件定位具体通道。"
            }
        };
        AddProbeRunContextData(evt, context);
        return evt;
    }

    /// <summary>
    /// Adds sample-root attribution to probe health events so summaries remain
    /// useful even when the actual probe emitted no artifact rows.
    /// </summary>
    private static void AddProbeRunContextData(SandboxEvent evt, GuestProbeContext context)
    {
        evt.Data["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context";
        evt.Data["samplePath"] = context.SamplePath;
        if (context.RootProcessId is not null)
        {
            var rootPid = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["rootProcessId"] = rootPid;
            evt.Data.TryAdd("processId", rootPid);
            evt.Data.TryAdd("treeDepth", "0");
            evt.Data.TryAdd("treeLineage", rootPid);
        }

        if (context.RootParentProcessId is not null)
        {
            evt.Data["rootParentProcessId"] = context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data.TryAdd("parentProcessId", context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture));
        }

        AddIfNotEmpty(evt.Data, "processName", context.RootProcessName ?? evt.ProcessName);
        AddIfNotEmpty(evt.Data, "rootProcessName", context.RootProcessName);
        AddIfNotEmpty(evt.Data, "processImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "commandLine", context.RootCommandLine);
        AddIfNotEmpty(evt.Data, "rootCommandLine", context.RootCommandLine);
        if (context.RootProcessStartTimeUtc is not null)
        {
            evt.Data["rootProcessStartTimeUtc"] = context.RootProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }
    }

    /// <summary>
    /// Adds artifact collection identity to known optional probe diagnostics.
    /// Inputs are a diagnostic event, probe, and run context; processing maps
    /// probe IDs to collection lanes; the method returns no value.
    /// </summary>
    private static void AddProbeCollectionData(SandboxEvent evt, IGuestProbe probe, GuestProbeContext context)
    {
        var collection = ProbeCollectionFor(probe.ProbeId);
        if (collection is null)
        {
            return;
        }

        evt.Data["collectionName"] = collection.Value.CollectionName;
        evt.Data["evidenceRole"] = collection.Value.EvidenceRole;
        evt.Data["expectedRelativePath"] = collection.Value.ExpectedRelativePath;
        evt.Data["captureEnabled"] = IsProbeCaptureEnabled(probe.ProbeId, context).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["implemented"] = "true";
        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);
        AddIfNotEmpty(evt.Data, "samplePath", context.SamplePath);
    }

    /// <summary>
    /// Maps known optional artifact probes to manifest collection metadata.
    /// </summary>
    private static ProbeCollection? ProbeCollectionFor(string probeId)
    {
        return probeId switch
        {
            "file-diff" => new ProbeCollection("dropped-files", "dropped-file", "artifacts/dropped-files/**"),
            "screenshot" => new ProbeCollection("screenshots", "screenshot", "screenshots/*.bmp"),
            "memory-dump" => new ProbeCollection("memory-dumps", "memory-dump", "memory-dumps/*.dmp"),
            "packet-capture" => new ProbeCollection("packet-captures", "packet-capture", "packet-captures/*.pcapng"),
            _ => null
        };
    }

    /// <summary>
    /// Reads whether an optional artifact probe was requested for failure
    /// diagnostics.
    /// </summary>
    private static bool IsProbeCaptureEnabled(string probeId, GuestProbeContext context)
    {
        return probeId switch
        {
            "file-diff" => context.CollectDroppedFiles,
            "screenshot" => context.CaptureScreenshots,
            "memory-dump" => context.CaptureMemoryDump,
            "packet-capture" => context.CapturePacketCapture,
            _ => true
        };
    }

    /// <summary>
    /// Maps probe health status to Chinese-first summary copy.
    /// </summary>
    private static string ProbeSummaryZhMessage(string status)
    {
        return status switch
        {
            "completed" => "Guest 探针执行完成。",
            "timeout" => "Guest 探针执行超时；整体采集继续。",
            "canceled" => "Guest 探针被取消；整体采集可能不完整。",
            "failed" => "Guest 探针执行失败；整体采集继续。",
            _ => "Guest 探针状态已记录。"
        };
    }

    /// <summary>
    /// Converts probe phases to stable lower-case labels.
    /// </summary>
    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }

    /// <summary>
    /// Reads a display process name for sample-scoped probe diagnostics.
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
    /// Adds a string Data value when it is non-empty.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private readonly record struct ProbeCollection(string CollectionName, string EvidenceRole, string ExpectedRelativePath);

    /// <summary>
    /// Marks an internal probe timeout without depending on localized exception
    /// messages. Inputs are none; processing is type identity only.
    /// </summary>
    private sealed class ProbeTimeoutException : TimeoutException
    {
    }
}
