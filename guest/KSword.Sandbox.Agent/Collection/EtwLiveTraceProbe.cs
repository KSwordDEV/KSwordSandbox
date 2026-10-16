using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures a real Windows ETW kernel trace for the lifetime of a sample.
/// This probe intentionally stores the ETL as an evidence artifact; it does
/// not claim that an ETL file is already parsed behavior.  A successful
/// start/stop pair is required before an event is marked captured.  Missing
/// logman, insufficient privilege, an existing session, or a missing/empty
/// ETL all produce explicit failed rows so reports cannot confuse readiness
/// with live collection.
/// </summary>
internal sealed class EtwLiveTraceProbe : IGuestProbe
{
    private const string CollectorSource = "etwLive";
    private const string CollectionName = "etw-traces";
    private const string LogmanExecutable = "logman.exe";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);
    private EtwTraceSession? activeSession;

    public string ProbeId => "etw-live-trace";

    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!context.CaptureEtwLiveTrace)
        {
            return phase == ProbePhase.BeforeStart ? [CreateDisabledEvent(context)] : [];
        }

        if (!OperatingSystem.IsWindows())
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateFailureEvent("platformUnsupported", "before-start", context, null, null, null)]
                : [];
        }

        return phase switch
        {
            ProbePhase.BeforeStart => await StartAsync(context, cancellationToken).ConfigureAwait(false),
            ProbePhase.AfterRun => await StopAsync(context, cancellationToken).ConfigureAwait(false),
            _ => []
        };
    }

    private async Task<IReadOnlyList<SandboxEvent>> StartAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (activeSession is not null)
        {
            return [CreateFailureEvent("captureAlreadyActive", "before-start", context, activeSession, null, null)];
        }

        var traceDirectory = Path.Combine(context.OutputDirectory, CollectionName);
        Directory.CreateDirectory(traceDirectory);
        var sessionName = "KSwordSandboxEtw_" + Guid.NewGuid().ToString("N");
        var etlPath = Path.Combine(traceDirectory, sessionName + ".etl");
        var session = new EtwTraceSession(sessionName, etlPath, DateTimeOffset.UtcNow);
        var result = await BoundedProcessRunner.RunAsync(
            LogmanExecutable,
            BuildStartArguments(session),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return [CreateFailureEvent(
                result.TimedOut ? "logmanStartTimedOut" : "logmanStartFailed",
                "before-start",
                context,
                session,
                result,
                null)];
        }

        activeSession = session;
        var evt = CreateBaseEvent("etw_live.started", "before-start", context, session);
        evt.Data["captureState"] = "started";
        evt.Data["status"] = "started";
        evt.Data["commandExitCode"] = FormatExitCode(result.ExitCode);
        evt.Data["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture);
        evt.Data["startCommand"] = FormatCommand(LogmanExecutable, BuildStartArguments(session));
        evt.Data["semanticRowsAvailable"] = "false";
        evt.Data["etlDecodeRequired"] = "true";
        evt.Data["zhMessage"] = "ETW 内核实时会话已启动，结束后将保存 ETL 原始证据。";
        evt.Data["zhHint"] = "started 只表示 logman 已创建会话；必须同时看到 etw_live.captured 和 ETL 文件校验字段，才能认为实时证据可用。ETL 尚未解析为行为行。";
        return [evt];
    }

    private async Task<IReadOnlyList<SandboxEvent>> StopAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (activeSession is null)
        {
            return [CreateFailureEvent("captureWasNotStarted", "after-run", context, null, null, null)];
        }

        var session = activeSession;
        activeSession = null;
        var result = await BoundedProcessRunner.RunAsync(
            LogmanExecutable,
            ["stop", session.SessionName, "-ets"],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return [CreateFailureEvent(
                result.TimedOut ? "logmanStopTimedOut" : "logmanStopFailed",
                "after-run",
                context,
                session,
                result,
                null)];
        }

        if (!File.Exists(session.EtlPath))
        {
            return [CreateFailureEvent("etlMissingAfterStop", "after-run", context, session, result, null)];
        }

        var info = new FileInfo(session.EtlPath);
        if (info.Length <= 0)
        {
            return [CreateFailureEvent("etlEmptyAfterStop", "after-run", context, session, result, info)];
        }

        var evt = CreateBaseEvent("etw_live.captured", "after-run", context, session);
        evt.Data["captureState"] = "captured";
        evt.Data["status"] = "captured";
        evt.Data["commandExitCode"] = FormatExitCode(result.ExitCode);
        evt.Data["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture);
        evt.Data["stopCommand"] = $"{LogmanExecutable} stop {session.SessionName} -ets";
        evt.Data["captureStoppedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
        evt.Data["lastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["artifactRelativePathStatus"] = "captured";
        evt.Data["semanticRowsAvailable"] = "false";
        evt.Data["etlDecodeRequired"] = "true";
        evt.Data["parsedEventCount"] = "0";
        evt.Data["zhMessage"] = "ETW 内核实时会话已停止并保存 ETL 原始证据。";
        evt.Data["zhHint"] = "该事件证明 ETW 原始文件已落盘；ETL 仍需使用 Windows ETW 解码器解析为 process/thread/image 行，不能把 readiness 或 ETL 文件本身当作样本行为命中。";
        return [evt];
    }

    private static IReadOnlyList<string> BuildStartArguments(EtwTraceSession session)
    {
        // Kernel-Process/Thread/Image are built-in providers.  The broad mask
        // keeps short-lived process and image edges visible; ETL is bounded by
        // the per-run duration and the OS logger buffer policy.
        return
        [
            "create", "trace", session.SessionName,
            "-o", session.EtlPath,
            "-ets",
            "-p", "Microsoft-Windows-Kernel-Process", "0xFFFFFFFF", "0x5",
            "-p", "Microsoft-Windows-Kernel-Thread", "0xFFFFFFFF", "0x5",
            "-p", "Microsoft-Windows-Kernel-Image", "0xFFFFFFFF", "0x5"
        ];
    }

    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = CreateBaseEvent("etw_live.disabled", "before-start", context, null);
        evt.Data["captureState"] = "disabled";
        evt.Data["status"] = "disabled";
        evt.Data["captureEnabled"] = "false";
        evt.Data["reason"] = "etwLiveNotRequested";
        evt.Data["zhMessage"] = "ETW 内核实时采集未启用。";
        evt.Data["zhHint"] = "当前报告没有 ETW live 原始证据；如需覆盖短命进程、线程和镜像边沿，请显式传入 --etw-live，并在结果中检查 etw_live.captured。";
        return evt;
    }

    private static SandboxEvent CreateFailureEvent(
        string reason,
        string phase,
        GuestProbeContext context,
        EtwTraceSession? session,
        BoundedCommandResult? result,
        FileInfo? file)
    {
        var evt = CreateBaseEvent("etw_live.failed", phase, context, session);
        evt.Data["captureState"] = "failed";
        evt.Data["status"] = "failed";
        evt.Data["reason"] = reason;
        evt.Data["reasonCode"] = reason;
        evt.Data["captureEnabled"] = "true";
        evt.Data["nonfatal"] = "true";
        evt.Data["commandExitCode"] = FormatExitCode(result?.ExitCode);
        evt.Data["commandTimedOut"] = (result?.TimedOut ?? false).ToString(CultureInfo.InvariantCulture);
        AddIfNotEmpty(evt.Data, "exceptionType", result?.ExceptionType);
        AddIfNotEmpty(evt.Data, "message", result?.Message);
        AddIfNotEmpty(evt.Data, "stderr", Truncate(result?.StandardError));
        if (file is not null)
        {
            evt.Data["sizeBytes"] = file.Length.ToString(CultureInfo.InvariantCulture);
        }

        evt.Data["zhMessage"] = "ETW 内核实时采集未完成，已明确记录证据缺口。";
        evt.Data["zhHint"] = reason switch
        {
            "platformUnsupported" => "当前 guest 不是 Windows，无法启动 logman ETW 会话。",
            "captureAlreadyActive" => "上一 ETW 会话仍处于活动状态；请检查 logman query -ets 后清理残留会话。",
            "captureWasNotStarted" => "after-run 没有对应的 started 事件，不能把本次运行称为 ETW live captured。",
            _ => "请检查 guest 管理员权限、logman 输出、ETW 会话名称和 trace 文件；本次运行的 ETW 证据不可用。"
        };
        return evt;
    }

    private static SandboxEvent CreateBaseEvent(
        string eventType,
        string phase,
        GuestProbeContext context,
        EtwTraceSession? session)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = "etw-kernel-trace",
            ["phase"] = phase,
            ["capturePhase"] = phase,
            ["capturePolicy"] = "explicit-opt-in-etw-kernel-trace",
            ["captureTool"] = LogmanExecutable,
            ["captureToolMode"] = "windows-logman-kernel-etw",
            ["traceProviders"] = "Microsoft-Windows-Kernel-Process;Microsoft-Windows-Kernel-Thread;Microsoft-Windows-Kernel-Image",
            ["etwLiveCaptureEnabled"] = "true",
            ["etwSessionStarted"] = session is not null && phase == "before-start" ? "true" : "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["behaviorCounted"] = "false",
            ["sampleBehaviorCandidate"] = "false",
            ["semanticRowsAvailable"] = "false",
            ["etlDecodeRequired"] = "true",
            ["implemented"] = "true",
            ["reasonTaxonomy"] = "guest-artifact.etw-live.reason.v1"
        };
        if (session is not null)
        {
            data["traceSessionName"] = session.SessionName;
            data["traceFilePath"] = session.EtlPath;
            data["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["relativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["stableArtifactSelector"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["canonicalArtifactSelector"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["captureStartedUtc"] = session.StartedAtUtc.ToString("O", CultureInfo.InvariantCulture);
            data["expectedRelativePath"] = $"{CollectionName}/*.etl";
        }

        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = CollectorSource,
            ProcessName = SafeFileName(context.RootProcessPath ?? context.SamplePath),
            ProcessId = context.RootProcessId,
            Path = session?.EtlPath ?? context.SamplePath,
            CommandLine = context.RootCommandLine,
            Data = data
        };
        AddIfNotEmpty(data, "samplePath", context.SamplePath);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        return evt;
    }

    private static string RelativeToOutput(string outputDirectory, string path)
    {
        return NormalizeRelativePath(Path.GetRelativePath(outputDirectory, path));
    }

    private static string NormalizeRelativePath(string path) => path.Replace('\\', '/');

    private static string FormatExitCode(int? exitCode) => exitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;

    private static string? Truncate(string? value) => string.IsNullOrWhiteSpace(value)
        ? null
        : value.Length <= 512 ? value : value[..512];

    private static void AddIfNotEmpty(IDictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path); }
        catch { return string.Empty; }
    }

    private static string FormatCommand(string fileName, IEnumerable<string> args) =>
        fileName + " " + string.Join(" ", args.Select(static arg => arg.Any(char.IsWhiteSpace) ? $"\"{arg}\"" : arg));

    private sealed record EtwTraceSession(string SessionName, string EtlPath, DateTimeOffset StartedAtUtc);
}
