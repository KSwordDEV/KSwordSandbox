using System.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Execution;

/// <summary>
/// Executes a sample as a normal guest process.
/// Inputs are a sample launch plan; processing starts the process, waits for
/// timeout or exit, and returns normalized process events.
/// </summary>
internal sealed class ProcessSampleExecutor : ISampleExecutor
{
    /// <inheritdoc />
    public async Task<SampleExecutionResult> ExecuteAsync(SampleLaunchPlan plan, CancellationToken cancellationToken = default)
    {
        var events = new List<SandboxEvent>();
        var startInfo = new ProcessStartInfo
        {
            FileName = plan.SamplePath,
            WorkingDirectory = plan.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return new SampleExecutionResult { Started = false, Events = events };
        }

        events.Add(new SandboxEvent
        {
            EventType = "process.start",
            Source = "guest",
            ProcessName = process.ProcessName,
            ProcessId = process.Id,
            Path = plan.SamplePath,
            CommandLine = plan.SamplePath
        });

        var exited = await WaitForExitAsync(process, plan.Duration, cancellationToken);
        if (!exited)
        {
            events.Add(new SandboxEvent { EventType = "process.timeout", Source = "guest", ProcessId = process.Id, Path = plan.SamplePath });
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(cancellationToken);
        }

        events.Add(new SandboxEvent
        {
            EventType = "process.exit",
            Source = "guest",
            ProcessName = SafeProcessName(process),
            ProcessId = process.Id,
            Path = plan.SamplePath,
            Data = { ["exitCode"] = SafeExitCode(process) }
        });

        return new SampleExecutionResult
        {
            Started = true,
            TimedOut = !exited,
            ExitCode = exited ? process.ExitCode : null,
            Events = events
        };
    }

    /// <summary>
    /// Waits for process exit or timeout.
    /// Inputs are process, timeout, and cancellation token; processing races
    /// process exit against delay; the method returns true when exited.
    /// </summary>
    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var exitTask = process.WaitForExitAsync(cancellationToken);
        var delayTask = Task.Delay(timeout, cancellationToken);
        return await Task.WhenAny(exitTask, delayTask) == exitTask;
    }

    /// <summary>
    /// Reads a process name defensively.
    /// The input is a Process, processing catches exited-process errors, and
    /// the method returns a process name or fallback.
    /// </summary>
    private static string SafeProcessName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch (InvalidOperationException)
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Reads a process exit code defensively.
    /// The input is a Process, processing catches invalid state, and the method
    /// returns exit code text or "unknown".
    /// </summary>
    private static string SafeExitCode(Process process)
    {
        try
        {
            return process.ExitCode.ToString();
        }
        catch (InvalidOperationException)
        {
            return "unknown";
        }
    }
}
