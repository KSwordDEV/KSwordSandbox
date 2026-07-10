using System.Diagnostics;
using System.Globalization;
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

        Process? startedProcess;
        try
        {
            startedProcess = Process.Start(startInfo);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            events.Add(CreateExecutionExceptionEvent("process.start_failed", plan.SamplePath, processId: null, ex));
            return new SampleExecutionResult { Started = false, Events = events };
        }

        using var process = startedProcess;
        if (process is null)
        {
            events.Add(new SandboxEvent
            {
                EventType = "process.start_failed",
                Source = "guest",
                Path = plan.SamplePath,
                Data =
                {
                    ["message"] = "Process.Start returned null."
                }
            });
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

        bool exited;
        try
        {
            exited = await WaitForExitAsync(process, plan.Duration, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            events.Add(CreateExecutionExceptionEvent("process.wait_failed", plan.SamplePath, process.Id, ex));
            exited = SafeHasExited(process);
        }

        var timedOut = !exited;
        if (timedOut)
        {
            events.Add(new SandboxEvent
            {
                EventType = "process.timeout",
                Source = "guest",
                ProcessId = process.Id,
                Path = plan.SamplePath,
                Data =
                {
                    ["timeoutSeconds"] = plan.Duration.TotalSeconds.ToString("0", CultureInfo.InvariantCulture)
                }
            });

            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                events.Add(CreateExecutionExceptionEvent("process.kill_failed", plan.SamplePath, process.Id, ex));
            }
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
            TimedOut = timedOut,
            ExitCode = exited ? SafeExitCodeValue(process) : null,
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
            return process.ExitCode.ToString(CultureInfo.InvariantCulture);
        }
        catch (InvalidOperationException)
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Reads a process exit code defensively.
    /// The input is a Process, processing catches invalid state, and the method
    /// returns a nullable exit code.
    /// </summary>
    private static int? SafeExitCodeValue(Process process)
    {
        try
        {
            return process.ExitCode;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads process exit state defensively.
    /// The input is a Process, processing catches invalid state, and the method
    /// returns true when the process is known to have exited.
    /// </summary>
    private static bool SafeHasExited(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    /// <summary>
    /// Creates a normalized execution exception event.
    /// Inputs are event type, sample path, optional PID, and exception;
    /// processing copies exception type/message into Data; the method returns a
    /// SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateExecutionExceptionEvent(string eventType, string samplePath, int? processId, Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessId = processId,
            Path = samplePath,
            Data =
            {
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message
            }
        };
    }
}
