using System.ComponentModel;
using System.Diagnostics;

namespace KSword.Sandbox.Agent.Diagnostics;

/// <summary>
/// Runs small helper commands with a hard timeout and redirected output.
/// Inputs are an executable name, argument list, timeout, and cancellation
/// token; processing starts the child process without a shell and kills it on
/// timeout; RunAsync returns stdout, stderr, exit state, or a captured launch
/// error without throwing for expected command failures.
/// </summary>
internal static class BoundedProcessRunner
{
    /// <summary>
    /// Runs a command with bounded wall-clock time.
    /// Inputs are file name, arguments, timeout, and cancellation token;
    /// processing redirects output and terminates the process tree on timeout;
    /// the method returns command metadata for diagnostic events.
    /// </summary>
    public static async Task<BoundedCommandResult> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var argumentList = arguments.ToList();
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var argument in argumentList)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                return BoundedCommandResult.Failed(
                    fileName,
                    FormatArguments(argumentList),
                    typeof(InvalidOperationException).FullName ?? nameof(InvalidOperationException),
                    "Process.Start returned false.");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            var exitTask = process.WaitForExitAsync(cancellationToken);
            var delayTask = Task.Delay(timeout > TimeSpan.Zero ? timeout : TimeSpan.FromSeconds(1), cancellationToken);

            if (await Task.WhenAny(exitTask, delayTask).ConfigureAwait(false) != exitTask)
            {
                cancellationToken.ThrowIfCancellationRequested();
                TryKillProcessTree(process);
                return BoundedCommandResult.FromTimeout(
                    fileName,
                    FormatArguments(argumentList),
                    await ReadCompletedTextAsync(stdoutTask).ConfigureAwait(false),
                    await ReadCompletedTextAsync(stderrTask).ConfigureAwait(false),
                    timeout);
            }

            await exitTask.ConfigureAwait(false);
            return new BoundedCommandResult(
                fileName,
                FormatArguments(argumentList),
                process.ExitCode,
                await ReadCompletedTextAsync(stdoutTask).ConfigureAwait(false),
                await ReadCompletedTextAsync(stderrTask).ConfigureAwait(false),
                TimedOut: false,
                ExceptionType: null,
                Message: null,
                Timeout: timeout);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return BoundedCommandResult.Failed(
                fileName,
                FormatArguments(argumentList),
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Message);
        }
    }

    /// <summary>
    /// Reads already-running output tasks without allowing cleanup to hang.
    /// The input is a stdout/stderr read task; processing waits briefly and
    /// suppresses read failures; the method returns available text or empty.
    /// </summary>
    private static async Task<string> ReadCompletedTextAsync(Task<string> readTask)
    {
        try
        {
            return await readTask.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or InvalidOperationException or OperationCanceledException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Terminates a process tree while suppressing expected process-race errors.
    /// The input is a process; processing attempts Kill(entireProcessTree) only
    /// when it has not exited; the method returns no value.
    /// </summary>
    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
        }
    }

    /// <summary>
    /// Formats arguments for diagnostics without using a shell.
    /// The input is the argument list; processing adds quotes around whitespace;
    /// the method returns a display-only command-line suffix.
    /// </summary>
    private static string FormatArguments(IEnumerable<string> arguments)
    {
        return string.Join(
            " ",
            arguments.Select(argument => argument.Any(char.IsWhiteSpace)
                ? '"' + argument.Replace("\"", "\\\"", StringComparison.Ordinal) + '"'
                : argument));
    }
}

/// <summary>
/// Describes the result of a bounded helper-command execution.
/// Inputs are process metadata, output text, timeout state, and launch errors;
/// processing is immutable storage; records are converted into probe events or
/// parsing inputs by guest collectors.
/// </summary>
internal sealed record BoundedCommandResult(
    string FileName,
    string Arguments,
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    string? ExceptionType,
    string? Message,
    TimeSpan Timeout)
{
    public bool Succeeded => !TimedOut && ExceptionType is null && ExitCode == 0;

    /// <summary>
    /// Creates a command-timeout result.
    /// Inputs are command identity, partial output, and timeout; processing
    /// stores timeout metadata; the method returns a BoundedCommandResult.
    /// </summary>
    public static BoundedCommandResult FromTimeout(
        string fileName,
        string arguments,
        string stdout,
        string stderr,
        TimeSpan timeout)
    {
        return new BoundedCommandResult(
            fileName,
            arguments,
            ExitCode: null,
            stdout,
            stderr,
            TimedOut: true,
            ExceptionType: typeof(TimeoutException).FullName,
            Message: $"Command exceeded {timeout.TotalMilliseconds:0} ms.",
            Timeout: timeout);
    }

    /// <summary>
    /// Creates a command-launch or read-failure result.
    /// Inputs are command identity plus exception type/message; processing
    /// stores an empty output payload; the method returns a result record.
    /// </summary>
    public static BoundedCommandResult Failed(
        string fileName,
        string arguments,
        string exceptionType,
        string message)
    {
        return new BoundedCommandResult(
            fileName,
            arguments,
            ExitCode: null,
            StandardOutput: string.Empty,
            StandardError: string.Empty,
            TimedOut: false,
            ExceptionType: exceptionType,
            Message: message,
            Timeout: TimeSpan.Zero);
    }
}
