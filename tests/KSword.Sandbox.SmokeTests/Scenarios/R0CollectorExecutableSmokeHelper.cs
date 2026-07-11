using System.Diagnostics;
using System.ComponentModel;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Builds and runs the native R0Collector executable for no-device smoke tests.
/// Inputs are repository/runtime paths and collector CLI arguments; processing
/// writes only under D:\Temp\KSwordSandbox\verify and never opens the driver
/// device; return values expose the collector process result and parsed JSONL.
/// </summary>
internal static class R0CollectorExecutableSmokeHelper
{
    private const string VerifyRoot = @"D:\Temp\KSwordSandbox\verify\r0collector-smoke";
    private static readonly SemaphoreSlim BuildLock = new(1, 1);
    private static R0CollectorBuildResult? cachedBuild;

    private static readonly JsonSerializerOptions JsonLineOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Builds the collector once into the verification directory. Inputs are a
    /// smoke context and cancellation token; processing invokes MSBuild with
    /// OutDir/IntDir outside the repository; return value is the built exe path.
    /// </summary>
    public static async Task<R0CollectorBuildResult> BuildCollectorAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        await BuildLock.WaitAsync(cancellationToken);
        try
        {
            if (cachedBuild is not null && File.Exists(cachedBuild.ExecutablePath))
            {
                return cachedBuild;
            }

            var projectPath = Path.Combine(
                context.RepositoryRoot,
                "guest",
                "KSword.Sandbox.R0Collector",
                "KSword.Sandbox.R0Collector.vcxproj");
            SmokeAssert.True(File.Exists(projectPath), $"R0Collector native project is missing: {projectPath}");

            var msbuildPath = ResolveMsBuildPath();
            var outputRoot = Path.Combine(VerifyRoot, Guid.NewGuid().ToString("N"));
            var outDir = AddTrailingSeparator(Path.Combine(outputRoot, "bin"));
            var intDir = AddTrailingSeparator(Path.Combine(outputRoot, "obj"));
            Directory.CreateDirectory(outDir);
            Directory.CreateDirectory(intDir);

            var result = await RunProcessAsync(
                msbuildPath,
                [
                    projectPath,
                    "/p:Configuration=Debug",
                    "/p:Platform=x64",
                    $"/p:OutDir={outDir}",
                    $"/p:IntDir={intDir}",
                    "/m:1",
                    "/v:minimal"
                ],
                context.RepositoryRoot,
                cancellationToken);
            SmokeAssert.True(
                result.ExitCode == 0,
                $"R0Collector native build should succeed without writing repository bin/obj. Output: {result.CombinedOutput}");

            var executablePath = Path.Combine(outDir, "KSword.Sandbox.R0Collector.exe");
            SmokeAssert.True(File.Exists(executablePath), $"Built R0Collector executable is missing: {executablePath}");

            cachedBuild = new R0CollectorBuildResult(executablePath, outputRoot);
            return cachedBuild;
        }
        finally
        {
            BuildLock.Release();
        }
    }

    /// <summary>
    /// Runs the collector with captured output. Inputs are the exe path, CLI
    /// arguments, working directory, and cancellation token; processing waits for
    /// normal process exit; return value contains exit code and combined output.
    /// </summary>
    public static Task<R0CollectorProcessResult> RunCollectorAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        return RunProcessAsync(executablePath, arguments, workingDirectory, cancellationToken);
    }

    public static bool IsExecutionBlockedByHostPolicy(R0CollectorProcessResult result)
    {
        return result.ExitCode == R0CollectorProcessResult.ExecutionBlockedExitCode;
    }

    /// <summary>
    /// Reads collector JSONL while explicitly tolerating blank/malformed rows.
    /// Inputs are an output path; processing parses valid SandboxEvent rows and
    /// counts blank/malformed noise; return value contains rows and diagnostics.
    /// </summary>
    public static R0CollectorJsonLines ReadJsonLines(string path)
    {
        SmokeAssert.True(File.Exists(path), $"Collector JSONL output is missing: {path}");

        var events = new List<SandboxEvent>();
        var malformedLines = new List<string>();
        var blankLineCount = 0;
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                blankLineCount++;
                continue;
            }

            try
            {
                var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonLineOptions);
                if (evt is not null)
                {
                    events.Add(evt);
                }
            }
            catch (JsonException)
            {
                malformedLines.Add(line);
            }
        }

        return new R0CollectorJsonLines(events, blankLineCount, malformedLines);
    }

    /// <summary>
    /// Creates a unique output path under the native build verification root.
    /// Inputs are a build result and filename; processing creates the run
    /// directory; return value is an absolute path for collector output.
    /// </summary>
    public static string CreateRunOutputPath(R0CollectorBuildResult build, string fileName)
    {
        var runRoot = Path.Combine(build.OutputRoot, "runs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runRoot);
        return Path.Combine(runRoot, fileName);
    }

    private static string ResolveMsBuildPath()
    {
        var candidates = new List<string>();
        var overridePath = Environment.GetEnvironmentVariable("KSW_R0COLLECTOR_MSBUILD_PATH");
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            candidates.Add(overridePath);
        }

        candidates.AddRange(
        [
            @"D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe",
            @"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
            @"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
            @"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
            @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
        ]);

        var pathCandidate = Environment.GetEnvironmentVariable("PATH")?
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, "MSBuild.exe"))
            .FirstOrDefault(File.Exists);
        if (pathCandidate is not null)
        {
            candidates.Add(pathCandidate);
        }

        var resolved = candidates.FirstOrDefault(File.Exists);
        SmokeAssert.True(
            resolved is not null,
            "MSBuild.exe is required for the executable R0Collector smoke. Set KSW_R0COLLECTOR_MSBUILD_PATH or install VS Build Tools.");
        return resolved!;
    }

    private static async Task<R0CollectorProcessResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 5 or 32)
        {
            return new R0CollectorProcessResult(
                R0CollectorProcessResult.ExecutionBlockedExitCode,
                $"Execution blocked by host policy while starting '{fileName}': {ex.Message}");
        }

        using (process ?? throw new InvalidOperationException($"Failed to start {fileName}."))
        {
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new R0CollectorProcessResult(process.ExitCode, string.Concat(stdout, stderr));
        }
    }

    private static string AddTrailingSeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
    }
}

internal sealed record R0CollectorBuildResult(string ExecutablePath, string OutputRoot);

internal sealed record R0CollectorProcessResult(int ExitCode, string CombinedOutput)
{
    public const int ExecutionBlockedExitCode = -10005;
}

internal sealed record R0CollectorJsonLines(
    IReadOnlyList<SandboxEvent> Events,
    int BlankLineCount,
    IReadOnlyList<string> MalformedLines);
