using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;

var exitCode = ProgramMain.Run(args);
return exitCode;

internal static class ProgramMain
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static int Run(string[] args)
    {
        try
        {
            if (args.Length == 0 || IsHelp(args[0]))
            {
                PrintUsage();
                return args.Length == 0 ? 1 : 0;
            }

            var command = args[0];
            var options = ParseOptions(args.Skip(1));
            return command.Equals("import-live", StringComparison.OrdinalIgnoreCase)
                ? ImportLive(options)
                : UnknownCommand(command);
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or DirectoryNotFoundException or InvalidOperationException or JsonException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"[ksword-jobtool] failed: {ex.Message}");
            return 2;
        }
    }

    private static int ImportLive(IReadOnlyDictionary<string, string> options)
    {
        var repositoryRoot = Path.GetFullPath(GetOption(options, "repo-root", Directory.GetCurrentDirectory()));
        var configPath = GetOption(options, "config", Path.Combine(repositoryRoot, "config", "sandbox.example.json"));
        var samplePath = RequireFile(options, "sample");
        var eventsPath = RequireFile(options, "events");
        var runbookExecutionPath = OptionalFile(options, "runbook-execution");
        var jobIdText = RequireOption(options, "job-id");
        if (!Guid.TryParse(jobIdText, out var jobId))
        {
            throw new ArgumentException($"--job-id must be a GUID. Value: {jobIdText}");
        }

        var duration = ParseInt(GetOption(options, "duration", "120"), "duration");
        var displayName = GetOption(options, "display-name", Path.GetFileName(samplePath));
        var config = SandboxConfigLoader.Load(configPath, repositoryRoot);
        var rulesPath = Path.Combine(config.Paths.RulesDirectory, "behavior-rules.json");
        var rules = RuleEngine.LoadRuleSet(rulesPath);
        var service = new SandboxJobService(config, rules);
        var job = service.ImportExternalRun(
            jobId,
            new SandboxSubmission
            {
                SamplePath = samplePath,
                DisplayName = displayName,
                DurationSeconds = duration,
                DryRun = false,
                GoldenVmName = GetOption(options, "vm", string.Empty),
                GoldenSnapshotName = GetOption(options, "checkpoint", string.Empty)
            },
            eventsPath,
            runbookExecutionPath);

        var result = new
        {
            status = job.Status.ToString(),
            jobId = job.JobId,
            jsonReportPath = job.JsonReportPath,
            htmlReportPath = job.HtmlReportPath,
            htmlReportZhPath = job.HtmlReportZhPath,
            htmlReportEnPath = job.HtmlReportEnPath,
            guestEventsPath = job.GuestEventsPath,
            runbookExecutionResultPath = job.RunbookExecutionResultPath,
            messages = job.Messages
        };
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        return 0;
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"[ksword-jobtool] unknown command: {command}");
        PrintUsage();
        return 1;
    }

    private static Dictionary<string, string> ParseOptions(IEnumerable<string> args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var enumerator = args.GetEnumerator();
        while (enumerator.MoveNext())
        {
            var token = enumerator.Current;
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected positional argument: {token}");
            }

            var name = token[2..];
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Empty option name is not valid.");
            }

            if (!enumerator.MoveNext())
            {
                throw new ArgumentException($"Option --{name} requires a value.");
            }

            result[name] = enumerator.Current;
        }

        return result;
    }

    private static string RequireOption(IReadOnlyDictionary<string, string> options, string name)
    {
        var value = GetOption(options, name, string.Empty);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"Missing required option --{name}.");
        }

        return value;
    }

    private static string GetOption(IReadOnlyDictionary<string, string> options, string name, string defaultValue)
    {
        return options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : defaultValue;
    }

    private static string RequireFile(IReadOnlyDictionary<string, string> options, string name)
    {
        var path = RequireOption(options, name);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Required file for --{name} was not found.", path);
        }

        return Path.GetFullPath(path);
    }

    private static string? OptionalFile(IReadOnlyDictionary<string, string> options, string name)
    {
        if (!options.TryGetValue(name, out var path) || string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Optional file for --{name} was not found.", path);
        }

        return Path.GetFullPath(path);
    }

    private static int ParseInt(string value, string name)
    {
        if (!int.TryParse(value, out var parsed) || parsed < 0)
        {
            throw new ArgumentException($"--{name} must be a non-negative integer. Value: {value}");
        }

        return parsed;
    }

    private static bool IsHelp(string value)
    {
        return value.Equals("help", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("--help", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("-h", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("/?", StringComparison.OrdinalIgnoreCase);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("KSword Sandbox JobTool");
        Console.WriteLine("Usage:");
        Console.WriteLine("  KSword.Sandbox.JobTool import-live --job-id <guid> --sample <exe> --events <events.json> [--runbook-execution <runbook-execution.json>] [--config <sandbox.json>] [--repo-root <path>] [--duration <seconds>]");
        Console.WriteLine();
        Console.WriteLine("Generates report.json/report.html/report.zh.html/report.en.html for a collected Hyper-V job without requiring the WebUI in-memory job list.");
    }
}
