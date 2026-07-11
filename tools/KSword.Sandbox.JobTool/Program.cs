using System.Text.Json;

var exitCode = ProgramMain.Run(args);
return exitCode;

internal static partial class ProgramMain
{
    private const string ToolPrefix = "[ksword-jobtool]";
    private const string DefaultRuntimeRoot = "D:\\Temp\\KSwordSandbox";

    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static int Run(string[] args)
    {
        try
        {
            if (args.Length == 0 || IsHelp(args[0]))
            {
                PrintUsage();
                return args.Length == 0 ? 1 : 0;
            }

            var command = NormalizeCommand(args, out var optionStartIndex);
            var options = ParseOptions(args.Skip(optionStartIndex).ToArray());
            return command.ToLowerInvariant() switch
            {
                "plan" => PlanJob(options),
                "list" or "list-jobs" => ListJobs(options),
                "status" or "show-job" => ShowJob(options),
                "report" or "report-rebuild" or "rebuild-report" => RebuildReport(options, "rebuild-report"),
                "import" or "import-live" => RebuildReport(options, "import-live"),
                "artifacts" or "artifacts-inspect" or "inspect-artifacts" => InspectArtifacts(options),
                "recover" => RecoverJob(options),
                "readiness" => CheckReadiness(options),
                _ => UnknownCommand(command)
            };
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or DirectoryNotFoundException or InvalidOperationException or JsonException or IOException or UnauthorizedAccessException or KeyNotFoundException or FormatException)
        {
            Console.Error.WriteLine($"{ToolPrefix} 失败 / failed: {Safe(ex.Message)}");
            return 2;
        }
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"{ToolPrefix} 未知命令 / unknown command: {Safe(command)}");
        PrintUsage();
        return 1;
    }

    private static string NormalizeCommand(string[] args, out int optionStartIndex)
    {
        optionStartIndex = 1;
        var command = args[0];
        if (args.Length < 2 || args[1].StartsWith("--", StringComparison.Ordinal))
        {
            return command;
        }

        var action = args[1];
        var normalizedCommand = command.ToLowerInvariant();
        var normalizedAction = action.ToLowerInvariant();
        if ((normalizedCommand == "report" && normalizedAction == "rebuild") ||
            (normalizedCommand == "artifacts" && normalizedAction == "inspect") ||
            (normalizedCommand == "import" && normalizedAction == "live"))
        {
            optionStartIndex = 2;
            return $"{normalizedCommand}-{normalizedAction}";
        }

        return command;
    }
}
