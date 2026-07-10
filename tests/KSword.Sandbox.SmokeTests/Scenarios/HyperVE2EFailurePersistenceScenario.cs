using System.Text.RegularExpressions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the top-level Hyper-V E2E script persists a failed live start.
/// Inputs are repository text files; processing statically checks child-script
/// launch structure and failure persistence reachability without invoking
/// Hyper-V; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class HyperVE2EFailurePersistenceScenario : ISmokeTestScenario
{
    public string ScenarioId => "hyperv.e2e.failure-persistence.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var scriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-HyperVE2E.ps1");
        SmokeAssert.True(File.Exists(scriptPath), "Invoke-HyperVE2E.ps1 is missing.");

        var script = File.ReadAllText(scriptPath);
        var functions = FindPowerShellFunctions(script);
        var helper = FindChildScriptInvocationHelper(functions);
        SmokeAssert.True(
            helper is not null,
            "Invoke-HyperVE2E.ps1 should launch child scripts through a helper/wrapper that catches child launch failures and reports an exit code for persistence.");

        AssertChildLaunchHelperContract(helper!);
        AssertChildScriptsUseHelper(script, helper!.Name);
        AssertStartFailureCanPersist(script, helper!.Name);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V E2E child launch failures remain reachable to runbook execution persistence."
        });
    }

    /// <summary>
    /// Finds a helper function that executes child PowerShell scripts and
    /// reports structured exit status. Inputs are parsed function blocks;
    /// processing filters by call operator, catch block, and exit-code handling;
    /// the method returns the best matching function or null.
    /// </summary>
    private static PowerShellFunction? FindChildScriptInvocationHelper(IReadOnlyList<PowerShellFunction> functions)
    {
        return functions.FirstOrDefault(function =>
            function.Name.StartsWith("Invoke-", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(function.Text, @"(?i)\b(?:ScriptPath|FilePath|Path|Arguments?)\b") &&
            Regex.IsMatch(function.Body, @"(?i)(?:\bStart-Process\b|\bProcessStartInfo\b|\[Diagnostics\.Process\]|(?m)&\s+\$[A-Za-z_][A-Za-z0-9_]*\b)") &&
            Regex.IsMatch(function.Body, @"(?i)\bcatch\b") &&
            Regex.IsMatch(function.Body, @"(?i)(?:\$LASTEXITCODE|\bExitCode\b)"));
    }

    /// <summary>
    /// Verifies the child launch wrapper preserves catch-path failure details
    /// instead of throwing past the caller. Inputs are a PowerShell function
    /// block; processing checks literal contract markers; return value is none.
    /// </summary>
    private static void AssertChildLaunchHelperContract(PowerShellFunction helper)
    {
        SmokeAssert.True(
            Regex.IsMatch(helper.Body, @"(?i)(?:\bStart-Process\b|\bProcessStartInfo\b|\[Diagnostics\.Process\]|(?m)&\s+\$[A-Za-z_][A-Za-z0-9_]*\b)"),
            $"Child launch helper {helper.Name} should execute the supplied script path through a child PowerShell process.");
        SmokeAssert.True(
            Regex.IsMatch(helper.Body, @"(?i)(?:\$LASTEXITCODE|\bExitCode\b)"),
            $"Child launch helper {helper.Name} should capture or return the child script exit code.");

        var catchBlock = ExtractFirstCatchBlock(helper.Body);
        SmokeAssert.True(
            !string.IsNullOrWhiteSpace(catchBlock),
            $"Child launch helper {helper.Name} should have a catch block for launch failures.");
        SmokeAssert.True(
            Regex.IsMatch(catchBlock, @"(?i)(?:Exception\.Message|\$_\.Exception|\bErrorRecord\b|\bErrorMessage\b)"),
            $"Child launch helper {helper.Name} catch path should preserve the child launch error message.");
        SmokeAssert.True(
            Regex.IsMatch(catchBlock, @"(?i)(?:\bExitCode\b|Success\s*=\s*\$false|Success\s*=\s*false)"),
            $"Child launch helper {helper.Name} catch path should return a failed result for Save-RunbookExecutionRecord to persist.");
        SmokeAssert.True(
            !Regex.IsMatch(catchBlock, @"(?im)^\s*(?:throw\b|exit\b)"),
            $"Child launch helper {helper.Name} catch path should not throw or exit before the orchestrator can persist the failed run.");
    }

    /// <summary>
    /// Verifies both live child scripts are launched through the same helper
    /// instead of direct call-operator invocations. Inputs are script text and
    /// helper name; processing searches invocation windows; return value is none.
    /// </summary>
    private static void AssertChildScriptsUseHelper(string script, string helperName)
    {
        SmokeAssert.True(
            FindInvocationIndex(script, helperName, "$startScript") >= 0,
            "Invoke-HyperVE2E.ps1 should launch Start-SandboxHyperVJob.ps1 through the child script helper/wrapper.");
        SmokeAssert.True(
            FindInvocationIndex(script, helperName, "$collectScript") >= 0,
            "Invoke-HyperVE2E.ps1 should launch Collect-GuestOutputs.ps1 through the child script helper/wrapper.");
        SmokeAssert.True(
            !Regex.IsMatch(script, @"(?m)^\s*&\s+\$startScript\b"),
            "Invoke-HyperVE2E.ps1 should not directly invoke $startScript; direct invocation can bypass failed-start persistence on launch errors.");
        SmokeAssert.True(
            !Regex.IsMatch(script, @"(?m)^\s*&\s+\$collectScript\b"),
            "Invoke-HyperVE2E.ps1 should not directly invoke $collectScript; direct invocation can bypass structured persistence.");
    }

    /// <summary>
    /// Verifies the failed start path cannot exit before saving a runbook
    /// execution record. Inputs are script text and helper name; processing
    /// checks ordering from start launch through Save-RunbookExecutionRecord;
    /// return value is none.
    /// </summary>
    private static void AssertStartFailureCanPersist(string script, string helperName)
    {
        var startInvocationIndex = FindInvocationIndex(script, helperName, "$startScript");
        SmokeAssert.True(startInvocationIndex >= 0, "Start child invocation through helper/wrapper was not found.");

        var saveIndex = script.IndexOf("Save-RunbookExecutionRecord", startInvocationIndex, StringComparison.Ordinal);
        SmokeAssert.True(
            saveIndex > startInvocationIndex,
            "Save-RunbookExecutionRecord should be reachable after the start child script returns a failed/caught result.");

        var betweenStartAndSave = script[startInvocationIndex..saveIndex];
        SmokeAssert.True(
            Regex.IsMatch(betweenStartAndSave, @"(?i)(?:Start phase failed|\$startExitCode|\bStartExitCode\b|\bExitCode\b)"),
            "The live path should inspect and label failed start child results before saving the runbook execution record.");
        SmokeAssert.True(
            !Regex.IsMatch(betweenStartAndSave, @"(?im)^\s*(?:throw\b|exit\s+[1-9]\b)"),
            "The live path should not throw or exit on a failed start child result before Save-RunbookExecutionRecord runs.");
    }

    /// <summary>
    /// Finds a helper invocation involving a child script variable. Inputs are
    /// script text, helper name, and child variable; processing scans local
    /// windows around each child variable occurrence; the method returns the
    /// invocation index or -1.
    /// </summary>
    private static int FindInvocationIndex(string script, string helperName, string childScriptVariable)
    {
        var searchIndex = 0;
        while (searchIndex < script.Length)
        {
            var variableIndex = script.IndexOf(childScriptVariable, searchIndex, StringComparison.Ordinal);
            if (variableIndex < 0)
            {
                return -1;
            }

            var windowStart = Math.Max(0, variableIndex - 500);
            var windowLength = Math.Min(script.Length - windowStart, 1200);
            var window = script.Substring(windowStart, windowLength);
            var helperOffset = window.IndexOf(helperName, StringComparison.Ordinal);
            if (helperOffset >= 0 && !Regex.IsMatch(window, @"(?im)^\s*function\s+" + Regex.Escape(helperName) + @"\b"))
            {
                return windowStart + helperOffset;
            }

            searchIndex = variableIndex + childScriptVariable.Length;
        }

        return -1;
    }

    /// <summary>
    /// Extracts PowerShell function blocks with simple brace matching. Inputs
    /// are script text; processing finds top-level function declarations; the
    /// method returns function name/body records.
    /// </summary>
    private static IReadOnlyList<PowerShellFunction> FindPowerShellFunctions(string script)
    {
        var functions = new List<PowerShellFunction>();
        foreach (Match match in Regex.Matches(script, @"(?im)^\s*function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\{"))
        {
            var openBraceIndex = script.IndexOf('{', match.Index);
            var closeBraceIndex = FindMatchingBrace(script, openBraceIndex);
            if (openBraceIndex < 0 || closeBraceIndex <= openBraceIndex)
            {
                continue;
            }

            var text = script.Substring(match.Index, closeBraceIndex - match.Index + 1);
            var body = script.Substring(openBraceIndex + 1, closeBraceIndex - openBraceIndex - 1);
            functions.Add(new PowerShellFunction(match.Groups[1].Value, text, body));
        }

        return functions;
    }

    /// <summary>
    /// Extracts the first catch block body from a function body. Inputs are
    /// PowerShell function body text; processing finds the catch braces; the
    /// method returns catch contents or an empty string.
    /// </summary>
    private static string ExtractFirstCatchBlock(string body)
    {
        var match = Regex.Match(body, @"(?i)\bcatch\b[^{]*\{");
        if (!match.Success)
        {
            return string.Empty;
        }

        var openBraceIndex = body.IndexOf('{', match.Index);
        var closeBraceIndex = FindMatchingBrace(body, openBraceIndex);
        if (openBraceIndex < 0 || closeBraceIndex <= openBraceIndex)
        {
            return string.Empty;
        }

        return body.Substring(openBraceIndex + 1, closeBraceIndex - openBraceIndex - 1);
    }

    /// <summary>
    /// Finds the matching close brace for a PowerShell block. Inputs are text
    /// and an opening brace index; processing counts nested braces; the method
    /// returns the close index or -1.
    /// </summary>
    private static int FindMatchingBrace(string text, int openBraceIndex)
    {
        if (openBraceIndex < 0 || openBraceIndex >= text.Length || text[openBraceIndex] != '{')
        {
            return -1;
        }

        var depth = 0;
        for (var index = openBraceIndex; index < text.Length; index++)
        {
            if (text[index] == '{')
            {
                depth++;
            }
            else if (text[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
    }

    /// <summary>
    /// Holds a PowerShell function declaration extracted from script text.
    /// Inputs are name/text/body values; processing is record initialization;
    /// properties expose the parsed values.
    /// </summary>
    private sealed record PowerShellFunction(string Name, string Text, string Body);
}
