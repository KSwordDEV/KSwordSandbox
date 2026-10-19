using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the Guest Agent against being attributed to the sample it runs.
///
/// The Agent is launched as
///   KSword.Sandbox.Agent.exe --sample &lt;path&gt; --out &lt;dir&gt;
/// so its own command line necessarily contains the submitted sample path.
/// Path matching therefore matched the Agent itself, seeded it as a sample root
/// PID, and ExpandSampleProcessTree then swept every collector tool the Agent
/// starts into the sample tree.
///
/// Observed on Shamoon: wevtutil, auditpol, logman, pktmon, ipconfig and
/// netsh were all reported as confirmed sample behavior, and on WannaCry 1416
/// conhost, 541 wevtutil and 269 powershell rows were attributed to the worm.
/// Only the sample and what it genuinely spawns may be confirmed.
/// </summary>
internal sealed class GuestAgentNotSampleAttributionScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.guest-agent-not-sample";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        const int agentPid = 9656;
        const int samplePid = 8032;
        var start = DateTimeOffset.UtcNow;
        var samplePath = @"C:\KSwordSandbox\incoming\Shamoon.exe";
        var agentPath = @"C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe";
        var outDir = @"\\vmware-host\Shared Folders\KSwordOutput";

        var classified = SampleCorrelationClassifier.Apply(
        [
            // The collector. Its command line names the sample, which is exactly
            // why it must be excluded by image rather than by path matching.
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start,
                ProcessName = "KSword.Sandbox.Agent.exe",
                ProcessId = agentPid,
                Path = agentPath,
                CommandLine = $"\"{agentPath}\" --sample {samplePath} --out \"{outDir}\""
            },
            // A collector tool. Real malware launches these too, so only the
            // parentage may distinguish them.
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start.AddMilliseconds(10),
                ProcessName = "wevtutil.exe",
                ProcessId = 2872,
                ParentProcessId = agentPid,
                Path = @"C:\Windows\system32\wevtutil.exe",
                CommandLine = @"C:\Windows\system32\wevtutil.exe gp Microsoft-Windows-Security-Auditing /ge:true /gm:false"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start.AddMilliseconds(20),
                ProcessName = "logman.exe",
                ProcessId = 9360,
                ParentProcessId = agentPid,
                Path = @"C:\Windows\system32\logman.exe",
                CommandLine = "\"logman.exe\" start \"NT Kernel Logger\" -p {9e814aad-3204-11d2-9a82-006008a86939} -o \"" + outDir + "\\trace\""
            },
            // The actual sample.
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start.AddMilliseconds(30),
                ProcessName = "Shamoon.exe",
                ProcessId = samplePid,
                ParentProcessId = agentPid,
                Path = samplePath,
                CommandLine = $"\"{samplePath}\""
            },
            // And something the sample itself spawns, which must stay confirmed.
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start.AddMilliseconds(40),
                ProcessName = "cmd.exe",
                ProcessId = 9156,
                ParentProcessId = samplePid,
                Path = @"C:\Windows\system32\cmd.exe",
                CommandLine = "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures"
            }
        ], samplePath);

        string Correlation(int pid)
        {
            var row = classified.Single(candidate => candidate.EventType == "process.start" && candidate.ProcessId == pid);
            return row.Data.TryGetValue("sampleCorrelation", out var value) ? value : "(none)";
        }

        // The sample and its own child remain attributed.
        SmokeAssert.True(Correlation(samplePid) == "confirmed",
            "The submitted sample must stay confirmed even though the Agent is its parent.");
        SmokeAssert.True(Correlation(9156) == "confirmed",
            "A process the sample itself spawns must stay confirmed.");

        // The collector and its tools must not be.
        foreach (var collectorPid in new[] { agentPid, 2872, 9360 })
        {
            var correlation = Correlation(collectorPid);
            SmokeAssert.True(correlation != "confirmed" && correlation != "probable",
                $"Guest Agent tooling (pid {collectorPid}) must not be attributed to the sample, but was '{correlation}'.");
            var row = classified.Single(candidate => candidate.EventType == "process.start" && candidate.ProcessId == collectorPid);
            SmokeAssert.True(row.Data.TryGetValue("sampleConclusionPromoted", out var promoted) && promoted == "false",
                $"Guest Agent tooling (pid {collectorPid}) must never be promoted into a sample conclusion.");
        }

        // wevtutil is also a real anti-analysis tool when malware uses it, so the
        // guard must key on parentage rather than on the image alone.
        var malwareWevtutil = SampleCorrelationClassifier.Apply(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start,
                ProcessName = "Shamoon.exe",
                ProcessId = samplePid,
                Path = samplePath,
                CommandLine = $"\"{samplePath}\""
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start.AddMilliseconds(10),
                ProcessName = "wevtutil.exe",
                ProcessId = 5555,
                ParentProcessId = samplePid,
                Path = @"C:\Windows\system32\wevtutil.exe",
                CommandLine = @"C:\Windows\system32\wevtutil.exe cl Security"
            }
        ], samplePath);

        var malwareRow = malwareWevtutil.Single(evt => evt.EventType == "process.start" && evt.ProcessId == 5555);
        SmokeAssert.True(malwareRow.Data.TryGetValue("sampleCorrelation", out var malwareCorrelation) && malwareCorrelation == "confirmed",
            "A wevtutil launched by the sample must stay confirmed; the self-noise guard must not blanket-ban system utilities.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "The Guest Agent and the tools it launches stay environment noise, while the sample and its own children remain attributed."
        });
    }
}