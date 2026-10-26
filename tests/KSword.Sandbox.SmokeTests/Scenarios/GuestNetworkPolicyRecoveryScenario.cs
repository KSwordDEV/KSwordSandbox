using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Agent.Execution;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Exercises network-policy failure cleanup with a fake command runner. No
/// network adapter, firewall setting, VM, or sample is touched on the host.
/// </summary>
internal sealed class GuestNetworkPolicyRecoveryScenario : ISmokeTestScenario
{
    private const string AdapterSnapshot = "[{\"Name\":\"Ethernet\",\"InterfaceGuid\":\"11111111-1111-1111-1111-111111111111\",\"Status\":\"Up\",\"PnPDeviceID\":\"PCI\\\\VEN_1234\"},{\"Name\":\"Ethernet 2\",\"InterfaceGuid\":\"22222222-2222-2222-2222-222222222222\",\"Status\":\"Up\",\"PnPDeviceID\":\"PCI\\\\VEN_5678\"}]";
    private const string FirewallSnapshot = "[{\"Name\":\"Domain\",\"Enabled\":\"False\"},{\"Name\":\"Private\",\"Enabled\":\"True\"},{\"Name\":\"Public\",\"Enabled\":\"NotConfigured\"}]";

    public string ScenarioId => "guest.network-policy-recovery.contract";

    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await NoNicIsSafelyBlockedAsync(string.Empty);
        await NoNicIsSafelyBlockedAsync("[]");
        await AdapterSnapshotFailureRemainsClosedAsync(1, string.Empty, string.Empty);
        await AdapterSnapshotFailureRemainsClosedAsync(0, "[{", string.Empty);
        await AdapterSnapshotFailureRemainsClosedAsync(0, string.Empty, "Get-NetAdapter diagnostic");
        await PartialAdapterDisableIsRestoredAsync();
        await ExitZeroDisableWithoutStateChangeRemainsClosedAsync();
        await MissingAdapterVerificationRemainsClosedAsync();
        await FirewallStateIsRestoredAsync(failFirewallEnable: false);
        await FirewallStateIsRestoredAsync(failFirewallEnable: true);
        await FirewallStateIsRestoredAsync(failFirewallEnable: false, failDomainRestore: true);
        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "NIC-free guests block safely; adapter query/parse failures and exit-zero non-disables stay closed; partial adapter and firewall failures restore original state."
        };
    }

    private static async Task NoNicIsSafelyBlockedAsync(string adapterOutput)
    {
        var commands = new List<string>();
        Task<BoundedCommandResult> Run(string file, IReadOnlyList<string> args)
        {
            var command = string.Join(" ", args);
            commands.Add(command);
            var output = command.Contains("Select-Object Name,InterfaceGuid,Status,PnPDeviceID", StringComparison.Ordinal)
                ? adapterOutput
                : command.Contains("Get-NetFirewallProfile -PolicyStore PersistentStore", StringComparison.Ordinal)
                    ? FirewallSnapshot : "absent";
            return Task.FromResult(Result(file, command, 0, output));
        }

        var guard = new GuestNetworkPolicyGuard(SandboxNetworkPolicy.Block, Run);
        var events = new List<SandboxEvent>();
        await guard.ApplyAsync(events);
        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.AppliedEventType &&
            e.Data["adaptersDisabled"] == "0"),
            "An exit-0 empty NIC snapshot must produce blocked state with zero disabled adapters.");
        SmokeAssert.True(!commands.Any(command => command.Contains("Disable-NetAdapter", StringComparison.Ordinal) ||
            command.Contains("Disable-PnpDevice", StringComparison.Ordinal)),
            "A NIC-free guest must not invoke adapter-disable commands.");
        SmokeAssert.True(commands.Any(command => command.Contains("advfirewall firewall add rule", StringComparison.Ordinal)),
            "A NIC-free guest must still install firewall rules for adapters that may appear later.");
        await guard.RestoreAsync(events);
        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.RestoredEventType),
            "A NIC-free guest must complete cleanup without attempting to enable an adapter.");
    }

    private static async Task AdapterSnapshotFailureRemainsClosedAsync(int exitCode, string output, string error)
    {
        var commands = new List<string>();
        Task<BoundedCommandResult> Run(string file, IReadOnlyList<string> args)
        {
            var command = string.Join(" ", args);
            commands.Add(command);
            return Task.FromResult(Result(file, command, exitCode, output, error));
        }

        var guard = new GuestNetworkPolicyGuard(SandboxNetworkPolicy.Block, Run);
        var events = new List<SandboxEvent>();
        try
        {
            await guard.ApplyAsync(events);
            throw new InvalidOperationException("A failed or malformed NIC query must fail closed.");
        }
        catch (GuestNetworkPolicyException)
        {
        }

        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.ApplyFailedEventType),
            "A failed or malformed NIC query must emit networkPolicy.apply_failed.");
        SmokeAssert.True(!commands.Any(command => command.Contains("advfirewall", StringComparison.Ordinal)),
            "A failed NIC query must not proceed to policy application.");
    }

    private static async Task PartialAdapterDisableIsRestoredAsync()
    {
        var commands = new List<string>();
        Task<BoundedCommandResult> Run(string file, IReadOnlyList<string> args)
        {
            var command = string.Join(" ", args);
            commands.Add(command);
            if (command.Contains("Disable-NetAdapter", StringComparison.Ordinal))
            {
                // The first adapter was disabled before the cmdlet failed on
                // the second; the fallback also fails.
                return Task.FromResult(Result(file, command, 1, error: "second adapter failed"));
            }

            if (command.Contains("Disable-PnpDevice", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, 1, error: "fallback failed"));
            }

            return Task.FromResult(Result(file, command, 0, output: command.Contains("Select-Object Name,InterfaceGuid,Status,PnPDeviceID", StringComparison.Ordinal)
                ? AdapterSnapshot
                : command.Contains("$missing =", StringComparison.Ordinal) ? "0" : "absent"));
        }

        var guard = new GuestNetworkPolicyGuard(SandboxNetworkPolicy.Block, Run);
        var events = new List<SandboxEvent>();
        try
        {
            await guard.ApplyAsync(events);
            throw new InvalidOperationException("Partial disable must fail closed.");
        }
        catch (GuestNetworkPolicyException)
        {
        }

        await guard.RestoreAsync(events);
        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.ApplyFailedEventType && e.Data["adaptersDisabled"] == "2"),
            "Apply failure must retain all originally enabled adapters for cleanup.");
        SmokeAssert.True(commands.Any(command => command.Contains("Enable-NetAdapter", StringComparison.Ordinal)),
            "Cleanup must attempt to re-enable the adapter disabled before the error.");
        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.RestoredEventType),
            "Partial adapter disable must produce a successful cleanup event when restore succeeds.");
    }

    private static async Task ExitZeroDisableWithoutStateChangeRemainsClosedAsync()
    {
        await VerifyFailedDisableStateRemainsClosedAsync(AdapterSnapshot, "Up");
    }

    private static async Task MissingAdapterVerificationRemainsClosedAsync()
    {
        await VerifyFailedDisableStateRemainsClosedAsync("[]", "missing");
    }

    private static async Task VerifyFailedDisableStateRemainsClosedAsync(string verificationOutput, string expectedStatus)
    {
        var commands = new List<string>();
        Task<BoundedCommandResult> Run(string file, IReadOnlyList<string> args)
        {
            var command = string.Join(" ", args);
            commands.Add(command);
            var output = command.Contains("Select-Object Name,InterfaceGuid,Status,PnPDeviceID", StringComparison.Ordinal)
                ? AdapterSnapshot
                : command.Contains("Get-NetAdapter -IncludeHidden", StringComparison.Ordinal)
                    ? verificationOutput
                    : command.Contains("Get-NetFirewallProfile -PolicyStore PersistentStore", StringComparison.Ordinal)
                        ? FirewallSnapshot
                        : command.Contains("$missing =", StringComparison.Ordinal) ? "0" : "absent";
            return Task.FromResult(Result(file, command, 0, output));
        }

        var guard = new GuestNetworkPolicyGuard(SandboxNetworkPolicy.Block, Run);
        var events = new List<SandboxEvent>();
        try
        {
            await guard.ApplyAsync(events);
            throw new InvalidOperationException("An exit-zero disable without verified Disabled status must fail closed.");
        }
        catch (GuestNetworkPolicyException ex)
        {
            SmokeAssert.True(ex.Message.Contains(expectedStatus, StringComparison.OrdinalIgnoreCase),
                "The apply failure must identify the independently observed adapter status.");
        }

        SmokeAssert.True(commands.Any(command => command.Contains("Disable-NetAdapter", StringComparison.Ordinal)),
            "The disable command must have returned exit zero before the independent state check.");
        SmokeAssert.True(commands.Any(command => command.Contains("Get-NetAdapter -IncludeHidden", StringComparison.Ordinal)),
            "The guard must independently query adapter state after the disable command.");
        SmokeAssert.True(events.Any(e => e.EventType == GuestNetworkPolicyGuard.ApplyFailedEventType) &&
            !events.Any(e => e.EventType == GuestNetworkPolicyGuard.AppliedEventType),
            "An adapter that remains Up or cannot be found must emit apply_failed without a blocked success event.");
    }

    private static async Task FirewallStateIsRestoredAsync(bool failFirewallEnable, bool failDomainRestore = false)
    {
        var commands = new List<string>();
        Task<BoundedCommandResult> Run(string file, IReadOnlyList<string> args)
        {
            var command = string.Join(" ", args);
            commands.Add(command);
            if (command.Contains("Select-Object Name,InterfaceGuid,Status,PnPDeviceID", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, 0, output: AdapterSnapshot));
            }

            if (command.Contains("Get-NetFirewallProfile -PolicyStore PersistentStore", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, 0, output: FirewallSnapshot));
            }

            if (command.Contains("Get-NetAdapter -IncludeHidden", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, 0, output: AdapterSnapshot.Replace("\"Up\"", "\"Disabled\"", StringComparison.Ordinal)));
            }

            if (command.Contains("advfirewall set allprofiles state on", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, failFirewallEnable ? 1 : 0,
                    error: failFirewallEnable ? "profile command failed after partial change" : ""));
            }

            if (failDomainRestore && command.Contains("Set-NetFirewallProfile", StringComparison.Ordinal) &&
                command.Contains("-Name 'Domain'", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(file, command, 1, error: "domain restore refused"));
            }

            return Task.FromResult(Result(file, command, 0, output: command.Contains("$missing =", StringComparison.Ordinal) ? "0" : "absent"));
        }

        var guard = new GuestNetworkPolicyGuard(SandboxNetworkPolicy.Block, Run);
        var events = new List<SandboxEvent>();
        if (failFirewallEnable)
        {
            try
            {
                await guard.ApplyAsync(events);
                throw new InvalidOperationException("Failed firewall enable must fail closed.");
            }
            catch (GuestNetworkPolicyException)
            {
            }
        }
        else
        {
            await guard.ApplyAsync(events);
        }

        await guard.RestoreAsync(events);
        foreach (var expected in new[]
        {
            "-Name 'Domain' -Enabled 'False'",
            "-Name 'Private' -Enabled 'True'",
            "-Name 'Public' -Enabled 'NotConfigured'"
        })
        {
            SmokeAssert.True(commands.Any(command => command.Contains(expected, StringComparison.Ordinal)),
                $"Cleanup must restore the original firewall profile setting: {expected}");
        }

        SmokeAssert.True(events.Any(e => e.EventType == (failDomainRestore
                ? GuestNetworkPolicyGuard.RestoreFailedEventType
                : GuestNetworkPolicyGuard.RestoredEventType)),
            "Firewall cleanup must report whether all original profile states were restored.");
    }

    private static BoundedCommandResult Result(string file, string arguments, int exitCode, string output = "", string error = "") =>
        new(file, arguments, exitCode, output, error, TimedOut: false, ExceptionType: null,
            Message: null, Timeout: TimeSpan.FromSeconds(20));
}
