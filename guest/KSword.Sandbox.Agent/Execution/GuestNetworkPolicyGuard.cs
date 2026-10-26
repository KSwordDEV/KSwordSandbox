using System.Globalization;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Agent.Diagnostics;

namespace KSword.Sandbox.Agent.Execution;

/// <summary>
/// Enforces the selected network policy inside the guest VM. Inputs are the
/// parsed policy and the guest event list; processing applies two layers —
/// first the network adapter devices are disabled with
/// Disable-NetAdapter (falling back to an equivalent PnP device disable when
/// the NetAdapter cmdlet path fails, so malware cannot re-enable a path by
/// editing firewall rules), then KSword-prefixed Windows Firewall block
/// rules are added as a second layer — and both layers are undone at
/// cleanup; the guard never touches hypervisor network configuration and
/// never throws for restore failures, while an apply failure throws so the
/// caller can fail closed.
/// </summary>
internal sealed class GuestNetworkPolicyGuard
{
    internal const string AppliedEventType = "networkPolicy.applied";

    internal const string ApplyFailedEventType = "networkPolicy.apply_failed";

    internal const string RestoredEventType = "networkPolicy.restored";

    internal const string RestoreFailedEventType = "networkPolicy.restore_failed";

    internal const string OutboundRuleName = "KSwordSandbox Network Policy Block (Outbound)";

    internal const string InboundRuleName = "KSwordSandbox Network Policy Block (Inbound)";

    private const string NetshExecutable = "netsh.exe";

    private const string PowerShellExecutable = "powershell.exe";

    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(20);

    private readonly SandboxNetworkPolicy policy;
    private readonly Func<string, IReadOnlyList<string>, Task<BoundedCommandResult>> runCommand;

    private List<GuestNetworkAdapterSnapshot> disabledAdapters = [];
    private List<GuestFirewallProfileSnapshot> originalFirewallProfiles = [];
    private bool firewallStateMayHaveChanged;

    public GuestNetworkPolicyGuard(SandboxNetworkPolicy policy)
        : this(policy, (fileName, arguments) => BoundedProcessRunner.RunAsync(fileName, arguments, CommandTimeout))
    {
    }

    internal GuestNetworkPolicyGuard(
        SandboxNetworkPolicy policy,
        Func<string, IReadOnlyList<string>, Task<BoundedCommandResult>> runCommand)
    {
        this.policy = policy;
        this.runCommand = runCommand ?? throw new ArgumentNullException(nameof(runCommand));
    }

    /// <summary>
    /// Applies the selected policy before the sample starts. Inputs are the
    /// shared event list; processing is a no-op for Allow, and for Block
    /// snapshots the enabled adapters, disables them at the device level,
    /// and adds the firewall rules as a second layer; the method records
    /// evidence events and throws <see cref="GuestNetworkPolicyException"/>
    /// when the requested block could not be enforced so the caller never
    /// runs the sample unprotected.
    /// </summary>
    public async Task ApplyAsync(List<SandboxEvent> events)
    {
        if (policy != SandboxNetworkPolicy.Block)
        {
            return;
        }

        List<GuestNetworkAdapterSnapshot> adapters;
        try
        {
            adapters = await SnapshotEnabledAdaptersAsync();
            // Disable-NetAdapter or its PnP fallback can disable some devices
            // and then fail. Record the whole original snapshot first so the
            // finally path also restores that partial failure.
            disabledAdapters = adapters;
            if (adapters.Count > 0)
            {
                await DisableAdaptersAsync(adapters);
            }

            // Second layer: firewall rules. Stale same-named rules from an
            // earlier interrupted run are removed first so repeated adds stay
            // idempotent.
            await DeleteFirewallRuleIfPresentAsync(OutboundRuleName);
            await DeleteFirewallRuleIfPresentAsync(InboundRuleName);

            originalFirewallProfiles = await SnapshotFirewallProfilesAsync();
            // netsh can change one or more profiles before it reports an
            // error, so cleanup must restore the snapshot even on failure.
            firewallStateMayHaveChanged = true;
            var enableFirewall = await RunNetshAsync(
                ["advfirewall", "set", "allprofiles", "state", "on"]);
            if (!enableFirewall.Succeeded)
            {
                throw new GuestNetworkPolicyException(
                    $"Enabling Windows Firewall failed (exit={FormatExitCode(enableFirewall)}): {enableFirewall.StandardError}");
            }

            var outbound = await RunNetshAsync(
                ["advfirewall", "firewall", "add", "rule", $"name={OutboundRuleName}", "dir=out", "action=block", "enable=yes"]);
            if (!outbound.Succeeded)
            {
                throw new GuestNetworkPolicyException(
                    $"Adding the outbound block rule failed (exit={FormatExitCode(outbound)}): {outbound.StandardError}");
            }

            var inbound = await RunNetshAsync(
                ["advfirewall", "firewall", "add", "rule", $"name={InboundRuleName}", "dir=in", "action=block", "enable=yes"]);
            if (!inbound.Succeeded)
            {
                throw new GuestNetworkPolicyException(
                    $"Adding the inbound block rule failed (exit={FormatExitCode(inbound)}): {inbound.StandardError}");
            }

            // An exit-zero disable command is insufficient: an empty
            // Get-NetAdapter pipeline also exits zero, and the adapter may
            // remain Up. Check each original GUID after both block layers
            // have been installed and before the sample can start.
            await VerifyDisabledAdaptersAsync(adapters);
        }
        catch (GuestNetworkPolicyException ex)
        {
            events.Add(CreatePolicyEvent(
                ApplyFailedEventType,
                "apply_failed",
                ex.Message,
                adaptersDisabled: disabledAdapters.Count,
                adaptersMissingAfterRestore: 0,
                zhMessage: "请求的网络阻断未能在客户机内生效，按失败关闭（fail-closed）原则未启动样本。",
                zhHint: "请检查 Guest 帐户是否具备管理员权限、网络适配器与 Windows Firewall 是否可用；修复后重新运行任务。"));
            throw;
        }

        events.Add(CreatePolicyEvent(
            AppliedEventType,
            "blocked",
            adapters.Count == 0
                ? "No enabled network adapters were present; firewall block rules were added for any adapter that appears later."
                : $"Disabled {adapters.Count} network adapter device(s) at the device level and added firewall block rules as a second layer; connection attempts remain visible to the telemetry lanes.",
            adaptersDisabled: adapters.Count,
            adaptersMissingAfterRestore: 0));
    }

    /// <summary>
    /// Restores the guest network state after the analysis window. Inputs are
    /// the shared event list; processing re-enables exactly the adapters that
    /// were disabled (matched by recorded InterfaceGuid, so adapters the
    /// sample uninstalled or renamed are skipped instead of failing) and
    /// deletes the firewall rules; the method records evidence events and
    /// never throws, because cleanup must not mask an already-collected
    /// sample result and disposable VMs are reverted anyway.
    /// </summary>
    public async Task RestoreAsync(List<SandboxEvent> events)
    {
        if (policy != SandboxNetworkPolicy.Block)
        {
            return;
        }

        Exception? restoreFailure = null;
        var adaptersMissingAfterRestore = 0;
        if (disabledAdapters.Count > 0)
        {
            try
            {
                var enableResult = await RunPowerShellAsync(
                    BuildEnableAdaptersScript(disabledAdapters.Select(adapter => adapter.InterfaceGuid).ToList()));
                if (!enableResult.Succeeded)
                {
                    // The NetAdapter path can fail when the sample uninstalled
                    // or corrupted the NIC stack; retry once through the PnP
                    // device path using the recorded InstanceIds before
                    // declaring the restore failed.
                    if (!await EnableViaPnpAsync(disabledAdapters))
                    {
                        throw new GuestNetworkPolicyException(
                            $"Re-enabling network adapters failed (exit={FormatExitCode(enableResult)}): {enableResult.StandardError}");
                    }
                }

                adaptersMissingAfterRestore = await CountMissingAdaptersAsync(disabledAdapters);
                if (adaptersMissingAfterRestore > 0 && await EnableViaPnpAsync(disabledAdapters))
                {
                    adaptersMissingAfterRestore = await CountMissingAdaptersAsync(disabledAdapters);
                }
            }
            catch (GuestNetworkPolicyException ex)
            {
                restoreFailure = ex;
            }
        }

        try
        {
            await DeleteFirewallRuleIfPresentAsync(OutboundRuleName);
            await DeleteFirewallRuleIfPresentAsync(InboundRuleName);
        }
        catch (GuestNetworkPolicyException ex)
        {
            restoreFailure ??= ex;
        }

        if (firewallStateMayHaveChanged)
        {
            try
            {
                await RestoreFirewallProfilesAsync(originalFirewallProfiles);
                firewallStateMayHaveChanged = false;
            }
            catch (GuestNetworkPolicyException ex)
            {
                restoreFailure ??= ex;
            }
        }

        if (restoreFailure is not null || adaptersMissingAfterRestore > 0)
        {
            events.Add(CreatePolicyEvent(
                RestoreFailedEventType,
                "restore_failed",
                restoreFailure?.Message ?? $"{adaptersMissingAfterRestore} recorded adapter(s) were no longer present and could not be re-enabled.",
                adaptersDisabled: disabledAdapters.Count,
                adaptersMissingAfterRestore: adaptersMissingAfterRestore,
                zhMessage: "分析结束后恢复客户机网络未完全成功；一次性虚拟机随后会还原基线，但请复核该虚拟机网络状态。",
                zhHint: "若为长期使用的手动虚拟机，请核对被禁用的适配器、KSwordSandbox 阻断规则和原防火墙配置。"));
            return;
        }

        events.Add(CreatePolicyEvent(
            RestoredEventType,
            "restored",
            "Guest network adapters re-enabled, firewall block rules removed, and firewall profile states restored after the analysis window.",
            adaptersDisabled: disabledAdapters.Count,
            adaptersMissingAfterRestore: 0));
    }

    /// <summary>
    /// Snapshots the currently enabled network adapters for later restore.
    /// Inputs are none; processing runs Get-NetAdapter inside the guest and
    /// parses the emitted JSON; the method returns name/guid/PNP-device-id
    /// triples for every adapter that is not already disabled, so cleanup
    /// can re-enable the same device through either the NetAdapter or the
    /// PnP device path.
    /// </summary>
    private async Task<List<GuestNetworkAdapterSnapshot>> SnapshotEnabledAdaptersAsync()
    {
        var result = await RunPowerShellAsync(
            "$ErrorActionPreference = 'Stop'; " +
            "Get-NetAdapter -ErrorAction Stop | Select-Object Name,InterfaceGuid,Status,PnPDeviceID | ConvertTo-Json -Compress");
        if (!result.Succeeded || !string.IsNullOrWhiteSpace(result.StandardError))
        {
            throw new GuestNetworkPolicyException(
                $"Enumerating network adapters failed (exit={FormatExitCode(result)}): {result.StandardError}");
        }

        // An isolated VM may have no NIC at all. ConvertTo-Json produces no
        // stdout for an empty pipeline, which is a valid zero-adapter result
        // when the command itself succeeded without diagnostics.
        if (string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput.Trim());
            var root = document.RootElement;
            var adapters = new List<GuestNetworkAdapterSnapshot>();
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in root.EnumerateArray())
                {
                    TryAddAdapter(entry, adapters);
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                TryAddAdapter(root, adapters);
            }
            else
            {
                throw new GuestNetworkPolicyException(
                    "Network adapter snapshot JSON was neither an adapter object nor an array.");
            }

            return adapters;
        }
        catch (JsonException ex)
        {
            throw new GuestNetworkPolicyException($"Parsing the network adapter snapshot failed: {ex.Message}");
        }
    }

    private static void TryAddAdapter(JsonElement entry, List<GuestNetworkAdapterSnapshot> adapters)
    {
        if (entry.ValueKind != JsonValueKind.Object)
        {
            throw new GuestNetworkPolicyException("Network adapter snapshot contained a non-object entry.");
        }

        if (!entry.TryGetProperty("Status", out var status) ||
            status.ValueKind != JsonValueKind.String)
        {
            throw new GuestNetworkPolicyException("Network adapter snapshot entry lacked a valid Status.");
        }

        if (string.Equals(status.GetString(), "Disabled", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var name = entry.TryGetProperty("Name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String
            ? nameElement.GetString() : null;
        var guid = entry.TryGetProperty("InterfaceGuid", out var guidElement) && guidElement.ValueKind == JsonValueKind.String
            ? guidElement.GetString() : null;
        if (string.IsNullOrWhiteSpace(name) || !Guid.TryParse(guid, out var parsedGuid))
        {
            throw new GuestNetworkPolicyException("Enabled network adapter snapshot entry lacked a valid name or InterfaceGuid.");
        }

        var pnpDeviceId = entry.TryGetProperty("PnPDeviceID", out var pnpElement) &&
            pnpElement.ValueKind is JsonValueKind.String or JsonValueKind.Null ? pnpElement.GetString() : null;
        adapters.Add(new GuestNetworkAdapterSnapshot(name, parsedGuid.ToString("D"), pnpDeviceId));
    }

    /// <summary>
    /// Captures the local firewall configuration before netsh enables all
    /// profiles. PersistentStore is the setting changed by netsh; ActiveStore
    /// can include group policy values that must not be written back locally.
    /// </summary>
    private async Task<List<GuestFirewallProfileSnapshot>> SnapshotFirewallProfilesAsync()
    {
        var result = await RunPowerShellAsync(
            "$ErrorActionPreference = 'Stop'; " +
            "Get-NetFirewallProfile -PolicyStore PersistentStore | " +
            "ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled } } | " +
            "ConvertTo-Json -Compress");
        if (!result.Succeeded || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            throw new GuestNetworkPolicyException(
                $"Snapshotting firewall profiles failed (exit={FormatExitCode(result)}): {result.StandardError}");
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput.Trim());
            var root = document.RootElement;
            var entries = root.ValueKind == JsonValueKind.Array
                ? root.EnumerateArray().ToList()
                : [root];
            var profiles = new List<GuestFirewallProfileSnapshot>();
            foreach (var entry in entries)
            {
                if (entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("Name", out var nameElement) ||
                    !entry.TryGetProperty("Enabled", out var enabledElement))
                {
                    continue;
                }

                var name = nameElement.GetString();
                var enabled = enabledElement.GetString();
                if (name is not ("Domain" or "Private" or "Public") ||
                    enabled is not ("True" or "False" or "NotConfigured"))
                {
                    continue;
                }

                profiles.Add(new GuestFirewallProfileSnapshot(name, enabled));
            }

            if (profiles.Count != 3 ||
                profiles.Select(profile => profile.Name).Distinct(StringComparer.Ordinal).Count() != 3)
            {
                throw new GuestNetworkPolicyException(
                    "Firewall profile snapshot did not contain one valid Domain, Private, and Public setting; refusing to change it.");
            }

            return profiles;
        }
        catch (JsonException ex)
        {
            throw new GuestNetworkPolicyException($"Parsing the firewall profile snapshot failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Restores every captured local firewall setting independently so one
    /// failed profile does not prevent the other profiles from being restored.
    /// </summary>
    private async Task RestoreFirewallProfilesAsync(IReadOnlyList<GuestFirewallProfileSnapshot> profiles)
    {
        var errors = new List<string>();
        foreach (var profile in profiles)
        {
            var result = await RunPowerShellAsync(
                "$ErrorActionPreference = 'Stop'; " +
                $"Set-NetFirewallProfile -PolicyStore PersistentStore -Name {PsSingleQuote(profile.Name)} -Enabled {PsSingleQuote(profile.Enabled)}");
            if (!result.Succeeded)
            {
                errors.Add($"{profile.Name} (exit={FormatExitCode(result)}): {result.StandardError}");
            }
        }

        if (errors.Count > 0)
        {
            throw new GuestNetworkPolicyException("Restoring firewall profile states failed: " + string.Join("; ", errors));
        }
    }

    /// <summary>
    /// Disables the snapshot adapters at the device level. Inputs are the
    /// recorded adapters; processing first matches them by InterfaceGuid and
    /// pipes them to Disable-NetAdapter, then falls back to an equivalent
    /// PnP device disable (Disable-PnpDevice on the recorded InstanceId) for
    /// adapters the NetAdapter path could not take down; the method throws
    /// when neither mechanism succeeded.
    /// </summary>
    private async Task DisableAdaptersAsync(List<GuestNetworkAdapterSnapshot> adapters)
    {
        var result = await RunPowerShellAsync(BuildDisableAdaptersScript(adapters.Select(adapter => adapter.InterfaceGuid).ToList()));
        if (result.Succeeded)
        {
            return;
        }

        var pnpInstanceIds = adapters
            .Select(adapter => adapter.PnPDeviceID)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .ToList();
        if (pnpInstanceIds.Count > 0)
        {
            var fallback = await RunPowerShellAsync(BuildDisablePnpDevicesScript(pnpInstanceIds));
            if (fallback.Succeeded)
            {
                return;
            }

            throw new GuestNetworkPolicyException(
                $"Disabling network adapters failed via Disable-NetAdapter (exit={FormatExitCode(result)}): {result.StandardError}; " +
                $"the PnP device disable fallback also failed (exit={FormatExitCode(fallback)}): {fallback.StandardError}");
        }

        throw new GuestNetworkPolicyException(
            $"Disabling network adapters failed (exit={FormatExitCode(result)}): {result.StandardError}");
    }

    /// <summary>
    /// Independently checks the actual state of every adapter captured before
    /// applying Block. An absent, duplicated, or non-disabled GUID cannot be
    /// treated as proof of a disabled device, so any such result fails closed.
    /// </summary>
    private async Task VerifyDisabledAdaptersAsync(IReadOnlyList<GuestNetworkAdapterSnapshot> adapters)
    {
        if (adapters.Count == 0)
        {
            return;
        }

        var result = await RunPowerShellAsync(
            "$ErrorActionPreference = 'Stop'; " +
            "Get-NetAdapter -IncludeHidden -ErrorAction Stop | " +
            "Select-Object InterfaceGuid,Status | ConvertTo-Json -Compress");
        if (!result.Succeeded || !string.IsNullOrWhiteSpace(result.StandardError) ||
            string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            throw new GuestNetworkPolicyException(
                $"Verifying disabled network adapters failed (exit={FormatExitCode(result)}): {result.StandardError}");
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput.Trim());
            var root = document.RootElement;
            var entries = root.ValueKind switch
            {
                JsonValueKind.Array => root.EnumerateArray().ToList(),
                JsonValueKind.Object => [root],
                _ => throw new GuestNetworkPolicyException("Network adapter verification JSON was neither an object nor an array.")
            };
            var states = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in entries)
            {
                if (entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("InterfaceGuid", out var guidElement) ||
                    guidElement.ValueKind != JsonValueKind.String ||
                    !Guid.TryParse(guidElement.GetString(), out var parsedGuid) ||
                    !entry.TryGetProperty("Status", out var statusElement) ||
                    statusElement.ValueKind != JsonValueKind.String ||
                    !states.TryAdd(parsedGuid.ToString("D"), statusElement.GetString() ?? string.Empty))
                {
                    throw new GuestNetworkPolicyException("Network adapter verification contained an invalid or duplicate adapter state.");
                }
            }

            foreach (var adapter in adapters)
            {
                if (!states.TryGetValue(adapter.InterfaceGuid, out var status) ||
                    !string.Equals(status, "Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    throw new GuestNetworkPolicyException(
                        $"Network adapter {adapter.InterfaceGuid} was not independently verified as Disabled (status={status ?? "missing"}).");
                }
            }
        }
        catch (JsonException ex)
        {
            throw new GuestNetworkPolicyException($"Parsing the network adapter verification failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Re-enables snapshot adapters through the PnP device path. Inputs are
    /// the recorded adapters carrying a PnP InstanceId; processing runs
    /// Enable-PnpDevice for each recorded id; the method returns whether the
    /// command succeeded.
    /// </summary>
    private async Task<bool> EnableViaPnpAsync(List<GuestNetworkAdapterSnapshot> adapters)
    {
        var pnpInstanceIds = adapters
            .Select(adapter => adapter.PnPDeviceID)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .ToList();
        if (pnpInstanceIds.Count == 0)
        {
            return false;
        }

        var fallback = await RunPowerShellAsync(BuildEnablePnpDevicesScript(pnpInstanceIds));
        return fallback.Succeeded;
    }

    /// <summary>
    /// Counts how many snapshot adapters are no longer present in the guest
    /// after the restore attempt (for example when the sample uninstalled the
    /// NIC driver). Inputs are the recorded adapters; processing matches by
    /// InterfaceGuid; the method returns the number of missing adapters.
    /// </summary>
    private async Task<int> CountMissingAdaptersAsync(List<GuestNetworkAdapterSnapshot> adapters)
    {
        var result = await RunPowerShellAsync(BuildCountMissingAdaptersScript(adapters.Select(adapter => adapter.InterfaceGuid).ToList()));
        if (!result.Succeeded || !int.TryParse(result.StandardOutput.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var missing))
        {
            // A counting probe must never turn cleanup into a hard failure;
            // reporting zero keeps the tolerated-missing evidence honest only
            // when it can be measured, so surface the probe failure as one
            // unverifiable adapter instead of guessing.
            return adapters.Count;
        }

        return Math.Clamp(missing, 0, adapters.Count);
    }

    private static string BuildDisableAdaptersScript(IReadOnlyList<string> interfaceGuids)
    {
        return
            "$ErrorActionPreference = 'Stop'; " +
            $"$guids = @({JoinGuids(interfaceGuids)}); " +
            "Get-NetAdapter | Where-Object { $guids -contains $_.InterfaceGuid.ToString() } | Disable-NetAdapter -Confirm:$false";
    }

    private static string BuildEnableAdaptersScript(IReadOnlyList<string> interfaceGuids)
    {
        return
            "$ErrorActionPreference = 'Stop'; " +
            $"$guids = @({JoinGuids(interfaceGuids)}); " +
            "Get-NetAdapter | Where-Object { $guids -contains $_.InterfaceGuid.ToString() -and $_.Status -eq 'Disabled' } | Enable-NetAdapter -Confirm:$false";
    }

    private static string BuildCountMissingAdaptersScript(IReadOnlyList<string> interfaceGuids)
    {
        return
            "$ErrorActionPreference = 'Stop'; " +
            $"$guids = @({JoinGuids(interfaceGuids)}); " +
            "$missing = $guids | Where-Object { $guid = $_; -not (Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $guid }) }; " +
            "Write-Output ($missing | Measure-Object).Count";
    }

    private static string BuildDisablePnpDevicesScript(IReadOnlyList<string> instanceIds)
    {
        return
            "$ErrorActionPreference = 'Stop'; " +
            $"$ids = @({JoinInstanceIds(instanceIds)}); " +
            "$ids | ForEach-Object { Disable-PnpDevice -InstanceId $_ -Confirm:$false }";
    }

    private static string BuildEnablePnpDevicesScript(IReadOnlyList<string> instanceIds)
    {
        return
            "$ErrorActionPreference = 'Stop'; " +
            $"$ids = @({JoinInstanceIds(instanceIds)}); " +
            "$ids | ForEach-Object { Enable-PnpDevice -InstanceId $_ -Confirm:$false }";
    }

    /// <summary>
    /// Renders validated PnP instance ids as single-quoted PowerShell
    /// literals (doubling embedded quotes) so device scripts cannot be
    /// broken by identifier text.
    /// </summary>
    private static string JoinInstanceIds(IReadOnlyList<string> instanceIds)
    {
        return string.Join(", ", instanceIds.Select(id => $"'{id.Replace("'", "''")}'"));
    }

    /// <summary>
    /// Renders validated GUID strings as single-quoted PowerShell literals so
    /// embedded adapter scripts cannot be broken by identifier text.
    /// </summary>
    private static string JoinGuids(IReadOnlyList<string> interfaceGuids)
    {
        return string.Join(", ", interfaceGuids.Select(guid =>
            $"'{(Guid.TryParse(guid, out var parsed) ? parsed.ToString("D") : string.Empty)}'"));
    }

    /// <summary>
    /// Deletes one firewall rule while tolerating an already-absent rule.
    /// Inputs are the stable rule name; processing first checks existence
    /// through the language-neutral NetSecurity cmdlets and only then runs
    /// netsh delete, which must succeed once the rule is known to exist; the
    /// method throws only for real command failures.
    /// </summary>
    /// <remarks>
    /// netsh answers "rule absent" in the guest display language (measured on
    /// a Chinese guest: "没有规则匹配" on stdout with exit=1), so matching the
    /// English "No rules match" marker fails on non-English guests and the
    /// guard used to fail-closed before the sample ever started. Rule
    /// existence must therefore never be decided from netsh text output.
    /// </remarks>
    private async Task DeleteFirewallRuleIfPresentAsync(string ruleName)
    {
        var presence = await RunPowerShellAsync(
            "$r = Get-NetFirewallRule -DisplayName " + PsSingleQuote(ruleName) + " -ErrorAction SilentlyContinue; " +
            "if ($null -eq $r) { 'absent' } else { 'present' }");
        if (!presence.Succeeded)
        {
            throw new GuestNetworkPolicyException(
                $"Checking firewall rule '{ruleName}' failed (exit={FormatExitCode(presence)}): stdout={presence.StandardOutput}; stderr={presence.StandardError}");
        }

        if (presence.StandardOutput.Contains("absent", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var result = await RunNetshAsync(
            ["advfirewall", "firewall", "delete", "rule", $"name={ruleName}"]);
        if (result.Succeeded)
        {
            return;
        }

        throw new GuestNetworkPolicyException(
            $"Deleting firewall rule '{ruleName}' failed (exit={FormatExitCode(result)}): stdout={result.StandardOutput}; stderr={result.StandardError}");
    }

    /// <summary>
    /// Renders validated firewall rule names as single-quoted PowerShell
    /// literals so embedded adapter scripts cannot be broken by rule text.
    /// </summary>
    private static string PsSingleQuote(string value)
    {
        return "'" + value.Replace("'", "''") + "'";
    }

    private Task<BoundedCommandResult> RunNetshAsync(IReadOnlyList<string> arguments)
    {
        return runCommand(NetshExecutable, arguments);
    }

    private Task<BoundedCommandResult> RunPowerShellAsync(string script)
    {
        return runCommand(
            PowerShellExecutable,
            ["-NoProfile", "-NonInteractive", "-Command", script]);
    }

    private static string FormatExitCode(BoundedCommandResult result)
    {
        return result.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? (result.TimedOut ? "timeout" : "launch-error");
    }

    private SandboxEvent CreatePolicyEvent(
        string eventType,
        string state,
        string summary,
        int adaptersDisabled,
        int adaptersMissingAfterRestore,
        string? zhMessage = null,
        string? zhHint = null)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["policy"] = policy.ToString(),
            ["state"] = state,
            ["mechanism"] = "net-adapter-or-pnp-device-disable+windows-firewall",
            ["scope"] = "guest-internal",
            ["enforcementPoint"] = "guest",
            ["directions"] = "inbound,outbound",
            ["hypervisorNetworkConfigChanged"] = "false",
            ["adaptersDisabled"] = adaptersDisabled.ToString(CultureInfo.InvariantCulture),
            ["adaptersMissingAfterRestore"] = adaptersMissingAfterRestore.ToString(CultureInfo.InvariantCulture),
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["collectionNoise"] = "true",
            ["summary"] = summary
        };

        if (!string.IsNullOrWhiteSpace(zhMessage))
        {
            data["zhMessage"] = zhMessage;
        }

        if (!string.IsNullOrWhiteSpace(zhHint))
        {
            data["zhHint"] = zhHint;
        }

        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data = data
        };
    }

    /// <summary>
    /// Records one adapter that the guard disabled so cleanup can re-enable
    /// exactly the same device even if the sample renamed interfaces or left
    /// the NetAdapter stack unusable.
    /// </summary>
    private sealed record GuestNetworkAdapterSnapshot(string Name, string InterfaceGuid, string? PnPDeviceID);

    private sealed record GuestFirewallProfileSnapshot(string Name, string Enabled);
}

/// <summary>
/// Signals that a requested guest-internal network block could not be
/// enforced. Inputs are a diagnostic message; processing fails the agent run
/// closed so the sample is never executed without the requested protection;
/// the exception is caught by the agent's execution boundary after the
/// guard has recorded its evidence event.
/// </summary>
internal sealed class GuestNetworkPolicyException : Exception
{
    public GuestNetworkPolicyException(string message)
        : base(message)
    {
    }
}
