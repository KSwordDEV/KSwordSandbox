using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Web.Contracts;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Performs a bounded, read-only inventory of the local sandbox host.
/// Inputs are the active normalized config and an optional refresh request;
/// processing checks filesystem/environment facts and runs only Get-VM /
/// Get-VMSnapshot in a child Windows PowerShell process; returned data contains
/// no passwords, command text, stdout, or VM-mutating operations.
/// </summary>
internal sealed class LocalHostReadinessProbe
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan HyperVProbeTimeout = TimeSpan.FromSeconds(8);
    private readonly SandboxConfig config;
    private readonly SemaphoreSlim probeGate = new(1, 1);
    private LocalHostReadinessContract? cached;
    private DateTimeOffset cacheExpiresAtUtc;

    public LocalHostReadinessProbe(SandboxConfig config)
    {
        this.config = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// Returns current host facts, using a short cache to avoid starting a
    /// PowerShell inventory process for every dashboard repaint. A forced
    /// refresh bypasses the cache. Cancellation stops the bounded child query.
    /// </summary>
    public async Task<LocalHostReadinessContract> ProbeAsync(bool forceRefresh, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (!forceRefresh && cached is not null && now < cacheExpiresAtUtc)
        {
            return cached;
        }

        await probeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = DateTimeOffset.UtcNow;
            if (!forceRefresh && cached is not null && now < cacheExpiresAtUtc)
            {
                return cached;
            }

            var hyperVProbe = await ProbeHyperVAsync(cancellationToken).ConfigureAwait(false);
            var hyperV = BuildHyperVReadiness(hyperVProbe);
            var guest = BuildGuestReadiness();
            var paths = BuildPathReadiness();
            cached = new LocalHostReadinessContract(
                DetectedAtUtc: DateTimeOffset.UtcNow,
                MachineName: Environment.MachineName,
                OperatingSystem: RuntimeInformation.OSDescription,
                IsElevated: IsCurrentProcessElevated(),
                ReadOnly: true,
                HyperV: hyperV,
                Guest: guest,
                Paths: paths);
            cacheExpiresAtUtc = DateTimeOffset.UtcNow.Add(CacheLifetime);
            return cached;
        }
        finally
        {
            probeGate.Release();
        }
    }

    private LocalHyperVReadinessContract BuildHyperVReadiness(HyperVProbeResult probe)
    {
        var configuredVmName = config.HyperV.GoldenVmName?.Trim() ?? string.Empty;
        var configuredCheckpointName = config.HyperV.GoldenSnapshotName?.Trim() ?? string.Empty;
        LocalVmCandidateContract? selectedVm = null;
        var vmSource = probe.ManagementAvailable
            ? (probe.QuerySucceeded ? "not-found" : "query-failed")
            : "management-missing";

        if (probe.QuerySucceeded)
        {
            selectedVm = probe.Vms.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, configuredVmName, StringComparison.OrdinalIgnoreCase));
            if (selectedVm is not null)
            {
                vmSource = "detected-config-match";
            }
            else if (probe.Vms.Count == 1)
            {
                selectedVm = probe.Vms[0];
                vmSource = "detected-single";
            }
            else if (probe.Vms.Count > 1)
            {
                vmSource = "ambiguous";
            }
        }

        string? selectedCheckpoint = null;
        var checkpointSource = selectedVm is null ? vmSource : "not-found";
        if (selectedVm is not null)
        {
            selectedCheckpoint = selectedVm.Checkpoints.FirstOrDefault(name =>
                string.Equals(name, configuredCheckpointName, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(selectedCheckpoint))
            {
                checkpointSource = "detected-config-match";
            }
            else if (selectedVm.Checkpoints.Count == 1)
            {
                selectedCheckpoint = selectedVm.Checkpoints[0];
                checkpointSource = "detected-single";
            }
            else if (selectedVm.Checkpoints.Count > 1)
            {
                checkpointSource = "ambiguous";
            }
        }

        return new LocalHyperVReadinessContract(
            ManagementAvailable: probe.ManagementAvailable,
            QuerySucceeded: probe.QuerySucceeded,
            AccessDenied: string.Equals(probe.DiagnosticCode, "HYPERV_ACCESS_DENIED", StringComparison.Ordinal),
            ConfiguredVmName: configuredVmName,
            VmName: selectedVm?.Name,
            VmSource: vmSource,
            VmState: selectedVm?.State,
            VmExists: selectedVm is not null,
            ConfiguredCheckpointName: configuredCheckpointName,
            CheckpointName: selectedCheckpoint,
            CheckpointSource: checkpointSource,
            CheckpointExists: !string.IsNullOrWhiteSpace(selectedCheckpoint),
            VmCandidates: probe.Vms,
            DiagnosticCode: probe.DiagnosticCode,
            DiagnosticMessage: probe.DiagnosticMessage);
    }

    private LocalGuestReadinessContract BuildGuestReadiness()
    {
        var secretName = string.IsNullOrWhiteSpace(config.Guest.PasswordSecretName)
            ? "KSWORDBOX_GUEST_PASSWORD"
            : config.Guest.PasswordSecretName.Trim();
        var secretAvailable = TryResolveEnvironmentVariable(secretName, out var source);
        return new LocalGuestReadinessContract(
            UserName: config.Guest.UserName,
            UserNameSource: "active-config",
            WorkingDirectory: config.Guest.WorkingDirectory,
            WorkingDirectorySource: "active-config",
            PasswordSecretName: secretName,
            PasswordSecretAvailable: secretAvailable,
            PasswordSecretSource: source);
    }

    private LocalPathReadinessContract BuildPathReadiness()
    {
        var payloadRoot = config.Paths.GuestPayloadRoot;
        return new LocalPathReadinessContract(
            RuntimeRoot: DirectoryFact(config.Paths.RuntimeRoot),
            GuestPayloadRoot: DirectoryFact(payloadRoot),
            PayloadManifest: FileFact(Path.Combine(payloadRoot, "payload-manifest.json")),
            AgentExecutable: FileFact(Path.Combine(payloadRoot, "agent", config.Guest.AgentExecutableName)),
            CollectorExecutable: FileFact(Path.Combine(payloadRoot, "r0collector", "KSword.Sandbox.R0Collector.exe")),
            BaseVhdx: FileFact(config.HyperV.BaseVhdxPath));
    }

    private static LocalPathFactContract DirectoryFact(string? path)
    {
        var configured = !string.IsNullOrWhiteSpace(path);
        var exists = configured && Directory.Exists(path);
        return new LocalPathFactContract(path, configured, exists, "directory", PathSource(configured, exists));
    }

    private static LocalPathFactContract FileFact(string? path)
    {
        var configured = !string.IsNullOrWhiteSpace(path);
        var exists = configured && File.Exists(path);
        return new LocalPathFactContract(path, configured, exists, "file", PathSource(configured, exists));
    }

    private static string PathSource(bool configured, bool exists) => !configured
        ? "not-configured"
        : exists
            ? "config-path-detected"
            : "config-path-missing";

    private static bool TryResolveEnvironmentVariable(string name, out string source)
    {
        foreach (var scope in new[]
                 {
                     EnvironmentVariableTarget.Process,
                     EnvironmentVariableTarget.User,
                     EnvironmentVariableTarget.Machine
                 })
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name, scope)))
                {
                    source = scope.ToString().ToLowerInvariant();
                    return true;
                }
            }
            catch (SecurityException)
            {
                // Continue with the remaining scopes; no secret value is exposed.
            }
        }

        source = "not-found";
        return false;
    }

    private static bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<HyperVProbeResult> ProbeHyperVAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return HyperVProbeResult.Failed(false, "HYPERV_WINDOWS_REQUIRED", "Hyper-V inventory is available only on Windows hosts.");
        }

        var script = """
            $ProgressPreference = 'SilentlyContinue'
            $ErrorActionPreference = 'Stop'
            $result = [ordered]@{
              managementAvailable = $false
              querySucceeded = $false
              diagnosticCode = ''
              diagnosticMessage = ''
              vms = @()
            }
            try {
              $command = Get-Command Get-VM -ErrorAction SilentlyContinue
              if ($null -eq $command) {
                $result.diagnosticCode = 'HYPERV_CMDLET_MISSING'
                $result.diagnosticMessage = 'Hyper-V PowerShell management cmdlets were not found.'
              } else {
                $result.managementAvailable = $true
                try {
                  $items = @()
                  foreach ($vm in @(Get-VM -ErrorAction Stop | Sort-Object Name)) {
                    $checkpointNames = @()
                    $checkpointDiagnostic = ''
                    try {
                      $checkpointNames = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction Stop | Sort-Object Name | ForEach-Object { [string]$_.Name })
                    } catch {
                      $checkpointDiagnostic = [string]$_.Exception.Message
                    }
                    $items += [pscustomobject][ordered]@{
                      name = [string]$vm.Name
                      state = [string]$vm.State
                      checkpoints = @($checkpointNames)
                      checkpointDiagnostic = $checkpointDiagnostic
                    }
                  }
                  $result.vms = @($items)
                  $result.querySucceeded = $true
                  $result.diagnosticCode = if ($items.Count -eq 0) { 'HYPERV_NO_VMS' } else { 'HYPERV_QUERY_OK' }
                  $result.diagnosticMessage = if ($items.Count -eq 0) { 'No local Hyper-V virtual machines were detected.' } else { "Detected $($items.Count) local Hyper-V virtual machine(s)." }
                } catch {
                  $message = [string]$_.Exception.Message
                  $result.diagnosticCode = if ($message -match 'Access is denied|Access denied|拒绝访问') { 'HYPERV_ACCESS_DENIED' } else { 'HYPERV_QUERY_FAILED' }
                  $result.diagnosticMessage = $message
                }
              }
            } catch {
              $result.diagnosticCode = 'HYPERV_PROBE_FAILED'
              $result.diagnosticMessage = [string]$_.Exception.Message
            }
            [pscustomobject]$result | ConvertTo-Json -Depth 6 -Compress
            """;

        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encodedCommand);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return HyperVProbeResult.Failed(false, "POWERSHELL_LAUNCH_FAILED", SafeDiagnostic(ex.Message));
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HyperVProbeTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return HyperVProbeResult.Failed(true, "HYPERV_QUERY_TIMEOUT", "The read-only Hyper-V inventory query timed out.");
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return HyperVProbeResult.Failed(
                false,
                "HYPERV_EMPTY_RESPONSE",
                SafeDiagnostic(string.IsNullOrWhiteSpace(stderr) ? "PowerShell returned no Hyper-V inventory JSON." : stderr));
        }

        try
        {
            return ParseHyperVProbe(stdout);
        }
        catch (JsonException ex)
        {
            return HyperVProbeResult.Failed(false, "HYPERV_INVALID_RESPONSE", SafeDiagnostic(ex.Message));
        }
    }

    private static HyperVProbeResult ParseHyperVProbe(string stdout)
    {
        var start = stdout.IndexOf('{');
        var end = stdout.LastIndexOf('}');
        if (start < 0 || end < start)
        {
            throw new JsonException("PowerShell output did not contain a JSON object.");
        }

        using var document = JsonDocument.Parse(stdout[start..(end + 1)]);
        var root = document.RootElement;
        var candidates = new List<LocalVmCandidateContract>();
        if (root.TryGetProperty("vms", out var vms) && vms.ValueKind == JsonValueKind.Array)
        {
            foreach (var vm in vms.EnumerateArray())
            {
                var checkpoints = ReadStringList(vm, "checkpoints");
                candidates.Add(new LocalVmCandidateContract(
                    Name: ReadString(vm, "name"),
                    State: ReadString(vm, "state"),
                    Checkpoints: checkpoints,
                    CheckpointDiagnostic: NullIfBlank(ReadString(vm, "checkpointDiagnostic"))));
            }
        }

        return new HyperVProbeResult(
            ManagementAvailable: ReadBoolean(root, "managementAvailable"),
            QuerySucceeded: ReadBoolean(root, "querySucceeded"),
            DiagnosticCode: ReadString(root, "diagnosticCode"),
            DiagnosticMessage: SafeDiagnostic(ReadString(root, "diagnosticMessage")),
            Vms: candidates);
    }

    private static IReadOnlyList<string> ReadStringList(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            return Array.Empty<string>();
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            return value.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString() ?? string.Empty)
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .ToArray();
        }

        return value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? new[] { value.GetString()! }
            : Array.Empty<string>();
    }

    private static string ReadString(JsonElement parent, string propertyName) =>
        parent.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static bool ReadBoolean(JsonElement parent, string propertyName) =>
        parent.TryGetProperty(propertyName, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False && value.GetBoolean();

    private static string SafeDiagnostic(string? value)
    {
        var normalized = string.Join(" ", (value ?? string.Empty)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return normalized.Length <= 240 ? normalized : normalized[..240] + "…";
    }

    private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : SafeDiagnostic(value);

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort only; the process has an independent bounded command.
        }
    }

    private sealed record HyperVProbeResult(
        bool ManagementAvailable,
        bool QuerySucceeded,
        string DiagnosticCode,
        string DiagnosticMessage,
        IReadOnlyList<LocalVmCandidateContract> Vms)
    {
        internal static HyperVProbeResult Failed(bool managementAvailable, string code, string message) =>
            new(managementAvailable, false, code, message, Array.Empty<LocalVmCandidateContract>());
    }
}
