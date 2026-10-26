# Exercises the production VMware sync path with a file-only VIX stub.
# No VM is started and no submitted program is executed.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$runbook = Join-Path $repo 'scripts\Invoke-VmwareOfflineRunbook.ps1'
$compilerCommand = Get-Command csc.exe -ErrorAction SilentlyContinue
$compiler = if ($compilerCommand) { $compilerCommand.Source } else { 'D:\Software\VS\MSBuild\Current\Bin\Roslyn\csc.exe' }
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'C# compiler is unavailable for the file-only VIX stub.' }
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$temp = Join-Path $tempBase ('KSwordVmwareQuickEvidence-' + [guid]::NewGuid().ToString('N'))
$tempFull = [IO.Path]::GetFullPath($temp)
if (-not $tempFull.StartsWith($tempBase + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Test path escaped TEMP.' }
New-Item -ItemType Directory -Path $tempFull -ErrorAction Stop | Out-Null
$previousCredential = [Environment]::GetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD','Process')

try {
    $source = Join-Path $tempFull 'VixStub.cs'
    $helper = Join-Path $tempFull 'VixStub.exe'
    [IO.File]::WriteAllText($source, @'
using System;
using System.IO;
internal static class VixStub {
    private static int Main(string[] args) {
        if (args.Length < 2) return 2;
        if (args[0] == "copy-from" && args.Length == 4) {
            if (!File.Exists(args[2])) return 3;
            File.Copy(args[2], args[3], true);
            return 0;
        }
        if (args[0] == "run") return 4;
        return 2;
    }
}
'@, [Text.UTF8Encoding]::new($false))
    & $compiler /nologo /target:exe ("/out:$helper") $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'VIX stub compilation failed.' }

    $vmx = Join-Path $tempFull 'isolated.vmx'
    [IO.File]::WriteAllText($vmx, @'
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
'@, [Text.UTF8Encoding]::new($false))
    $sampleHash = 'A' * 64
    $samplePath = 'C:\KSwordSandbox\incoming\sample.exe'

    foreach ($case in @(@{ name = 'valid case'; tamper = $false }, @{ name = 'cross job'; tamper = $true })) {
        $caseRoot = Join-Path $tempFull $case.name
        $guestOut = Join-Path $caseRoot 'guest-source'
        $control = Join-Path $caseRoot 'job\control'
        $evidence = Join-Path $caseRoot 'job\guest'
        New-Item -ItemType Directory -Force -Path $guestOut,$control,$evidence | Out-Null
        [IO.File]::WriteAllText((Join-Path $evidence 'agent.exit'),'0',[Text.Encoding]::ASCII)
        $jobId = [guid]::NewGuid().ToString('D')
        $evidenceJob = if ($case.tamper) { [guid]::NewGuid().ToString('D') } else { $jobId }
        $identity = [ordered]@{ schema = 'ksword-live-events-v1'; eventFormat = 'SandboxEvent-jsonl'; jobId = $evidenceJob; samplePath = $samplePath; sampleSha256 = $sampleHash; sampleSizeBytes = 4096 }
        $proof = [ordered]@{ schema = 'ksword-sample-launch-proof-v1'; state = 'started'; jobId = $evidenceJob; samplePath = $samplePath; sampleSha256 = $sampleHash; sampleSizeBytes = 4096; processId = 1234; parentProcessId = 4321; startedAtUtc = '2026-10-26T00:00:00Z' }
        [IO.File]::WriteAllText((Join-Path $guestOut 'live-events.identity.json'),($identity | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $guestOut 'sample-launch-proof.json'),($proof | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $guestOut 'live-events.jsonl'),"{`"eventType`":`"process.start`"}`n",[Text.UTF8Encoding]::new($false))
        $settings = [ordered]@{ jobId = $jobId; vmxPath = $vmx; vixHelperPath = $helper; hostControl = $control; hostEvidence = $evidence; hostSample = ''; sampleSha256 = $sampleHash; sampleSizeBytes = 4096; guestPublic = 'C:\Users\Public'; guestOutput = $guestOut; guestRoot = 'C:\KSwordSandbox'; guestSample = $samplePath; durationSeconds = 1 }
        $settingsPath = Join-Path $caseRoot 'settings.json'
        [IO.File]::WriteAllText($settingsPath,($settings | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        [Environment]::SetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD','mock-only','Process')
        try { & $runbook -Mode sync -SettingsPath $settingsPath | Out-Null } catch { }
        $status = Get-Content -LiteralPath (Join-Path $evidence 'guest-agent-run-status.json') -Raw | ConvertFrom-Json
        if ($status.state -ne 'incomplete-output') { throw "Expected incomplete status after fake GuestOps loss: $($case.name)" }
        $names = @('live-events.identity.json','sample-launch-proof.json','live-events.jsonl')
        foreach ($name in $names) {
            $present = Test-Path -LiteralPath (Join-Path $evidence $name) -PathType Leaf
            if ($present -eq $case.tamper) { throw "Quick recovery identity gate failed for $($case.name): $name" }
        }
    }
    Write-Output 'PASS: production VMware quick recovery retains same-job evidence and rejects cross-job evidence.'
}
finally {
    [Environment]::SetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD',$previousCredential,'Process')
    if (Test-Path -LiteralPath $tempFull) {
        $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $tempFull).Path)
        if (-not $resolved.StartsWith($tempBase + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing cleanup outside TEMP.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
}
