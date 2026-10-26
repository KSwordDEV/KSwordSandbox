# GuestOps transport for the production VMware Block runbook. The host never
# mounts a guest-writable folder and never executes submitted sample bytes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('ready','stage','copy-sample','prepare-output','runtime-preflight','launch','sync','verify')][string]$Mode,
    [Parameter(Mandatory)][string]$SettingsPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$s = Get-Content -LiteralPath $SettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$vmx = [IO.Path]::GetFullPath([string]$s.vmxPath)
$vix = [IO.Path]::GetFullPath([string]$s.vixHelperPath)
$control = [IO.Path]::GetFullPath([string]$s.hostControl)
$evidence = [IO.Path]::GetFullPath([string]$s.hostEvidence)
$guestPublic = [string]$s.guestPublic
$guestOut = [string]$s.guestOutput
$guestRoot = [string]$s.guestRoot
$guestProgram = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:manifestScriptInstalled = $false
$script:manifestScriptPath = ''
if (-not (Test-Path -LiteralPath $vmx -PathType Leaf) -or -not (Test-Path -LiteralPath $vix -PathType Leaf)) { throw 'VMware GuestOps resource is missing.' }
if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD','Process'))) { throw 'GuestOps credential environment is unavailable.' }
New-Item -ItemType Directory -Force -Path $control,$evidence | Out-Null
$jobRoot = [IO.Path]::GetFullPath((Split-Path -Parent $control)).TrimEnd('\')
foreach ($rootToCheck in @($control,$evidence)) {
    $rootPath = [IO.Path]::GetFullPath($rootToCheck).TrimEnd('\')
    if (-not ($rootPath + '\').StartsWith($jobRoot + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'GuestOps host path is outside its job root.' }
    $walk = $rootPath
    while ($true) {
        if (((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'GuestOps host output path contains a reparse point.' }
        if ($walk.Equals($jobRoot,[StringComparison]::OrdinalIgnoreCase)) { break }
        $walk = Split-Path -Parent $walk
        if ([string]::IsNullOrWhiteSpace($walk)) { throw 'GuestOps host path ancestor validation failed.' }
    }
}

function Assert-Isolation {
    $lines = @(Get-Content -LiteralPath $vmx -ErrorAction Stop)
    if ($lines | Where-Object { $_ -match '(?i)^\s*(ethernet\d+|sharedFolder\d+|usb|ehci|usb_xhci|serial\d+|parallel\d+|sound|floppy\d+|ide1:0)\.present\s*=\s*"?TRUE"?\s*$' }) { throw 'VMX exposes a network, shared-folder or peripheral device.' }
    foreach ($key in @('isolation.tools.copy.disable','isolation.tools.paste.disable','isolation.tools.dnd.disable')) {
        if (-not ($lines | Where-Object { $_ -match ('(?i)^\s*' + [regex]::Escape($key) + '\s*=\s*"?TRUE"?\s*$') })) { throw "VMX isolation key is not enabled: $key" }
    }
    if ($lines | Where-Object { $_ -match '(?i)^\s*sharedFolder\.maxNum\s*=\s*"?[1-9]\d*"?\s*$' }) { throw 'VMX has guest-visible shared-folder capacity.' }
}

function Get-Sha256Hex([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Quote-WindowsArgument([string]$Value) {
    $quoted=[Text.StringBuilder]::new()
    [void]$quoted.Append('"')
    $slashes=0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$quoted.Append('\' * ($slashes * 2 + 1))
            [void]$quoted.Append('"')
            $slashes=0
            continue
        }
        [void]$quoted.Append('\' * $slashes)
        $slashes=0
        [void]$quoted.Append($character)
    }
    [void]$quoted.Append('\' * ($slashes * 2))
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-Vix([string]$Operation,[string[]]$Arguments = @(),[int[]]$AllowedExitCodes = @(0),[int]$TimeoutSeconds = 90) {
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 180) { throw 'VIX timeout is outside the bounded range.' }
    $start=[Diagnostics.ProcessStartInfo]::new($vix)
    $start.Arguments=(@($Operation,$vmx) + $Arguments | ForEach-Object { Quote-WindowsArgument ([string]$_) }) -join ' '
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    if ($null -eq $process) { throw "VIX $Operation could not start." }
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync()
        $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill(); [void]$process.WaitForExit(5000) } catch {}
            throw "VIX $Operation timed out after $TimeoutSeconds seconds."
        }
        if (-not [Threading.Tasks.Task]::WaitAll(@($stdout,$stderr),5000)) { throw "VIX $Operation output did not close." }
        $code=[int]$process.ExitCode
        if ($code -notin $AllowedExitCodes) {
            $detail=(($stdout.Result+' '+$stderr.Result).Trim() -replace '[\r\n]+',' ')
            if ($detail.Length -gt 500) { $detail=$detail.Substring(0,500) }
            throw "VIX $Operation failed (exit $code): $detail"
        }
        return $code
    }
    finally { $process.Dispose() }
}

function Copy-ToGuest([string]$HostPath,[string]$GuestPath) {
    [void](Invoke-Vix 'copy-to' @($HostPath,$GuestPath))
}

function Copy-FromGuest([string]$GuestPath,[string]$HostPath,[switch]$Optional,[int]$TimeoutSeconds = 90) {
    $parent = Split-Path -Parent $HostPath
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $temp = $HostPath + '.vix.tmp'
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    try {
        $code = Invoke-Vix 'copy-from' @($GuestPath,$temp) @(0,3) -TimeoutSeconds $TimeoutSeconds
        if ($code -eq 3 -and $Optional) { return $false }
        if ($code -ne 0) { throw "Required guest file was not available: $GuestPath" }
        Move-Item -LiteralPath $temp -Destination $HostPath -Force -ErrorAction Stop
        return $true
    }
    finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
}

function Test-QuickEvidenceIdentity([string]$Path,[switch]$LaunchProof) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($file.Length -le 0 -or $file.Length -gt 4096 -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    try {
        $record=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([string]$record.jobId -ne [string]$s.jobId -or
            -not ([string]$record.samplePath).Equals([string]$s.guestSample,[StringComparison]::OrdinalIgnoreCase) -or
            -not ([string]$record.sampleSha256).Equals([string]$s.sampleSha256,[StringComparison]::OrdinalIgnoreCase) -or
            [int64]$record.sampleSizeBytes -ne [int64]$s.sampleSizeBytes -or
            [int64]$s.sampleSizeBytes -le 0) { return $false }
        if ($LaunchProof) {
            return [string]$record.schema -ceq 'ksword-sample-launch-proof-v1' -and
                [string]$record.state -ceq 'started' -and
                [int]$record.processId -gt 0 -and
                -not [string]::IsNullOrWhiteSpace([string]$record.startedAtUtc)
        }
        return [string]$record.schema -ceq 'ksword-live-events-v1' -and
            [string]$record.eventFormat -ceq 'SandboxEvent-jsonl'
    }
    catch { return $false }
}

function Pull-QuickEvidence {
    $identity=Join-Path $evidence 'live-events.identity.json'
    $proof=Join-Path $evidence 'sample-launch-proof.json'
    $journal=Join-Path $evidence 'live-events.jsonl'
    if (-not (Test-QuickEvidenceIdentity $identity)) {
        $candidate=$identity+'.quick'
        try {
            if (Copy-FromGuest (Join-Path $guestOut 'live-events.identity.json') $candidate -Optional -TimeoutSeconds 5) {
                if (Test-QuickEvidenceIdentity $candidate) { Move-Item -LiteralPath $candidate -Destination $identity -Force }
            }
        } catch {} finally { Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue }
    }
    if (-not (Test-QuickEvidenceIdentity $proof -LaunchProof)) {
        $candidate=$proof+'.quick'
        try {
            if (Copy-FromGuest (Join-Path $guestOut 'sample-launch-proof.json') $candidate -Optional -TimeoutSeconds 5) {
                if (Test-QuickEvidenceIdentity $candidate -LaunchProof) {
                    Move-Item -LiteralPath $candidate -Destination $proof -Force
                    Write-Host 'GuestOps recovered a pinned sample launch proof before the full manifest.'
                }
            }
        } catch {} finally { Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue }
    }
    if (Test-QuickEvidenceIdentity $identity) {
        $candidate=$journal+'.quick'
        try {
            if (Copy-FromGuest (Join-Path $guestOut 'live-events.jsonl') $candidate -Optional -TimeoutSeconds 5) {
                $size=(Get-Item -LiteralPath $candidate -Force -ErrorAction Stop).Length
                $retained=if (Test-Path -LiteralPath $journal -PathType Leaf) { (Get-Item -LiteralPath $journal).Length } else { 0L }
                if ($size -gt $retained -and $size -le 67108864L) {
                    Move-Item -LiteralPath $candidate -Destination $journal -Force
                    Write-Host "GuestOps retained $size bytes of pinned live events before the full manifest."
                }
            }
        } catch {} finally { Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue }
    }
}

function Run-GuestPowerShell([string]$GuestScript,[string[]]$Arguments = @()) {
    $argumentString = '-NoProfile -ExecutionPolicy Bypass -File "' + $GuestScript + '"'
    foreach ($argument in $Arguments) { $argumentString += ' "' + $argument.Replace('"','') + '"' }
    [void](Invoke-Vix 'run' @($guestProgram,$argumentString))
}

function Install-GuestScript([string]$Name,[string]$Source) {
    $hostPath = Join-Path $control "$Name.ps1"
    $guestPath = Join-Path $guestPublic "$Name.ps1"
    [IO.File]::WriteAllText($hostPath,$Source,[Text.UTF8Encoding]::new($false))
    Copy-ToGuest $hostPath $guestPath
    return $guestPath
}

function Pull-Evidence([switch]$Final) {
    $script:lastPullMissing = @()
    $script:lastPullErrors = @()
    $manifestGuest = Join-Path $guestOut 'guestops-manifest.json'
    $manifestScript = @'
param([string]$Root)
$ErrorActionPreference='Stop'
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) { throw 'Guest output is missing.' }
$path=Join-Path $rootPath 'guestops-manifest.json'
$files=@(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -ErrorAction Stop | Where-Object { $_.FullName -ne $path } | ForEach-Object { [pscustomobject]@{ relativePath=$_.FullName.Substring($rootPath.Length).TrimStart('\'); length=[int64]$_.Length } })
[IO.File]::WriteAllText($path,(ConvertTo-Json -InputObject $files -Depth 3 -Compress),[Text.UTF8Encoding]::new($false))
'@
    # A sync step polls repeatedly in one PowerShell process. Re-copying the
    # same guest script on every poll needlessly exercises GuestOps while the
    # Agent is active and can prevent later evidence pulls from being retried.
    if (-not $script:manifestScriptInstalled) {
        $script:manifestScriptPath = Install-GuestScript 'ksword-guestops-manifest' $manifestScript
        $script:manifestScriptInstalled = $true
    }
    $scriptGuest = $script:manifestScriptPath
    Run-GuestPowerShell $scriptGuest @($guestOut)
    $manifestHost = Join-Path $control 'guestops-manifest.json'
    [void](Copy-FromGuest $manifestGuest $manifestHost)
    # Windows PowerShell 5.1 may preserve the JSON root array as one pipeline
    # object when ConvertFrom-Json is wrapped in @(...). Accessing
    # $entry.relativePath then joins every manifest path into one string and
    # VIX reports VIX_E_FILE_NAME_TOO_LONG (20004). Enumerate the parsed
    # array explicitly, and reject any nested/non-scalar entry.
    $parsedManifest = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $manifestHost -Raw) -ErrorAction Stop
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($manifestItem in $parsedManifest) {
        if ($manifestItem -is [array]) {
            foreach ($nestedItem in $manifestItem) { $entries.Add($nestedItem) }
        }
        else { $entries.Add($manifestItem) }
    }
    foreach ($entry in $entries) {
        if ($entry -is [array] -or $entry -isnot [pscustomobject] -or
            $entry.relativePath -is [array] -or $entry.length -is [array]) {
            throw 'Guest manifest contains a non-scalar file entry.'
        }
    }
    if ($entries.Count -gt 20000) { throw 'Guest manifest exceeds 20000 files.' }
    $root = $evidence.TrimEnd('\')
    $prefix = $root + '\'
    $declared = 0L
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $relative = [string]$entry.relativePath
        $length = [int64]$entry.length
        if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains(':') -or $relative.Contains('/') -or [IO.Path]::IsPathRooted($relative) -or @($relative.Split('\') | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0 -or $length -lt 0 -or $length -gt 17179869184L) { throw "Guest manifest path or length was rejected: $relative" }
        if (-not $seen.Add($relative)) { throw "Guest manifest contains a duplicate path: $relative" }
        $declared += $length
        if ($declared -gt 68719476736L) { throw 'Guest manifest exceeds 64 GiB.' }
    }
    foreach ($entry in $entries) {
        $relative = [string]$entry.relativePath
        $length = [int64]$entry.length
        $destination = [IO.Path]::GetFullPath((Join-Path $root $relative))
        if (-not $destination.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest manifest escaped evidence root.' }
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
        $walk = $parent
        while ($walk.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            if (((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Evidence path contains a host reparse point.' }
            $walk = Split-Path -Parent $walk
        }
        if (-not $Final -and (Test-Path -LiteralPath $destination -PathType Leaf) -and [int64](Get-Item -LiteralPath $destination).Length -eq $length) { continue }
        if ($relative -eq 'live-events.jsonl' -and (Test-Path -LiteralPath $destination -PathType Leaf) -and
            [int64](Get-Item -LiteralPath $destination).Length -gt $length) { continue }
        $temp = $destination + '.vix.tmp'
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        try { $code = Invoke-Vix 'copy-from' @((Join-Path $guestOut $relative),$temp) @(0,3) }
        catch {
            $script:lastPullErrors += "$relative`: $($_.Exception.Message)"
            if ($Final) { $script:lastPullMissing += $relative }
            continue
        }
        if ($code -eq 3 -or -not (Test-Path -LiteralPath $temp -PathType Leaf)) { if ($Final) { $script:lastPullMissing += $relative }; continue }
        if ([int64](Get-Item -LiteralPath $temp).Length -ne $length) { Remove-Item -LiteralPath $temp -Force; if ($Final) { $script:lastPullMissing += $relative }; continue }
        Move-Item -LiteralPath $temp -Destination $destination -Force -ErrorAction Stop
    }
}

Assert-Isolation
switch ($Mode) {
    'ready' {
        $deadline=(Get-Date).AddSeconds(180)
        do {
            $code=Invoke-Vix 'file-exists' @('C:\Windows\System32\notepad.exe') @(0,1,3)
            if ($code -eq 0) { Write-Host 'VMware GuestOps authenticated and ready.'; break }
            Start-Sleep -Seconds 3
        } while ((Get-Date) -lt $deadline)
        if ($code -ne 0) { throw 'VMware Tools GuestOps did not become ready in 180 seconds.' }
    }
    'stage' {
        $agentSource=Join-Path ([string]$s.payloadRoot) 'agent'
        $agentExe=Join-Path $agentSource ([string]$s.agentExecutableName)
        foreach ($path in @($agentSource,$agentExe,(Join-Path $agentSource 'KSword.Sandbox.Agent.runtimeconfig.json'),(Join-Path $agentSource 'KSword.Sandbox.Agent.deps.json'))) { if (-not (Test-Path -LiteralPath $path)) { throw "Guest Agent payload is missing: $path" } }
        if (Get-ChildItem -LiteralPath $agentSource -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue) { throw 'Guest Agent payload contains a reparse point.' }
        $zip=Join-Path $control 'agent.zip'
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($agentSource,$zip,[IO.Compression.CompressionLevel]::Optimal,$false)
        $zipHash=Get-Sha256Hex $zip
        $agentHash=Get-Sha256Hex $agentExe
        $guestZip=Join-Path $guestPublic 'ksword-agent.zip'
        Copy-ToGuest $zip $guestZip
        $script=@'
param([string]$Root,[string]$Zip,[string]$ExpectedZip,[string]$ExpectedAgent,[string]$AgentName,[string]$Result)
$ErrorActionPreference='Stop'
function Hash([string]$Path) { $stream=[IO.File]::OpenRead($Path); try { $sha=[Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') } finally { $sha.Dispose() } } finally { $stream.Dispose() } }
function Assert-DedicatedRoot([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\') { throw 'Guest working directory must be an absolute local drive path.' }
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $drive=[IO.Path]::GetPathRoot($full)
    if ($full.Equals($drive.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest working directory cannot be a drive root.' }
    $relative=$full.Substring($drive.Length)
    if (@($relative.Split('\') | Where-Object { $_ -match '^(?i:Windows|Users|Program Files(?: \(x86\))?|ProgramData|Recovery|System Volume Information|\$Recycle\.Bin)$' }).Count -gt 0) { throw 'Guest working directory cannot be inside a system or user profile tree.' }
    $walk=$full
    while ($true) {
        $candidate=$walk
        if (Test-Path -LiteralPath $candidate) {
            if (((Get-Item -LiteralPath $candidate -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest working directory contains a reparse point.' }
        }
        if ($candidate.Equals($drive.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or $candidate.Equals($drive,[StringComparison]::OrdinalIgnoreCase)) { break }
        $walk=Split-Path -Parent $walk
        if ([string]::IsNullOrWhiteSpace($walk)) { throw 'Guest working directory ancestry could not be verified.' }
    }
    $marker=Join-Path $full '.ksword-sandbox-guest-root'
    if (-not $full.Equals('C:\KSwordSandbox',[StringComparison]::OrdinalIgnoreCase)) {
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or
            ((Get-Item -LiteralPath $marker -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-Content -LiteralPath $marker -Raw -ErrorAction Stop).Trim() -ne 'KSwordSandbox guest working directory v1') {
            throw 'Custom guest working directory must be prepared by the guest bootstrap before staging.'
        }
    }
    return $full
}
function Assert-NoReparseTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest cleanup path contains a reparse point.' }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop) { Assert-NoReparseTree $child.FullName }
    }
}
try {
    $hash=Hash $Zip
    if ($hash -ne $ExpectedZip) { throw 'Agent archive hash mismatch.' }
    $Root=Assert-DedicatedRoot $Root
    foreach ($name in @('incoming','out','agent')) { Assert-NoReparseTree (Join-Path $Root $name) }
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    $Root=Assert-DedicatedRoot $Root
    foreach ($name in @('incoming','out')) { $path=Join-Path $Root $name; if (Test-Path -LiteralPath $path) { Get-ChildItem -LiteralPath $path -Force | Remove-Item -Recurse -Force }; New-Item -ItemType Directory -Force -Path $path | Out-Null }
    $target=Join-Path $Root 'agent'
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    Expand-Archive -LiteralPath $Zip -DestinationPath $target -Force
    $exe=Join-Path $target $AgentName
    $actual=Hash $exe
    if ($actual -ne $ExpectedAgent) { throw 'Staged Agent hash mismatch.' }
    [ordered]@{ state='ready'; zipSha256=$hash; agentSha256=$actual; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Result -Encoding UTF8
} catch { [ordered]@{ state='failed'; error=$_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $Result -Encoding UTF8; exit 1 }
'@
        $guestScript=Install-GuestScript 'ksword-stage' $script
        $guestResult=Join-Path $guestPublic 'ksword-stage-result.json'
        $runCode=Invoke-Vix 'run' @($guestProgram,('-NoProfile -ExecutionPolicy Bypass -File "'+$guestScript+'" "'+$guestRoot+'" "'+$guestZip+'" "'+$zipHash+'" "'+$agentHash+'" "'+[string]$s.agentExecutableName+'" "'+$guestResult+'"')) @(0,4)
        $hostResult=Join-Path $control 'stage-result.json'
        [void](Copy-FromGuest $guestResult $hostResult)
        $result=Get-Content -LiteralPath $hostResult -Raw | ConvertFrom-Json
        if ($runCode -ne 0 -or $result.state -ne 'ready' -or $result.agentSha256 -ne $agentHash) { throw 'Guest Agent staging failed; see stage-result.json.' }
    }
    'copy-sample' {
        $source=[IO.Path]::GetFullPath([string]$s.hostSample)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Submitted sample is missing on host.' }
        if ((Get-Sha256Hex $source) -ne [string]$s.sampleSha256) { throw 'Submitted sample hash changed before copy.' }
        Copy-ToGuest $source ([string]$s.guestSample)
        $script=@'
param([string]$Sample,[string]$Expected,[string]$Result)
$ErrorActionPreference='Stop'
function Hash([string]$Path) { $stream=[IO.File]::OpenRead($Path); try { $sha=[Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') } finally { $sha.Dispose() } } finally { $stream.Dispose() } }
try { $actual=Hash $Sample; if ($actual -ne $Expected) { throw 'Copied sample hash mismatch.' }; [ordered]@{ state='ready'; sampleSha256=$actual; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Result -Encoding UTF8 }
catch { [ordered]@{ state='failed'; error=$_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $Result -Encoding UTF8; exit 1 }
'@
        $guestScript=Install-GuestScript 'ksword-sample-hash' $script
        $guestResult=Join-Path $guestPublic 'ksword-sample-hash-result.json'
        $runCode=Invoke-Vix 'run' @($guestProgram,('-NoProfile -ExecutionPolicy Bypass -File "'+$guestScript+'" "'+[string]$s.guestSample+'" "'+[string]$s.sampleSha256+'" "'+$guestResult+'"')) @(0,4)
        $hostResult=Join-Path $control 'sample-hash-result.json'
        [void](Copy-FromGuest $guestResult $hostResult)
        $result=Get-Content -LiteralPath $hostResult -Raw | ConvertFrom-Json
        if ($runCode -ne 0 -or $result.state -ne 'ready' -or $result.sampleSha256 -ne [string]$s.sampleSha256) { throw 'Guest sample copy/hash verification failed.' }
    }
    'prepare-output' {
        $script=@'
param([string]$Output,[string]$Root)
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($Root) -or $Root -notmatch '^[A-Za-z]:\\') { throw 'Guest working directory must be an absolute local drive path.' }
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
$drive=[IO.Path]::GetPathRoot($rootPath)
if ($rootPath.Equals($drive.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest working directory cannot be a drive root.' }
$relative=$rootPath.Substring($drive.Length)
if (@($relative.Split('\') | Where-Object { $_ -match '^(?i:Windows|Users|Program Files(?: \(x86\))?|ProgramData|Recovery|System Volume Information|\$Recycle\.Bin)$' }).Count -gt 0) { throw 'Guest working directory cannot be inside a system or user profile tree.' }
$expectedOut=Join-Path $rootPath 'out'
$outputPath=[IO.Path]::GetFullPath($Output).TrimEnd('\')
if (-not $outputPath.StartsWith($expectedOut+'\',[StringComparison]::OrdinalIgnoreCase) -or
    $outputPath.Substring($expectedOut.Length+1) -notmatch '^[a-fA-F0-9]{32}$') { throw 'Guest output must be a single job directory below the guest working root.' }
if (-not $rootPath.Equals('C:\KSwordSandbox',[StringComparison]::OrdinalIgnoreCase)) {
    $marker=Join-Path $rootPath '.ksword-sandbox-guest-root'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or
        ((Get-Item -LiteralPath $marker -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-Content -LiteralPath $marker -Raw -ErrorAction Stop).Trim() -ne 'KSwordSandbox guest working directory v1') { throw 'Custom guest working directory is not bootstrapped.' }
}
$walk=$outputPath
while ($true) {
    if (Test-Path -LiteralPath $walk) {
        if (((Get-Item -LiteralPath $walk -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest output path contains a reparse point.' }
    }
    if ($walk.Equals($drive.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or $walk.Equals($drive,[StringComparison]::OrdinalIgnoreCase)) { break }
    $walk=Split-Path -Parent $walk
    if ([string]::IsNullOrWhiteSpace($walk)) { throw 'Guest output ancestry could not be verified.' }
}
function Assert-NoReparseTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest output tree contains a reparse point.' }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop) { Assert-NoReparseTree $child.FullName }
    }
}
Assert-NoReparseTree $outputPath
if (Test-Path -LiteralPath $Output) { Remove-Item -LiteralPath $Output -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$service=Get-Service -Name 'KSwordSandboxDriver' -ErrorAction SilentlyContinue
[ordered]@{ serviceName='KSwordSandboxDriver'; present=($null -ne $service); status=if ($service) { [string]$service.Status } else { 'absent' }; startType=if ($service) { [string]$service.StartType } else { $null }; mode='read-only-inventory'; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'driver-readiness.json') -Encoding UTF8
[ordered]@{ state='ready'; output=$Output; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'output-ready.json') -Encoding UTF8
'@
        $guestScript=Install-GuestScript 'ksword-prepare-output' $script
        Run-GuestPowerShell $guestScript @($guestOut,$guestRoot)
        [void](Copy-FromGuest (Join-Path $guestOut 'output-ready.json') (Join-Path $evidence 'output-ready.json'))
        [void](Copy-FromGuest (Join-Path $guestOut 'driver-readiness.json') (Join-Path $evidence 'driver-readiness.json'))
    }
    'runtime-preflight' {
        $sample=[IO.Path]::GetFullPath([string]$s.hostSample)
        $sampleInfo=Get-Item -LiteralPath $sample -ErrorAction Stop
        $scanLength=[int][Math]::Min([int64]$sampleInfo.Length,[int64](32*1024*1024))
        $bytes=[byte[]]::new($scanLength)
        $stream=[IO.File]::OpenRead($sample)
        try { $readTotal=0; while ($readTotal -lt $scanLength) { $read=$stream.Read($bytes,$readTotal,$scanLength-$readTotal); if ($read -le 0) { break }; $readTotal+=$read } } finally { $stream.Dispose() }
        $scanLength=$readTotal
        $ascii=[Text.Encoding]::ASCII.GetString($bytes,0,$scanLength)
        $legacyMarker=$ascii -match '(?i)v2\.0\.50727|v3\.0(?:\.\d+)?|v3\.5(?:\.\d+)?'
        $managed=$false
        if ($bytes.Length -ge 256 -and $bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a) {
            $peOffset=[BitConverter]::ToInt32($bytes,0x3c)
            if ($peOffset -ge 0 -and $peOffset+256 -lt $bytes.Length -and $bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                $optional=$peOffset+24; $magic=[BitConverter]::ToUInt16($bytes,$optional); $dir=if ($magic -eq 0x20b) { $optional+112 } elseif ($magic -eq 0x10b) { $optional+96 } else { -1 }
                if ($dir -ge 0 -and $dir+14*8+4 -le $bytes.Length) { $managed=[BitConverter]::ToUInt32($bytes,$dir+14*8) -ne 0 }
            }
        }
        $script=@'
param([string]$Sample,[string]$Output)
$ErrorActionPreference='Stop'
$feature=$null
try { $feature=Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop } catch {}
$state=if ($feature) { [string]$feature.State } else { 'query-failed' }
[ordered]@{ samplePresent=(Test-Path -LiteralPath $Sample -PathType Leaf); guestNetFx3State=$state; guestNetFx3Enabled=($state -eq 'Enabled'); guestComputerName=$env:COMPUTERNAME; readOnly=$true; sampleExecuted=$false; checkedAtUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'sample-runtime-preflight.json') -Encoding UTF8
'@
        $guestScript=Install-GuestScript 'ksword-runtime-preflight' $script
        Run-GuestPowerShell $guestScript @([string]$s.guestSample,$guestOut)
        $diagnosticPath=Join-Path $evidence 'sample-runtime-preflight.json'
        [void](Copy-FromGuest (Join-Path $guestOut 'sample-runtime-preflight.json') $diagnosticPath)
        $diagnostic=Get-Content -LiteralPath $diagnosticPath -Raw | ConvertFrom-Json
        if (-not $diagnostic.samplePresent) { throw 'Guest sample disappeared before launch.' }
        if ($managed -and $legacyMarker -and -not $diagnostic.guestNetFx3Enabled) { throw 'Legacy CLR sample requires NetFx3; guest is not ready.' }
    }
    'launch' {
        if (Test-Path -LiteralPath (Join-Path $evidence 'agent.pid')) { throw 'Existing Agent marker prevents duplicate launch.' }
        $wrapper=@'
param([string]$Output)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$marker=Join-Path $Output ('agent.pid.tmp.'+$PID)
[IO.File]::WriteAllText($marker,[string]$PID,[Text.Encoding]::ASCII)
Move-Item -LiteralPath $marker -Destination (Join-Path $Output 'agent.pid') -Force
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[ordered]@{ isElevatedAdministrator=$admin; identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'token-status.json') -Encoding UTF8
if (-not $admin) { [IO.File]::WriteAllText((Join-Path $Output 'agent.exit'),'1'); exit 1 }
'@
        $wrapper += "`r`n" + [string]$s.agentInvocation + "`r`n"
        $guestWrapper=Install-GuestScript 'ksword-agent-wrapper' $wrapper
        $taskScript=@'
param([string]$Wrapper,[string]$Output,[string]$Root,[string]$User,[string]$TaskName)
$ErrorActionPreference='Stop'
$result=Join-Path $Output 'launch-task-result.json'
try {
    if ((Test-Path -LiteralPath (Join-Path $Output 'agent.pid')) -or (Test-Path -LiteralPath (Join-Path $Output 'agent.exit'))) { throw 'Guest Agent markers already exist; refusing duplicate launch.' }
    $identity=if ($User.Contains('\') -or $User.Contains('@')) { $User } else { "$env:COMPUTERNAME\$User" }
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$Wrapper+'" "'+$Output+'"'
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory $Root
    $principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType S4U -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 24)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $deadline=(Get-Date).AddSeconds(60)
    do { Start-Sleep -Milliseconds 250 } while (-not (Test-Path -LiteralPath (Join-Path $Output 'agent.pid')) -and (Get-Date) -lt $deadline)
    if (-not (Test-Path -LiteralPath (Join-Path $Output 'agent.pid'))) { throw 'S4U Agent task did not publish its PID marker.' }
    [ordered]@{ state='started'; logonType='S4U'; taskName=$TaskName; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $result -Encoding UTF8
} catch {
    $info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    [ordered]@{ state='failed'; error=$_.Exception.Message; lastTaskResult=if ($info) { [int64]$info.LastTaskResult } else { $null }; taskName=$TaskName; atUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $result -Encoding UTF8
    exit 1
}
'@
        $guestLauncher=Install-GuestScript 'ksword-launch-agent' $taskScript
        $taskName='KSwordOffline-'+([string]$s.jobId).Replace('-','')
        $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$guestLauncher+'" "'+$guestWrapper+'" "'+$guestOut+'" "'+$guestRoot+'" "'+[string]$s.guestUser+'" "'+$taskName+'"'
        $runCode=Invoke-Vix 'run' @($guestProgram,$arguments) @(0,4)
        [void](Copy-FromGuest (Join-Path $guestOut 'launch-task-result.json') (Join-Path $evidence 'launch-task-result.json') -Optional)
        if ($runCode -ne 0) { try { Pull-Evidence -Final } catch {}; throw 'S4U Agent launch failed; retained available guest diagnostics.' }
    }
    'sync' {
        $deadline=(Get-Date).AddSeconds([Math]::Max(180,[int]$s.durationSeconds+180))
        $lastError=''
        # A destructive sample can remove VMware Tools or reset the guest
        # while the complete manifest is being generated. Recover the flushed
        # identity, launch proof, and growing journal first in a bounded window.
        $quickDeadline=(Get-Date).AddSeconds([Math]::Min(20,[int]$s.durationSeconds))
        do {
            Pull-QuickEvidence
            Start-Sleep -Milliseconds 700
        } while ((Get-Date) -lt $quickDeadline)
        do {
            Pull-QuickEvidence
            try { Pull-Evidence; $lastError=($script:lastPullErrors -join '; ') } catch { $lastError=$_.Exception.Message }
            if (Test-Path -LiteralPath (Join-Path $evidence 'agent.exit') -PathType Leaf) { break }
            Start-Sleep -Seconds 3
        } while ((Get-Date) -lt $deadline)
        try { Pull-Evidence -Final; $lastError=($script:lastPullErrors -join '; ') } catch { $lastError=$_.Exception.Message }
        $copyMissing=@($script:lastPullMissing)
        $required=@('events.json','agent-summary.json','agent.pid','agent.exit','token-status.json')
        $missing=@($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $evidence $_) -PathType Leaf) })
        $exitText=if (Test-Path -LiteralPath (Join-Path $evidence 'agent.exit')) { (Get-Content -LiteralPath (Join-Path $evidence 'agent.exit') -Raw).Trim() } else { '' }
        $exitCode=0; $exitValid=[int]::TryParse($exitText,[ref]$exitCode)
        $token=if (Test-Path -LiteralPath (Join-Path $evidence 'token-status.json')) { Get-Content -LiteralPath (Join-Path $evidence 'token-status.json') -Raw | ConvertFrom-Json } else { $null }
        $adminConfirmed=$null -ne $token -and [bool]$token.isElevatedAdministrator
        $state=if ($missing.Count -gt 0 -or $copyMissing.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($lastError) -or -not $exitValid -or -not $adminConfirmed) { 'incomplete-output' } elseif ($exitCode -ne 0) { 'agent-failed' } else { 'completed' }
        [ordered]@{ state=$state; exitCode=if ($exitValid) { $exitCode } else { $null }; sampleSha256=[string]$s.sampleSha256; missingArtifacts=$missing; copyMissing=$copyMissing; copyErrors=@($script:lastPullErrors); collectionChannel='vmware-vix-guest-operations'; collectionError=$lastError; capturedAtUtc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'guest-agent-run-status.json') -Encoding UTF8
        if ($state -ne 'completed') { throw "GuestOps evidence collection failed or Agent exited nonzero: $state; $lastError" }
    }
    'verify' {
        $status=Get-Content -LiteralPath (Join-Path $evidence 'guest-agent-run-status.json') -Raw | ConvertFrom-Json
        if ($status.state -ne 'completed') { throw 'GuestOps Agent status is not complete.' }
        $summary=Get-Content -LiteralPath (Join-Path $evidence 'agent-summary.json') -Raw | ConvertFrom-Json
        if (-not ([string]$summary.sampleSha256).Equals([string]$s.sampleSha256,[StringComparison]::OrdinalIgnoreCase)) { throw 'Agent summary sample hash does not match the submitted sample.' }
        $events=Get-Content -LiteralPath (Join-Path $evidence 'events.json') -Raw | ConvertFrom-Json
        if (@($events | Where-Object { $_.eventType -eq 'networkPolicy.applied' }).Count -eq 0) { throw 'Guest evidence has no networkPolicy.applied proof.' }
        if (@($events | Where-Object { $_.eventType -eq 'process.start' }).Count -eq 0) { throw 'Guest evidence has no sample process.start proof.' }
        Write-Host 'VMware offline user-mode run and raw evidence passed.'
    }
}
