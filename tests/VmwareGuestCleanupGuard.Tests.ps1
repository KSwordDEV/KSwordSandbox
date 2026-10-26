# Runs the embedded guest cleanup scripts against disposable, non-executable
# fixtures under this repository. No VMware operation or submitted sample is used.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$source = Join-Path $repo 'scripts\Invoke-VmwareOfflineRunbook.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'VMware runbook did not parse.' }
$strings = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true))
$stageSource = @($strings | Where-Object { $_.Value.Contains('function Assert-DedicatedRoot') -and $_.Value.Contains('Agent archive hash mismatch.') })
$outputSource = @($strings | Where-Object { $_.Value.Contains('Guest output must be a single job directory') -and $_.Value.Contains('driver-readiness.json') })
if ($stageSource.Count -ne 1 -or $outputSource.Count -ne 1) { throw 'Expected embedded cleanup scripts were not found exactly once.' }

$fixture = Join-Path $repo ('artifacts\_build\vmware-cleanup-guard-' + [guid]::NewGuid().ToString('N'))
if (-not ([IO.Path]::GetFullPath($fixture) + '\').StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Test fixture escaped repository.' }
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
$stagePath = Join-Path $fixture 'stage.ps1'
$outputPath = Join-Path $fixture 'prepare-output.ps1'
[IO.File]::WriteAllText($stagePath, $stageSource[0].Value, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($outputPath, $outputSource[0].Value, [Text.UTF8Encoding]::new($false))

$payload = Join-Path $fixture 'payload'
New-Item -ItemType Directory -Path $payload | Out-Null
$agent = Join-Path $payload 'harmless-agent.txt'
[IO.File]::WriteAllText($agent, 'harmless test payload', [Text.Encoding]::ASCII)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $fixture 'payload.zip'
[IO.Compression.ZipFile]::CreateFromDirectory($payload, $zip)
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
$agentHash = (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash

function New-Root([string]$Name) {
    $root = Join-Path $fixture $Name
    New-Item -ItemType Directory -Path (Join-Path $root 'incoming') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $root '.ksword-sandbox-guest-root'), "KSwordSandbox guest working directory v1`n", [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $root 'incoming\sentinel.txt'), 'must survive rejected cleanup', [Text.Encoding]::ASCII)
    return $root
}
function Invoke-Stage([string]$Root, [string]$Case) {
    $result = Join-Path $fixture ($Case + '.json')
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stagePath $Root $zip $zipHash $agentHash 'harmless-agent.txt' $result 2>&1 | Out-Null
    return [int]$LASTEXITCODE
}
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

$missingMarker = New-Root 'missing-marker'
Remove-Item -LiteralPath (Join-Path $missingMarker '.ksword-sandbox-guest-root') -Force
Require ((Invoke-Stage $missingMarker 'missing-marker') -ne 0) 'Unmarked custom root was accepted.'
Require (Test-Path -LiteralPath (Join-Path $missingMarker 'incoming\sentinel.txt')) 'Unmarked root was cleaned.'

$protected = New-Root 'Users\test-profile'
Require ((Invoke-Stage $protected 'protected-root') -ne 0) 'User profile tree was accepted.'
Require (Test-Path -LiteralPath (Join-Path $protected 'incoming\sentinel.txt')) 'Protected tree was cleaned.'

$reparse = New-Root 'reparse-root'
$victim = Join-Path $fixture 'victim'
New-Item -ItemType Directory -Path $victim | Out-Null
[IO.File]::WriteAllText((Join-Path $victim 'victim.txt'), 'must remain', [Text.Encoding]::ASCII)
$junction = Join-Path $reparse 'incoming\junction'
New-Item -ItemType Junction -Path $junction -Target $victim -ErrorAction Stop | Out-Null
Require ((Invoke-Stage $reparse 'reparse-root') -ne 0) 'Reparse descendant was accepted.'
Require (Test-Path -LiteralPath (Join-Path $reparse 'incoming\sentinel.txt')) 'Reparse root was partly cleaned.'
Require (Test-Path -LiteralPath (Join-Path $victim 'victim.txt')) 'Junction target was modified.'

$normal = New-Root 'normal-root'
Require ((Invoke-Stage $normal 'normal-root') -eq 0) 'Prepared custom root did not stage.'
Require (-not (Test-Path -LiteralPath (Join-Path $normal 'incoming\sentinel.txt'))) 'Normal staging did not clear its own incoming folder.'
Require (Test-Path -LiteralPath (Join-Path $normal 'agent\harmless-agent.txt')) 'Normal staging did not extract harmless payload.'

$jobOutput = Join-Path $normal ('out\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $jobOutput | Out-Null
[IO.File]::WriteAllText((Join-Path $jobOutput 'sentinel.txt'), 'must survive rejected output cleanup', [Text.Encoding]::ASCII)
$outputJunction = Join-Path $jobOutput 'junction'
New-Item -ItemType Junction -Path $outputJunction -Target $victim -ErrorAction Stop | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $outputPath $jobOutput $normal 2>&1 | Out-Null
Require ($LASTEXITCODE -ne 0) 'Output cleanup accepted a reparse descendant.'
Require (Test-Path -LiteralPath (Join-Path $jobOutput 'sentinel.txt')) 'Output tree was partly cleaned.'
Require (Test-Path -LiteralPath (Join-Path $victim 'victim.txt')) 'Output junction target was modified.'

Write-Output 'VMware guest cleanup guard: missing marker, protected path and reparse descendants rejected; prepared custom root staged.'
