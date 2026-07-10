<#
.SYNOPSIS
Installs a local pre-commit hook for repository policy checks.

.DESCRIPTION
Inputs are the current repository path. Processing configures core.hooksPath
and writes a small hook that calls Test-RepositoryPolicy.ps1. The script returns
exit code 0 when installation succeeds.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$hooksRoot = Join-Path $repoRoot '.githooks'
$hookPath = Join-Path $hooksRoot 'pre-commit'

New-Item -ItemType Directory -Force -Path $hooksRoot | Out-Null
@'
#!/bin/sh
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
pwsh -NoProfile -ExecutionPolicy Bypass -File "$repo_root/scripts/Test-RepositoryPolicy.ps1" -StagedOnly
exit $?
'@ | Set-Content -NoNewline -Encoding UTF8 -Path $hookPath

git config core.hooksPath .githooks
Write-Host "Installed git hooks at .githooks"
exit 0
