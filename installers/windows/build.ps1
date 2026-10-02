<#
.SYNOPSIS
    Builds the OfficeHQ MDM Windows MSI.

.DESCRIPTION
    A thin wrapper around installers/windows/build-plan.mjs: the output path
    and the exit codes come from the Node planner, so PowerShell and Node agree
    on both. The planner's exit code is this script's exit code.

.EXAMPLE
    .\build.ps1 -Version 1.2.3 -Arch x64 -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$Arch = 'x64',

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$plannerArgs = @(
    (Join-Path $PSScriptRoot 'build-plan.mjs'),
    '--version', $Version,
    '--arch', $Arch
)
if ($DryRun) {
    $plannerArgs += '--dry-run'
}

& node @plannerArgs
exit $LASTEXITCODE
