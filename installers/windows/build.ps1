<#
.SYNOPSIS
    Builds the OfficeHQ MDM Windows MSI.

.DESCRIPTION
    A thin wrapper around installers/windows/build-plan.mjs: the output path,
    the value checks and the exit codes come from the Node planner, so
    PowerShell and Node agree on all three. The planner's exit code is this
    script's exit code. scripts/deploy/package-installers.sh reads the
    collection URL, tenant id and client id from the deployed stack and
    builds through the planner directly.

.EXAMPLE
    .\build.ps1 -Version 1.2.3 -Arch x64 -CollectionUrl https://mdm.example/ `
        -TenantId <tenant> -ClientId <client> -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$Arch = 'x64',

    [Parameter(Mandatory = $true)]
    [string]$CollectionUrl,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$plannerArgs = @(
    (Join-Path $PSScriptRoot 'build-plan.mjs'),
    '--version', $Version,
    '--arch', $Arch,
    '--collection-url', $CollectionUrl,
    '--tenant-id', $TenantId,
    '--client-id', $ClientId
)
if ($DryRun) {
    $plannerArgs += '--dry-run'
}

& node @plannerArgs
exit $LASTEXITCODE
