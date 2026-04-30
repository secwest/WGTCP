<#
.SYNOPSIS Tear down the entire perf-test fleet.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Subscription,
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
& az account set --subscription $Subscription | Out-Null

if (-not $Force) {
    $resp = Read-Host "DELETE entire RG '$ResourceGroup'? Type 'yes' to confirm"
    if ($resp -ne 'yes') { Write-Host "aborted"; exit 0 }
}

Write-Host "=== deleting RG $ResourceGroup (no-wait)"
& az group delete -n $ResourceGroup --yes --no-wait
Write-Host "Submitted. Track with: az group show -n $ResourceGroup"
