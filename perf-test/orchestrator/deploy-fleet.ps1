<#
.SYNOPSIS
  Provisions the perf-test fleet: hub + spoke VMs across regions and archs.

.DESCRIPTION
  Idempotent. Creates one RG, one VNet per region, peerings hub<->spoke,
  and one VM per (region, arch) pair. Uses the WireguardTCP-FAST gallery
  images. Skips anything already present.

.PARAMETER Subscription      Azure subscription ID.
.PARAMETER ResourceGroup     RG to create / use (e.g. rg-wgtcp-perf).
.PARAMETER ImageVersion      Gallery image version to deploy (e.g. 1.0.0).
.PARAMETER Gallery           Gallery name (e.g. wireguardtcp_gallery).
.PARAMETER GalleryRG         RG that contains the Gallery.
.PARAMETER ImageDefX64       e.g. wireguardtcp-fast-ubuntu24-tls
.PARAMETER ImageDefArm       e.g. wireguardtcp-fast-ubuntu24-arm64-tls
.PARAMETER HubRegion         Region for hub (default canadacentral).
.PARAMETER SpokeRegions      Regions for spokes (default westus3,australiaeast,southafricanorth).
.PARAMETER VmSizeX64         (default Standard_D2s_v5)
.PARAMETER VmSizeArm         (default Standard_D2ps_v6)
.PARAMETER SshKey            (default $env:USERPROFILE\.ssh\wgtcp_id_ed25519)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Subscription,
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $ImageVersion,
    [string] $Gallery        = 'wireguardtcp_gallery',
    [string] $GalleryRG      = 'rg-wireguardtcp-fast',
    [string] $ImageDefX64    = 'wireguardtcp-fast-ubuntu24-tls',
    [string] $ImageDefArm    = 'wireguardtcp-fast-ubuntu24-arm64-tls',
    [string] $HubRegion      = 'canadacentral',
    [string[]] $SpokeRegions = @('westus3','australiaeast','southafricanorth'),
    [string] $VmSizeX64      = 'Standard_D2s_v5',
    [string] $VmSizeArm      = 'Standard_D2ps_v6',
    [string] $AdminUser      = 'azureuser',
    [string] $SshKey         = "$env:USERPROFILE\.ssh\wgtcp_id_ed25519"
)

$ErrorActionPreference = 'Stop'
function Run-Az([string[]]$argv) {
    $out = & az @argv 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($argv -join ' ') failed: $out" }
    return $out
}

# Network plan: hub 10.10.0.0/16; spokes 10.20, 10.30, 10.40 (in order).
$Plan = @{}
$Plan[$HubRegion] = '10.10.0.0/16'
$idx = 0
foreach ($r in $SpokeRegions) {
    $idx++
    $Plan[$r] = "10.{0}.0.0/16" -f (20 + ($idx-1)*10)
}

Write-Host "=== Subscription: $Subscription"
Run-Az @('account','set','--subscription',$Subscription) | Out-Null

# 1. RG
$rgExists = (& az group exists -n $ResourceGroup) -eq 'true'
if (-not $rgExists) { Run-Az @('group','create','-n',$ResourceGroup,'-l',$HubRegion) | Out-Null }

# 2. Quotas pre-flight
foreach ($r in @($HubRegion) + $SpokeRegions) {
    $j = az vm list-usage -l $r -o json | ConvertFrom-Json
    foreach ($fam in @('standardDSv5Family','StandardDpsv6Family')) {
        $q = $j | Where-Object { $_.name.value -eq $fam }
        if (-not $q) { continue }
        $headroom = $q.limit - $q.currentValue
        if ($headroom -lt 2) {
            throw "Quota in $r for $fam too low (used $($q.currentValue) / $($q.limit))"
        }
    }
    Write-Host "  quota OK in $r"
}

# 3. VNet per region
foreach ($r in $Plan.Keys) {
    $vnet = "vnet-$r"
    $exists = & az network vnet show -g $ResourceGroup -n $vnet --query name -o tsv 2>$null
    if (-not $exists) {
        Run-Az @('network','vnet','create','-g',$ResourceGroup,'-n',$vnet,'-l',$r,
                 '--address-prefixes',$Plan[$r],
                 '--subnet-name','main','--subnet-prefixes',($Plan[$r] -replace '/16','/24')) | Out-Null
    }
}

# 4. Peer hub <-> spokes
$hubVnet = "vnet-$HubRegion"
foreach ($r in $SpokeRegions) {
    $spokeVnet = "vnet-$r"
    $hubId   = (& az network vnet show -g $ResourceGroup -n $hubVnet   --query id -o tsv)
    $spokeId = (& az network vnet show -g $ResourceGroup -n $spokeVnet --query id -o tsv)
    foreach ($p in @(@{a=$hubVnet;b=$spokeVnet;rid=$spokeId},
                     @{a=$spokeVnet;b=$hubVnet;rid=$hubId})) {
        $name = "$($p.a)-to-$($p.b)"
        $ex = & az network vnet peering show -g $ResourceGroup --vnet-name $p.a -n $name --query name -o tsv 2>$null
        if (-not $ex) {
            Run-Az @('network','vnet','peering','create',
                     '-g',$ResourceGroup,'--vnet-name',$p.a,'-n',$name,
                     '--remote-vnet',$p.rid,
                     '--allow-vnet-access') | Out-Null
        }
    }
}

# 5. VMs
function Ensure-Vm($region, $arch) {
    $sz   = if ($arch -eq 'arm64') { $VmSizeArm } else { $VmSizeX64 }
    $imgD = if ($arch -eq 'arm64') { $ImageDefArm } else { $ImageDefX64 }
    $imgId = "/subscriptions/$Subscription/resourceGroups/$GalleryRG/providers/Microsoft.Compute/galleries/$Gallery/images/$imgD/versions/$ImageVersion"
    $name = "perf-$arch-$region"
    $exists = & az vm show -g $ResourceGroup -n $name --query name -o tsv 2>$null
    if ($exists) { Write-Host "  VM $name exists"; return $name }
    Write-Host "  creating VM $name ($sz) in $region"
    Run-Az @('vm','create','-g',$ResourceGroup,'-n',$name,
             '--image', $imgId,
             '--size', $sz, '-l', $region,
             '--admin-username', $AdminUser,
             '--ssh-key-values', "$SshKey.pub",
             '--vnet-name', "vnet-$region", '--subnet','main',
             '--public-ip-sku','Standard',
             '--accelerated-networking','true',
             '--security-type','TrustedLaunch',
             '--enable-secure-boot','true','--enable-vtpm','true',
             '--nsg-rule','SSH') | Out-Null
    return $name
}

$vms = @()
foreach ($r in @($HubRegion) + $SpokeRegions) {
    foreach ($a in @('x86_64','arm64')) {
        $vms += Ensure-Vm $r $a
    }
}

# 6. Inventory
$inv = @{
    Subscription = $Subscription
    ResourceGroup = $ResourceGroup
    ImageVersion  = $ImageVersion
    Hub           = $HubRegion
    Spokes        = $SpokeRegions
    VMs           = $vms
}
$inv | ConvertTo-Json -Depth 5 | Out-File "$PSScriptRoot\..\results\inventory-$ImageVersion.json"
Write-Host ""
Write-Host "=== fleet ready: $($vms.Count) VMs"
Write-Host "Inventory written to results\inventory-$ImageVersion.json"
