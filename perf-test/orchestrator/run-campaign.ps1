<#
.SYNOPSIS
  Walks the test matrix, executing run-cell.sh on each VM pair in parallel.

.DESCRIPTION
  Reads the inventory JSON written by deploy-fleet.ps1, generates the
  full cell list (per TESTPLAN.md §3), and dispatches cells to VM pairs
  via ssh. Each spoke VM pairs with its same-arch hub VM; LAN cells use
  hub-x64<->hub-arm to provide a same-region pair.

  Each cell takes ~90s; pairs run in parallel so wall-time = (#cells per pair)
  * 90s.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $InventoryFile,
    [Parameter(Mandatory)] [string] $ResultsDir,
    [string] $SshKey       = "$env:USERPROFILE\.ssh\wgtcp_id_ed25519",
    [string] $AdminUser    = 'azureuser',
    [int] $RunsPerCell     = 3,
    [double[]] $LossLevels = @(0, 0.5, 1, 2, 3, 5, 10, 20),
    [string[]] $Workloads  = @('short-transfer','long-transfer','web-mix','ssh-interactive'),
    [string[]] $Tunnels    = @('wireguard-udp','wireguard-tcp-fast'),
    [switch] $IncludeBaseline,
    [int] $MaxParallelPairs = 8
)

$ErrorActionPreference = 'Stop'
$inv = Get-Content $InventoryFile -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path "$ResultsDir\cells" | Out-Null

# Build pair list (same-arch peers between hub and each spoke + LAN intra-hub pair)
$pairs = @()
foreach ($a in @('x86_64','arm64')) {
    $hub  = "perf-$a-$($inv.Hub)"
    foreach ($s in $inv.Spokes) {
        $spoke = "perf-$a-$s"
        $pairs += [pscustomobject]@{
            Pair   = "$($inv.Hub)-$s-$a"
            Client = $hub
            Server = $spoke
            Region = "$($inv.Hub)<->$s"
        }
    }
}
# LAN pair: hub x64 <-> hub arm (cross-arch but same region; documented as LAN)
$pairs += [pscustomobject]@{
    Pair   = "$($inv.Hub)-LAN-x64arm"
    Client = "perf-x86_64-$($inv.Hub)"
    Server = "perf-arm64-$($inv.Hub)"
    Region = "$($inv.Hub)<->$($inv.Hub)"
}

Write-Host "=== Pairs: $($pairs.Count)"
$pairs | Format-Table | Out-String | Write-Host

# Cells per pair
function Build-CellList {
    param($pair)
    $list = @()
    foreach ($t in $Tunnels) { foreach ($w in $Workloads) {
      foreach ($loss in $LossLevels) { for ($r=1; $r -le $RunsPerCell; $r++) {
        $list += [pscustomobject]@{
            Pair    = $pair.Pair
            Client  = $pair.Client
            Server  = $pair.Server
            Tunnel  = $t
            Workload = $w
            Loss    = $loss
            Run     = $r
        }
    }}}}
    if ($IncludeBaseline) {
        foreach ($w in $Workloads) { foreach ($loss in $LossLevels) {
            for ($r=1; $r -le $RunsPerCell; $r++) {
                $list += [pscustomobject]@{
                    Pair=$pair.Pair; Client=$pair.Client; Server=$pair.Server
                    Tunnel='baseline'; Workload=$w; Loss=$loss; Run=$r
                }
            }
        }}
    }
    return $list
}

# Run a pair's worth of cells via a background ssh job.
$jobs = @()
foreach ($p in $pairs) {
    $cellList = Build-CellList $p
    Write-Host "  pair $($p.Pair): $($cellList.Count) cells"

    $jobs += Start-ThreadJob -ThrottleLimit $MaxParallelPairs -ScriptBlock {
        param($p, $cellList, $SshKey, $AdminUser, $ResultsDir)
        $clientIp = (& az vm list-ip-addresses -g $env:WGTCP_RG -n $p.Client `
                       --query '[0].virtualMachine.network.publicIpAddresses[0].ipAddress' `
                       -o tsv)
        $serverIp = (& az vm list-ip-addresses -g $env:WGTCP_RG -n $p.Server `
                       --query '[0].virtualMachine.network.privateIpAddresses[0]' `
                       -o tsv)
        foreach ($c in $cellList) {
            $cellId = "$($p.Pair)-$($c.Tunnel)-$($c.Workload)-loss$($c.Loss)-run$($c.Run)"
            $cellOut = "$ResultsDir\cells\$cellId"
            New-Item -ItemType Directory -Force -Path $cellOut | Out-Null
            $remoteOut = "/var/tmp/cell-$cellId"
            $cmd = "/opt/wgtcp-perf/run-cell.sh --server-ip $serverIp " +
                   "--tunnel $($c.Tunnel) --workload $($c.Workload) " +
                   "--loss-pct $($c.Loss) --run-index $($c.Run) " +
                   "--out-dir $remoteOut"
            ssh -i $SshKey -o StrictHostKeyChecking=no "$AdminUser@$clientIp" $cmd
            scp -i $SshKey -o StrictHostKeyChecking=no -r `
                "${AdminUser}@${clientIp}:$remoteOut/*" $cellOut
        }
    } -ArgumentList $p, $cellList, $SshKey, $AdminUser, $ResultsDir
}

$env:WGTCP_RG = (Split-Path -Leaf $InventoryFile) -replace 'inventory-(.+)\.json','rg-wgtcp-perf'
Write-Host "=== Waiting for $($jobs.Count) parallel pair jobs to complete..."
$jobs | Wait-Job | Receive-Job

Write-Host ""
Write-Host "=== campaign done. Cells written to $ResultsDir\cells"
Write-Host "Next: python harness\aggregate.py $ResultsDir -o $ResultsDir\matrix.csv"
