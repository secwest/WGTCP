<#
.SYNOPSIS
    Point-to-point WireguardTCP-FAST performance campaign (no hub).

.DESCRIPTION
    Replaces the multi-port hub topology of run-full-campaign.ps1 with a
    flat point-to-point design:
      - 8 pairs (LAN-x64, LAN-arm, MED-*, HIGH-*, MAX-*).
      - Each pair = 2 VMs (A in canadacentral, B in peer region).
      - Every VM runs exactly one wg-udp0 + one wg-tcp0 on the default
        WireGuard ports (51820, 51821). No port collision possible.
      - Per-pair /24 tunnel network 10.99.<index>.0/24  (A=.1, B=.2).
      - tc netem loss applied on A's WAN egress (run-cell.sh).
      - Workloads run from B (client) targeting A (server) on tunnel IP
        10.99.<index>.1.

    This sidesteps the topology-related anomaly A1 (cross-region tunnel
    handshake never establishing in v1.0.2 LAN-only campaign) by removing
    the multi-port hub interface entirely.

.PARAMETER Pairs
    Subset of pair IDs to run (default: all 8). Useful for smoke tests.

.PARAMETER LossPercents / RunsPerCell / Workloads / KeepResources /
.PARAMETER SkipDeploy / SkipBootstrap / SkipRun / SkipAggregate
    Same semantics as run-full-campaign.ps1.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup    = "rg-wgtcpbase-p2p",
    [string]$ImageVersionX64  = "1.0.0",
    [string]$ImageVersionArm  = "1.0.0",
    [string]$AdminUser        = "azureuser",
    [string]$ResultsDir       = "",
    [string[]]$Pairs          = @("LAN-x64","LAN-arm","MED-x64","MED-arm","HIGH-x64","HIGH-arm","MAX-x64","MAX-arm"),
    [double[]]$LossPercents   = @(0, 0.5, 1, 2, 3, 5, 10, 20),
    [int]$RunsPerCell         = 3,
    [string[]]$Workloads      = @("short-transfer","long-transfer","web-mix","ssh-interactive"),
    [switch]$KeepResources,
    [switch]$SkipDeploy,
    [switch]$SkipBootstrap,
    [switch]$SkipRun,
    [switch]$SkipAggregate
)

$ErrorActionPreference = "Stop"
$harnessSrc = Join-Path (Split-Path $PSScriptRoot -Parent) "harness"
if (-not $ResultsDir) { $ResultsDir = Join-Path (Split-Path $PSScriptRoot -Parent) "results\baseline-$ImageVersionX64-p2p" }
$null = New-Item -ItemType Directory -Force -Path $ResultsDir

$subId   = "87243d30-26d0-4f86-bd4e-198f8befe9fa"
$gallery = "wireguardtcp_gallery"
$galleryRg = "RG-WIREGUARDTCP-FAST"
$imgX64 = "/subscriptions/$subId/resourceGroups/$galleryRg/providers/Microsoft.Compute/galleries/$gallery/images/wireguardtcp-ubuntu24-tls/versions/$ImageVersionX64"
$imgArm = "/subscriptions/$subId/resourceGroups/$galleryRg/providers/Microsoft.Compute/galleries/$gallery/images/wireguardtcp-ubuntu24-arm64-tls/versions/$ImageVersionArm"

# ---- Pair table: each entry = one isolated 2-VM tunnel ----------------
# Index N -> tunnel /24 at 10.99.N.0/24; A=.1, B=.2.
# Every VM uses default ports (51820 udp, 51821 tcp). No multi-port hub.
$pairTable = @(
    [pscustomobject]@{ Id="LAN-x64";  Tier="LAN";  Arch="x64"; RegionA="canadacentral"; RegionB="canadacentral";    Index=0 }
    [pscustomobject]@{ Id="LAN-arm";  Tier="LAN";  Arch="arm"; RegionA="canadacentral"; RegionB="canadacentral";    Index=1 }
    [pscustomobject]@{ Id="MED-x64";  Tier="MED";  Arch="x64"; RegionA="canadacentral"; RegionB="westus2";          Index=2 }
    [pscustomobject]@{ Id="MED-arm";  Tier="MED";  Arch="arm"; RegionA="canadacentral"; RegionB="westus2";          Index=3 }
    [pscustomobject]@{ Id="HIGH-x64"; Tier="HIGH"; Arch="x64"; RegionA="canadacentral"; RegionB="australiaeast";    Index=4 }
    [pscustomobject]@{ Id="HIGH-arm"; Tier="HIGH"; Arch="arm"; RegionA="canadacentral"; RegionB="australiaeast";    Index=5 }
    [pscustomobject]@{ Id="MAX-x64";  Tier="MAX";  Arch="x64"; RegionA="canadacentral"; RegionB="southafricanorth"; Index=6 }
    [pscustomobject]@{ Id="MAX-arm";  Tier="MAX";  Arch="arm"; RegionA="canadacentral"; RegionB="southafricanorth"; Index=7 }
)
$pairTable = $pairTable | Where-Object { $Pairs -contains $_.Id }
if (-not $pairTable) { throw "No pairs selected." }

# ---- VMs: 2 per pair, A (server) and B (client) ------------------------
$vms = @()
foreach ($p in $pairTable) {
    $tagA = "$($p.Tier.ToLower())-$($p.Arch)-a"
    $tagB = "$($p.Tier.ToLower())-$($p.Arch)-b"
    $size = if ($p.Arch -eq "x64") { "Standard_D2s_v5" } else { "Standard_D2ps_v6" }
    $img  = if ($p.Arch -eq "x64") { $imgX64 } else { $imgArm }
    $vms += [pscustomobject]@{
        PairId=$p.Id; Role="A"; Index=$p.Index; Tier=$p.Tier; Arch=$p.Arch
        Region=$p.RegionA; Name="vm-$tagA"; Size=$size; Image=$img
        PubIp=""; PrivIp=""; WgPub=""
    }
    $vms += [pscustomobject]@{
        PairId=$p.Id; Role="B"; Index=$p.Index; Tier=$p.Tier; Arch=$p.Arch
        Region=$p.RegionB; Name="vm-$tagB"; Size=$size; Image=$img
        PubIp=""; PrivIp=""; WgPub=""
    }
}

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Sub($msg)  { Write-Host "  - $msg" -ForegroundColor DarkGray }

# ---- SSH keys for orchestrator + perfuser -----------------------------
$keyPath = Join-Path $PSScriptRoot "campaign_id_ed25519"
if (-not (Test-Path $keyPath)) {
    Sub "generating orchestrator ssh key"
    cmd /c "ssh-keygen -t ed25519 -N """" -f ""$keyPath"" -q"
}
$perfKey = Join-Path $PSScriptRoot "perfuser_id_ed25519"
if (-not (Test-Path $perfKey)) {
    cmd /c "ssh-keygen -t ed25519 -N """" -f ""$perfKey"" -q"
}

$sshOpts = @(
    "-i", $keyPath,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-o", "ConnectTimeout=20",
    "-o", "ServerAliveInterval=30"
)

function RunSsh($h, $cmd) {
    & ssh @sshOpts "$AdminUser@$h" $cmd
    if ($LASTEXITCODE) { throw "ssh $h rc=${LASTEXITCODE}: $cmd" }
}
function TrySsh($h, $cmd) { & ssh @sshOpts "$AdminUser@$h" $cmd 2>$null; return ($LASTEXITCODE -eq 0) }
function ScpTo($h, $src, $dst) { & scp @sshOpts -r $src "${AdminUser}@${h}:$dst"; if ($LASTEXITCODE) { throw "scp -> $h failed" } }

function Normalize-LF($dir) {
    Get-ChildItem $dir -Recurse -File -Include *.sh,*.py | ForEach-Object {
        $c = [IO.File]::ReadAllText($_.FullName) -replace "`r`n","`n"
        [IO.File]::WriteAllText($_.FullName, $c, [Text.UTF8Encoding]::new($false))
    }
}
Normalize-LF $harnessSrc

# =========================================================================
# 1. DEPLOY
# =========================================================================
if (-not $SkipDeploy) {
    Step "Deploy: RG + per-region VNets + VMs"
    az group create -n $ResourceGroup -l canadacentral -o none

    $regions = $vms.Region | Sort-Object -Unique
    foreach ($region in $regions) {
        $rsuf = $region -replace '[^a-z0-9]',''
        $vnet = "vnet-$rsuf"
        $nsg  = "nsg-$rsuf"
        Sub "${region}: nsg + vnet"

        az network nsg create -g $ResourceGroup -n $nsg -l $region -o none
        az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-ssh `
            --priority 100 --direction Inbound --access Allow `
            --protocol Tcp --destination-port-ranges 22 -o none

        # Default WG ports only — no multi-port hub. priority 102 to beat NRMS deny.
        az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-wg `
            --priority 102 --direction Inbound --access Allow `
            --protocol "*" --destination-port-ranges 51820-51821 -o none

        az network vnet create -g $ResourceGroup -n $vnet -l $region `
            --address-prefixes 10.50.0.0/16 `
            --subnet-name default --subnet-prefixes 10.50.0.0/24 `
            --network-security-group $nsg -o none
    }

    foreach ($vm in $vms) {
        $rsuf = $vm.Region -replace '[^a-z0-9]',''
        Sub "create $($vm.Name) in $($vm.Region) ($($vm.Size))"
        az vm create -g $ResourceGroup -n $vm.Name -l $vm.Region `
            --image $vm.Image --size $vm.Size `
            --admin-username $AdminUser `
            --ssh-key-values "$keyPath.pub" `
            --vnet-name "vnet-$rsuf" --subnet default `
            --public-ip-sku Standard `
            --accelerated-networking true `
            --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true `
            --no-wait -o none
    }

    Sub "waiting for VMs..."
    foreach ($vm in $vms) { az vm wait -g $ResourceGroup -n $vm.Name --created -o none }

    # Per-VM NIC NSGs auto-created by az vm create — patch them too.
    Sub "patching per-VM NSGs (allow-wg)"
    foreach ($vm in $vms) {
        $vmNsg = "$($vm.Name)NSG"
        az network nsg rule create -g $ResourceGroup --nsg-name $vmNsg -n allow-wg `
            --priority 102 --direction Inbound --access Allow `
            --protocol "*" --destination-port-ranges 51820-51821 -o none 2>$null
    }
}

Step "Discover IPs"
foreach ($vm in $vms) {
    $vm.PubIp  = az vm show -d -g $ResourceGroup -n $vm.Name --query publicIps  -o tsv
    $vm.PrivIp = az vm show -d -g $ResourceGroup -n $vm.Name --query privateIps -o tsv
    Sub "$($vm.Name) [$($vm.PairId)/$($vm.Role)] pub=$($vm.PubIp) priv=$($vm.PrivIp)"
}

# Persist inventory.
$inv = [pscustomobject]@{
    ResourceGroup = $ResourceGroup
    Topology      = "point-to-point"
    ImageX64      = $ImageVersionX64
    ImageArm      = $ImageVersionArm
    Pairs         = $pairTable
    VMs           = $vms
}
$inv | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 (Join-Path $ResultsDir "inventory.json")

Step "Wait for SSH on every VM"
foreach ($vm in $vms) {
    $ok = $false
    for ($i=0; $i -lt 60; $i++) {
        if (TrySsh $vm.PubIp "echo ready") { $ok = $true; break }
        Start-Sleep 5
    }
    if (-not $ok) { throw "ssh never came up: $($vm.Name) ($($vm.PubIp))" }
    Sub "$($vm.Name) ready"
}

# =========================================================================
# 2. BOOTSTRAP
# =========================================================================
if (-not $SkipBootstrap) {
    Step "Push harness + bootstrap (parallel)"
    $perfPub = (Get-Content "$perfKey.pub" -Raw).Trim()

    foreach ($vm in $vms) {
        Sub "push harness -> $($vm.Name)"
        RunSsh $vm.PubIp "rm -rf /tmp/harness && mkdir -p /tmp/harness"
        ScpTo $vm.PubIp "$harnessSrc\*" "/tmp/harness/"
        RunSsh $vm.PubIp "sudo rm -rf /opt/wgtcp-perf && sudo mv /tmp/harness /opt/wgtcp-perf && sudo chmod -R +x /opt/wgtcp-perf/*.sh /opt/wgtcp-perf/workloads/*.sh"
    }

    $jobs = @()
    foreach ($vm in $vms) {
        $vmCopy = $vm
        $script = if ($vm.Role -eq "A") { "bootstrap-server.sh" } else { "bootstrap-client.sh" }
        $jobs += Start-ThreadJob -ThrottleLimit 16 -Name "boot-$($vmCopy.Name)" -ScriptBlock {
            param($ip, $user, $key, $script)
            $opts = @("-i",$key,"-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL","-o","ConnectTimeout=20")
            & ssh @opts "$user@$ip" "sudo /opt/wgtcp-perf/$script" 2>&1
        } -ArgumentList $vmCopy.PubIp, $AdminUser, $keyPath, $script
    }
    Sub "waiting on $(($jobs|Measure).Count) bootstrap jobs..."
    $jobs | Wait-Job | ForEach-Object {
        $out = Receive-Job $_
        if ($_.State -ne "Completed") { Write-Warning "bootstrap $($_.Name) state=$($_.State); tail:`n$($out | Select-Object -Last 20 | Out-String)" }
        else { Sub "$($_.Name) done" }
    }
    $jobs | Remove-Job

    # Inject perfuser pubkey on every A (server) and the client's private key on B (for ssh-interactive workload).
    foreach ($vm in $vms) {
        if ($vm.Role -eq "A") {
            Sub "perfuser authorized_keys -> $($vm.Name)"
            RunSsh $vm.PubIp "echo '$perfPub' | sudo tee /home/perfuser/.ssh/authorized_keys >/dev/null && sudo chown -R perfuser:perfuser /home/perfuser/.ssh && sudo chmod 600 /home/perfuser/.ssh/authorized_keys"
        } else {
            Sub "perfuser private key -> $($vm.Name)"
            ScpTo $vm.PubIp $perfKey "/home/$AdminUser/wgtcp_id_ed25519"
            RunSsh $vm.PubIp "mkdir -p ~/.ssh && mv -f ~/wgtcp_id_ed25519 ~/.ssh/wgtcp_id_ed25519 && chmod 600 ~/.ssh/wgtcp_id_ed25519"
        }
    }

    Step "Generate WG keys"
    foreach ($vm in $vms) {
        RunSsh $vm.PubIp "umask 077; mkdir -p ~/wg && (test -f ~/wg/me.key || (wg genkey | tee ~/wg/me.key | wg pubkey > ~/wg/me.pub))"
        $vm.WgPub = (& ssh @sshOpts "$AdminUser@$($vm.PubIp)" "cat ~/wg/me.pub").Trim()
        Sub "$($vm.Name) wgPub=$($vm.WgPub)"
    }

    Step "Bring up tunnels (point-to-point)"
    foreach ($p in $pairTable) {
        $a = $vms | Where-Object { $_.PairId -eq $p.Id -and $_.Role -eq "A" }
        $b = $vms | Where-Object { $_.PairId -eq $p.Id -and $_.Role -eq "B" }
        $idx = $p.Index
        $aTunIp = "10.99.${idx}.1"
        $bTunIp = "10.99.${idx}.2"

        # LAN: peer over private IP. Cross-region: peer over public IP.
        $aEndpoint = if ($p.Tier -eq "LAN") { $a.PrivIp } else { $a.PubIp }
        $bEndpoint = if ($p.Tier -eq "LAN") { $b.PrivIp } else { $b.PubIp }

        Sub "pair $($p.Id) idx=$idx A=$($a.Name)($aTunIp) B=$($b.Name)($bTunIp) tier=$($p.Tier)"

        $aCmd = "sudo /opt/wgtcp-perf/setup-tunnel.sh --role server " +
                "--my-priv-key /home/$AdminUser/wg/me.key " +
                "--peer-pub-key '$($b.WgPub)' " +
                "--peer-host '$bEndpoint' " +
                "--my-tunnel-ip $aTunIp --peer-tunnel-ip $bTunIp " +
                "--udp-iface wg-udp0 --tcp-iface wg-tcp0 " +
                "--my-udp-port 51820 --my-tcp-port 51821 " +
                "--peer-udp-port 51820 --peer-tcp-port 51821 " +
                "--tunnel-cidr 24"
        RunSsh $a.PubIp $aCmd

        $bCmd = "sudo /opt/wgtcp-perf/setup-tunnel.sh --role client " +
                "--my-priv-key /home/$AdminUser/wg/me.key " +
                "--peer-pub-key '$($a.WgPub)' " +
                "--peer-host '$aEndpoint' " +
                "--my-tunnel-ip $bTunIp --peer-tunnel-ip $aTunIp " +
                "--udp-iface wg-udp0 --tcp-iface wg-tcp0 " +
                "--my-udp-port 51820 --my-tcp-port 51821 " +
                "--peer-udp-port 51820 --peer-tcp-port 51821 " +
                "--tunnel-cidr 24"
        RunSsh $b.PubIp $bCmd
    }

    Sub "tunnel ping checks (best-effort)"
    foreach ($p in $pairTable) {
        $b = $vms | Where-Object { $_.PairId -eq $p.Id -and $_.Role -eq "B" }
        $aTunIp = "10.99.$($p.Index).1"
        $r = & ssh @sshOpts "$AdminUser@$($b.PubIp)" "ping -c 3 -W 5 $aTunIp 2>&1 | tail -1" 2>&1
        Sub "$($p.Id): B->A ($aTunIp) -> $r"
    }
}

# =========================================================================
# 3. RUN MATRIX (one ThreadJob per pair B-side; cells iterate inside)
# =========================================================================
if (-not $SkipRun) {
    Step "Run matrix per pair (parallel)"
    $cellsRoot = Join-Path $ResultsDir "cells"
    $null = New-Item -ItemType Directory -Force -Path $cellsRoot

    $jobs = @()
    foreach ($p in $pairTable) {
        $b = $vms | Where-Object { $_.PairId -eq $p.Id -and $_.Role -eq "B" }
        $bIp       = $b.PubIp
        $aTunIp    = "10.99.$($p.Index).1"
        $pairId    = $p.Id
        $localOut  = Join-Path $cellsRoot $pairId
        $null      = New-Item -ItemType Directory -Force -Path $localOut

        $jobs += Start-ThreadJob -ThrottleLimit 16 -Name "run-$pairId" -ScriptBlock {
            param($ip, $user, $key, $aTunIp, $pairId, $localOut, $loss, $runs, $workloads)
            $opts = @("-i",$key,"-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL","-o","ConnectTimeout=20","-o","ServerAliveInterval=30")
            $log = Join-Path $localOut "run.log"
            "[$pairId] start $(Get-Date -Format o)" | Out-File $log -Encoding utf8
            foreach ($tun in @("wireguard-udp","wireguard-tcp-base")) {
                foreach ($wl in $workloads) {
                    foreach ($l in $loss) {
                        for ($r = 1; $r -le $runs; $r++) {
                            $cellId = "${tun}_${wl}_loss${l}_run${r}"
                            $remoteOut = "/var/tmp/cell-$cellId"
                            "[$pairId] cell $cellId" | Out-File $log -Append -Encoding utf8
                            & ssh @opts "$user@$ip" "sudo rm -rf $remoteOut && sudo /opt/wgtcp-perf/run-cell.sh --server-ip $aTunIp --tunnel $tun --workload $wl --loss-pct $l --run-index $r --out-dir $remoteOut" 2>&1 |
                                Out-File $log -Append -Encoding utf8
                            $rc = $LASTEXITCODE
                            $cellLocal = Join-Path $localOut $cellId
                            New-Item -ItemType Directory -Force -Path $cellLocal | Out-Null
                            & scp @opts -r "${user}@${ip}:$remoteOut/." $cellLocal 2>&1 | Out-File $log -Append -Encoding utf8
                            "[$pairId] $cellId rc=$rc" | Out-File $log -Append -Encoding utf8
                        }
                    }
                }
            }
            "[$pairId] done $(Get-Date -Format o)" | Out-File $log -Append -Encoding utf8
        } -ArgumentList $bIp, $AdminUser, $keyPath, $aTunIp, $pairId, $localOut, $LossPercents, $RunsPerCell, $Workloads
    }
    Sub "matrix jobs running: $(($jobs|Measure).Count)"
    Sub "tail any pair: Get-Content $cellsRoot\<pair>\run.log -Wait"
    $jobs | Wait-Job | ForEach-Object {
        if ($_.State -ne "Completed") { Write-Warning "run job $($_.Name) state=$($_.State)" }
        else { Sub "$($_.Name) complete" }
        Receive-Job $_ | Out-Null
    } | Out-Null
    $jobs | Remove-Job
}

# =========================================================================
# 4. AGGREGATE
# =========================================================================
if (-not $SkipAggregate) {
    Step "Aggregate matrix.csv"
    $cellsRoot = Join-Path $ResultsDir "cells"
    $matrix    = Join-Path $ResultsDir "matrix.csv"
    & python "$harnessSrc\aggregate.py" $cellsRoot -o $matrix 2>&1
    Sub "matrix -> $matrix"
    if (Test-Path $matrix) {
        $rows = (Get-Content $matrix).Count - 1
        Sub "rows: $rows"
    }
}

# =========================================================================
# 5. TEARDOWN
# =========================================================================
if (-not $KeepResources) {
    Step "Teardown (no-wait)"
    az group delete -n $ResourceGroup --yes --no-wait
} else {
    Write-Host "`nKeepResources set; manual teardown:`n  az group delete -n $ResourceGroup --yes --no-wait" -ForegroundColor Yellow
}

Write-Host "`nCampaign complete. Results: $ResultsDir" -ForegroundColor Green
