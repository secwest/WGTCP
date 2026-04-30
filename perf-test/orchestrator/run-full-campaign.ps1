<#
.SYNOPSIS
    Full multi-pair, multi-region WireguardTCP-FAST performance campaign.

.DESCRIPTION
    Provisions one resource group with up to 8 region-pairs (LAN-x64,
    LAN-arm, MED-x64, MED-arm, HIGH-x64, HIGH-arm, MAX-x64, MAX-arm) and
    sweeps the matrix described in TESTPLAN.md.

    Topology:
      cc-x64-A and cc-arm-A are dual-role hubs that terminate the LAN
      partner plus 3 cross-region peers each. Each pair has its own
      tunnel iface name (wg-udp{N}/wg-tcp{N}) and port pair on the hub.
      Spokes always use wg-udp0/wg-tcp0 (they only see one peer).

    Driven from the validated smoke-test pattern:
      deploy -> wait -> bootstrap -> keys -> tunnels -> run cells -> pull -> aggregate.

.PARAMETER Pairs
    Subset of pair IDs to run (default: all 8). Useful for resumption.

.PARAMETER LossPercents
    Override netem loss sweep (default 0,0.5,1,2,3,5,10,20).

.PARAMETER RunsPerCell
    Override repetition count (default 3).

.PARAMETER Workloads
    Subset of workloads (default short-transfer,long-transfer,web-mix,ssh-interactive).

.PARAMETER KeepResources
    Skip teardown so you can poke at the fleet.

.PARAMETER SkipDeploy / SkipBootstrap / SkipRun / SkipAggregate
    Resume into an existing fleet.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup    = "rg-wgtcp-perf",
    [string]$ImageVersionX64  = "1.0.2",
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
$repoRoot   = (Resolve-Path "$PSScriptRoot\..\..").Path
$harnessSrc = Join-Path $repoRoot "perf-test\harness"
if (-not $ResultsDir) { $ResultsDir = Join-Path $repoRoot "perf-test\results\v$ImageVersionX64" }
$null = New-Item -ItemType Directory -Force -Path $ResultsDir

$subId   = "87243d30-26d0-4f86-bd4e-198f8befe9fa"
$gallery = "wireguardtcp_gallery"
$galleryRg = "RG-WIREGUARDTCP-FAST"
$imgX64 = "/subscriptions/$subId/resourceGroups/$galleryRg/providers/Microsoft.Compute/galleries/$gallery/images/wireguardtcp-ubuntu24-tls/versions/$ImageVersionX64"
$imgArm = "/subscriptions/$subId/resourceGroups/$galleryRg/providers/Microsoft.Compute/galleries/$gallery/images/wireguardtcp-ubuntu24-arm64-tls/versions/$ImageVersionArm"

# ---- Pair table: drives every per-pair allocation ---------------------
# Index N -> hub iface wg-udpN/wg-tcpN, hub ports 51820+2N / 51821+2N,
# tunnel /24 at 10.99.N.0/24.
$pairTable = @(
    [pscustomobject]@{ Id="LAN-x64";  Tier="LAN";  Arch="x64"; HubArch="x64"; SpokeRegion="canadacentral";    Index=0 }
    [pscustomobject]@{ Id="MED-x64";  Tier="MED";  Arch="x64"; HubArch="x64"; SpokeRegion="westus3";          Index=1 }
    [pscustomobject]@{ Id="HIGH-x64"; Tier="HIGH"; Arch="x64"; HubArch="x64"; SpokeRegion="australiaeast";    Index=2 }
    [pscustomobject]@{ Id="MAX-x64";  Tier="MAX";  Arch="x64"; HubArch="x64"; SpokeRegion="southafricanorth"; Index=3 }
    [pscustomobject]@{ Id="LAN-arm";  Tier="LAN";  Arch="arm"; HubArch="arm"; SpokeRegion="canadacentral";    Index=0 }
    [pscustomobject]@{ Id="MED-arm";  Tier="MED";  Arch="arm"; HubArch="arm"; SpokeRegion="westus3";          Index=1 }
    [pscustomobject]@{ Id="HIGH-arm"; Tier="HIGH"; Arch="arm"; HubArch="arm"; SpokeRegion="australiaeast";    Index=2 }
    [pscustomobject]@{ Id="MAX-arm";  Tier="MAX";  Arch="arm"; HubArch="arm"; SpokeRegion="southafricanorth"; Index=3 }
)
$pairTable = $pairTable | Where-Object { $Pairs -contains $_.Id }
if (-not $pairTable) { throw "No pairs selected." }

# ---- Hubs: each arch gets one hub in canadacentral --------------------
$hubs = @{}
foreach ($a in ($pairTable.HubArch | Sort-Object -Unique)) {
    $hubs[$a] = [pscustomobject]@{
        Arch     = $a
        Region   = "canadacentral"
        Name     = "cc-${a}-A"
        Size     = if ($a -eq "x64") { "Standard_D2s_v5" } else { "Standard_D2ps_v6" }
        Image    = if ($a -eq "x64") { $imgX64 } else { $imgArm }
        PubIp    = ""
        PrivIp   = ""
        WgPub    = ""
    }
}

# ---- Spokes: one VM per pair (LAN spokes also live in cc) -------------
$spokes = @()
foreach ($p in $pairTable) {
    $name = if ($p.Tier -eq "LAN") { "cc-$($p.Arch)-B" } else { "$($p.SpokeRegion -replace '[^a-z0-9]','')-$($p.Arch)" }
    $spokes += [pscustomobject]@{
        PairId   = $p.Id
        Tier     = $p.Tier
        Arch     = $p.Arch
        Region   = $p.SpokeRegion
        Name     = $name
        Size     = if ($p.Arch -eq "x64") { "Standard_D2s_v5" } else { "Standard_D2ps_v6" }
        Image    = if ($p.Arch -eq "x64") { $imgX64 } else { $imgArm }
        Index    = $p.Index
        Hub      = $hubs[$p.HubArch]
        PubIp    = ""
        PrivIp   = ""
        WgPub    = ""
    }
}

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Sub($msg)  { Write-Host "  - $msg" -ForegroundColor DarkGray }

# ---- SSH key for orchestrator -----------------------------------------
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
function ScpFrom($h, $src, $dst) { & scp @sshOpts -r "${AdminUser}@${h}:$src" $dst 2>$null }

# Normalize LF on every harness script before any scp upload.
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

    $regions = @($hubs.Values.Region) + @($spokes.Region) | Sort-Object -Unique
    foreach ($region in $regions) {
        $rsuf = $region -replace '[^a-z0-9]',''
        $vnet = "vnet-$rsuf"
        $nsg  = "nsg-$rsuf"
        Sub "${region}: nsg + vnet"

        az network nsg create -g $ResourceGroup -n $nsg -l $region -o none
        az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-ssh `
            --priority 100 --direction Inbound --access Allow `
            --protocol Tcp --destination-port-ranges 22 -o none

        # WG ports: 51820..51827 (covers 4 pair indices for both transports).
        az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-wg-udp `
            --priority 200 --direction Inbound --access Allow `
            --protocol Udp --destination-port-ranges 51820-51827 -o none
        az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-wg-tcp `
            --priority 201 --direction Inbound --access Allow `
            --protocol Tcp --destination-port-ranges 51820-51827 -o none

        az network vnet create -g $ResourceGroup -n $vnet -l $region `
            --address-prefixes 10.50.0.0/16 `
            --subnet-name default --subnet-prefixes 10.50.0.0/24 `
            --network-security-group $nsg -o none
    }

    $allVms = @()
    foreach ($h in $hubs.Values) { $allVms += $h }
    foreach ($s in $spokes)      { $allVms += $s }

    foreach ($vm in $allVms) {
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
    foreach ($vm in $allVms) { az vm wait -g $ResourceGroup -n $vm.Name --created -o none }
}

Step "Discover IPs"
foreach ($vm in @($hubs.Values) + $spokes) {
    $vm.PubIp  = az vm show -d -g $ResourceGroup -n $vm.Name --query publicIps  -o tsv
    $vm.PrivIp = az vm show -d -g $ResourceGroup -n $vm.Name --query privateIps -o tsv
    Sub "$($vm.Name) pub=$($vm.PubIp) priv=$($vm.PrivIp)"
}

# Persist inventory.
$inv = [pscustomobject]@{
    ResourceGroup = $ResourceGroup
    ImageX64      = $ImageVersionX64
    ImageArm      = $ImageVersionArm
    Hubs          = @($hubs.Values)
    Spokes        = $spokes
    Pairs         = $pairTable
}
$inv | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 (Join-Path $ResultsDir "inventory.json")

Step "Wait for SSH on every VM"
foreach ($vm in @($hubs.Values) + $spokes) {
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

    $hubVms   = @($hubs.Values)
    $allVms   = $hubVms + $spokes
    $perfPub  = (Get-Content "$perfKey.pub" -Raw).Trim()

    # Push harness to every VM (sequential to keep ssh subprocesses sane;
    # bootstrap itself is run in parallel jobs below).
    foreach ($vm in $allVms) {
        Sub "push harness -> $($vm.Name)"
        RunSsh $vm.PubIp "rm -rf /tmp/harness && mkdir -p /tmp/harness"
        ScpTo $vm.PubIp "$harnessSrc\*" "/tmp/harness/"
        RunSsh $vm.PubIp "sudo rm -rf /opt/wgtcp-perf && sudo mv /tmp/harness /opt/wgtcp-perf && sudo chmod -R +x /opt/wgtcp-perf/*.sh /opt/wgtcp-perf/workloads/*.sh"
    }

    # Bootstrap hubs as servers, spokes as clients (parallel).
    $jobs = @()
    foreach ($vm in $hubVms) {
        $vmCopy = $vm
        $jobs += Start-ThreadJob -Name "boot-srv-$($vmCopy.Name)" -ScriptBlock {
            param($ip, $user, $key)
            $opts = @("-i",$key,"-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL","-o","ConnectTimeout=20")
            & ssh @opts "$user@$ip" "sudo /opt/wgtcp-perf/bootstrap-server.sh" 2>&1
        } -ArgumentList $vmCopy.PubIp, $AdminUser, $keyPath
    }
    foreach ($vm in $spokes) {
        $vmCopy = $vm
        $jobs += Start-ThreadJob -Name "boot-cli-$($vmCopy.Name)" -ScriptBlock {
            param($ip, $user, $key)
            $opts = @("-i",$key,"-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL","-o","ConnectTimeout=20")
            & ssh @opts "$user@$ip" "sudo /opt/wgtcp-perf/bootstrap-client.sh" 2>&1
        } -ArgumentList $vmCopy.PubIp, $AdminUser, $keyPath
    }
    Sub "waiting on $(($jobs|Measure).Count) bootstrap jobs..."
    $jobs | Wait-Job | ForEach-Object {
        $out = Receive-Job $_
        if ($_.State -ne "Completed") { Write-Warning "bootstrap $($_.Name) state=$($_.State); tail:`n$($out | Select-Object -Last 20 | Out-String)" }
        else { Sub "$($_.Name) done" }
    }
    $jobs | Remove-Job

    # Inject perfuser key on every hub (for ssh-interactive workload).
    foreach ($vm in $hubVms) {
        Sub "perfuser key -> $($vm.Name)"
        RunSsh $vm.PubIp "echo '$perfPub' | sudo tee /home/perfuser/.ssh/authorized_keys >/dev/null && sudo chown -R perfuser:perfuser /home/perfuser/.ssh && sudo chmod 600 /home/perfuser/.ssh/authorized_keys"
    }
    foreach ($s in $spokes) {
        Sub "perfuser key -> $($s.Name)"
        ScpTo $s.PubIp $perfKey "/home/$AdminUser/wgtcp_id_ed25519"
        RunSsh $s.PubIp "mkdir -p ~/.ssh && mv -f ~/wgtcp_id_ed25519 ~/.ssh/wgtcp_id_ed25519 && chmod 600 ~/.ssh/wgtcp_id_ed25519"
    }

    Step "Generate WG keys"
    foreach ($vm in @($hubs.Values) + $spokes) {
        RunSsh $vm.PubIp "umask 077; mkdir -p ~/wg && (test -f ~/wg/me.key || (wg genkey | tee ~/wg/me.key | wg pubkey > ~/wg/me.pub))"
        $vm.WgPub = (& ssh @sshOpts "$AdminUser@$($vm.PubIp)" "cat ~/wg/me.pub").Trim()
        Sub "$($vm.Name) wgPub=$($vm.WgPub)"
    }

    Step "Bring up tunnels"
    foreach ($s in $spokes) {
        $hub  = $s.Hub
        $idx  = $s.Index
        $hubUdpPort  = 51820 + 2*$idx
        $hubTcpPort  = 51821 + 2*$idx
        $hubTunIp    = "10.99.${idx}.1"
        $spokeTunIp  = "10.99.${idx}.2"

        # Use private IPs for LAN pairs (same VNet) and public IPs for cross-region.
        $hubEndpoint   = if ($s.Tier -eq "LAN") { $hub.PrivIp }   else { $hub.PubIp }
        $spokeEndpoint = if ($s.Tier -eq "LAN") { $s.PrivIp }     else { $s.PubIp }

        Sub "pair $($s.PairId) hub=$($hub.Name) spoke=$($s.Name) idx=$idx ports=$hubUdpPort/$hubTcpPort"

        # Hub side: per-pair iface names + per-pair listen ports.
        $hubCmd = "sudo /opt/wgtcp-perf/setup-tunnel.sh --role server " +
                  "--my-priv-key /home/$AdminUser/wg/me.key " +
                  "--peer-pub-key '$($s.WgPub)' " +
                  "--peer-host '$spokeEndpoint' " +
                  "--my-tunnel-ip $hubTunIp --peer-tunnel-ip $spokeTunIp " +
                  "--udp-iface wg-udp$idx --tcp-iface wg-tcp$idx " +
                  "--my-udp-port $hubUdpPort --my-tcp-port $hubTcpPort " +
                  "--peer-udp-port 51820 --peer-tcp-port 51821 " +
                  "--tunnel-cidr 24"
        RunSsh $hub.PubIp $hubCmd

        # Spoke side: always wg-udp0/wg-tcp0 listening on 51820/51821,
        # endpoint -> hub on per-pair port.
        $spkCmd = "sudo /opt/wgtcp-perf/setup-tunnel.sh --role client " +
                  "--my-priv-key /home/$AdminUser/wg/me.key " +
                  "--peer-pub-key '$($hub.WgPub)' " +
                  "--peer-host '$hubEndpoint' " +
                  "--my-tunnel-ip $spokeTunIp --peer-tunnel-ip $hubTunIp " +
                  "--udp-iface wg-udp0 --tcp-iface wg-tcp0 " +
                  "--my-udp-port 51820 --my-tcp-port 51821 " +
                  "--peer-udp-port $hubUdpPort --peer-tcp-port $hubTcpPort " +
                  "--tunnel-cidr 24"
        RunSsh $s.PubIp $spkCmd
    }

    Sub "tunnel ping checks (best-effort)"
    foreach ($s in $spokes) {
        $hubTunIp = "10.99.$($s.Index).1"
        & ssh @sshOpts "$AdminUser@$($s.PubIp)" "ping -c 2 -W 3 $hubTunIp" 2>&1 | Out-Null
        Sub "$($s.PairId) -> $hubTunIp ping rc=$LASTEXITCODE"
    }
}

# =========================================================================
# 3. RUN MATRIX (one ThreadJob per spoke; cells iterate inside)
# =========================================================================
if (-not $SkipRun) {
    Step "Run matrix per spoke (parallel)"
    $cellsRoot = Join-Path $ResultsDir "cells"
    $null = New-Item -ItemType Directory -Force -Path $cellsRoot

    $jobs = @()
    foreach ($s in $spokes) {
        $spokeIp   = $s.PubIp
        $hubTunIp  = "10.99.$($s.Index).1"
        $pairId    = $s.PairId
        $localOut  = Join-Path $cellsRoot $pairId
        $null      = New-Item -ItemType Directory -Force -Path $localOut

        $jobs += Start-ThreadJob -Name "run-$pairId" -ScriptBlock {
            param($ip, $user, $key, $hubTunIp, $pairId, $localOut, $loss, $runs, $workloads)
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
                            & ssh @opts "$user@$ip" "sudo rm -rf $remoteOut && sudo /opt/wgtcp-perf/run-cell.sh --server-ip $hubTunIp --tunnel $tun --workload $wl --loss-pct $l --run-index $r --out-dir $remoteOut" 2>&1 |
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
        } -ArgumentList $spokeIp, $AdminUser, $keyPath, $hubTunIp, $pairId, $localOut, $LossPercents, $RunsPerCell, $Workloads
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
