<#
.SYNOPSIS
    Deploy and run the isolated TCP-over-TCP meltdown campaign.

.DESCRIPTION
    Controls both existing Linux hosts from this workstation. All SSH and SCP
    operations use one caller-supplied key and pinned known-hosts file. No
    private key or secondary controller credential is copied to either host.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $HostA,
    [Parameter(Mandatory)] [int] $PortA,
    [Parameter(Mandatory)] [string] $HostB,
    [Parameter(Mandatory)] [int] $PortB,
    [Parameter(Mandatory)] [string] $PrivateIpA,
    [Parameter(Mandatory)] [string] $PrivateIpB,
    [Parameter(Mandatory)] [string] $SshKey,
    [Parameter(Mandatory)] [string] $KnownHostsFile,
    [Parameter(Mandatory)] [string] $ResultsDir,
    [string] $AdminUser = "azureuser",
    [string] $ExpectedHostA = "wgtcp-amp-b",
    [string] $ExpectedHostB = "wgtcp-amp-a",
    [string] $RemoteSourceDir = "/home/azureuser/WireguardTCP-build",
    [string] $RemoteResultsDir = "/home/azureuser/wgtcp-meltdown-results",
    [string] $MatrixFile = "",
    [string[]] $Stage = @("calibration", "queue", "boundary"),
    [string[]] $Cell = @(),
    [switch] $PrepareOnly,
    [switch] $SkipPrepare,
    [switch] $DownloadRaw
)

$ErrorActionPreference = "Stop"
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$meltdownRoot = (Resolve-Path "$PSScriptRoot\..").Path
$analyzer = Join-Path $meltdownRoot "harness\analyze.py"
if (-not $MatrixFile) {
    $MatrixFile = Join-Path $meltdownRoot "matrix-screening.csv"
}
$MatrixFile = (Resolve-Path $MatrixFile).Path
$SshKey = (Resolve-Path $SshKey).Path
$KnownHostsFile = (Resolve-Path $KnownHostsFile).Path
$ResultsDir = [IO.Path]::GetFullPath($ResultsDir)
$campaignSafetyStopPath = Join-Path $ResultsDir "campaign-safety-stop.json"
if (Test-Path -LiteralPath $campaignSafetyStopPath) {
    throw "campaign directory has an immutable safety-stop latch; investigate and use a fresh directory"
}
$null = New-Item -ItemType Directory -Force -Path (Join-Path $ResultsDir "cells")
$isolatedSshConfig = Join-Path $ResultsDir ".ssh-config"
$emptyGlobalKnownHosts = Join-Path $ResultsDir ".global-known-hosts"
[IO.File]::WriteAllText($isolatedSshConfig, "", [Text.Encoding]::ASCII)
[IO.File]::WriteAllText($emptyGlobalKnownHosts, "", [Text.Encoding]::ASCII)

if ($RemoteSourceDir -notmatch "^/[A-Za-z0-9._/-]+$" -or
    $RemoteResultsDir -notmatch "^/[A-Za-z0-9._/-]+$") {
    throw "remote paths contain unsupported characters"
}

$commonSsh = @(
    "-F", $isolatedSshConfig,
    "-i", $SshKey,
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PubkeyAuthentication=yes",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "GSSAPIAuthentication=no",
    "-o", "HostbasedAuthentication=no",
    "-o", "ForwardAgent=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=$KnownHostsFile",
    "-o", "GlobalKnownHostsFile=$emptyGlobalKnownHosts",
    "-o", "VerifyHostKeyDNS=no",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=20",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=20"
)

function ConvertTo-ShellQuoted {
    param([Parameter(Mandatory)] [string] $Value)
    return "'" + $Value.Replace("'", "'\''") + "'"
}

function Get-IperfServerVerificationCommand {
    param(
        [Parameter(Mandatory)] [string] $UnitName,
        [Parameter(Mandatory)] [string] $IperfHash
    )
    if ($UnitName -notmatch "^[A-Za-z0-9_.@-]+\.service$" -or
        $IperfHash -notmatch "^[A-Fa-f0-9]{64}$") {
        throw "invalid iperf server verification identity"
    }
    $unit = ConvertTo-ShellQuoted $UnitName
    $hash = ConvertTo-ShellQuoted $IperfHash
    return (
        "set -e; sudo systemctl restart $unit; " +
        "systemctl is-active --quiet $unit; " +
        "pid=`$(systemctl show -p MainPID --value $unit); " +
        "test `"`$pid`" -gt 0; " +
        "test `"`$(sudo readlink -f /proc/`$pid/exe)`" = " +
        "`"`$(readlink -f /usr/bin/iperf3)`"; " +
        "test `"`$(sudo sha256sum /proc/`$pid/exe | awk '{print `$1}')`" = $hash"
    )
}

function Get-EndpointIdentityVerificationCommand {
    param(
        [Parameter(Mandatory)] [string] $ExpectedHostname,
        [Parameter(Mandatory)] [string] $PrivateIp
    )
    if ($ExpectedHostname -notmatch "^[a-z0-9-]+$" -or
        $PrivateIp -notmatch "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") {
        throw "invalid endpoint identity"
    }
    $hostname = ConvertTo-ShellQuoted $ExpectedHostname
    $private = ConvertTo-ShellQuoted $PrivateIp
    return (
        "set -e; hostname | grep -Fxq $hostname; " +
        "ip -4 -o addr show dev eth0 | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $private"
    )
}

function Get-TopologyVerificationCommand {
    param(
        [Parameter(Mandatory)] [string] $PrivateIp,
        [Parameter(Mandatory)] [string] $LocalTcpIp,
        [Parameter(Mandatory)] [string] $PeerTcpIp,
        [Parameter(Mandatory)] [string] $LocalUdpIp,
        [Parameter(Mandatory)] [string] $PeerUdpIp
    )
    $values = @($PrivateIp, $LocalTcpIp, $PeerTcpIp, $LocalUdpIp, $PeerUdpIp)
    if ($values.Where({ $_ -notmatch "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" }).Count) {
        throw "invalid topology address"
    }
    $private = ConvertTo-ShellQuoted $PrivateIp
    $localTcp = ConvertTo-ShellQuoted $LocalTcpIp
    $peerTcp = ConvertTo-ShellQuoted $PeerTcpIp
    $localUdp = ConvertTo-ShellQuoted $LocalUdpIp
    $peerUdp = ConvertTo-ShellQuoted $PeerUdpIp
    return (
        "set -e; " +
        "ip -4 -o addr show dev eth0 | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $private; " +
        "ip -4 -o addr show dev wg-mt-tcp | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $localTcp; " +
        "! ip -4 -o addr show dev wg-mt-tcp | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $peerTcp; " +
        "ip -4 -o addr show dev wg-mt-udp | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $localUdp; " +
        "! ip -4 -o addr show dev wg-mt-udp | awk '{print `$4}' | cut -d/ -f1 | " +
        "grep -Fxq $peerUdp"
    )
}

function Invoke-Remote {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Command
    )
    $output = & ssh @commonSsh -p $Port "$AdminUser@$HostName" $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ssh failed on port ${Port}: $($output | Out-String)"
    }
    return $output
}

function Invoke-RemoteSafe {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Command
    )
    & ssh @commonSsh -p $Port "$AdminUser@$HostName" $Command *> $null
}

function Test-Remote {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Command
    )
    & ssh @commonSsh -p $Port "$AdminUser@$HostName" $Command *> $null
    return $LASTEXITCODE -eq 0
}

function Copy-ToRemote {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination
    )
    & scp @commonSsh -P $Port $Source "${AdminUser}@${HostName}:$Destination"
    if ($LASTEXITCODE -ne 0) {
        throw "scp upload failed on port $Port"
    }
}

function Copy-FromRemote {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination
    )
    $null = New-Item -ItemType Directory -Force -Path $Destination
    & scp @commonSsh -P $Port -r "${AdminUser}@${HostName}:$Source" $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "scp download failed on port $Port"
    }
}

function Write-CampaignLog {
    param([Parameter(Mandatory)] [string] $Message)
    $line = "$(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ') $Message"
    $line | Tee-Object -FilePath (Join-Path $ResultsDir "campaign.log") -Append
}

function Write-CampaignStatus {
    param(
        [Parameter(Mandatory)] [string] $Status,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $ExpectedCells,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $MatrixExpectedCells,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $FailedCells,
        [Parameter(Mandatory)] [string] $CampaignFingerprint,
        [Parameter(Mandatory)] [hashtable] $CellFingerprints
    )
    $targetedSelection = @(
        Compare-Object -ReferenceObject $MatrixExpectedCells -DifferenceObject $ExpectedCells
    ).Count -gt 0
    $completedCells = @(
        $ExpectedCells | Where-Object {
            $cell = Join-Path (Join-Path $ResultsDir "cells") $_
            $fingerprintPath = Join-Path $cell "cell.fingerprint"
            (Test-Path (Join-Path $cell "cell.json")) -and
                (Test-Path (Join-Path $cell "cell.complete")) -and
                (Test-Path $fingerprintPath) -and
                ((Get-Content $fingerprintPath -Raw).Trim() -eq $CellFingerprints[$_])
        }
    )
    $document = [ordered]@{
        status = $Status
        updated_at = (Get-Date -AsUTC -Format "o")
        expected_cells = @($ExpectedCells)
        matrix_expected_cells = @($MatrixExpectedCells)
        targeted_selection = $targetedSelection
        qualifying_complete = $Status -eq "complete" -and -not $targetedSelection
        completed_cells = @($completedCells)
        failed_cells = @($FailedCells)
        campaign_fingerprint = $CampaignFingerprint
        cell_fingerprints = $CellFingerprints
    } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(
        (Join-Path $ResultsDir "campaign-status.json"),
        $document + [Environment]::NewLine,
        $Utf8NoBom
    )
}

function Get-CellSafetyStopReasons {
    param([Parameter(Mandatory)] [string] $CellJson)
    $document = $CellJson | ConvertFrom-Json -Depth 100
    return @(
        $document.invalid_reasons | Where-Object {
            $_ -in @(
                "baseline_preflight",
                "kernel_anomaly",
                "timed_impairment",
                "unstable_tcp_carriers"
            )
        }
    )
}

function Write-CampaignSafetyStop {
    param(
        [Parameter(Mandatory)] [string] $CellId,
        [Parameter(Mandatory)] [string[]] $Reasons,
        [Parameter(Mandatory)] [string] $CampaignFingerprint
    )
    if (Test-Path -LiteralPath $campaignSafetyStopPath) {
        throw "campaign safety-stop latch already exists"
    }
    $document = [ordered]@{
        status = "safety_stopped"
        stopped_at = (Get-Date -AsUTC -Format "o")
        cell_id = $CellId
        reasons = @($Reasons)
        campaign_fingerprint = $CampaignFingerprint
    } | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText(
        $campaignSafetyStopPath,
        $document + [Environment]::NewLine,
        $Utf8NoBom
    )
}

function Test-OrderedStringArrayEqual {
    param(
        [AllowEmptyCollection()] [object[]] $Left,
        [AllowEmptyCollection()] [object[]] $Right
    )
    if ($Left.Count -ne $Right.Count) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ([string]$Left[$index] -cne [string]$Right[$index]) {
            return $false
        }
    }
    return $true
}

function Assert-ExistingCampaignIdentity {
    param(
        [Parameter(Mandatory)] [string] $CampaignFingerprint,
        [Parameter(Mandatory)] [string[]] $ExpectedCells,
        [Parameter(Mandatory)] [string[]] $MatrixExpectedCells,
        [Parameter(Mandatory)] [hashtable] $CellFingerprints
    )
    $statusPath = Join-Path $ResultsDir "campaign-status.json"
    $existingCellDirectories = @(
        Get-ChildItem (Join-Path $ResultsDir "cells") -Directory -ErrorAction SilentlyContinue
    )
    if (-not (Test-Path -LiteralPath $statusPath)) {
        if ($existingCellDirectories.Count -gt 0) {
            throw "existing cell artifacts lack a campaign manifest; use a fresh directory"
        }
        return $null
    }

    try {
        $existing = Get-Content $statusPath -Raw | ConvertFrom-Json -Depth 100
    } catch {
        throw "existing campaign manifest is unreadable; use a fresh directory"
    }
    if ($existing.status -notin @("running", "ready", "analysis_failed")) {
        throw "existing campaign is terminal ($($existing.status)); use a fresh directory"
    }
    if ($existing.campaign_fingerprint -cne $CampaignFingerprint -or
        -not (Test-OrderedStringArrayEqual @($existing.expected_cells) $ExpectedCells) -or
        -not (Test-OrderedStringArrayEqual @($existing.matrix_expected_cells) $MatrixExpectedCells)) {
        throw "existing campaign identity or selection differs; use a fresh directory"
    }

    $existingFingerprints = @($existing.cell_fingerprints.PSObject.Properties)
    if ($existingFingerprints.Count -ne $CellFingerprints.Count) {
        throw "existing campaign cell fingerprints differ; use a fresh directory"
    }
    foreach ($cellId in $CellFingerprints.Keys) {
        $properties = @(
            $existingFingerprints | Where-Object { $_.Name -ceq $cellId }
        )
        if ($properties.Count -ne 1 -or
            [string]$properties[0].Value -cne [string]$CellFingerprints[$cellId]) {
            throw "existing campaign cell fingerprints differ; use a fresh directory"
        }
    }

    $actualCompletedCells = [Collections.Generic.List[string]]::new()
    foreach ($directory in $existingCellDirectories) {
        if (@($ExpectedCells | Where-Object { $_ -ceq $directory.Name }).Count -ne 1) {
            throw "existing campaign contains an unexpected cell directory; use a fresh directory"
        }
        $cellId = $directory.Name
        $cellJsonPath = Join-Path $directory.FullName "cell.json"
        $cellCompletePath = Join-Path $directory.FullName "cell.complete"
        $cellFingerprintPath = Join-Path $directory.FullName "cell.fingerprint"
        $cellEnvPath = Join-Path $directory.FullName "cell.env"
        if (-not (Test-Path -LiteralPath $cellJsonPath) -or
            -not (Test-Path -LiteralPath $cellCompletePath) -or
            -not (Test-Path -LiteralPath $cellFingerprintPath) -or
            -not (Test-Path -LiteralPath $cellEnvPath)) {
            throw "existing campaign contains partial cell evidence; use a fresh directory"
        }

        $expectedCellFingerprint = [string]$CellFingerprints[$cellId]
        if ((Get-Content $cellFingerprintPath -Raw).Trim() -cne $expectedCellFingerprint) {
            throw "existing campaign contains mismatched cell evidence; use a fresh directory"
        }
        $envLines = @(Get-Content $cellEnvPath)
        if (@($envLines | Where-Object {
                    $_ -ceq "campaign_fingerprint=$CampaignFingerprint"
                }).Count -ne 1 -or
            @($envLines | Where-Object {
                    $_ -ceq "cell_fingerprint=$expectedCellFingerprint"
                }).Count -ne 1) {
            throw "existing campaign contains mismatched cell environment evidence; use a fresh directory"
        }
        try {
            $cellDocument = Get-Content $cellJsonPath -Raw | ConvertFrom-Json -Depth 100
        } catch {
            throw "existing campaign contains unreadable cell evidence; use a fresh directory"
        }
        if ([string]$cellDocument.cell_id -cne $cellId -or
            [string]$cellDocument.axes.campaign_fingerprint -cne $CampaignFingerprint -or
            [string]$cellDocument.axes.cell_fingerprint -cne $expectedCellFingerprint) {
            throw "existing campaign contains mismatched analyzed cell evidence; use a fresh directory"
        }
        $actualCompletedCells.Add($cellId)
    }
    $orderedCompletedCells = @(
        $ExpectedCells | Where-Object { $actualCompletedCells.Contains($_) }
    )
    if (-not (Test-OrderedStringArrayEqual @($existing.completed_cells) $orderedCompletedCells)) {
        throw "existing manifest completion state differs from cell evidence; use a fresh directory"
    }

    $seenFailedCells = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($failedCell in @($existing.failed_cells)) {
        if (-not $seenFailedCells.Add([string]$failedCell) -or
            @($ExpectedCells | Where-Object { $_ -ceq [string]$failedCell }).Count -ne 1) {
            throw "existing manifest failed-cell state is invalid; use a fresh directory"
        }
    }
    return $existing
}

function Get-StringSha256 {
    param([Parameter(Mandatory)] [string] $Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return [Convert]::ToHexString($sha256.ComputeHash($bytes)).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-CampaignSourceFingerprint {
    $files = @(
        Get-Item -LiteralPath $PSCommandPath
        Get-Item -LiteralPath $MatrixFile
        Get-Item -LiteralPath (Join-Path $meltdownRoot "TESTPLAN.md")
        Get-ChildItem -LiteralPath (Join-Path $meltdownRoot "harness") -Recurse -File |
            Where-Object {
                $_.Extension -notin @(".pyc", ".pyo") -and
                    $_.FullName -notmatch "[\\/]__pycache__[\\/]"
            }
    ) | Sort-Object -Property FullName -Unique
    $entries = foreach ($file in $files) {
        $relative = [IO.Path]::GetRelativePath($meltdownRoot, $file.FullName)
        "$relative=$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
    }
    $entries += "expected_host_a=$ExpectedHostA"
    $entries += "expected_host_b=$ExpectedHostB"
    $entries += "private_ip_a=$PrivateIpA"
    $entries += "private_ip_b=$PrivateIpB"
    return Get-StringSha256 ($entries -join "`n")
}

function Get-CellFingerprint {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Row,
        [Parameter(Mandatory)] [int] $Repetition,
        [Parameter(Mandatory)] [string] $CampaignFingerprint
    )
    $entries = [Collections.Generic.List[string]]::new()
    $entries.Add("campaign=$CampaignFingerprint")
    $entries.Add("repetition=$Repetition")
    foreach ($property in $Row.PSObject.Properties | Sort-Object -Property Name) {
        $entries.Add("$($property.Name)=$([string]$property.Value)")
    }
    return Get-StringSha256 ($entries -join "`n")
}

function Assert-MatrixValue {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $Pattern
    )
    if ($Value -notmatch $Pattern) {
        throw "invalid matrix value for ${Name}: $Value"
    }
}

function Get-MatrixValue {
    param(
        [Parameter(Mandatory)] [psobject] $Row,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Default
    )
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return $Default
    }
    return [string]$property.Value
}

function Wait-RemoteFiles {
    param(
        [Parameter(Mandatory)] [string] $PathA,
        [Parameter(Mandatory)] [string] $PathB,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $readyA = Test-Remote $HostA $PortA "test -e $(ConvertTo-ShellQuoted $PathA)"
        $readyB = Test-Remote $HostB $PortB "test -e $(ConvertTo-ShellQuoted $PathB)"
        if ($readyA -and $readyB) {
            return
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "remote readiness timeout: $PathA / $PathB"
}

function Wait-RemoteFile {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Remote $HostName $Port "test -e $(ConvertTo-ShellQuoted $Path)") {
            return
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "remote readiness timeout: $Path"
}

function Wait-RemoteNonemptyFile {
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Remote $HostName $Port "test -s $(ConvertTo-ShellQuoted $Path)") {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "remote nonempty-file timeout: $Path"
}

function Invoke-Cell {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Row,
        [Parameter(Mandatory)] [int] $Repetition,
        [Parameter(Mandatory)] [string] $CellFingerprint
    )

    foreach ($field in @("rate_mbps", "rtt_ms", "queue_bdp", "loss_pct",
            "burst_p", "burst_r", "burst_h", "burst_k")) {
        Assert-MatrixValue $field ([string]$Row.$field) "^[0-9]+([.][0-9]+)?$"
    }
    foreach ($field in @("flows", "duration_s", "warmup_s", "competitor")) {
        Assert-MatrixValue $field ([string]$Row.$field) "^[0-9]+$"
    }
    Assert-MatrixValue "stage" $Row.stage "^[A-Za-z0-9_.-]+$"
    Assert-MatrixValue "name" $Row.name "^[A-Za-z0-9_.-]+$"
    Assert-MatrixValue "tunnel" $Row.tunnel "^(tcp|udp)$"
    Assert-MatrixValue "queue_kind" $Row.queue_kind "^(bfifo|fq_codel)$"
    Assert-MatrixValue "loss_model" $Row.loss_model "^(none|random|gemodel)$"
    Assert-MatrixValue "inner_cc" $Row.inner_cc "^(cubic|reno|bbr)$"
    Assert-MatrixValue "direction" $Row.direction "^(forward|reverse|bidir)$"
    $workloadCompletion = [string]$Row.workload_completion
    if ([string]::IsNullOrWhiteSpace($workloadCompletion)) {
        $workloadCompletion = "strict"
    }
    Assert-MatrixValue "workload_completion" $workloadCompletion "^(strict|interval_complete)$"
    $impairmentValidation = [string]$Row.impairment_validation
    if ([string]::IsNullOrWhiteSpace($impairmentValidation)) {
        $impairmentValidation = "strict"
    }
    Assert-MatrixValue "impairment_validation" $impairmentValidation "^(strict|transport_aware)$"
    $impairmentSchedule = Get-MatrixValue $Row "impairment_schedule" "static"
    Assert-MatrixValue "impairment_schedule" $impairmentSchedule "^(static|timed)$"
    $lossEpochStart = Get-MatrixValue $Row "loss_epoch_start_s" ""
    $lossEpochMs = Get-MatrixValue $Row "loss_epoch_ms" ""
    $workloadDuration = Get-MatrixValue $Row "workload_duration_s" ([string]$Row.duration_s)
    Assert-MatrixValue "workload_duration_s" $workloadDuration "^[1-9][0-9]*$"
    if ([int]$workloadDuration -lt [int]$Row.duration_s) {
        throw "workload duration cannot be shorter than scored duration"
    }
    if ($impairmentSchedule -eq "timed") {
        Assert-MatrixValue "loss_epoch_start_s" $lossEpochStart "^[0-9]+([.][0-9]+)?$"
        Assert-MatrixValue "loss_epoch_ms" $lossEpochMs "^[1-9][0-9]*$"
        if ($Row.loss_model -eq "none") {
            throw "timed impairment requires a nonzero loss model"
        }
        if ([int]$Row.competitor -ne 0) {
            throw "timed impairment does not support a competitor flow"
        }
        if ($Row.direction -ne "reverse") {
            throw "timed impairment currently requires reverse traffic"
        }
        $recoverySeconds = [double]$Row.duration_s - [double]$lossEpochStart -
            ([double]$lossEpochMs / 1000.0)
        if ($recoverySeconds -lt 60.0) {
            throw "timed impairment must retain at least 60 seconds of recovery"
        }
        if ([int]$workloadDuration -lt [int]$Row.duration_s + 1) {
            throw "timed impairment requires a one-second unscored guard"
        }
    } elseif ($lossEpochStart -or $lossEpochMs) {
        throw "static impairment cannot declare a loss epoch"
    }

    $cellId = "$($Row.stage)-$($Row.name)-$($Row.tunnel)-r$Repetition"
    $localCell = Join-Path (Join-Path $ResultsDir "cells") $cellId
    $remoteCellA = "$RemoteResultsDir/server/$cellId"
    $remoteCellB = "$RemoteResultsDir/cells/$cellId"
    $safeId = $cellId -replace "[^A-Za-z0-9_.-]", "-"
    $serverUnit = "wgtcp-sample-$safeId-a"
    $clientUnit = "wgtcp-sample-$safeId-b"
    $competitorUnit = "wgtcp-competitor-$safeId"
    $clientWorkloadUnit = "wgtcp-workload-$safeId"
    $serverImpairmentUnit = "wgtcp-impairment-$safeId-a"
    $clientImpairmentUnit = "wgtcp-impairment-$safeId-b"
    $timedSchedulingProperties = @(
        "--property=CPUSchedulingPolicy=fifo",
        "--property=CPUSchedulingPriority=50"
    ) -join " "
    # bpftrace attachment takes 10-15 seconds on the ARM hosts. Keep the qdisc,
    # interface, and socket samplers alive beyond that startup interval.
    $sampleDuration = [int]$workloadDuration + [int]$Row.warmup_s + 30
    $shape = "/opt/wgtcp-meltdown/harness/shape-link.sh"
    $sample = "/opt/wgtcp-meltdown/harness/sample-endpoint.sh"
    $timedImpairment = "/opt/wgtcp-meltdown/harness/timed-impairment.py"
    $serverShaped = $false
    $clientShaped = $false
    $cellJson = $null
    [long]$workloadStartNs = 0
    [long]$scheduledLossStartNs = 0
    [long]$scheduledLossStopNs = 0

    if ($Row.tunnel -eq "tcp") {
        $tunnelInterface = "wg-mt-tcp"
        $targetIp = "10.99.1.1"
    } else {
        $tunnelInterface = "wg-mt-udp"
        $targetIp = "10.99.0.1"
    }

    $activeLossModel = if ($impairmentSchedule -eq "timed") {
        "none"
    } else {
        [string]$Row.loss_model
    }
    $shapeArgs = @(
        "--iface eth0",
        "--rate-mbps $($Row.rate_mbps)",
        "--rtt-ms $($Row.rtt_ms)",
        "--queue-bdp $($Row.queue_bdp)",
        "--queue-kind $($Row.queue_kind)",
        "--loss-model $activeLossModel",
        "--loss-pct $($Row.loss_pct)",
        "--burst-p $($Row.burst_p)",
        "--burst-r $($Row.burst_r)",
        "--burst-h $($Row.burst_h)",
        "--burst-k $($Row.burst_k)"
    ) -join " "

    if (Test-Path -LiteralPath $localCell) {
        throw "local cell artifacts already exist; use a fresh campaign directory"
    }
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $localCell "server")
    Invoke-Remote $HostA $PortA "rm -rf $(ConvertTo-ShellQuoted $remoteCellA); mkdir -p $(ConvertTo-ShellQuoted $remoteCellA)" | Out-Null
    Invoke-Remote $HostB $PortB "rm -rf $(ConvertTo-ShellQuoted $remoteCellB); mkdir -p $(ConvertTo-ShellQuoted $remoteCellB)" | Out-Null

    try {
        if ($impairmentValidation -eq "transport_aware") {
            try {
                Invoke-Remote $HostB $PortB (
                    "ping -I $tunnelInterface -c 10 -i 0.2 -W 2 $targetIp " +
                    "> $(ConvertTo-ShellQuoted "$remoteCellB/preimpairment-ping.txt") 2>&1 || true"
                ) | Out-Null
                Copy-FromRemote $HostB $PortB "$remoteCellB/preimpairment-ping.txt" $localCell
                $baselinePreflight = @(
                    & python $analyzer baseline (Join-Path $localCell "preimpairment-ping.txt") 2>&1
                )
                if ($LASTEXITCODE -ne 0) {
                    throw "validation failed: $($baselinePreflight | Out-String)"
                }
            } catch {
                throw "safety baseline failed: $($_.Exception.Message)"
            }
        }

        try {
            $serverShaped = $true
            $serverShape = Invoke-Remote $HostA $PortA "sudo $shape apply --peer-ip $PrivateIpB $shapeArgs"
            [IO.File]::WriteAllLines(
                (Join-Path $localCell "server-shape-apply.json"),
                [string[]]$serverShape,
                $Utf8NoBom
            )

            $clientShaped = $true
            $clientShape = Invoke-Remote $HostB $PortB "sudo $shape apply --peer-ip $PrivateIpA $shapeArgs"
            [IO.File]::WriteAllLines(
                (Join-Path $localCell "client-shape-apply.json"),
                [string[]]$clientShape,
                $Utf8NoBom
            )
        } catch {
            throw "safety shaping failed: $($_.Exception.Message)"
        }

        Invoke-Remote $HostB $PortB (
            "ping -I $tunnelInterface -c 10 -i 0.2 -W 2 $targetIp " +
            "> $(ConvertTo-ShellQuoted "$remoteCellB/preflight-ping.txt") 2>&1 || true"
        ) | Out-Null

        try {
            Invoke-Remote $HostA $PortA (
                Get-IperfServerVerificationCommand `
                    "wgtcp-meltdown-iperf-inner.service" $runtimeIperfHash
            ) | Out-Null
            if ([int]$Row.competitor -eq 1) {
                Invoke-Remote $HostA $PortA (
                    Get-IperfServerVerificationCommand `
                        "wgtcp-meltdown-iperf-competitor.service" $runtimeIperfHash
                ) | Out-Null
            }
        } catch {
            throw "safety runtime identity failed: $($_.Exception.Message)"
        }

        Invoke-Remote $HostA $PortA (
            "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $serverUnit) --collect --quiet " +
            "$sample --out $(ConvertTo-ShellQuoted $remoteCellA) --duration $sampleDuration " +
            "--tunnel-iface $tunnelInterface --owner $AdminUser"
        ) | Out-Null
        Invoke-Remote $HostB $PortB (
            "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $clientUnit) --collect --quiet " +
            "$sample --out $(ConvertTo-ShellQuoted "$remoteCellB/client") " +
            "--duration $sampleDuration --tunnel-iface $tunnelInterface --owner $AdminUser"
        ) | Out-Null

        Wait-RemoteFiles "$remoteCellA/ready" "$remoteCellB/client/ready" 30

        if ([int]$Row.competitor -eq 1) {
            $competitorDuration = [int]$Row.duration_s + [int]$Row.warmup_s + 5
            $competitorCommand = (
                "set +e; /usr/bin/iperf3 -c $PrivateIpA -p 5202 -t $competitorDuration -P 1 -C cubic --json " +
                "> $(ConvertTo-ShellQuoted "$remoteCellB/competitor-iperf3.json") " +
                "2> $(ConvertTo-ShellQuoted "$remoteCellB/competitor-iperf3.stderr"); " +
                "rc=`$?; printf '%s\n' `"`$rc`" > " +
                "$(ConvertTo-ShellQuoted "$remoteCellB/competitor.rc"); exit 0"
            )
            Invoke-Remote $HostB $PortB (
                "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $competitorUnit) --collect --quiet " +
                "/bin/bash -c $(ConvertTo-ShellQuoted $competitorCommand)"
            ) | Out-Null
        }

        $directionArgument = switch ($Row.direction) {
            "forward" { "" }
            "reverse" { "-R" }
            "bidir" { "--bidir" }
        }
        $iperfCommand = (
            "set +e; /usr/bin/iperf3 -c $targetIp -p 5201 -t $workloadDuration " +
            "-P $($Row.flows) -O $($Row.warmup_s) -i 0.1 -C $($Row.inner_cc) " +
            "--json --get-server-output $directionArgument " +
            "> $(ConvertTo-ShellQuoted "$remoteCellB/iperf3.json") " +
            "2> $(ConvertTo-ShellQuoted "$remoteCellB/iperf3.stderr"); " +
            "rc=`$?; printf '%s\n' `"`$rc`" > $(ConvertTo-ShellQuoted "$remoteCellB/workload.rc"); exit 0"
        )
        if ($impairmentSchedule -eq "timed") {
            try {
                Invoke-Remote $HostB $PortB (
                "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $clientWorkloadUnit) --collect --quiet " +
                "/bin/bash -c $(ConvertTo-ShellQuoted $iperfCommand)"
                ) | Out-Null
                Wait-RemoteNonemptyFile $HostB $PortB "$remoteCellB/client/first-inner-data.txt" 10
                $firstDataText = [string](
                    Invoke-Remote $HostB $PortB (
                    "awk 'NF {print `$1; exit}' " +
                    "$(ConvertTo-ShellQuoted "$remoteCellB/client/first-inner-data.txt")"
                    ) | Select-Object -Last 1
                )
                $firstDataText = $firstDataText.Trim()
                if ($firstDataText -notmatch "^[0-9]+([.][0-9]+)?$") {
                    throw "could not obtain the receiver first-data timestamp"
                }
                $workloadStartNs = [long][decimal]::Round(
                    [decimal]$firstDataText * 1000000000
                )
                $scheduledLossStartNs = $workloadStartNs + [long][Math]::Round(
                    ([double]$Row.warmup_s + [double]$lossEpochStart) * 1000000000.0
                )
                $scheduledLossStopNs = $scheduledLossStartNs + [long]$lossEpochMs * 1000000L
                $stateMarker = "/run/wgtcp-meltdown/eth0.active"
                $timedArguments = @(
                    "python3 $timedImpairment",
                    "--shape-link $shape",
                    "--iface eth0",
                    "--rtt-ms $($Row.rtt_ms)",
                    "--loss-model $($Row.loss_model)",
                    "--loss-pct $($Row.loss_pct)",
                    "--burst-p $($Row.burst_p)",
                    "--burst-r $($Row.burst_r)",
                    "--burst-h $($Row.burst_h)",
                    "--burst-k $($Row.burst_k)",
                    "--start-ns $scheduledLossStartNs",
                    "--duration-ms $lossEpochMs",
                    "--state-marker $stateMarker"
                ) -join " "
                Invoke-Remote $HostA $PortA (
                "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $serverImpairmentUnit) --collect --quiet " +
                "$timedSchedulingProperties $timedArguments " +
                "--event-log $(ConvertTo-ShellQuoted "$remoteCellA/impairment-events.jsonl") " +
                "--ready-file $(ConvertTo-ShellQuoted "$remoteCellA/impairment-ready") " +
                "--done-file $(ConvertTo-ShellQuoted "$remoteCellA/impairment-done")"
                ) | Out-Null
                Invoke-Remote $HostB $PortB (
                "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $clientImpairmentUnit) --collect --quiet " +
                "$timedSchedulingProperties $timedArguments " +
                "--event-log $(ConvertTo-ShellQuoted "$remoteCellB/client/impairment-events.jsonl") " +
                "--ready-file $(ConvertTo-ShellQuoted "$remoteCellB/client/impairment-ready") " +
                "--done-file $(ConvertTo-ShellQuoted "$remoteCellB/client/impairment-done")"
                ) | Out-Null
                Wait-RemoteFiles "$remoteCellA/impairment-ready" "$remoteCellB/client/impairment-ready" 10
                $transitionTimeout = [int][Math]::Ceiling(
                    [double]$Row.warmup_s + [double]$lossEpochStart +
                    [double]$lossEpochMs / 1000.0 + 10.0
                )
                Wait-RemoteFiles "$remoteCellA/impairment-done" "$remoteCellB/client/impairment-done" $transitionTimeout
                Wait-RemoteFile $HostB $PortB "$remoteCellB/workload.rc" (
                    [int]$workloadDuration + [int]$Row.warmup_s + 30
                )
            } catch {
                throw "safety timed impairment failed: $($_.Exception.Message)"
            }
        } else {
            Invoke-Remote $HostB $PortB $iperfCommand | Out-Null
        }
        if ([int]$Row.competitor -eq 1) {
            Wait-RemoteFile $HostB $PortB "$remoteCellB/competitor.rc" ($competitorDuration + 30)
        }
        Wait-RemoteFiles "$remoteCellA/done" "$remoteCellB/client/done" ($sampleDuration + 30)
        Invoke-RemoteSafe $HostA $PortA "sudo systemctl stop $(ConvertTo-ShellQuoted "$serverUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostB $PortB "sudo systemctl stop $(ConvertTo-ShellQuoted "$clientUnit.service") 2>/dev/null || true"

        Copy-FromRemote $HostB $PortB "$remoteCellB/." $localCell
        Copy-FromRemote $HostA $PortA "$remoteCellA/." (Join-Path $localCell "server")

        $workloadRcPath = Join-Path $localCell "workload.rc"
        $workloadRc = if (Test-Path $workloadRcPath) {
            (Get-Content $workloadRcPath -Raw).Trim()
        } else {
            "missing"
        }
        $competitorRcPath = Join-Path $localCell "competitor.rc"
        $competitorRc = if ([int]$Row.competitor -eq 0) {
            "0"
        } elseif (Test-Path $competitorRcPath) {
            (Get-Content $competitorRcPath -Raw).Trim()
        } else {
            "missing"
        }
        $envLines = @(
            "cell_id=$cellId",
            "tunnel=$($Row.tunnel)",
            "rate_mbps=$($Row.rate_mbps)",
            "rtt_ms=$($Row.rtt_ms)",
            "queue_bdp=$($Row.queue_bdp)",
            "queue_kind=$($Row.queue_kind)",
            "loss_model=$($Row.loss_model)",
            "loss_pct=$($Row.loss_pct)",
            "burst_p=$($Row.burst_p)",
            "burst_r=$($Row.burst_r)",
            "burst_h=$($Row.burst_h)",
            "burst_k=$($Row.burst_k)",
            "flows=$($Row.flows)",
            "duration_s=$($Row.duration_s)",
            "workload_duration_s=$workloadDuration",
            "warmup_s=$($Row.warmup_s)",
            "workload_completion=$workloadCompletion",
            "impairment_validation=$impairmentValidation",
            "impairment_schedule=$impairmentSchedule",
            "loss_epoch_start_s=$lossEpochStart",
            "loss_epoch_ms=$lossEpochMs",
            "scheduled_workload_start_ns=$workloadStartNs",
            "scheduled_loss_start_ns=$scheduledLossStartNs",
            "scheduled_loss_stop_ns=$scheduledLossStopNs",
            "inner_cc=$($Row.inner_cc)",
            "direction=$($Row.direction)",
            "competitor=$($Row.competitor)",
            "competitor_rc=$competitorRc",
            "campaign_fingerprint=$campaignFingerprint",
            "cell_fingerprint=$CellFingerprint",
            "module_srcversion=$runtimeSrcversion",
            "module_sha256=$runtimeModuleHash",
            "tool_sha256=$runtimeToolHash",
            "iperf_version=$runtimeIperfVersion",
            "iperf_sha256=$runtimeIperfHash",
            "workload_rc=$workloadRc"
        )
        [IO.File]::WriteAllLines(
            (Join-Path $localCell "cell.env"),
            $envLines,
            [Text.Encoding]::ASCII
        )

        $cellJson = @(& python $analyzer cell $localCell 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "cell analysis failed: $($cellJson | Out-String)"
        }
    } finally {
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        Invoke-RemoteSafe $HostA $PortA "sudo systemctl stop $(ConvertTo-ShellQuoted "$serverUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostB $PortB "sudo systemctl stop $(ConvertTo-ShellQuoted "$clientUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostB $PortB "sudo systemctl stop $(ConvertTo-ShellQuoted "$competitorUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostB $PortB "sudo systemctl stop $(ConvertTo-ShellQuoted "$clientWorkloadUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostA $PortA "sudo systemctl stop $(ConvertTo-ShellQuoted "$serverImpairmentUnit.service") 2>/dev/null || true"
        Invoke-RemoteSafe $HostB $PortB "sudo systemctl stop $(ConvertTo-ShellQuoted "$clientImpairmentUnit.service") 2>/dev/null || true"
        if ($serverShaped) {
            try {
                Invoke-Remote $HostA $PortA "sudo $shape clear --iface eth0" | Out-Null
            } catch {
                $cleanupFailures.Add("server: $($_.Exception.Message)")
            }
        }
        if ($clientShaped) {
            try {
                Invoke-Remote $HostB $PortB "sudo $shape clear --iface eth0" | Out-Null
            } catch {
                $cleanupFailures.Add("client: $($_.Exception.Message)")
            }
        }
        if ($cleanupFailures.Count -gt 0) {
            throw "shape restoration failed: $($cleanupFailures -join '; ')"
        }
    }
    if ($null -eq $cellJson) {
        throw "cell analysis produced no result"
    }
    [IO.File]::WriteAllLines(
        (Join-Path $localCell "cell.json"),
        [string[]]$cellJson,
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $localCell "cell.fingerprint"),
        $CellFingerprint + [Environment]::NewLine,
        [Text.Encoding]::ASCII
    )
    [IO.File]::WriteAllText(
        (Join-Path $localCell "cell.complete"),
        (Get-Date -AsUTC -Format "o") + [Environment]::NewLine,
        [Text.Encoding]::ASCII
    )
    return ($cellJson -join [Environment]::NewLine)
}

Assert-MatrixValue "ExpectedHostA" $ExpectedHostA "^[A-Za-z0-9.-]+$"
Assert-MatrixValue "ExpectedHostB" $ExpectedHostB "^[A-Za-z0-9.-]+$"
Invoke-Remote $HostA $PortA (
    Get-EndpointIdentityVerificationCommand $ExpectedHostA $PrivateIpA
) | Out-Null
Invoke-Remote $HostB $PortB (
    Get-EndpointIdentityVerificationCommand $ExpectedHostB $PrivateIpB
) | Out-Null

$archive = Join-Path $env:TEMP "wgtcp-meltdown-$PID.tar.gz"
try {
    & tar --exclude="__pycache__" --exclude="*.pyc" --exclude="*.pyo" `
        -czf $archive -C $meltdownRoot harness
    if ($LASTEXITCODE -ne 0) {
        throw "failed to package meltdown harness"
    }

    foreach ($endpoint in @(
        @{ Host = $HostA; Port = $PortA },
        @{ Host = $HostB; Port = $PortB }
    )) {
        Invoke-Remote $endpoint.Host $endpoint.Port "rm -rf /tmp/wgtcp-meltdown; mkdir -p /tmp/wgtcp-meltdown" | Out-Null
        Copy-ToRemote $endpoint.Host $endpoint.Port $archive "/tmp/wgtcp-meltdown/harness.tar.gz"
        Invoke-Remote $endpoint.Host $endpoint.Port (
            "tar -xzf /tmp/wgtcp-meltdown/harness.tar.gz -C /tmp/wgtcp-meltdown; " +
            "chmod +x /tmp/wgtcp-meltdown/harness/*.sh /tmp/wgtcp-meltdown/harness/*.py; " +
            "sudo install -d -m 0755 /opt/wgtcp-meltdown/harness; " +
            "sudo cp -a /tmp/wgtcp-meltdown/harness/. /opt/wgtcp-meltdown/harness/"
        ) | Out-Null
    }

    if (-not $SkipPrepare) {
        $moduleA = @(Invoke-Remote $HostA $PortA "sha256sum $RemoteSourceDir/kernel/wireguard.ko | awk '{print `$1}'")[-1].Trim()
        $moduleB = @(Invoke-Remote $HostB $PortB "sha256sum $RemoteSourceDir/kernel/wireguard.ko | awk '{print `$1}'")[-1].Trim()
        $toolA = @(Invoke-Remote $HostA $PortA "sha256sum $RemoteSourceDir/tools/wg | awk '{print `$1}'")[-1].Trim()
        $toolB = @(Invoke-Remote $HostB $PortB "sha256sum $RemoteSourceDir/tools/wg | awk '{print `$1}'")[-1].Trim()
        if ($moduleA -ne $moduleB -or $toolA -ne $toolB) {
            throw "host build hashes differ"
        }

        Invoke-Remote $HostA $PortA (
            "sudo /tmp/wgtcp-meltdown/harness/install-host.sh " +
            "--source-dir $(ConvertTo-ShellQuoted $RemoteSourceDir) --role server"
        ) | Write-Host
        Invoke-Remote $HostB $PortB (
            "sudo /tmp/wgtcp-meltdown/harness/install-host.sh " +
            "--source-dir $(ConvertTo-ShellQuoted $RemoteSourceDir) --role client"
        ) | Write-Host

        Invoke-Remote $HostA $PortA "sed -i '/wgtcp-meltdown-control/d' ~/.ssh/authorized_keys" | Out-Null
        $pubA = @(
            Invoke-Remote $HostA $PortA "sudo /opt/wgtcp-meltdown/harness/setup-tunnels.sh key"
        )[-1].Trim()
        $pubB = @(
            Invoke-Remote $HostB $PortB "sudo /opt/wgtcp-meltdown/harness/setup-tunnels.sh key"
        )[-1].Trim()
        if ($pubA -notmatch "^[A-Za-z0-9+/]{43}=$" -or
            $pubB -notmatch "^[A-Za-z0-9+/]{43}=$") {
            throw "invalid WireGuard public key output"
        }

        Invoke-Remote $HostA $PortA (
            "sudo /opt/wgtcp-meltdown/harness/setup-tunnels.sh up " +
            "--peer-pub $(ConvertTo-ShellQuoted $pubB) --peer-phys $PrivateIpB " +
            "--local-udp-ip 10.99.0.1 --peer-udp-ip 10.99.0.2 " +
            "--local-tcp-ip 10.99.1.1 --peer-tcp-ip 10.99.1.2 --tcp-role active"
        ) | Out-Null
        Invoke-Remote $HostB $PortB (
            "sudo /opt/wgtcp-meltdown/harness/setup-tunnels.sh up " +
            "--peer-pub $(ConvertTo-ShellQuoted $pubA) --peer-phys $PrivateIpA " +
            "--local-udp-ip 10.99.0.2 --peer-udp-ip 10.99.0.1 " +
            "--local-tcp-ip 10.99.1.2 --peer-tcp-ip 10.99.1.1 --tcp-role active"
        ) | Out-Null

        Invoke-Remote $HostB $PortB (
            "ping -q -I wg-mt-udp -c 3 -i 0.2 -W 2 10.99.0.1 >/dev/null 2>&1 || true; " +
            "ping -q -I wg-mt-tcp -c 3 -i 0.2 -W 2 10.99.1.1 >/dev/null 2>&1 || true; " +
            "ping -q -I wg-mt-udp -c 10 -i 0.1 -W 2 10.99.0.1 | " +
            "grep -Eq ' 0% packet loss' || " +
            "{ echo 'UDP tunnel control failed' >&2; exit 1; }; " +
            "ping -q -I wg-mt-tcp -c 10 -i 0.1 -W 2 10.99.1.1 | " +
            "grep -Eq ' 0% packet loss' || " +
            "{ echo 'TCP tunnel control failed' >&2; exit 1; }"
        ) | Write-Host
    }

    if ($PrepareOnly) {
        Write-Host "Preparation complete; both tunnel controls passed."
        return
    }

    Invoke-Remote $HostA $PortA (
        Get-TopologyVerificationCommand `
            $PrivateIpA "10.99.1.1" "10.99.1.2" "10.99.0.1" "10.99.0.2"
    ) | Out-Null
    Invoke-Remote $HostB $PortB (
        Get-TopologyVerificationCommand `
            $PrivateIpB "10.99.1.2" "10.99.1.1" "10.99.0.2" "10.99.0.1"
    ) | Out-Null

    $loadedSrcA = @(Invoke-Remote $HostA $PortA "cat /sys/module/wireguard/srcversion")[-1].Trim()
    $loadedSrcB = @(Invoke-Remote $HostB $PortB "cat /sys/module/wireguard/srcversion")[-1].Trim()
    $builtSrcA = @(Invoke-Remote $HostA $PortA "modinfo -F srcversion $RemoteSourceDir/kernel/wireguard.ko")[-1].Trim()
    $builtSrcB = @(Invoke-Remote $HostB $PortB "modinfo -F srcversion $RemoteSourceDir/kernel/wireguard.ko")[-1].Trim()
    $runtimeModuleHashA = @(Invoke-Remote $HostA $PortA "sha256sum $RemoteSourceDir/kernel/wireguard.ko | awk '{print `$1}'")[-1].Trim()
    $runtimeModuleHashB = @(Invoke-Remote $HostB $PortB "sha256sum $RemoteSourceDir/kernel/wireguard.ko | awk '{print `$1}'")[-1].Trim()
    $runtimeToolHashA = @(Invoke-Remote $HostA $PortA "sha256sum $RemoteSourceDir/tools/wg | awk '{print `$1}'")[-1].Trim()
    $runtimeToolHashB = @(Invoke-Remote $HostB $PortB "sha256sum $RemoteSourceDir/tools/wg | awk '{print `$1}'")[-1].Trim()
    Invoke-Remote $HostA $PortA (
        "systemctl show -p ExecStart --value wgtcp-meltdown-iperf-inner.service | " +
        "grep -Fq 'path=/usr/bin/iperf3 ;'"
    ) | Out-Null
    $runtimeIperfVersionA = @(Invoke-Remote $HostA $PortA "LC_ALL=C /usr/bin/iperf3 --version 2>/dev/null | head -n 1 | cut -d' ' -f1-2")[-1].Trim()
    $runtimeIperfVersionB = @(Invoke-Remote $HostB $PortB "LC_ALL=C /usr/bin/iperf3 --version 2>/dev/null | head -n 1 | cut -d' ' -f1-2")[-1].Trim()
    $runtimeIperfHashA = @(Invoke-Remote $HostA $PortA "sha256sum /usr/bin/iperf3 | awk '{print `$1}'")[-1].Trim()
    $runtimeIperfHashB = @(Invoke-Remote $HostB $PortB "sha256sum /usr/bin/iperf3 | awk '{print `$1}'")[-1].Trim()
    if ($loadedSrcA -ne $loadedSrcB -or
        $loadedSrcA -ne $builtSrcA -or
        $loadedSrcB -ne $builtSrcB -or
        $runtimeModuleHashA -ne $runtimeModuleHashB -or
        $runtimeToolHashA -ne $runtimeToolHashB -or
        $runtimeIperfVersionA -ne $runtimeIperfVersionB -or
        $runtimeIperfHashA -ne $runtimeIperfHashB) {
        throw "loaded module or host build identities differ"
    }
    if ($loadedSrcA -notmatch "^[A-Fa-f0-9]+$" -or
        $runtimeModuleHashA -notmatch "^[A-Fa-f0-9]{64}$" -or
        $runtimeToolHashA -notmatch "^[A-Fa-f0-9]{64}$" -or
        $runtimeIperfHashA -notmatch "^[A-Fa-f0-9]{64}$" -or
        [string]::IsNullOrWhiteSpace($runtimeIperfVersionA) -or
        $runtimeIperfVersionA.Length -gt 160 -or
        $runtimeIperfVersionA -notmatch "^[ -~]+$") {
        throw "invalid runtime build identity"
    }
    $runtimeSrcversion = $loadedSrcA
    $runtimeModuleHash = $runtimeModuleHashA.ToLowerInvariant()
    $runtimeToolHash = $runtimeToolHashA.ToLowerInvariant()
    $runtimeIperfVersion = $runtimeIperfVersionA
    $runtimeIperfHash = $runtimeIperfHashA.ToLowerInvariant()
    $sourceFingerprint = Get-CampaignSourceFingerprint
    $campaignFingerprint = Get-StringSha256 (
        "source=$sourceFingerprint`n" +
        "module_srcversion=$runtimeSrcversion`n" +
        "module_sha256=$runtimeModuleHash`n" +
        "tool_sha256=$runtimeToolHash`n" +
        "iperf_version=$runtimeIperfVersion`n" +
        "iperf_sha256=$runtimeIperfHash"
    )

    $selectedStages = [Collections.Generic.HashSet[string]]::new(
        [string[]]$Stage,
        [StringComparer]::OrdinalIgnoreCase
    )
    $selectedCells = [Collections.Generic.HashSet[string]]::new(
        [string[]]$Cell,
        [StringComparer]::Ordinal
    )
    $selectedRows = @(
        Import-Csv $MatrixFile | Where-Object {
            $_.enabled -eq "1" -and
                ($selectedStages.Count -eq 0 -or $selectedStages.Contains($_.stage))
        }
    )
    $expectedCells = [Collections.Generic.List[string]]::new()
    $matrixExpectedCells = [Collections.Generic.List[string]]::new()
    $cellFingerprints = @{}
    foreach ($row in $selectedRows) {
        $repetitions = [int]$row.repetitions
        for ($rep = 1; $rep -le $repetitions; $rep++) {
            $cellId = "$($row.stage)-$($row.name)-$($row.tunnel)-r$rep"
            $matrixExpectedCells.Add($cellId)
            if ($selectedCells.Count -gt 0 -and -not $selectedCells.Contains($cellId)) {
                continue
            }
            $expectedCells.Add($cellId)
            $cellFingerprints[$cellId] = Get-CellFingerprint $row $rep $campaignFingerprint
        }
    }
    if ($expectedCells.Count -eq 0) {
        throw "no enabled matrix cells matched the selected stages"
    }
    if ($selectedCells.Count -gt 0 -and $expectedCells.Count -ne $selectedCells.Count) {
        $missingSelection = @(
            $selectedCells | Where-Object { -not $expectedCells.Contains($_) }
        )
        throw "requested cells not found in enabled selected stages: $($missingSelection -join ', ')"
    }

    $existingCampaign = Assert-ExistingCampaignIdentity `
        $campaignFingerprint ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) `
        $cellFingerprints
    $failedCells = [Collections.Generic.List[string]]::new()
    if ($null -ne $existingCampaign) {
        foreach ($failedCell in @($existingCampaign.failed_cells)) {
            $failedCells.Add([string]$failedCell)
        }
    }
    Write-CampaignStatus "running" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
        $campaignFingerprint $cellFingerprints
    foreach ($row in $selectedRows) {
        $repetitions = [int]$row.repetitions
        for ($rep = 1; $rep -le $repetitions; $rep++) {
            $cellId = "$($row.stage)-$($row.name)-$($row.tunnel)-r$rep"
            if ($selectedCells.Count -gt 0 -and -not $selectedCells.Contains($cellId)) {
                continue
            }
            $cellJsonPath = Join-Path (Join-Path (Join-Path $ResultsDir "cells") $cellId) "cell.json"
            $cellDirectory = Split-Path $cellJsonPath
            $cellCompletePath = Join-Path (Split-Path $cellJsonPath) "cell.complete"
            $cellFingerprintPath = Join-Path (Split-Path $cellJsonPath) "cell.fingerprint"
            $fingerprintMatches = (Test-Path $cellFingerprintPath) -and
                ((Get-Content $cellFingerprintPath -Raw).Trim() -eq $cellFingerprints[$cellId])
            if ((Test-Path $cellJsonPath) -and
                (Test-Path $cellCompletePath) -and
                $fingerprintMatches) {
                $safetyStopReasons = @(
                    Get-CellSafetyStopReasons (Get-Content $cellJsonPath -Raw)
                )
                if ($safetyStopReasons.Count -gt 0) {
                    Write-CampaignLog "SAFETY_STOP $cellId $($safetyStopReasons -join ',')"
                    Write-CampaignSafetyStop $cellId ([string[]]$safetyStopReasons) $campaignFingerprint
                    Write-CampaignStatus "safety_stopped" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
                        $campaignFingerprint $cellFingerprints
                    throw "campaign safety stop at $cellId`: $($safetyStopReasons -join ', ')"
                }
                Write-CampaignLog "SKIP $cellId"
                continue
            }
            if (Test-Path -LiteralPath $cellDirectory) {
                throw "existing incomplete or mismatched artifacts for $cellId; use a fresh directory"
            }
            Write-CampaignLog "START $cellId"
            $safetyStopReasons = @()
            try {
                $cellResult = Invoke-Cell $row $rep $cellFingerprints[$cellId]
                Write-Host $cellResult
                Write-CampaignLog "DONE $cellId"
                $safetyStopReasons = @(Get-CellSafetyStopReasons $cellResult)
            } catch {
                Write-CampaignLog "FAILED $cellId $($_.Exception.Message)"
                $failedCells.Add($cellId)
                if ($_.Exception.Message -like "safety baseline failed:*") {
                    $safetyStopReasons = @("baseline_preflight")
                } elseif ($_.Exception.Message -like "safety shaping failed:*") {
                    $safetyStopReasons = @("shape_application")
                } elseif ($_.Exception.Message -like "safety runtime identity failed:*") {
                    $safetyStopReasons = @("runtime_identity")
                } elseif ($_.Exception.Message -like "safety timed impairment failed:*") {
                    $safetyStopReasons = @("timed_impairment")
                } elseif ($_.Exception.Message -like "shape restoration failed:*") {
                    $safetyStopReasons = @("shape_restoration")
                }
            }
            if ($safetyStopReasons.Count -gt 0) {
                Write-CampaignLog "SAFETY_STOP $cellId $($safetyStopReasons -join ',')"
                Write-CampaignSafetyStop $cellId ([string[]]$safetyStopReasons) $campaignFingerprint
                Write-CampaignStatus "safety_stopped" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
                    $campaignFingerprint $cellFingerprints
                throw "campaign safety stop at $cellId`: $($safetyStopReasons -join ', ')"
            }
            Write-CampaignStatus "running" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
                $campaignFingerprint $cellFingerprints
        }
    }

    $missingCells = @(
        $expectedCells | Where-Object {
            $cell = Join-Path (Join-Path $ResultsDir "cells") $_
            $fingerprintPath = Join-Path $cell "cell.fingerprint"
            -not (
                (Test-Path (Join-Path $cell "cell.json")) -and
                (Test-Path (Join-Path $cell "cell.complete")) -and
                (Test-Path $fingerprintPath) -and
                ((Get-Content $fingerprintPath -Raw).Trim() -eq $cellFingerprints[$_])
            )
        }
    )
    if ($failedCells.Count -gt 0 -or $missingCells.Count -gt 0) {
        Write-CampaignStatus "incomplete" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
            $campaignFingerprint $cellFingerprints
        throw "campaign incomplete: failed=$($failedCells.Count), missing=$($missingCells.Count)"
    }

    Write-CampaignStatus "ready" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
        $campaignFingerprint $cellFingerprints
    $campaignOutput = & python $analyzer campaign $ResultsDir `
        --csv (Join-Path $ResultsDir "cells.csv") `
        --report (Join-Path $ResultsDir "REPORT.generated.md") 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-CampaignStatus "analysis_failed" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
            $campaignFingerprint $cellFingerprints
        throw "campaign analysis failed: $($campaignOutput | Out-String)"
    }
    Write-CampaignStatus "complete" ([string[]]$expectedCells) ([string[]]$matrixExpectedCells) ([string[]]$failedCells) `
        $campaignFingerprint $cellFingerprints
    $campaignOutput | Write-Host
} finally {
    Remove-Item $archive -Force -ErrorAction SilentlyContinue
}
