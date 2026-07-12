#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")),
    [string]$ResultsDirectory = (Join-Path $PSScriptRoot "results"),
    [string]$MultipassPath,
    [string]$VmA = "wgtcp-a",
    [string]$VmB = "wgtcp-b",
    [string]$Path0Switch = "WGTCP-Path0",
    [string]$Path1Switch = "WGTCP-Path1",
    [string]$UbuntuImage = "release:24.04",
    [ValidateRange(1, 64)][int]$CpuCount = 4,
    [string]$Memory = "8G",
    [string]$Disk = "60G",
    [switch]$Recreate,
    [switch]$ForceRecreateUnmanaged,
    [switch]$SkipGuestBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$owner = "WireguardTCP tests/hyperv/Provision-HyperV.ps1"
$statePath = Join-Path $ResultsDirectory "provision-state.json"
$networkTemplate = Join-Path $PSScriptRoot "netplan.yaml"

$guests = @(
    [ordered]@{ Name = $VmA; Path0Mac = "52:54:00:10:00:0a"; Path0Address = "10.77.0.10"; Path1Mac = "52:54:00:20:00:0a"; Path1Address = "10.77.1.10" },
    [ordered]@{ Name = $VmB; Path0Mac = "52:54:00:10:00:0b"; Path0Address = "10.77.0.11"; Path1Mac = "52:54:00:20:00:0b"; Path1Address = "10.77.1.11" }
)

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepoRoot
    )
    Write-Verbose ("{0} {1}" -f $FilePath, ($Arguments -join " "))
    Push-Location $WorkingDirectory
    try {
        $output = @(& $FilePath @Arguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
        }
        return $output
    } finally {
        Pop-Location
    }
}

function Invoke-Multipass {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return Invoke-Checked -FilePath $script:Multipass -Arguments $Arguments
}

function Invoke-MultipassExecProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 20
    )
    $stdoutPath = Join-Path $ResultsDirectory ("exec-probe-{0}.stdout.log" -f $Name)
    $stderrPath = Join-Path $ResultsDirectory ("exec-probe-{0}.stderr.log" -f $Name)
    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $script:Multipass `
        -ArgumentList @("exec", $Name, "--", "true") `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit()
            return [ordered]@{ Success = $false; Failure = "probe timed out after $TimeoutSeconds seconds" }
        }
        if ($process.ExitCode -eq 0) {
            return [ordered]@{ Success = $true; Failure = $null }
        }
        $failure = @(
            Get-Content -LiteralPath $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
        ) -join [Environment]::NewLine
        return [ordered]@{ Success = $false; Failure = "exit $($process.ExitCode): $failure" }
    } finally {
        $process.Dispose()
    }
}

function Wait-MultipassExec {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 300
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastFailure = "guest execution did not start"
    do {
        $probe = Invoke-MultipassExecProbe -Name $Name
        if ($probe.Success) {
            return
        }
        $lastFailure = $probe.Failure
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for Multipass exec on '$Name'. Last failure:`n$lastFailure"
}

function Get-MultipassInstances {
    $document = (Invoke-Multipass -Arguments @("list", "--format", "json") | Out-String) | ConvertFrom-Json
    return @($document.list)
}

function Get-MultipassNames {
    return @(Get-MultipassInstances | ForEach-Object { [string]$_.name })
}

function Get-HyperVVmIdentity {
    param([Parameter(Mandatory = $true)][string]$Name)
    $vms = @(Get-VM -Name $Name -ErrorAction SilentlyContinue)
    if ($vms.Count -ne 1 -or [string]$vms[0].Name -cne $Name) {
        throw "Hyper-V did not return exactly the VM '$Name'."
    }
    return [ordered]@{
        Vm = $vms[0]
        HyperVVmId = ([guid]$vms[0].VMId).ToString("D")
    }
}

function Assert-HyperVVmIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedHyperVVmId
    )
    $expected = ([guid]$ExpectedHyperVVmId).ToString("D")
    $identity = Get-HyperVVmIdentity -Name $Name
    if ($identity.HyperVVmId -ne $expected) {
        throw "Hyper-V VM '$Name' has ID '$($identity.HyperVVmId)', not the managed ID '$expected'. Refusing to modify or delete it."
    }
    return $identity
}

function Get-PriorVmIdentities {
    param([AllowNull()][object]$State)
    $identities = [ordered]@{}
    if ($null -eq $State -or
        $null -eq $State.PSObject.Properties["VmIdentities"]) {
        return $identities
    }
    foreach ($record in @($State.VmIdentities)) {
        if ($null -eq $record -or
            $null -eq $record.PSObject.Properties["Name"] -or
            $null -eq $record.PSObject.Properties["HyperVVmId"]) {
            throw "Managed state contains an incomplete VM identity record."
        }
        $name = [string]$record.Name
        if ($name -notin @($VmA, $VmB)) {
            throw "Managed state contains an unexpected VM identity: '$name'."
        }
        if ($identities.Contains($name)) {
            throw "Managed state contains duplicate identity records for '$name'."
        }
        try {
            $identities[$name] = ([guid][string]$record.HyperVVmId).ToString("D")
        } catch {
            throw "Managed state contains an invalid Hyper-V VM ID for '$name'."
        }
    }
    return $identities
}

function ConvertTo-VmIdentityRecords {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Identities)
    return @($guests | Where-Object { $Identities.Contains([string]$_.Name) } | ForEach-Object {
        [ordered]@{
            Name = [string]$_.Name
            HyperVVmId = ([guid][string]$Identities[[string]$_.Name]).ToString("D")
        }
    })
}

function Get-HyperVSwitchIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$AllowMissing
    )
    $switches = @(Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue)
    if ($switches.Count -eq 0 -and $AllowMissing) {
        return $null
    }
    if ($switches.Count -ne 1 -or [string]$switches[0].Name -cne $Name) {
        throw "Hyper-V did not return exactly the switch '$Name'."
    }
    return [ordered]@{
        Switch = $switches[0]
        HyperVSwitchId = ([guid]$switches[0].Id).ToString("D")
    }
}

function Assert-HyperVSwitchIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedHyperVSwitchId
    )
    $expected = ([guid]$ExpectedHyperVSwitchId).ToString("D")
    $identity = Get-HyperVSwitchIdentity -Name $Name
    if ($identity.HyperVSwitchId -ne $expected) {
        throw "Hyper-V switch '$Name' has ID '$($identity.HyperVSwitchId)', not the managed ID '$expected'. Refusing to use it."
    }
    if ([string]$identity.Switch.SwitchType -ne "Private") {
        throw "Managed Hyper-V switch '$Name' is $($identity.Switch.SwitchType), not Private."
    }
    return $identity
}

function Get-PriorSwitchIdentities {
    param([AllowNull()][object]$State)
    $identities = [ordered]@{}
    if ($null -eq $State -or
        $null -eq $State.PSObject.Properties["SwitchIdentities"]) {
        return $identities
    }
    foreach ($record in @($State.SwitchIdentities)) {
        if ($null -eq $record -or
            $null -eq $record.PSObject.Properties["Name"] -or
            $null -eq $record.PSObject.Properties["HyperVSwitchId"]) {
            throw "Managed state contains an incomplete switch identity record."
        }
        $name = [string]$record.Name
        if ($name -notin @($Path0Switch, $Path1Switch)) {
            throw "Managed state contains an unexpected switch identity: '$name'."
        }
        if ($identities.Contains($name)) {
            throw "Managed state contains duplicate switch identity records for '$name'."
        }
        try {
            $identities[$name] = ([guid][string]$record.HyperVSwitchId).ToString("D")
        } catch {
            throw "Managed state contains an invalid Hyper-V switch ID for '$name'."
        }
    }
    return $identities
}

function ConvertTo-SwitchIdentityRecords {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Identities)
    return @(@($Path0Switch, $Path1Switch) | Where-Object { $Identities.Contains($_) } | ForEach-Object {
        [ordered]@{
            Name = $_
            HyperVSwitchId = ([guid][string]$Identities[$_]).ToString("D")
        }
    })
}

function Write-ManagedState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Configuration,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Identities,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$SwitchIdentities,
        [AllowNull()][System.Collections.IDictionary]$Snapshot
    )
    $document = [ordered]@{
        Schema = 2
        Owner = $owner
        UpdatedAt = (Get-Date).ToUniversalTime().ToString("o")
        Status = $Status
        Configuration = $Configuration
        VmIdentities = @(ConvertTo-VmIdentityRecords -Identities $Identities)
        SwitchIdentities = @(ConvertTo-SwitchIdentityRecords -Identities $SwitchIdentities)
    }
    if ($null -ne $Snapshot) {
        $document["Snapshot"] = $Snapshot
    }
    $temporaryPath = "$statePath.tmp"
    $json = $document | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText(
        $temporaryPath, $json + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryPath -Destination $statePath -Force
    return $document
}

function Assert-SafeGuestName {
    param([string]$Name)
    if ($Name -notmatch '^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$') {
        throw "Unsafe Multipass instance name: $Name"
    }
}

function Assert-LegacyPrivateSwitchTopology {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedVmIdentities
    )
    if ($ExpectedVmIdentities.Count -ne $guests.Count) {
        throw "Cannot migrate switch '$Name' without every managed VM identity."
    }
    $adapters = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
        [string]$_.SwitchName -ceq $Name
    })
    if ($adapters.Count -ne $guests.Count) {
        throw "Cannot migrate switch '$Name': expected exactly $($guests.Count) managed adapters, found $($adapters.Count)."
    }
    foreach ($guest in $guests) {
        $vmName = [string]$guest.Name
        if (-not $ExpectedVmIdentities.Contains($vmName)) {
            throw "Cannot migrate switch '$Name' without the managed identity for '$vmName'."
        }
        Assert-HyperVVmIdentity -Name $vmName `
            -ExpectedHyperVVmId ([string]$ExpectedVmIdentities[$vmName]) | Out-Null
        $expectedMac = if ($Name -ceq $Path0Switch) {
            [string]$guest.Path0Mac
        } elseif ($Name -ceq $Path1Switch) {
            [string]$guest.Path1Mac
        } else {
            throw "Refusing to migrate unexpected switch '$Name'."
        }
        $normalizedMac = ($expectedMac -replace '[:-]', '').ToUpperInvariant()
        $matches = @($adapters | Where-Object {
            [string]$_.VMName -ceq $vmName -and
            ([string]$_.MacAddress).ToUpperInvariant() -eq $normalizedMac
        })
        if ($matches.Count -ne 1) {
            throw "Cannot migrate switch '$Name': its adapter for '$vmName' does not uniquely match managed MAC '$expectedMac'."
        }
    }
}

function Ensure-PrivateSwitch {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$ExpectedHyperVSwitchId
    )
    $existing = Get-HyperVSwitchIdentity -Name $Name -AllowMissing
    if ($null -ne $existing) {
        if (-not $ExpectedHyperVSwitchId) {
            throw "Hyper-V switch '$Name' already exists without a persisted managed switch ID. Refusing to adopt it."
        }
        return (Assert-HyperVSwitchIdentity -Name $Name `
            -ExpectedHyperVSwitchId $ExpectedHyperVSwitchId).HyperVSwitchId
    }
    if ($ExpectedHyperVSwitchId) {
        throw "Managed Hyper-V switch '$Name' with ID '$ExpectedHyperVSwitchId' is missing. Refusing to replace it implicitly."
    }
    New-VMSwitch -Name $Name -SwitchType Private | Out-Null
    $created = Get-HyperVSwitchIdentity -Name $Name
    if ([string]$created.Switch.SwitchType -ne "Private") {
        throw "New Hyper-V switch '$Name' is not Private."
    }
    return $created.HyperVSwitchId
}

function Test-GuestNetworkAdapterNeeded {
    param(
        [object[]]$Adapters,
        [string]$Name,
        [string]$SwitchName,
        [string]$MacAddress
    )
    $desiredMac = ($MacAddress -replace '[:-]', '').ToUpperInvariant()
    $macMatches = @($Adapters | Where-Object { [string]$_.MacAddress -eq $desiredMac })
    if ($macMatches.Count -gt 1) {
        throw "VM '$Name' has multiple adapters with managed MAC '$MacAddress'."
    }
    if ($macMatches.Count -eq 1) {
        if ([string]$macMatches[0].SwitchName -ne $SwitchName) {
            throw "VM '$Name' adapter '$MacAddress' is attached to '$($macMatches[0].SwitchName)', not '$SwitchName'."
        }
        return $false
    }

    $switchMatches = @($Adapters | Where-Object { [string]$_.SwitchName -eq $SwitchName })
    if ($switchMatches.Count -gt 0) {
        throw "VM '$Name' already has an unexpected adapter on managed switch '$SwitchName'."
    }
    return $true
}

function Ensure-GuestVmConfiguration {
    param(
        [System.Collections.IDictionary]$Guest,
        [Parameter(Mandatory = $true)][string]$ExpectedHyperVVmId,
        [Parameter(Mandatory = $true)][string]$ExpectedPath0SwitchId,
        [Parameter(Mandatory = $true)][string]$ExpectedPath1SwitchId,
        [switch]$ActivateStagedNetwork
    )
    $Name = [string]$Guest.Name
    if ($Name -notin @($VmA, $VmB)) {
        throw "Refusing to modify unmanaged Hyper-V VM '$Name'."
    }
    $identity = Assert-HyperVVmIdentity -Name $Name -ExpectedHyperVVmId $ExpectedHyperVVmId
    Assert-HyperVSwitchIdentity -Name $Path0Switch `
        -ExpectedHyperVSwitchId $ExpectedPath0SwitchId | Out-Null
    Assert-HyperVSwitchIdentity -Name $Path1Switch `
        -ExpectedHyperVSwitchId $ExpectedPath1SwitchId | Out-Null
    $vm = $identity.Vm
    $firmware = Get-VMFirmware -VM $vm
    $memory = Get-VMMemory -VM $vm
    $needsConfigurationChange = $firmware.SecureBoot -ne "Off" -or $memory.DynamicMemoryEnabled
    $adapters = @(Get-VMNetworkAdapter -VM $vm)
    $adapterPlans = @(
        [ordered]@{ SwitchName = $Path0Switch; MacAddress = [string]$Guest.Path0Mac },
        [ordered]@{ SwitchName = $Path1Switch; MacAddress = [string]$Guest.Path1Mac }
    )
    $neededAdapters = @($adapterPlans | Where-Object {
        Test-GuestNetworkAdapterNeeded -Adapters $adapters -Name $Name `
            -SwitchName $_.SwitchName -MacAddress $_.MacAddress
    })
    if (-not $needsConfigurationChange -and -not $ActivateStagedNetwork -and
        $neededAdapters.Count -eq 0) {
        return
    }

    $wasRunning = $vm.State -eq "Running"
    if ($wasRunning) {
        Invoke-Multipass -Arguments @("stop", "--timeout", "120", $Name) | Out-Null
    }
    try {
        $identity = Assert-HyperVVmIdentity -Name $Name -ExpectedHyperVVmId $ExpectedHyperVVmId
        Assert-HyperVSwitchIdentity -Name $Path0Switch `
            -ExpectedHyperVSwitchId $ExpectedPath0SwitchId | Out-Null
        Assert-HyperVSwitchIdentity -Name $Path1Switch `
            -ExpectedHyperVSwitchId $ExpectedPath1SwitchId | Out-Null
        $vm = $identity.Vm
        if ($needsConfigurationChange) {
            Set-VMFirmware -VM $vm -EnableSecureBoot Off
            Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
        }
        foreach ($plan in $neededAdapters) {
            $staticMac = ($plan.MacAddress -replace '[:-]', '').ToUpperInvariant()
            Add-VMNetworkAdapter -VMName $Name -SwitchName $plan.SwitchName `
                -StaticMacAddress $staticMac | Out-Null
        }
    } finally {
        if ($wasRunning) {
            Invoke-Multipass -Arguments @("start", "--timeout", "120", $Name) | Out-Null
        }
    }
}

function New-GuestNetworkFiles {
    param([System.Collections.IDictionary]$Guest)
    $content = Get-Content -LiteralPath $networkTemplate -Raw
    $tokens = [ordered]@{
        "__PATH0_MAC__" = $Guest.Path0Mac
        "__PATH0_ADDRESS__" = $Guest.Path0Address
        "__PATH1_MAC__" = $Guest.Path1Mac
        "__PATH1_ADDRESS__" = $Guest.Path1Address
    }
    foreach ($token in $tokens.Keys) {
        $content = $content.Replace($token, $tokens[$token])
    }
    if ($content -match '__[A-Z0-9_]+__') {
        throw "Unresolved token in rendered network configuration for '$($Guest.Name)'."
    }

    $netplanPath = Join-Path $ResultsDirectory ("netplan-{0}.yaml" -f $Guest.Name)
    Set-Content -LiteralPath $netplanPath -Value $content -Encoding utf8NoBOM
    $markerPath = Join-Path $ResultsDirectory ("wireguardtcp-lab-{0}" -f $Guest.Name)
    @(
        "managed-by=tests/hyperv/Provision-HyperV.ps1"
        "path0=$($Guest.Path0Address)/24"
        "path1=$($Guest.Path1Address)/24"
    ) | Set-Content -LiteralPath $markerPath -Encoding utf8NoBOM
    return [ordered]@{ Netplan = $netplanPath; Marker = $markerPath }
}

function Write-PathList {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyCollection()][string[]]$Items
    )
    $content = if ($Items.Count -gt 0) { ($Items -join "`n") + "`n" } else { "" }
    [System.IO.File]::WriteAllText(
        $Path, $content, [System.Text.UTF8Encoding]::new($false)
    )
}

function New-SourceSnapshot {
    $snapshotDirectory = Join-Path $ResultsDirectory "snapshot"
    if (Test-Path -LiteralPath $snapshotDirectory) {
        Remove-Item -LiteralPath $snapshotDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $snapshotDirectory | Out-Null

    $head = (Invoke-Checked -FilePath "git.exe" -Arguments @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    $statusBefore = (Invoke-Checked -FilePath "git.exe" -Arguments @("status", "--porcelain=v2", "--branch", "--untracked-files=all") | Out-String).TrimEnd()
    $baseArchive = Join-Path $snapshotDirectory "base.tar"
    Invoke-Checked -FilePath "git.exe" -Arguments @("archive", "--format=tar", "--output=$baseArchive", $head) | Out-Null

    $modified = @(Invoke-Checked -FilePath "git.exe" -Arguments @(
        "-c", "core.safecrlf=false", "diff", "--name-only", "--no-renames",
        "--diff-filter=ACMRTUXB", $head, "--"
    ))
    $untracked = @(Invoke-Checked -FilePath "git.exe" -Arguments @("ls-files", "--others", "--exclude-standard"))
    $overlayPaths = @($modified + $untracked | Where-Object { $_ } | Sort-Object -Unique)
    $overlayList = Join-Path $snapshotDirectory "overlay-files.txt"
    Write-PathList -Path $overlayList -Items $overlayPaths
    $overlayArchive = Join-Path $snapshotDirectory "overlay.tar"
    Invoke-Checked -FilePath "tar.exe" -Arguments @("--format", "pax", "-cf", $overlayArchive, "-T", $overlayList) | Out-Null

    $deleted = @(Invoke-Checked -FilePath "git.exe" -Arguments @(
        "-c", "core.safecrlf=false", "diff", "--name-only", "--no-renames",
        "--diff-filter=D", $head, "--"
    ))
    $deletionsPath = Join-Path $snapshotDirectory "deletions.txt"
    Write-PathList -Path $deletionsPath -Items $deleted
    $statusAfter = (Invoke-Checked -FilePath "git.exe" -Arguments @("status", "--porcelain=v2", "--branch", "--untracked-files=all") | Out-String).TrimEnd()
    if ($statusBefore -ne $statusAfter) {
        throw "The worktree changed while the guest snapshot was being built. Run provisioning again."
    }

    $baseHash = (Get-FileHash -LiteralPath $baseArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $overlayHash = (Get-FileHash -LiteralPath $overlayArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        Schema = 1
        Head = $head
        CreatedAt = (Get-Date).ToUniversalTime().ToString("o")
        GitStatus = $statusBefore
        BaseArchive = "base.tar"
        BaseArchiveSha256 = $baseHash
        OverlayArchive = "overlay.tar"
        OverlayArchiveSha256 = $overlayHash
        Deletions = $deleted
    }
    $manifestPath = Join-Path $snapshotDirectory "snapshot-manifest.json"
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    return [ordered]@{
        Directory = $snapshotDirectory
        Base = $baseArchive
        Overlay = $overlayArchive
        Deletions = $deletionsPath
        Manifest = $manifestPath
        Id = $overlayHash.Substring(0, 12)
        Head = $head
        Status = $statusBefore
        BaseHash = $baseHash
        OverlayHash = $overlayHash
    }
}

function Install-Snapshot {
    param([string]$Name, [System.Collections.IDictionary]$Snapshot)
    $remote = "/home/ubuntu/.wgtcp-transfer-$($Snapshot.Id)"
    Invoke-Multipass -Arguments @("exec", $Name, "--", "mkdir", "-p", $remote) | Out-Null
    foreach ($file in @($Snapshot.Base, $Snapshot.Overlay, $Snapshot.Deletions, $Snapshot.Manifest)) {
        Invoke-Multipass -Arguments @("transfer", $file, "${Name}:$remote/") | Out-Null
    }
    $install = @'
set -euo pipefail
transfer="$1"
snapshot_id="$2"
base_hash="$3"
overlay_hash="$4"
repo=/home/ubuntu/WireguardTCP
stage="/home/ubuntu/.wgtcp-stage-$snapshot_id"
previous=/home/ubuntu/.wgtcp-previous
printf '%s  %s\n%s  %s\n' "$base_hash" "$transfer/base.tar" "$overlay_hash" "$transfer/overlay.tar" | sha256sum -c -
rm -rf -- "$stage"
mkdir -p -- "$stage"
tar -xf "$transfer/base.tar" -C "$stage"
while IFS= read -r relative; do
    [ -z "$relative" ] && continue
    case "$relative" in .|..|/*|../*|*/../*|*/..) echo "unsafe deletion path: $relative" >&2; exit 1;; esac
    rm -rf -- "$stage/$relative"
done < "$transfer/deletions.txt"
tar --unlink-first -xf "$transfer/overlay.tar" -C "$stage"
rm -rf -- "$previous"
if [ -e "$repo" ]; then mv -- "$repo" "$previous"; fi
mv -- "$stage" "$repo"
cp -- "$transfer/snapshot-manifest.json" /home/ubuntu/.wgtcp-current-snapshot.json
'@
    Invoke-Multipass -Arguments @(
        "exec", $Name, "--", "bash", "-c", $install, "snapshot-install",
        $remote, $Snapshot.Id, $Snapshot.BaseHash, $Snapshot.OverlayHash
    ) | Out-Null
}

foreach ($guest in $guests) { Assert-SafeGuestName -Name $guest.Name }
if ($VmA -eq $VmB) { throw "VM names must be distinct." }
if ($ForceRecreateUnmanaged -and -not $Recreate) { throw "-ForceRecreateUnmanaged requires -Recreate." }
if (-not (Test-Path -LiteralPath $networkTemplate -PathType Leaf)) { throw "Missing $networkTemplate" }
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot ".git"))) { throw "RepoRoot is not a Git worktree: $RepoRoot" }
foreach ($requiredCommand in @("git.exe", "tar.exe")) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "Required host command was not found: $requiredCommand"
    }
}
New-Item -ItemType Directory -Force -Path $ResultsDirectory | Out-Null

if (-not $MultipassPath) {
    $command = Get-Command multipass.exe -ErrorAction SilentlyContinue
    if ($command) { $MultipassPath = $command.Source }
}
if (-not $MultipassPath) {
    $MultipassPath = @(
        "$env:ProgramFiles\Multipass\bin\multipass.exe",
        "$env:ProgramFiles\Multipass\multipass.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $MultipassPath -or -not (Test-Path -LiteralPath $MultipassPath -PathType Leaf)) {
    throw "Multipass was not found. Run Enable-HyperV.ps1 and reboot first."
}
$script:Multipass = (Resolve-Path $MultipassPath).Path

$driver = (Invoke-Multipass -Arguments @("get", "local.driver") | Select-Object -First 1).Trim()
if ($driver -ne "hyperv") { throw "Multipass driver is '$driver'; set local.driver=hyperv before provisioning." }

$desired = [ordered]@{
    Owner = $owner
    VmNames = @($VmA, $VmB)
    Switches = @($Path0Switch, $Path1Switch)
    UbuntuImage = $UbuntuImage
    CpuCount = $CpuCount
    Memory = $Memory
    Disk = $Disk
    Guests = $guests
}
$prior = $null
if (Test-Path -LiteralPath $statePath) { $prior = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
$existingNames = @(Get-MultipassNames)
$priorOwnerMatches = $false
$priorUsesLegacyIdentityState = $false
$priorVmNames = @()
$priorSwitchNames = @()
if ($prior) {
    if ($null -eq $prior.PSObject.Properties["Owner"]) {
        throw "Managed state has no Owner field: $statePath"
    }
    $priorOwnerMatches = [string]$prior.Owner -eq $owner
    if ($priorOwnerMatches) {
        if ($null -eq $prior.PSObject.Properties["Configuration"] -or
            $null -eq $prior.Configuration.PSObject.Properties["VmNames"] -or
            $null -eq $prior.Configuration.PSObject.Properties["Switches"]) {
            throw "Managed state has no VM configuration: $statePath"
        }
        $priorVmNames = @($prior.Configuration.VmNames | ForEach-Object { [string]$_ })
        $priorSwitchNames = @($prior.Configuration.Switches | ForEach-Object { [string]$_ })
        $hasSchema = $null -ne $prior.PSObject.Properties["Schema"]
        $hasVmIdentities = $null -ne $prior.PSObject.Properties["VmIdentities"]
        if (-not $hasSchema -and -not $hasVmIdentities) {
            $priorUsesLegacyIdentityState = $true
        } elseif (-not $hasSchema -or -not $hasVmIdentities -or [int]$prior.Schema -ne 2) {
            throw "Managed state has an unsupported or incomplete identity schema: $statePath"
        }
    }
}
$priorIdentities = if ($priorOwnerMatches) {
    Get-PriorVmIdentities -State $prior
} else {
    [ordered]@{}
}
$priorSwitchIdentities = if ($priorOwnerMatches) {
    Get-PriorSwitchIdentities -State $prior
} else {
    [ordered]@{}
}
if (-not $Recreate -and $priorOwnerMatches) {
    $priorConfiguration = $prior.Configuration | ConvertTo-Json -Depth 12 -Compress
    $desiredConfiguration = $desired | ConvertTo-Json -Depth 12 -Compress
    if ($priorConfiguration -ne $desiredConfiguration -and @($existingNames | Where-Object { $_ -in @($VmA, $VmB) }).Count -gt 0) {
        throw "The requested VM configuration differs from the managed state. Use -Recreate to apply it."
    }
}
$vmIdentities = [ordered]@{}
$observedExistingIdentities = [ordered]@{}
foreach ($guest in $guests) {
    $name = [string]$guest.Name
    if ($name -notin $existingNames) { continue }
    $identity = Get-HyperVVmIdentity -Name $name
    $observedExistingIdentities[$name] = $identity.HyperVVmId
    $nameWasManaged = $priorOwnerMatches -and $name -in $priorVmNames
    $hasRecordedIdentity = $nameWasManaged -and $priorIdentities.Contains($name)
    if ($hasRecordedIdentity) {
        $recordedIdentity = [string]$priorIdentities[$name]
        if ($recordedIdentity -eq $identity.HyperVVmId) {
            if (-not $Recreate) {
                $vmIdentities[$name] = $identity.HyperVVmId
            }
            continue
        }
        if (-not $Recreate -or -not $ForceRecreateUnmanaged) {
            throw "Instance '$name' replaced the managed Hyper-V VM ID '$recordedIdentity' with '$($identity.HyperVVmId)'. Refusing to adopt or delete it; use -Recreate -ForceRecreateUnmanaged only after verifying it is disposable."
        }
        Write-Warning "Force recreation will delete replacement VM '$name' with verified ID '$($identity.HyperVVmId)'."
        continue
    }
    if ($nameWasManaged -and $priorUsesLegacyIdentityState -and -not $Recreate) {
        # Legacy state recorded only names. Pin the current ID before any VM changes,
        # but never treat this migration as sufficient authority for deletion.
        Write-Warning "Migrating legacy name-only state for '$name' to Hyper-V VM ID '$($identity.HyperVVmId)'."
        $vmIdentities[$name] = $identity.HyperVVmId
        continue
    }
    if (-not $ForceRecreateUnmanaged) {
        $reason = if ($nameWasManaged -and $priorUsesLegacyIdentityState) {
            "its legacy state has no Hyper-V VM ID"
        } else {
            "it has no matching harness identity"
        }
        throw "Instance '$name' already exists but $reason. Refusing to adopt or delete it. Run once without -Recreate to migrate legacy owned state, or use -Recreate -ForceRecreateUnmanaged only after verifying the VM is disposable."
    }
    Write-Warning "Force recreation will delete unmanaged VM '$name' with verified ID '$($identity.HyperVVmId)'."
}

$switchIdentities = [ordered]@{}
foreach ($name in $priorSwitchIdentities.Keys) {
    $switchIdentities[[string]$name] = [string]$priorSwitchIdentities[$name]
}
$migratedSwitchIdentity = $false
foreach ($name in @($Path0Switch, $Path1Switch)) {
    $live = Get-HyperVSwitchIdentity -Name $name -AllowMissing
    if ($null -eq $live) {
        if ($switchIdentities.Contains($name)) {
            throw "Managed Hyper-V switch '$name' with ID '$($switchIdentities[$name])' is missing. Refusing to replace it implicitly."
        }
        continue
    }
    if ($switchIdentities.Contains($name)) {
        Assert-HyperVSwitchIdentity -Name $name `
            -ExpectedHyperVSwitchId ([string]$switchIdentities[$name]) | Out-Null
        continue
    }
    if (-not $priorOwnerMatches -or $Recreate -or $name -cnotin $priorSwitchNames) {
        throw "Hyper-V switch '$name' already exists without a persisted managed switch ID. Refusing to adopt it. Run provisioning normally to migrate an older owned state only after verifying its topology."
    }
    Assert-LegacyPrivateSwitchTopology -Name $name `
        -ExpectedVmIdentities $vmIdentities
    $observedId = $live.HyperVSwitchId
    Assert-HyperVSwitchIdentity -Name $name `
        -ExpectedHyperVSwitchId $observedId | Out-Null
    Write-Warning "Migrating legacy switch state for '$name' to Hyper-V switch ID '$observedId' after verifying its exact managed adapter topology."
    $switchIdentities[$name] = $observedId
    $migratedSwitchIdentity = $true
}
if ($migratedSwitchIdentity) {
    # Persist verified switch IDs before any VM or switch configuration changes.
    Write-ManagedState -Status "Provisioning" -Configuration $desired `
        -Identities $vmIdentities -SwitchIdentities $switchIdentities | Out-Null
}

if ($Recreate) {
    foreach ($guest in $guests) {
        $name = [string]$guest.Name
        if ($name -in $existingNames) {
            # Re-read immediately before deletion so a same-named replacement cannot
            # be removed after the ownership decision above.
            Assert-HyperVVmIdentity -Name $name `
                -ExpectedHyperVVmId ([string]$observedExistingIdentities[$name]) | Out-Null
            Invoke-Multipass -Arguments @("delete", "--purge", $name) | Out-Null
            if (@(Get-VM -Name $name -ErrorAction SilentlyContinue).Count -ne 0) {
                throw "Multipass returned after deleting '$name', but a same-named Hyper-V VM still exists. Refusing to continue."
            }
        }
    }
}

# A normal legacy migration is persisted before any Hyper-V configuration is
# changed. Recreate keeps the old identity state until all verified deletions
# complete, then starts a fresh provisioning record.
Write-ManagedState -Status "Provisioning" -Configuration $desired `
    -Identities $vmIdentities -SwitchIdentities $switchIdentities | Out-Null

foreach ($name in @($Path0Switch, $Path1Switch)) {
    $expectedId = if ($switchIdentities.Contains($name)) {
        [string]$switchIdentities[$name]
    } else {
        $null
    }
    $switchIdentities[$name] = Ensure-PrivateSwitch -Name $name `
        -ExpectedHyperVSwitchId $expectedId
    # A newly created switch is not used until its immutable ID is durable.
    Write-ManagedState -Status "Provisioning" -Configuration $desired `
        -Identities $vmIdentities -SwitchIdentities $switchIdentities | Out-Null
}

$instances = @(Get-MultipassInstances)
$existingNames = @($instances | ForEach-Object { [string]$_.name })
foreach ($guest in $guests) {
    Write-Host "[network] Ensuring $($guest.Name)"
    if ($guest.Name -notin $existingNames) {
        Invoke-Multipass -Arguments @(
            "launch", $UbuntuImage, "--name", $guest.Name,
            "--cpus", [string]$CpuCount, "--memory", $Memory, "--disk", $Disk,
            "--timeout", "1800"
        ) | Out-Null
        $identity = Get-HyperVVmIdentity -Name $guest.Name
        $vmIdentities[[string]$guest.Name] = $identity.HyperVVmId
        Write-ManagedState -Status "Provisioning" -Configuration $desired `
            -Identities $vmIdentities -SwitchIdentities $switchIdentities | Out-Null
    } else {
        Assert-HyperVVmIdentity -Name $guest.Name `
            -ExpectedHyperVVmId ([string]$vmIdentities[[string]$guest.Name]) | Out-Null
        $instance = $instances | Where-Object { $_.name -eq $guest.Name } | Select-Object -First 1
        if ([string]$instance.state -ne "Running") {
            Invoke-Multipass -Arguments @("start", "--timeout", "120", $guest.Name) | Out-Null
        }
    }
    Wait-MultipassExec -Name $guest.Name
    Assert-HyperVVmIdentity -Name $guest.Name `
        -ExpectedHyperVVmId ([string]$vmIdentities[[string]$guest.Name]) | Out-Null
    $networkFiles = New-GuestNetworkFiles -Guest $guest
    Invoke-Multipass -Arguments @(
        "transfer", $networkFiles.Netplan, "$($guest.Name):/home/ubuntu/.wgtcp-netplan.yaml"
    ) | Out-Null
    Invoke-Multipass -Arguments @(
        "transfer", $networkFiles.Marker, "$($guest.Name):/home/ubuntu/.wgtcp-lab-marker"
    ) | Out-Null
    $installNetwork = @'
set -euo pipefail
source_file="$1"
target=/etc/netplan/60-wireguardtcp-lab.yaml
if cmp -s -- "$source_file" "$target"; then
    netplan generate
    printf 'changed=0\n'
    exit 0
fi
backup=$(mktemp /run/wgtcp-netplan.XXXXXX)
had_target=0
if [ -e "$target" ]; then
    cp -a -- "$target" "$backup"
    had_target=1
fi
install -o root -g root -m 0600 -- "$source_file" "$target"
if ! netplan generate; then
    if [ "$had_target" -eq 1 ]; then
        mv -f -- "$backup" "$target"
    else
        rm -f -- "$target" "$backup"
    fi
    netplan generate >/dev/null 2>&1 || true
    exit 1
fi
rm -f -- "$backup"
printf 'changed=1\n'
'@
    $networkInstallOutput = @(Invoke-Multipass -Arguments @(
        "exec", $guest.Name, "--", "sudo", "bash", "-c", $installNetwork,
        "netplan-install", "/home/ubuntu/.wgtcp-netplan.yaml"
    ))
    $networkChanged = $networkInstallOutput -contains "changed=1"
    if (-not $networkChanged -and $networkInstallOutput -notcontains "changed=0") {
        throw "Guest '$($guest.Name)' did not report whether its netplan changed."
    }
    Invoke-Multipass -Arguments @(
        "exec", $guest.Name, "--", "sudo", "install", "-o", "root", "-g", "root", "-m", "0644",
        "/home/ubuntu/.wgtcp-lab-marker", "/etc/wireguardtcp-lab"
    ) | Out-Null
    # Attach the private adapters only after the standard management boot is healthy.
    Ensure-GuestVmConfiguration -Guest $guest `
        -ExpectedHyperVVmId ([string]$vmIdentities[[string]$guest.Name]) `
        -ExpectedPath0SwitchId ([string]$switchIdentities[$Path0Switch]) `
        -ExpectedPath1SwitchId ([string]$switchIdentities[$Path1Switch]) `
        -ActivateStagedNetwork:$networkChanged
    Wait-MultipassExec -Name $guest.Name
    $networkCheck = "set -euo pipefail; ip -4 -o address show dev path0 | grep -F -- ' $($guest.Path0Address)/24 '; ip -4 -o address show dev path1 | grep -F -- ' $($guest.Path1Address)/24 '"
    Invoke-Multipass -Arguments @("exec", $guest.Name, "--", "bash", "-c", $networkCheck) | Out-Null
}

Write-Host "[snapshot] Capturing the current Git worktree"
$snapshot = New-SourceSnapshot
foreach ($guest in $guests) {
    Assert-HyperVVmIdentity -Name $guest.Name `
        -ExpectedHyperVVmId ([string]$vmIdentities[[string]$guest.Name]) | Out-Null
    Write-Host "[source] Installing snapshot on $($guest.Name)"
    Install-Snapshot -Name $guest.Name -Snapshot $snapshot
    Write-Host "[bootstrap] Preparing $($guest.Name)"
    Invoke-Multipass -Arguments @("exec", $guest.Name, "--", "sudo", "bash", "/home/ubuntu/WireguardTCP/tests/hyperv/guest-bootstrap.sh") | Out-Null
    if (-not $SkipGuestBuild) {
        Write-Host "[build] Compiling tools and modules on $($guest.Name)"
        Invoke-Multipass -Arguments @("exec", $guest.Name, "--", "sudo", "bash", "/home/ubuntu/WireguardTCP/tests/hyperv/guest-build.sh") | Out-Null
    }
}

$snapshotState = [ordered]@{
    Head = $snapshot.Head
    GitStatus = $snapshot.Status
    BaseArchiveSha256 = $snapshot.BaseHash
    OverlayArchiveSha256 = $snapshot.OverlayHash
}
foreach ($name in @($Path0Switch, $Path1Switch)) {
    Assert-HyperVSwitchIdentity -Name $name `
        -ExpectedHyperVSwitchId ([string]$switchIdentities[$name]) | Out-Null
}
$state = Write-ManagedState -Status "Ready" -Configuration $desired `
    -Identities $vmIdentities -SwitchIdentities $switchIdentities `
    -Snapshot $snapshotState
$state | ConvertTo-Json -Depth 12
