# Hyper-V lab creation and recovery guide

This document records the complete host and guest setup used for the
WireguardTCP regression lab, including the changes made after the first VM
creation attempts exposed Multipass, networking, source-transfer, and module
loading problems. The automated entry points remain
[`Enable-HyperV.ps1`](Enable-HyperV.ps1),
[`Provision-HyperV.ps1`](Provision-HyperV.ps1), and
[`Run-HyperVRegression.ps1`](Run-HyperVRegression.ps1).

## Tested layout

The recorded campaign used Windows 11 Pro, Hyper-V, Multipass 1.16.3 with the
`hyperv` driver, and two Ubuntu 24.04 guests running kernel
`6.8.0-124-generic`.

| Component | `wgtcp-a` | `wgtcp-b` |
|---|---|---|
| CPU, memory, disk | 4 vCPU, 8 GB, 60 GB | 4 vCPU, 8 GB, 60 GB |
| Management | Hyper-V Default Switch DHCP | Hyper-V Default Switch DHCP |
| `WGTCP-Path0` | `52:54:00:10:00:0a`, `10.77.0.10/24` | `52:54:00:10:00:0b`, `10.77.0.11/24` |
| `WGTCP-Path1` | `52:54:00:20:00:0a`, `10.77.1.10/24` | `52:54:00:20:00:0b`, `10.77.1.11/24` |

The two `WGTCP-Path*` switches are private and have no host adapter, DHCP,
gateway, or DNS. The ordinary Multipass management NIC is deliberately kept
separate so package installation and `multipass exec` do not depend on either
test path.

## 1. Check the host before changing it

1. Confirm Windows is Pro, Enterprise, or Education. Hyper-V is not available
   as a supported feature on the Home edition.
2. Enable Intel VT-x or AMD-V, second-level address translation (SLAT), and
   hardware-enforced data-execution prevention (Intel XD or AMD NX) in
   firmware. VT-d/IOMMU is useful for device assignment but is not the
   Hyper-V prerequisite being checked here.
3. Reserve at least 16 GB of free RAM and 120 GB of free disk for the two
   default guests.
4. Install PowerShell 7, Python 3, Git for Windows (`git.exe`), and a Windows
   `tar.exe` that supports pax archives. Current Windows and Git for Windows
   installations normally provide the required tar implementation. The
   provisioner checks both executable names before changing VM state.
5. Download the Canonical Multipass MSI to a local path. Do not bypass the
   hash and signer checks in the bootstrap script.

Useful read-only checks from PowerShell are:

```powershell
Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-Service vmms,Multipass -ErrorAction SilentlyContinue
systeminfo.exe | Select-String 'Hyper-V Requirements'
```

## 2. Enable Hyper-V and install Multipass

Open an elevated PowerShell 7 window and run from the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./tests/hyperv/Enable-HyperV.ps1 `
    -MultipassMsi C:/Installers/multipass-installer.msi `
    -StatePath ./tests/hyperv/results/host-enable.json
```

The script performs these host changes:

1. Verifies the exact MSI SHA-256.
2. Verifies a valid Authenticode signature from `CANONICAL GROUP LIMITED` and
   the pinned signing-certificate thumbprint.
3. Enables `Microsoft-Hyper-V-All` without forcing an immediate reboot.
4. Installs Multipass silently when it is not already installed.
5. Adds the current account to `Hyper-V Administrators` when necessary.
6. Writes the observed state and `RestartNeeded` value to the requested JSON
   file.

Changing Multipass versions requires deliberately updating both pins in
`Enable-HyperV.ps1` after independently checking the new installer. A hash
match alone is not accepted.

UAC is a Windows secure-desktop prompt. It may appear behind other windows and
cannot be accepted from a Codex terminal. If no prompt appears, open PowerShell
with **Run as administrator** first and invoke the script there. Do not wait on
a non-elevated `#Requires -RunAsAdministrator` failure expecting a later UAC
dialog.

Reboot after enabling Hyper-V or changing local group membership, even if the
installer itself reports that no restart is required. The new logon token must
contain `Hyper-V Administrators`, and the hypervisor must be active before
Multipass can create a VM.

After reboot, open a new PowerShell window and verify:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-LocalGroupMember 'Hyper-V Administrators'
Get-Service vmms,Multipass
Get-VM -ErrorAction Stop | Select-Object Name,VMId,State
multipass version
multipass get local.driver
multipass networks
```

The `Get-VM` check must succeed in the exact PowerShell or automation token
that will invoke provisioning. Group membership shown by
`Get-LocalGroupMember` does not prove that an already-running process has the
updated group in its token. If `Get-VM` returns `Access denied`, start a new
elevated PowerShell 7 session or use an approved brokered administrator shell
and run both the check and provisioner there. Do not continue from a token
that cannot read the managed VMs: identity checks would otherwise fail before
the harness can safely change them.

`local.driver` must be `hyperv`. If another backend was previously used, stop
its instances before changing it:

```powershell
multipass stop --all
multipass set local.driver=hyperv
```

## 3. Establish Multipass health

Before provisioning, these commands must return promptly:

```powershell
multipass list
multipass networks
multipass launch release:24.04 --name wgtcp-probe --cpus 1 --memory 1G --disk 8G --timeout 600
multipass exec wgtcp-probe -- true
multipass delete --purge wgtcp-probe
```

The disposable probe is optional when the host already has a known-good
Multipass instance. Never use either managed name, `wgtcp-a` or `wgtcp-b`, for
this check.

Before every regression, also prove that both managed guests accept a command
within a fixed deadline. The regression wrapper performs bounded
`multipass exec <name> -- true` probes and aborts as an infrastructure failure
if either guest cannot be reached; `-KeepGoing` applies to independent test
case failures, not to a missing control channel. A raw `multipass exec` or
`Test-NetConnection` left waiting indefinitely is not an acceptable health
check.

### Stuck Multipass service

During initial setup, `Restart-Service Multipass` remained at "Waiting for
service ... to stop" because `multipassd` did not exit. Closing the Multipass
GUI, tray process, shells, and outstanding `multipass` clients should be the
first recovery step. Then, from an elevated PowerShell:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Multipass'" |
    Select-Object Name,State,ProcessId,PathName
sc.exe stop Multipass
Get-Service Multipass
```

If it is still stopping after 30 seconds, verify that the service PID belongs
to `multipassd` before terminating that exact process, then start the service:

```powershell
$service = Get-CimInstance Win32_Service -Filter "Name='Multipass'"
$process = Get-Process -Id $service.ProcessId
if ($process.ProcessName -ne 'multipassd') { throw 'Unexpected service PID' }
Stop-Process -Id $process.Id -Force
(Get-Service Multipass).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
Start-Service Multipass
(Get-Service Multipass).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
```

This recovery is intentionally PID-checked. A broad process kill can terminate
unrelated Hyper-V or user workloads. If the service again cannot stop or the
driver remains unresponsive, reboot Windows rather than repeatedly forcing it.

### Exceptional stuck VM worker recovery

Terminating `vmwp.exe` is not routine Multipass recovery: it is equivalent to
removing power from one guest and can corrupt that guest's filesystem. First
try a bounded `multipass stop`, normal Hyper-V shutdown/turn-off, Multipass
service recovery, and a host reboot. Use the following only when one managed
guest remains stuck, its schema-2 identity is already recorded, and the guest
is disposable or recoverable. This maps the recorded VM GUID to exactly one
worker and then verifies that worker's PID before stopping it:

```powershell
$name = 'wgtcp-a'
$state = Get-Content ./tests/hyperv/results/provision-state.json -Raw |
    ConvertFrom-Json
$records = @($state.VmIdentities | Where-Object Name -CEQ $name)
if ($records.Count -ne 1) { throw 'No unique managed VM identity' }

$vms = @(Get-VM -Name $name -ErrorAction Stop)
if ($vms.Count -ne 1 -or $vms[0].Name -cne $name) {
    throw 'No unique same-case Hyper-V VM'
}
$recordedId = ([guid]$records[0].HyperVVmId).ToString('D')
$liveId = ([guid]$vms[0].VMId).ToString('D')
if ($liveId -ne $recordedId) { throw 'VM identity mismatch; stop here' }

$idPattern = [regex]::Escape($liveId)
$workers = @(Get-CimInstance Win32_Process -Filter "Name='vmwp.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine -match $idPattern })
if ($workers.Count -ne 1) { throw 'No unique worker for the recorded VM ID' }
$workerPid = [uint32]$workers[0].ProcessId

# Re-read both identities immediately before the destructive operation. This
# catches a same-named VM replacement or PID reuse after the initial lookup.
$liveAgain = @(Get-VM -Name $name -ErrorAction Stop)
if ($liveAgain.Count -ne 1 -or $liveAgain[0].Name -cne $name -or
    ([guid]$liveAgain[0].VMId).ToString('D') -ne $recordedId) {
    throw 'VM identity changed; stop here'
}
$workerAgain = @(Get-CimInstance Win32_Process -Filter "ProcessId=$workerPid")
if ($workerAgain.Count -ne 1 -or $workerAgain[0].Name -cne 'vmwp.exe' -or
    -not $workerAgain[0].CommandLine -or
    $workerAgain[0].CommandLine -notmatch $idPattern) {
    throw 'Worker PID or command line changed; stop here'
}
Stop-Process -Id $workerPid -Force
```

Re-read `Get-VM`, recover or recreate that one guest, and run provisioning
again. Never use `Stop-Process -Name vmwp`, and never select a worker by VM
name alone. If the recorded ID is missing or mismatched, a reboot is the safer
recovery boundary.

### Management SSH wait

The first creation attempt attached custom data NICs and cloud-init networking
at `multipass launch` time. The VM reached `Running`, but Multipass waited for
SSH on its Default Switch address and an interactive `Test-NetConnection`
remained at "Waiting for response" for many minutes. That screen is a blocked
diagnostic, not useful progress; close it.

The final provisioner uses a bounded child-process probe for
`multipass exec <name> -- true`. Each attempt is killed after 20 seconds and
the overall wait is capped. Probe stdout and stderr are retained beneath the
ignored results directory. This prevents an unreachable SSH endpoint from
wedging the whole provisioning process.

VM creation and power transitions are synchronous. The provisioner waits for
`multipass launch` with a Multipass operation timeout of 1,800 seconds and for
each `start` or provisioning `stop` with a 120-second operation timeout. It
then applies the independent, bounded `multipass exec` readiness loop; it does
not start a second launch in the background while the first is unresolved. A
Multipass client that remains frozen beyond its own operation timeout is a
service failure: stop that exact client, inspect the service, and recover it
before rerunning provisioning.

If a standard management-only guest is unreachable, inspect:

```powershell
multipass list
Get-VM -Name wgtcp-a,wgtcp-b | Format-Table Name,State,Status
Get-VMNetworkAdapter -VMName wgtcp-a,wgtcp-b |
    Format-Table VMName,SwitchName,Status,IPAddresses
Get-HnsNetwork | Where-Object Name -EQ 'Default Switch'
```

The lab does not create a console password or another interactive guest
account. The Hyper-V console can confirm boot progress, but it is not an
alternate login path. After restoring the Multipass control channel, inspect
`/var/log/cloud-init.log`, `/var/log/cloud-init-output.log`, and
`systemctl status ssh` with `multipass exec`. Do not add a diagnostic password
or SSH key to committed cloud-init data just to obtain console access.

The Hyper-V Default Switch is shared host infrastructure. Removing its HNS
network can disrupt Multipass, WSL, containers, and other VMs. Consider that
only after saving `Get-HnsNetwork` output, confirming a management-only guest
also fails, and closing dependent workloads. Windows normally recreates the
Default Switch after the HNS network is removed or the host is rebooted.

## 4. Provision the two managed guests

Run this from the repository root in PowerShell 7:

```powershell
./tests/hyperv/Provision-HyperV.ps1
```

Once Hyper-V is enabled and the account has a fresh
`Hyper-V Administrators` token, this command normally does not need a fully
elevated administrator token. Confirm this from the invoking token with
`Get-VM -Name wgtcp-a,wgtcp-b`; if it is denied, run the provisioner in a new
elevated PowerShell 7 session or through an approved brokered administrator
shell.

The provisioner executes the following sequence:

1. Validates VM names, repository paths, the Multipass executable, and the
   `hyperv` driver, plus the host `git.exe` and `tar.exe` prerequisites.
2. Reads `tests/hyperv/results/provision-state.json`, compares each existing
   VM's immutable Hyper-V `VMId` with its persisted identity, and refuses to
   adopt or delete a same-named replacement.
3. Creates private switches `WGTCP-Path0` and `WGTCP-Path1`, immediately
   persists each immutable Hyper-V switch ID, and verifies that ID before use.
   A same-named existing switch is never adopted by name alone.
4. Launches Ubuntu 24.04 with only Multipass's standard management NIC.
5. Proves `multipass exec` works before changing networking.
6. Renders a MAC-matched netplan for each guest, transfers it, installs it
   atomically as `/etc/netplan/60-wireguardtcp-lab.yaml`, and runs
   `netplan generate`. A failed generation restores the prior file.
7. Stops the guest, disables Secure Boot, disables Dynamic Memory, and attaches
   the two private adapters with deterministic static MAC addresses.
8. Restarts the guest and verifies both `path0` and `path1` addresses.
9. Captures the source as `git archive HEAD` plus a tar overlay of Git-visible
   modified and untracked files and a deletion manifest. This is the exact
   Git-visible snapshot reported by the captured status; ignored files and
   other unreported filesystem content are not included. It rejects a
   worktree whose Git status changes during capture and records host-computed
   SHA-256 hashes.
10. Installs the verified snapshot into `/home/ubuntu/WireguardTCP` on each
    guest without losing Git symlinks.
11. Installs dependencies, verifies the stock driver is a removable module,
    builds the fork tool, copies the stock tool, and builds production and
    DEBUG fork modules with `W=1`.
12. Records a schema-2 `Ready` state with exact Hyper-V VM and switch IDs,
    source base, host Git status, and archive hashes.

Use `-Recreate` to delete and rebuild only instances already recorded as owned
by this harness:

```powershell
./tests/hyperv/Provision-HyperV.ps1 -Recreate
```

`-ForceRecreateUnmanaged` is a separate, explicit override. Use it only after
manually confirming that a colliding or replaced instance is disposable. The
script re-reads the exact Hyper-V VM ID immediately before deletion even when
the override is present. The harness never implicitly deletes switches or
unrelated VMs.

### Identity state and legacy migration

Current state contains records shaped like:

```json
"VmIdentities": [
  { "Name": "wgtcp-a", "HyperVVmId": "00000000-0000-0000-0000-000000000000" }
],
"SwitchIdentities": [
  { "Name": "WGTCP-Path0", "HyperVSwitchId": "00000000-0000-0000-0000-000000000000" }
]
```

The GUID is host-specific; the value above is illustrative. A matching name is
never sufficient for recreation. On every normal run, the script verifies the
live `Get-VM` ID before changing firmware, memory, adapters, or guest content.
On `-Recreate`, a stored ID must match again immediately before
`multipass delete --purge`.

State written by the earlier provisioner recorded only names. A normal run
without `-Recreate` may migrate that legacy state when its owner and requested
configuration still match and Multipass still reports the named instance. It
pins the currently observed IDs to schema-2 state before making further VM
changes. This cannot prove historical identity, so a legacy record is never
accepted as deletion authority: run once normally to migrate it, inspect the
recorded IDs, and only then use `-Recreate`. Direct recreation from name-only
state requires the conspicuous `-ForceRecreateUnmanaged` override. An ID
mismatch in schema-2 state is treated as a replacement and has the same force
requirement.

A schema-2 state that lacks an identity for an existing VM is not treated as
legacy. That can happen only across an interrupted create-before-record window
or manual state editing, so the script refuses adoption and requires manual
inspection. This fail-closed case is different from the recognized pre-schema
state produced by the earlier provisioner.

The first schema-2 implementation recorded VM IDs but not switch IDs. A normal
run may migrate one of those older owned states only when the live private
switch has exactly the two expected managed VM adapters, both managed VM IDs
still match, both static MAC addresses match, and no extra adapter uses the
switch. The script then re-reads and persists the switch GUID before making
configuration changes. Migration is disabled during `-Recreate`; run once
normally and inspect the recorded IDs first. With no matching older owned
state, an existing same-named switch is a collision and provisioning stops.

## 5. Guest preparation details

[`guest-bootstrap.sh`](guest-bootstrap.sh) installs `build-essential`, the
matching kernel headers, `linux-modules-extra` when available, `libmnl-dev`,
`iproute2`, `iperf3`, `tcpdump`, Python, and stock `wireguard-tools`. It checks
that `CONFIG_WIREGUARD=m`, proves the stock module can load and unload, and
fails early when the image has a built-in driver that cannot be exchanged.

[`guest-build.sh`](guest-build.sh) copies the transferred source into an
isolated build directory under `/var/lib/wireguardtcp`, excluding prior build
outputs. It produces:

```text
/var/lib/wireguardtcp/artifacts/bin/wg-stock
/var/lib/wireguardtcp/artifacts/bin/wg-fork
/var/lib/wireguardtcp/artifacts/modules/<kernel>/wireguard-fork.ko
/var/lib/wireguardtcp/artifacts/modules/<kernel>/wireguard-fork-debug.ko
```

Secure Boot was disabled because these local test modules are unsigned.
Dynamic Memory was disabled so each build and regression case has predictable
guest memory. The provisioner prepares `wgtcp-a` and then `wgtcp-b`; it does
not compile both guests concurrently. Within the active guest,
`guest-build.sh` deliberately runs make with `-j$(nproc)`, so one build can use
all four assigned vCPUs. These settings are applied only to ID-verified
managed VMs while they are stopped.

The installed source is a reproducible snapshot, not a Git checkout: it has
the content visible to the host's Git commands but no `.git` directory. The
authoritative source record is
`/home/ubuntu/.wgtcp-current-snapshot.json`, copied from the host manifest. It
contains the host `HEAD`, captured Git status, and the base and overlay hashes;
the guest verifies both tar hashes before extraction. By contrast,
`/var/lib/wireguardtcp/artifacts/manifest.json` is a build-environment record.
Its `revision` may read `snapshot-without-git-metadata`, which is expected and
does not replace the snapshot manifest or host `provision-state.json`.

## 6. Process changes made during bring-up

| Initial approach or failure | Final process modification |
|---|---|
| Custom `--network` NICs and cloud-init were supplied during `multipass launch`; initialization then waited indefinitely for management SSH. | Launch and prove the Default Switch management path first; stage netplan, stop once, attach private NICs, then restart. |
| An early diagnostic cloud-config failed schema validation and used settings unsuitable for a reusable lab. | The final VM creation path uses Multipass's standard cloud-init and installs a small, validated netplan afterward. Diagnostic cloud-init, including any temporary access mechanism, stays under the ignored results tree and is excluded from the repository and source snapshot. |
| `Test-NetConnection <guest>:22` could sit on "Waiting for response" indefinitely. | `Invoke-MultipassExecProbe` runs `multipass exec -- true` as a child process with a 20-second attempt timeout and a bounded overall deadline. |
| Multipass service stop could hang even after UAC was accepted. | Close clients first; verify the `multipassd` service PID before a forced stop; reboot if service recovery does not remain stable. |
| Private NICs could steal attention from management-network diagnosis. | The management NIC and both data-plane NICs have separate roles; provisioning checks management before and private addresses after attachment. |
| Direct cloud-init/netplan activation could strand a guest. | Render per-guest files, use MAC matching and `set-name`, validate with `netplan generate`, preserve a backup, and activate only after adapters exist. |
| Unsigned module insertion was blocked and memory allocation varied. | Disable Secure Boot and Dynamic Memory while each managed VM is stopped. |
| A plain Windows-created tar did not provide a trustworthy Git worktree representation, especially for symlinks and deletions. | Combine `git archive HEAD`, a path-list overlay tar, and an explicit deletion manifest; hash both archives and verify them in the guest. |
| Re-running setup could accidentally adopt or remove a pre-existing same-named VM. | Persist immutable Hyper-V VM IDs beside owner/configuration state, verify the ID before every managed change and again before deletion, migrate old name-only state only on a normal non-delete run, and require a separate force flag for unmanaged or replaced collisions. |
| Building in the transferred tree left stale outputs and obscured provenance. | `rsync --delete` into an isolated guest build root and store a build manifest with the kernel release and source identity. |
| Switching stock and fork modules could unload a driver with live interfaces. | `guest-module.sh` enumerates root and network-namespace WireGuard links and refuses to unload until owned links are removed. |
| Interrupted tests left interfaces or an underlay down. | Each case writes ownership state before mutation; cleanup restores only that case's interfaces, namespaces, and underlay. A later run refuses abandoned ownership. |
| Failure logs were too narrow to diagnose TCP state. | Capture public WireGuard selectors, listening sockets, established TCP details, and kernel messages after a per-case log reset; never collect private keys. |
| Host Python discovery could select the Windows Store alias or hang. | The wrapper probes real `python.exe`/`py.exe -3` applications with a 10-second process timeout. |
| A single failing case prevented useful independent coverage. | The runner supports `-KeepGoing`, repeatable `--only-case`, production/DEBUG TCP variants, and always performs best-effort owned cleanup. Bounded command probes run first, and loss of all guest command execution is classified as infrastructure failure and aborts even with `-KeepGoing`. |

The one-off recovery scripts, diagnostic cloud-init, and raw logs created
during diagnosis remain under the ignored `tests/hyperv/results/` tree. They
are evidence from this machine, not portable provisioning inputs, and are
intentionally neither committed nor transferred in the Git-visible source
snapshot. The diagnostic cloud-init must not be promoted into the harness.

## 7. Validate provisioning

```powershell
multipass list
multipass exec wgtcp-a -- ip -br address
multipass exec wgtcp-b -- ip -br address
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-build.sh --verify
multipass exec wgtcp-b -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-build.sh --verify
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh underlay 10.77.0.10 10.77.1.10
multipass exec wgtcp-b -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh underlay 10.77.0.11 10.77.1.11
```

The expected final host state is two running VMs, one Default Switch adapter
and two private adapters per VM, and both test addresses visible in each guest.

## 8. Run and reproduce the regression

```powershell
./tests/hyperv/Run-HyperVRegression.ps1
```

For focused work:

```powershell
python ./tests/hyperv/regression.py `
    --only-case tcp-smoke `
    --only-case tcp-configured-path-change `
    --tcp-kernel-variant fork-debug
```

After source changes, rerun the provisioner before the regression. This creates
and records a new source overlay; restoring a Multipass snapshot does not
replace that provenance step. Machine-readable results and command logs remain
under the ignored `tests/hyperv/results/<run-id>/` directory. The curated,
committed outcome is [`RESULTS.md`](RESULTS.md).

The valid brokered-host campaign `wg20260712T212739Z` passed all 26 cases in
208.713 seconds. An earlier sandboxed attempt, `wg20260712T200006Z`, could not
reach TCP port 22 on either management address and no guest command succeeded;
it was a 0-of-26 infrastructure run, not regression evidence. Treat this
pattern as a control-channel failure, recover Multipass or the Default Switch,
then start a new run rather than interpreting the case list as product
failures.

## 9. Recovery and cleanup boundaries

If a test runner is interrupted, use the exact `RUN`, `CASE`, and interface
reported by the ownership error:

```powershell
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup RUN CASE wgt0
```

Do not delete an interface by name when the state file says another case owns
it. That guard is what makes reruns safe after partial failures.

Before deleting either VM manually, use an elevated or brokered shell whose
invoking token can call `Get-VM`, load the schema-2 state, and verify the exact
Hyper-V VM ID immediately before each deletion:

```powershell
$state = Get-Content ./tests/hyperv/results/provision-state.json -Raw |
    ConvertFrom-Json
foreach ($name in 'wgtcp-a','wgtcp-b') {
    $record = @($state.VmIdentities | Where-Object Name -CEQ $name)
    $live = @(Get-VM -Name $name -ErrorAction Stop)
    if ($record.Count -ne 1 -or $live.Count -ne 1 -or
        ([guid]$record[0].HyperVVmId) -ne ([guid]$live[0].VMId)) {
        throw "VM identity mismatch for $name; nothing was deleted"
    }
    multipass delete --purge $name
    if ($LASTEXITCODE -ne 0) { throw "Multipass deletion failed for $name" }
}
foreach ($name in 'WGTCP-Path0','WGTCP-Path1') {
    $record = @($state.SwitchIdentities | Where-Object Name -CEQ $name)
    $live = @(Get-VMSwitch -Name $name -ErrorAction Stop)
    if ($record.Count -ne 1 -or $live.Count -ne 1 -or
        $live[0].Name -cne $name -or $live[0].SwitchType -ne 'Private' -or
        ([guid]$record[0].HyperVSwitchId) -ne ([guid]$live[0].Id)) {
        throw "Switch identity mismatch for $name; nothing was removed"
    }
    $attached = @(Get-VMNetworkAdapter -All -ErrorAction Stop |
        Where-Object SwitchName -CEQ $name)
    if ($attached.Count -ne 0) {
        $attached | Format-Table VMName,Name,MacAddress,SwitchName
        throw "Switch $name still has adapters; nothing was removed"
    }
    # Re-read the immutable ID after the adapter check and immediately before
    # removing the exact object.
    $live = @(Get-VMSwitch -Name $name -ErrorAction Stop)
    if ($live.Count -ne 1 -or $live[0].Name -cne $name -or
        ([guid]$record[0].HyperVSwitchId) -ne ([guid]$live[0].Id)) {
        throw "Switch identity changed for $name; nothing was removed"
    }
    $attached = @(Get-VMNetworkAdapter -All -ErrorAction Stop |
        Where-Object SwitchName -CEQ $name)
    if ($attached.Count -ne 0) {
        throw "Switch $name gained an adapter; nothing was removed"
    }
    $live[0] | Remove-VMSwitch -Force
}
```

This per-VM ordering keeps the identity read adjacent to the destructive
operation and stops on a replacement or malformed state. The cleanup commands
are intentionally manual because Hyper-V switches and same-named VMs may be
valuable outside this test harness. The switch block verifies the persisted
GUID and proves that no managed or unrelated adapter remains attached before
removing the exact switch object.
