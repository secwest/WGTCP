# Hyper-V lab creation and recovery guide

This document records the complete host and guest setup used for the
WireguardTCP regression lab, including the changes made after the first VM
creation attempts exposed Multipass, networking, source-transfer, and module
loading problems. The automated entry points remain
[`Enable-HyperV.ps1`](Enable-HyperV.ps1),
[`Provision-HyperV.ps1`](Provision-HyperV.ps1), and
[`Run-HyperVRegression.ps1`](Run-HyperVRegression.ps1).

## Current follow-up note (2026-07-15)

The managed guests now run Ubuntu kernel `6.8.0-134-generic`. The current
integrated exact-owner source passes 205 local contracts. Both guests built overlay
`18e3aab15eb64257e73f491849133f9a332d2467c66777214cd2481e459252a7`;
the remote writer/parser/handoff integration, callback module pin, and final
device-reopen quarantine guard were added afterward and require one more
provision/build pass before runtime results are accepted. The current
registry contains 39 cases, and no green 39-case campaign has completed for
the final source.

An important process correction came from an intentionally interrupted focused
run: stopping the host runner did not necessarily stop an already spawned
elevated `python regression.py` child or its active `multipass exec`. Before a
rerun, inspect the exact host PID, parent PID, executable, and full command line,
then allow the guest timeout/trap to complete or terminate only that verified
process tree. Verify both guests have no WireGuard links and no matching guest
harness process. Do not start another regression while the abandoned command
still owns a case.

If `multipass list` reports that it cannot connect to the local socket after the
orphan is gone, confirm the `Multipass` Windows service state. A service restart
requires an administrator token and may present UAC; use it only for a verified
unresponsive control socket, then wait for both existing VMs to report ready.
This is recovery of the existing managed VMs, not permission to delete or
recreate them.

## Historical tested layout

The latest historical complete campaign used Windows 11 Pro, Hyper-V,
Multipass 1.16.3 with the `hyperv` driver, and two Ubuntu 24.04 guests running kernel
`6.8.0-124-generic`.

That historical full campaign, `wg20260714T010310Z`, used source HEAD
`83d424cb0191bc2b90090c071728db6348f7b983`, base archive SHA-256
`2de2c670dba76cac01dd1bd35f9de99605d36b032070048d6b94f5e6f3ec0d12`, and
Git-visible overlay SHA-256
`40c4db67c0b9660f3589239ca85ac1870d40306075ce67617085a40b1a3d3e9a`.

The later roaming snapshot retained HEAD
`c1d898a1f48c09c8a64c32fe76b5d2ddb4737624` and used base archive SHA-256
`6dd8fe9466b068173f7aec42b7ce66100ab5aa563485ffeca55e261eb5406b7a` plus
Git-visible overlay SHA-256
`899b5ec7f1126852b6147f41f39dc900807768365979ad547a66d95874d25fdc`.
That overlay includes the modified and untracked files reported by Git at
capture time; it is not a long-lived VM image or an implicit source cache.

| Component | `wgtcp-a` | `wgtcp-b` |
|---|---|---|
| CPU, memory, disk | 4 vCPU, 8 GB, 60 GB | 4 vCPU, 8 GB, 60 GB |
| Management | Hyper-V Default Switch DHCP | Hyper-V Default Switch DHCP |
| `WGTCP-Path0` | `52:54:00:10:00:0a`, `10.77.0.10/24` | `52:54:00:10:00:0b`, `10.77.0.11/24` |
| `WGTCP-Path1` | `52:54:00:20:00:0a`, `10.77.1.10/24` | `52:54:00:20:00:0b`, `10.77.1.11/24` |

The schema-2 state used for the roaming run records exact VM IDs
`69fcac18-eb3f-46c1-a32f-4aa421e54e42` (`wgtcp-a`) and
`48902a17-0dfe-4bbb-ab4f-86bcfb97f96d` (`wgtcp-b`), plus exact switch IDs
`a795c92c-e6d9-4ece-ad04-f835cfd70e93` (`WGTCP-Path0`) and
`2f6d2b77-2ade-42e7-af23-417eab54ec2f` (`WGTCP-Path1`). These values identify
this managed lab only. A new lab must record its own Hyper-V GUIDs rather than
copying these identifiers.

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

An interactive shell and an automation host can have different Windows tokens
and network policy even under the same account. A restricted or non-elevated
automation context can therefore report `Access denied` from Hyper-V cmdlets or
a socket-access/management-SSH failure while an approved administrator shell
works. Run `Get-VM` and `multipass exec <guest> -- true` from the exact context
that will run the provisioner or regression. Treat a failure before any guest
command succeeds as infrastructure evidence, not as a WireguardTCP result.

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

### Orphaned Multipass client recovery

A timed-out host command can leave its `multipass.exe` client alive even while
the `multipassd` service and VMs remain healthy. After the two excluded
2026-07-13 runs, seven such clients were consuming CPU. Each was inspected by
exact PID, creation time, executable path, and complete command line before
only those seven exact client PIDs were terminated. `multipassd`, `vmwp.exe`,
and both managed VMs were left untouched; the next clean 32-case run passed,
and the later expanded historical campaign passed all 36 cases.

First inventory clients and correlate their age and CPU use:

```powershell
$clients = @(Get-CimInstance Win32_Process -Filter "Name='multipass.exe'" |
    Select-Object ProcessId,CreationDate,ExecutablePath,CommandLine)
$clients | Sort-Object CreationDate | Format-List
$clients | ForEach-Object {
    Get-Process -Id ([int]$_.ProcessId) |
        Select-Object Id,StartTime,CPU,Path
}
```

A candidate is not safe to stop merely because its name is `multipass.exe` or
it is using CPU. Its complete command line and age must match a known completed
or timed-out harness invocation. For each candidate, copy the exact command
line from the inventory, then re-read and compare that same PID immediately
before termination:

```powershell
$clientPid = 12345 # Replace with one inspected stale client PID.
$expectedCommandLine = 'copy the complete inspected command line here'
$live = @(Get-CimInstance Win32_Process -Filter "ProcessId=$clientPid")
if ($live.Count -ne 1 -or $live[0].Name -cne 'multipass.exe' -or
    -not $live[0].CommandLine -or
    $live[0].CommandLine -cne $expectedCommandLine) {
    throw 'Client PID or command line changed; nothing was stopped'
}
Stop-Process -Id $clientPid -Force
```

Repeat that verification separately for each confirmed stale client. Never
use `Stop-Process -Name multipass*` or another blanket kill. Do not stop
`multipassd`, the `Multipass` service, `vmwp.exe`, or a VM as part of stale
client cleanup. If a PID has been reused, its command line is incomplete, or
the invocation may still be active, leave it alone and investigate further.

After clearing verified clients, recover guest ownership from the failed
run's evidence. The external case name is not the ownership key: read the last
successful `prepare` command for that case and use the run ID, internal case
ID, and interface from its argument vector:

```powershell
$run = 'wg20260713T183821Z'
$report = Get-Content "./tests/hyperv/results/$run/report.json" -Raw |
    ConvertFrom-Json
$failed = @($report.results | Where-Object status -EQ 'FAIL')[-1]
$report.commands |
    Where-Object { $_.case -ceq $failed.name -and $_.label -ceq 'prepare' } |
    ForEach-Object { $_.argv -join ' ' }
```

For the first excluded run, the logged ownership tuple was
`wg20260713T183821Z m13 wgt0`; for the second it was
`wg20260713T184512Z m10 wgt0`. Cleanup was issued on both guests for each
applicable tuple, for example:

```powershell
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup wg20260713T183821Z m13 wgt0
multipass exec wgtcp-b -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup wg20260713T183821Z m13 wgt0
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup wg20260713T184512Z m10 wgt0
multipass exec wgtcp-b -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup wg20260713T184512Z m10 wgt0
```

Use values from the current failed run rather than reusing these historical
ones. The ownership guard will reject a mismatched tuple; do not bypass it or
delete an interface by name.

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
    builds the fork tool, copies the stock tool, and builds production, DEBUG,
    and isolated fault-injection fork modules with `W=1`. It verifies their
    parameter isolation with `modinfo`.
12. Records a schema-2 `Ready` state with exact Hyper-V VM and switch IDs,
    source base, host Git status, and archive hashes.

Step 7 uses a process-level timeout because Multipass 1.16.3 does not provide a
timeout switch for `multipass stop`. In that release, `--time` means "wait this
long before initiating shutdown," and `stop --timeout` is unsupported. The
provisioner launches exactly `multipass stop <managed-name>`, redirects its two
streams to per-guest result logs, waits 120 seconds, and terminates only that
exact child client PID if it does not exit. The daemon, VM worker, other
Multipass clients, and other guests are not stopped by this timeout path.

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
`iproute2`, `iperf3`, `tcpdump`, Python, stock `wireguard-tools`, and the
`nftables` and `conntrack` packages required by the NAT44 regression. It checks
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
/var/lib/wireguardtcp/artifacts/modules/<kernel>/wireguard-fork-fault.ko
```

`wireguard-fork.ko` is the production artifact. `wireguard-fork-debug.ko`
enables the ordinary DEBUG initialization selftests but does not expose stream
fault controls. `wireguard-fork-fault.ko` additionally defines the explicit
`WG_TCP_FAULT_INJECTION` build guard and is used only by the isolated
`hostile-stream` case. After cleanly building each variant, `guest-build.sh`
uses `modinfo` to prove that all `tcp_test_*` parameters are absent from the
production and ordinary DEBUG artifacts and present in the fault artifact.
Reuse-only verification recomputes that metadata, compares it with the saved
manifests, repeats the isolation checks, and rejects a manifest for a different
running kernel.

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
| An attempted `multipass stop --timeout` was unsupported, while `--time` was initially mistaken for a command timeout. | On Multipass 1.16.3 run plain `multipass stop <name>` as an exact child, wait 120 seconds, retain its output logs, and terminate only that child PID on timeout. `--time` schedules a delayed shutdown and is not used. |
| Multipass service stop could hang even after UAC was accepted. | Close clients first; verify the `multipassd` service PID before a forced stop; reboot if service recovery does not remain stable. |
| Host timeouts left orphaned `multipass.exe` clients consuming CPU while the service and VMs remained healthy. | Inspect PID, age, executable, CPU, and complete command line; re-read and terminate only each exact verified stale client PID. Never blanket-kill Multipass or stop `multipassd`; then cleanup guest ownership with the run/internal case ID recorded by the successful `prepare` command. |
| An interrupted elevated runner survived its parent and continued launching guest cases. | Inspect the exact `python regression.py` PID and child `multipass exec` command line, stop only that verified tree or wait for its bounded guest timeout, then verify guest links/processes before rerunning. Do not treat module-unload refusal from the overlap as a product failure. |
| `multipass list` cannot connect after orphan cleanup or VM restart. | Confirm the exact orphan is gone and the Windows `Multipass` service is truly unresponsive; obtain administrator UAC for a targeted service restart, wait for both existing VMs, and re-run provisioning. Do not delete VMs or switches as a socket-recovery shortcut. |
| Private NICs could steal attention from management-network diagnosis. | The management NIC and both data-plane NICs have separate roles; provisioning checks management before and private addresses after attachment. |
| Direct cloud-init/netplan activation could strand a guest. | Render per-guest files, use MAC matching and `set-name`, validate with `netplan generate`, preserve a backup, and activate only after adapters exist. |
| Unsigned module insertion was blocked and memory allocation varied. | Disable Secure Boot and Dynamic Memory while each managed VM is stopped. |
| A plain Windows-created tar did not provide a trustworthy Git worktree representation, especially for symlinks and deletions. | Combine `git archive HEAD`, a path-list overlay tar, and an explicit deletion manifest; hash both archives and verify them in the guest. |
| Re-running setup could accidentally adopt or remove a pre-existing same-named VM. | Persist immutable Hyper-V VM IDs beside owner/configuration state, verify the ID before every managed change and again before deletion, migrate old name-only state only on a normal non-delete run, and require a separate force flag for unmanaged or replaced collisions. |
| Building in the transferred tree left stale outputs and obscured provenance. | `rsync --delete` into an isolated guest build root and store a build manifest with the kernel release and source identity. |
| Switching stock and fork modules could unload a driver with live interfaces. | `guest-module.sh` enumerates root and network-namespace WireGuard links and refuses to unload until owned links are removed. |
| Interrupted tests left interfaces or an underlay down. | Each case writes ownership state before mutation; cleanup restores only that case's interfaces, namespaces, and underlay. A later run refuses abandoned ownership. |
| A NAT test could accidentally alter host or VM management networking. | Build its client, router, server, forwarding sysctl, nftables table, and conntrack reset in owned PID-suffixed guest network namespaces; record veth names before their brief root-namespace creation and delete only recorded resources during trap or managed-case cleanup. |
| Bringing a keyless preplumb WireGuard device down removed its device route, and adding the route while it was already down failed. | Configure the new listener and mark without a key or peer, keep the device administratively up so its path-specific inner route persists, and activate its identity only after the stale old-path record is confirmed queued. |
| Repeated probes could stage more than one delayed record or obscure exactly when the old carrier was cut off. | Submit one old-path echo request, poll TX and netem backlog without resending, record enqueue bounds, then explicitly bring the old device down and require its exact `ESTABLISHED` tuple to disappear before new-peer activation. |
| Failure logs were too narrow to diagnose TCP state. | Capture public WireGuard selectors, listening sockets, established TCP details, and kernel messages after a per-case log reset; never collect private keys. |
| Printing every quiet-window sample made long timing diagnostics difficult to read. | Keep successful polling quiet; on acquisition failure print compact first/previous/last valid signatures, the last invalid signature, sample counts, reset count, and longest stable duration. |
| Host Python discovery could select the Windows Store alias or hang. | The wrapper probes real `python.exe`/`py.exe -3` applications with a 10-second process timeout. |
| A single failing case prevented useful independent coverage. | The runner supports `-KeepGoing`, repeatable `--only-case`, production/DEBUG TCP variants, a dedicated isolated fault-module case, and always performs best-effort owned cleanup. Bounded command probes run first, and loss of all guest command execution is classified as infrastructure failure and aborts even with `-KeepGoing`. |

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

Run the guest-local NAT44 regression by itself with:

```powershell
./tests/hyperv/Provision-HyperV.ps1
python ./tests/hyperv/regression.py `
    --only-case tcp-nat44-dual-reachable
```

Run the focused reconnect, roaming, half-open, and hostile-stream set with:

```powershell
python ./tests/hyperv/regression.py `
    --keep-going `
    --only-case tcp-policy-reconnect-churn `
    --only-case tcp-nat44-single-private-address-roam `
    --only-case tcp-nat44-half-open-recovery `
    --only-case tcp-debug-hostile-stream
```

The policy-churn case reserves up to 900 seconds per guest command. Each
roaming mode reserves at least 600 seconds on the host and runs under a
570-second guest timeout, leaving the runner time to collect state and clean up.

### NAT44 topology, assertions, and cleanup

`tcp-nat44-dual-reachable` invokes `tests/tcp-nat-netns.sh dual-reachable`
independently on `wgtcp-a` and `wgtcp-b`. Each invocation creates three
PID-suffixed namespaces and two veth pairs; it does not connect the two VMs or
use their Hyper-V data-plane adapters:

```text
wgtcp-nc-<pid>                  wgtcp-nr-<pid>                 wgtcp-ns-<pid>
private client                 NAT router                     public server
10.240.0.2/24  <---------->  10.240.0.1/24
                              192.0.2.1/24  <---------->      192.0.2.2/24
wga 10.212.0.1/32                                             wgb 10.212.0.2/32
listen 52221                                                  listen 52220
                              public forward 52241 -> 52221
```

The private client routes through `10.240.0.1`. Only the router namespace has
IPv4 forwarding enabled. Its namespace-local nftables table `ip wgtcp_nat`
SNATs a client connection to `192.0.2.1:41001` and DNATs server connections to
`192.0.2.1:52241` back to `10.240.0.2:52221`. Both peers configure explicit
dial targets: the client uses `192.0.2.2:52220`, and the server uses the public
forward `192.0.2.1:52241`.

The pass criteria require all of the following on each guest:

1. Tunnel pings succeed in both directions.
2. Two-second persistent keepalives advance both peers' transmitted-byte
   counters and traffic remains usable.
3. nftables SNAT and DNAT packet counters are nonzero and `conntrack -L`
   contains both expected translated TCP tuples.
4. After the router namespace flushes its conntrack state and changes only the
   outbound SNAT port from `41001` to `41002`, tunnel traffic reconnects in
   both directions and the new translated tuple is established.
5. The server's configured client endpoint remains
   `192.0.2.1:52241`; neither observed SNAT source port is promoted into the
   configured remote listen port.
6. A live server `FwMark` change forces its outbound carrier to reconnect, the
   router's forwarding chain counts a new SYN to the DNATed listener, and
   bidirectional tunnel traffic remains usable.

This topology is intentionally called `dual-reachable`: the private client's
listen service is reachable through an explicit DNAT rule, so it does not test
ordinary responder-only operation behind NAT without a forward. It also does
not implement or prove authenticated accepted-socket promotion. After the
source-port rebind, `old_accepted_carrier=retained|retired` records whether the
old server-side accepted stream is still visible, but either value is accepted.
Flushing middlebox state does not guarantee that an endpoint immediately
receives FIN or RST, and deterministic peer-bound duplicate-carrier retirement
belongs to the future promotion design.

`nft` comes from the Ubuntu `nftables` package and `conntrack` from the Ubuntu
`conntrack` package; `guest-bootstrap.sh` installs both explicitly. The test
checks for those commands before creating resources. Forwarding changes,
nftables rules, and `conntrack -F` execute with `ip netns exec` in the router
namespace, never in the guest root namespace.

Before each namespace or root-visible veth is created, its name is written to
the case's auxiliary ownership directory. The script's `EXIT` trap prints
namespace, socket, nftables, and conntrack diagnostics on failure, then deletes
only those recorded namespaces and links. If the host runner is interrupted,
`guest-node.sh cleanup RUN CASE wgt0` reads the same ownership record and
removes any surviving resources. The PID suffix prevents parallel name
collisions; creation also refuses a pre-existing name instead of adopting it.
Neither cleanup path changes the Multipass management NIC, `path0`, `path1`,
host Hyper-V switches, or host NAT policy.

### Dual-router roaming and half-open recovery

`tcp-nat44-dual-router-address-roam` invokes
`tests/tcp-roaming-netns.sh dual-router` independently inside each VM. The
disposable topology has one client namespace, old and new router namespaces, a
shared public-fabric namespace, and one server namespace. The client has `wga`
on the old private path and `wgc` on the new private path. Both devices use the
same private key only after new-path activation, while the server has one peer
whose AllowedIPs include both client tunnel addresses. The two NAT routers
expose the same configured forward, TCP `52241`, from public addresses
`192.0.2.1` and `192.0.2.129`; their fixed SNAT ports are `41001` and `41002`.

Both outer policy tables are installed before peer activation. Inner routes
also specify path-specific preferred sources: old traffic uses
`10.212.0.1 -> 10.212.0.2`, while new traffic uses
`10.213.0.1 -> 10.213.0.2`. The new device is initially configured only with
TCP listener `52222` and `FwMark 0x241`; it remains keyless and peerless. It
must remain administratively up because Linux removes its device route on link
down. This is preplumb, not identity activation.

After a 12-second exact-tuple pre-stage baseline and refreshing the old path's
key age, the test submits exactly one old encrypted ICMP record into a selective
110-second netem delay. It does not send
additional probes while waiting: it polls WireGuard TX and qdisc backlog until
both prove that record was accepted, and records before/after enqueue bounds.
It then brings `wga` down, requires its exact client `ESTABLISHED` carrier to
disappear, and only then installs the shared key and server peer on `wgc`.
Path-specific preferred sources keep these route lookups deterministic.

The new route must establish bidirectional traffic, move the authenticated
server endpoint to `192.0.2.129:52241`, preserve the configured forwarded port,
and produce a new-DNAT reverse SYN. A 12-second automatic-authentication gate,
longer than twice the five-second provisional idle timeout, precedes the
reset-on-change sampler. That sampler then requires one
exact socket, mark, endpoint, handshake, NAT-counter, and transfer-counter
signature to remain stable for 16 continuous seconds. After the old record is
released, an nftables counter tied to the old tunnel source proves delivery of
that data record while the endpoint and reverse-dial target remain new. A
second 16-second quiet barrier precedes a server `FwMark` change. The resulting
carrier must pass another 12-second automatic-authentication gate and create a
different marked outbound tuple through the new DNAT.

Socket assertions distinguish active transport from normal TCP cleanup. The
pre-`FwMark` tuple must leave `ESTABLISHED`; a residual terminal entry such as
`TIME-WAIT` may remain and is reported as `present` without being treated as an
active duplicate carrier. Quiet polling does not print every sample. On
failure it emits compact first, previous, and last valid signatures, the last
invalid signature, sample and reset counts, and the longest stable duration.

The reported physical topology is `independent-outbound-pair`: this is
explicitly a same-identity, two-device carrier surrogate. The
`tcp-policy-reconnect-churn` case owns same-device route, address, uplink, and
mark movement. The dual-router case does not by itself prove a general
responder-only NAT design, simultaneous-connection arbitration, or arbitrary
provider behavior. Static public-key ordering controls Noise initiation only;
the test does not instrument it as physical TCP-carrier arbitration.

`tcp-nat44-half-open-recovery` runs the same script in `half-open` mode with a
single NAT router. It first captures complete, stable accepted and outbound
socket sets during a four-second `SYN-SENT`-free window. An owned drop-only
nftables table then makes the exact established carrier half-open. The test
requires the exact socket's `TCP_INFO` retransmission accounting and namespace
`RetransSegs` to advance before accepting a reconnect SYN. After removing only
that table, it requires a distinct client/server tuple pair correlated by the
unchanged conntrack state, absence of the old outbound tuple, and independent
RX-counter advances in both tunnel directions with keepalives disabled.

The half-open namespace uses `tcp_retries2=5` and `tcp_syn_retries=3` solely to
make the regression bounded. These values accelerate established-carrier
failure detection and bound failed SYN retries; the timings do not claim
production-default Linux recovery latency.

After source changes, rerun the provisioner before the regression. This creates
and records a new source overlay; restoring a Multipass snapshot does not
replace that provenance step. Machine-readable results and command logs remain
under the ignored `tests/hyperv/results/<run-id>/` directory. The curated,
committed outcome is [`RESULTS.md`](RESULTS.md).

Historical focused run `wg20260714T084959Z` passed the dual-router case on both
guests: **1 PASS, 0 FAIL, 0 SKIP** in 238.500 seconds. Run
`wg20260714T070320Z` had already passed policy churn and half-open recovery on
both guests; its dual-router entry failed in the then-incomplete topology and
queue-accounting setup. That failed entry and the later keyless-route setup
iterations are infrastructure/test-mechanics diagnostics, not evidence of a
WireguardTCP behavior failure. The successful `084959` run is the product
evidence for this case. A combined focused rerun and the expanded full campaign
remain pending for the final snapshot.

The historical valid brokered-host campaign `wg20260714T010310Z` started at
2026-07-14 01:03:10 UTC and passed all 36 cases with no failures or skips in
558.520 seconds across 541 recorded commands. Its preflight passed all 107
local source-contract checks on both Ubuntu 24.04 guests running kernel
`6.8.0-124-generic`.

The expanded cases completed live configuration round trips through `showconf`,
`setconf`, and `syncconf`, plus `wg-quick` SaveConfig serialization, while
keeping secret-bearing files guest-local and mode 0600. They also preserved
scoped link-local IPv6 endpoint zones and carried tunnel traffic over link-local
outer TCP connections. The
isolated fault artifact produced per-guest deltas of `80/4/4/437` on
`wgtcp-a` and `80/4/4/442` on `wgtcp-b` for short
writes/prefixes/resynchronizations/queue drops, followed by successful traffic
recovery after clearing the controls.

The remaining validation boundary covers authenticated carrier promotion for
responder-only NAT without a forward, deterministic stale-carrier retirement,
arbitrary NAT/provider behavior, a cookie-equivalent TCP pre-authentication
cost defense, VRF and namespace-move behavior, broader MTU and fragmentation
coverage, long-duration multi-flow soak testing, and wider kernel-version and
distribution breadth.

Focused hardening run `wg20260713T225629Z` used overlay SHA-256
`efe576b3c226089de2bbbd23670c599f78a45d8ec315c896cf6c6494a9692dd7` and
passed the real `wg-quick` save/down/up reload plus the guest-owned one-shot
hostile case: **2 PASS, 0 FAIL, 0 SKIP** in 134.149 seconds. Reuse-only artifact
verification and all 103 source contracts then passed independently on both
guests.

Two immediately preceding runs are excluded from product evidence.
`wg20260713T183821Z` completed 12 passing cases before a `wgtcp-a` collection
client reached its 180-second host timeout. `wg20260713T184512Z` completed nine
passing cases before the same failure pattern. Seven orphaned `multipass.exe`
clients were verified and stopped by exact PID as described above, while the
service and VMs remained running; exact ownership cleanup used `m13` and `m10`
from the respective logged `prepare` commands. The next clean 32-case campaign
passed, and the later expanded historical run passed all 36 cases. These aborts were
control-client infrastructure failures, not product regressions or partial
release results.

A much earlier sandboxed attempt, `wg20260712T200006Z`, could not reach TCP
port 22 on either management address and no guest command succeeded; it was a
0-of-26 infrastructure run, not regression evidence. Treat either pattern as
a control-channel failure, recover the relevant client or Multipass/Default
Switch layer, perform exact ownership cleanup when preparation occurred, and
start a new run rather than interpreting the case list as product failures.

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
