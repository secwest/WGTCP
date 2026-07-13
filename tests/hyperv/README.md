# Hyper-V regression lab

This harness provisions two `release:24.04` Ubuntu Multipass instances on
Hyper-V and runs the WireguardTCP cross-host regression suite. Each guest
receives the normal Multipass management NIC plus two isolated data-plane NICs:

The complete host bootstrap, VM creation sequence, recovery procedures, and
bring-up process changes are recorded in
[`HYPERV_SETUP.md`](HYPERV_SETUP.md). This page is the shorter operating guide.

| Guest | Resources | `path0` | `path1` |
| --- | --- | --- | --- |
| `wgtcp-a` | 4 vCPU, 8 GB RAM, 60 GB disk | `10.77.0.10/24` | `10.77.1.10/24` |
| `wgtcp-b` | 4 vCPU, 8 GB RAM, 60 GB disk | `10.77.0.11/24` | `10.77.1.11/24` |

`path0` and `path1` use separate private Hyper-V switches. Their deterministic
MAC addresses and addresses make roaming and path-transition tests repeatable.
The management NIC remains available for package installation and Multipass
control.

## Prerequisites

- Windows 10/11 Pro, Enterprise, or Education with hardware virtualization
  enabled in firmware.
- PowerShell 7 for the provisioning and regression wrappers.
- A Windows account in the local `Hyper-V Administrators` group. Sign out and
  back in, or reboot, after the account is added.
- At least 16 GB of free RAM and 120 GB of free disk for the two guests.
- Canonical Multipass using its `hyperv` driver.
- Python 3 on the Windows host for `regression.py`.

From an elevated PowerShell, enable Hyper-V and install a locally downloaded,
verified Canonical Multipass MSI:

```powershell
.\tests\hyperv\Enable-HyperV.ps1 `
    -MultipassMsi C:\Installers\multipass-installer.msi `
    -StatePath .\tests\hyperv\results\host-enable.json
```

The bootstrap script pins both the expected SHA-256 and Canonical Authenticode
signing certificate for the tested installer. Supplying a different release
requires intentionally updating both expected values after independent
verification; it will not install an unrecognized MSI.

Reboot when `RestartNeeded` is `true`, then open a new PowerShell session.
Confirm the backend before provisioning:

```powershell
multipass get local.driver
multipass networks
```

The driver must be `hyperv`. On a fresh Windows installation Hyper-V is the
Multipass default; otherwise use `multipass set local.driver=hyperv` after
stopping instances belonging to the previous backend.

## Provision

Run from the repository root:

```powershell
.\tests\hyperv\Provision-HyperV.ps1
```

Provisioning does not require a fully elevated token when the invoking process
has an active `Hyper-V Administrators` token. Test the exact PowerShell or
automation context first with `Get-VM -Name wgtcp-a,wgtcp-b`. If it returns
`Access denied`, use a new elevated PowerShell 7 session or an approved
brokered administrator shell for both that check and provisioning. The
one-time host bootstrap still requires elevation to enable Windows features,
install Multipass, and add group membership.

Provisioning creates `WGTCP-Path0` and `WGTCP-Path1`, launches each guest on its
management NIC with the standard Multipass cloud-init, and proves guest command
execution before changing its networking. It then transfers and validates the
lab netplan, stops the guest once to attach the two private adapters, and
activates that netplan on the next boot. It then transfers the current source
tree and runs the guest bootstrap and build steps.
The same controlled stop disables Secure Boot and Dynamic Memory on these two
managed VMs so the locally built unsigned test module can load and each guest
retains its requested 8 GB. The source transfer is intentionally not a
plain Windows tar: it combines `git archive HEAD` with an overlay of modified
and untracked files plus a deletion manifest. This preserves Git symlinks and
tests the exact Git-visible snapshot described by the captured status. Ignored
and other Git-unreported filesystem content is excluded. The recorded commit,
status, and SHA-256 hashes are written beneath `tests/hyperv/results/`.

Each guest build produces three fork kernel artifacts. `wireguard-fork.ko` is
the production build, `wireguard-fork-debug.ko` enables initialization
selftests, and `wireguard-fork-fault.ko` additionally enables the isolated
hostile-stream controls. `guest-build.sh` uses `modinfo` to require every
`tcp_test_*` parameter in the fault artifact and to prove those parameters are
absent from the production and ordinary DEBUG artifacts. Reuse-only
`--verify` calls recompute live module metadata, compare it with the saved
manifests, repeat parameter-isolation checks, and validate the manifest kernel.

The command is idempotent for instances recorded in its state manifest. It
refuses to adopt or delete same-named instances that it did not create. Rebuild
managed guests from clean Ubuntu images with:

```powershell
.\tests\hyperv\Provision-HyperV.ps1 -Recreate
```

`-ForceRecreateUnmanaged` is deliberately separate and should only be used
after manually confirming that colliding `wgtcp-a` or `wgtcp-b` instances are
disposable. `-SkipGuestBuild` transfers and bootstraps without compiling.

## Run regressions

```powershell
.\tests\hyperv\Run-HyperVRegression.ps1
```

The runner writes machine-readable JSON, logs, and a Markdown summary to
`tests/hyperv/results/`. A failing case returns a nonzero exit code. Use
`-KeepGoing` to execute independent later cases after a case failure. Before
the case loop, bounded `multipass exec <guest> -- true` probes must succeed for
both managed guests. Loss of the guest command channel is an infrastructure
failure and aborts even with `-KeepGoing`; do not let a raw SSH or
`Test-NetConnection` probe wait indefinitely.

For a focused configured-path diagnostic with the DEBUG module, invoke the
Python runner directly. `--only-case` may be repeated to select more than one
named case:

```powershell
python .\tests\hyperv\regression.py `
    --only-case tcp-configured-path-change `
    --tcp-kernel-variant fork-debug
```

The `tcp-debug-hostile-stream` case selects `wireguard-fork-fault.ko` and
restores production inside one guest-side command. An `EXIT` trap covers normal
failure and catchable termination, and the host requires an explicit restore
acknowledgement from both guests. After a guest power loss or uncatchable
process termination, inspect the module variant before resuming. The fault
artifact is not a general TCP kernel variant and should not be used for
unrelated cases.

On a managed-pair failure the runner captures both guests before cleanup. The
failure logs include public WireGuard state, listening and connected TCP
sockets, and the kernel log emitted after the per-case reset; private keys are
never collected.

The 35 cases include preflight validation; all 16 combinations of stock/fork
kernels and stock/fork tools in UDP mode; focused UDP/TCP namespace,
authenticated roaming, random-port, and output tests; DEBUG initialization
selftests; stock kernel capability and live-mode-change guards, including TCP
listen-port mutation and random-port coupling; and TCP cases covering static
traffic, asymmetric listen ports, stock-tool management, configuration round
trips, configured underlay migration, full-tunnel live `FwMark` changes,
route/source/uplink reconnects, ULA and scoped link-local IPv6 carriers,
dual-stack listeners, authenticated-carrier lifetime, and isolated
short-write/parser/queue-pressure faults with recovery.
The latest committed campaign summary is in [`RESULTS.md`](RESULTS.md).

Each case records interface and underlay ownership before making changes and
restores both during cleanup. If the host runner itself is terminated, a later
run refuses to claim the abandoned interface and reports its original
`RUN/CASE`; clean that exact state on both affected guests with:

```powershell
multipass exec wgtcp-a -- sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh cleanup RUN CASE wgt0
```

The TCP path-change case explicitly updates both configured endpoints before
moving to `path1` and cycling both WireGuard links down and up. The runtime
parity cases additionally exercise authenticated dial-target updates and
notifier-driven reconnects after live route, source-address, uplink, and
`FwMark` changes. They also validate independent asymmetric listen ports,
IPv4/IPv6 listeners with an IPv6 outer carrier, and a carrier that remains
authenticated and usable for 40 seconds on each guest.

The configuration case round-trips TCP state through `showconf`, `setconf`,
`syncconf`, and an actual `wg-quick` save/down/up reload. Secret-bearing files
remain guest-local, under a mode-0700 temporary directory, with mode 0600. The
link-local case proves that `%interface` endpoint scopes survive configuration
and serialization and that both guests carry tunnel traffic over scoped IPv6
TCP connections.

The hostile-stream case uses only the isolated fault module. After the tunnel
is established, it forces real short writes, bounded garbage prefixes and
parser resynchronization, and deterministic queue pressure. The recorded
per-guest counter deltas were `80/4/4/2380` on `wgtcp-a` and `80/4/4/2378` on
`wgtcp-b` for short writes/prefixes/resyncs/drops; normal traffic recovered on
both guests after the controls were cleared.

Run `wg20260713T221904Z` passed all of these checks for **35 PASS, 0 FAIL, 0
SKIP** in 452.476 seconds, recording 533 commands. Its source identity is HEAD
`7c398d543158b5ef77d8c822b64f90bb99229a44`, base archive SHA-256
`5133a0d1c67879de26510d242d01d198b08e71ccbe305bcd197eec13ffc15bc7`, and
dirty overlay SHA-256
`9d107084a83ab3778b09e1de0ef87804b1ffea16d2d474009d57e9be247262a3`.
Preflight passed all 100 local source-contract checks on each guest running
Ubuntu 24.04 with kernel `6.8.0-124-generic`.

The same campaign proved the live TCP listen-port guard returns `EBUSY`
without changing either listener. After the interface was brought down,
`ListenPort = 0` selected a nonzero random port and the TCP listener and its
UDP companion used that same port. These checks cover the tested lifecycle;
they do not replace broader bind-race or multi-namespace stress testing.

The excluded runs `wg20260713T183821Z` and `wg20260713T184512Z` completed 12
and nine passing cases, respectively, before the `wgtcp-a` collection client
reached its 180-second host timeout. Seven orphaned, CPU-spinning
`multipass.exe` clients were inspected by exact PID, age, and command line and
then terminated by exact PID without stopping `multipassd` or either VM. The
guest state was ownership-cleaned using the internal IDs from the logged
successful `prepare` commands (`m13` for the first run and `m10` for the
second). The next clean 32-case campaign passed, and the later expanded run
above passed all 35 cases. These were control-client infrastructure aborts, not
product failures or partial campaigns.

When a host timeout leaves Multipass clients consuming CPU, inspect before
terminating anything:

```powershell
$clients = @(Get-CimInstance Win32_Process -Filter "Name='multipass.exe'" |
    Select-Object ProcessId,CreationDate,ExecutablePath,CommandLine)
$clients | Sort-Object CreationDate | Format-List
$clients | ForEach-Object {
    Get-Process -Id ([int]$_.ProcessId) |
        Select-Object Id,StartTime,CPU,Path
}
```

Match each stale client to an old, timed-out command by exact PID, command
line, and age, re-read that PID immediately before stopping it, and terminate
only that exact `multipass.exe` client. Never use a blanket process-name kill,
and do not stop `multipassd`, `vmwp.exe`, or either VM for this condition. Then
read the failed run's last successful `prepare` commands and invoke
`guest-node.sh cleanup` on both guests with their logged run ID, internal case
ID, and interface. The fully PID-checked procedure and the exact `m13`/`m10`
recovery record are in
[`HYPERV_SETUP.md`](HYPERV_SETUP.md#orphaned-multipass-client-recovery).

The runtime evidence still stops short of authenticated carrier promotion for
arbitrary NAT ephemeral-port roaming, a cookie-equivalent TCP pre-authentication
cost defense, VRF and namespace-move behavior, broader MTU and fragmentation
coverage, long-duration multi-flow soak testing, and wider kernel-version and
distribution breadth.

Focused hardening run `wg20260713T225629Z` passed `tcp-config-roundtrip` and
`tcp-debug-hostile-stream` for **2 PASS, 0 FAIL, 0 SKIP** in 134.149 seconds.
Both guests returned `wg_quick_roundtrip=pass` and
`restored_kernel_variant=fork`; the one-shot fault deltas were `80/4/4/434` on
`wgtcp-a` and `80/4/4/441` on `wgtcp-b`. Its overlay SHA-256 was
`efe576b3c226089de2bbbd23670c599f78a45d8ec315c896cf6c6494a9692dd7`.

Useful inspection commands are:

```powershell
multipass exec wgtcp-a -- ip -br address
multipass exec wgtcp-b -- ip -br address
multipass shell wgtcp-a
```

Multipass snapshots are optional convenience checkpoints, not source-of-truth
test inputs. After a successful provision, create them explicitly when the
installed Multipass version supports snapshots:

```powershell
multipass snapshot wgtcp-a --name clean-built
multipass snapshot wgtcp-b --name clean-built
```

Rerunning the provisioner always transfers a newly hashed worktree snapshot,
so restoring an older checkpoint cannot silently select stale source.

## Cleanup

The harness has no implicit cleanup command. This avoids deleting unrelated
VMs or switches. Before deleting each guest, follow the schema-2 cleanup block
in [`HYPERV_SETUP.md`](HYPERV_SETUP.md#9-recovery-and-cleanup-boundaries): it
loads the recorded Hyper-V GUID, calls `Get-VM` from the invoking elevated or
brokered token, compares the exact live GUID, and only then issues that guest's
`multipass delete --purge`. A name-only check is not deletion authority.

After both ID-verified VM deletions, load each schema-2 `SwitchIdentities`
record and compare its `HyperVSwitchId` with the exact live switch `Id`. Before
either removal, `Get-VMNetworkAdapter -All` must report zero adapters attached
to that switch; any managed or unrelated adapter is a hard stop. The complete
ID-checked removal block is in
[`HYPERV_SETUP.md`](HYPERV_SETUP.md#9-recovery-and-cleanup-boundaries).

```powershell
$attached = @(Get-VMNetworkAdapter -All | Where-Object SwitchName -CEQ 'WGTCP-Path0')
if ($attached.Count -ne 0) { throw 'WGTCP-Path0 still has adapters' }
# Now use the guide's persisted-GUID re-read and exact-object removal block.
```

If launch hangs, inspect `multipass list`, `multipass networks`, and the guest's
`/var/log/cloud-init*.log`. Windows' Hyper-V Default Switch supplies management
DHCP/DNS and is established before the lab netplan or private adapters are
installed. Endpoint security or a damaged Default Switch can prevent Multipass
from reaching a guest even when the two private test paths are healthy.
