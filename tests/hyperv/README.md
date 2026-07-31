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

### Current follow-up status

The merged 2026-07-31 tree passes 213 local source and contract tests.
Production, DEBUG, and fault-injection variants built on both managed Ubuntu
guests. Focused run `wg20260731T074807Z` passed the four current NAT/recovery
cases with clean kernel logs: single-private SNAT-only operation,
dual-reachable initiation with either authenticated direction retained,
outbound-only address/port roaming, and half-open recovery. The older 36-case
campaign remains the latest complete broad registry run; it is historical
compatibility evidence rather than the acceptance gate for the new promotion
path.

Do not interrupt a focused runner by stopping only its visible parent and then
immediately start another run. An elevated child `python regression.py` and its
`multipass exec` may still own a guest case. Inspect the exact host process tree
and guest harness, allow the bounded guest timeout/trap to finish or terminate
only the verified tree, and confirm both guests have no WireGuard test links
before rerunning. If the orphan is gone but `multipass list` cannot connect,
the targeted Windows `Multipass` service restart requires administrator UAC;
see the recovery guide rather than deleting VMs or switches.

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
The bootstrap explicitly installs the `nftables` and `conntrack` Ubuntu
packages used by the guest-local NAT44 case; `nft` and `conntrack` must both be
available before that case can run.
The same controlled stop disables Secure Boot and Dynamic Memory on these two
managed VMs so the locally built unsigned test module can load and each guest
retains its requested 8 GB. The source transfer is intentionally not a
plain Windows tar: it combines `git archive HEAD` with an overlay of modified
and untracked files plus a deletion manifest. This preserves Git symlinks and
tests the exact Git-visible snapshot described by the captured status. Ignored
and other Git-unreported filesystem content is excluded. The recorded commit,
status, and SHA-256 hashes are written beneath `tests/hyperv/results/`.

The tested Multipass 1.16.3 `stop` command has no command-timeout option.
Its `--time` option schedules a delayed shutdown, and `stop --timeout` is not
supported. The provisioner therefore starts exactly `multipass stop <name>` as
a child process, waits up to 120 seconds, and, on timeout, terminates only that
exact client PID. Standard output and error are retained as
`stop-<name>.stdout.log` and `stop-<name>.stderr.log`. Do not replace this with
`--time 120`, which would delay the shutdown, or with a process-name-wide kill.

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

The currently recorded managed identities are listed below. These GUIDs are a
record of this lab, not names to reuse when creating another lab; the
provisioner must persist the IDs returned by that host and compare them before
each managed change.

| Object | Recorded Hyper-V identity |
|---|---|
| `wgtcp-a` | `69fcac18-eb3f-46c1-a32f-4aa421e54e42` |
| `wgtcp-b` | `48902a17-0dfe-4bbb-ab4f-86bcfb97f96d` |
| `WGTCP-Path0` | `a795c92c-e6d9-4ece-ad04-f835cfd70e93` |
| `WGTCP-Path1` | `2f6d2b77-2ade-42e7-af23-417eab54ec2f` |

For the successful dual-router run, the transferred source snapshot was HEAD
`c1d898a1f48c09c8a64c32fe76b5d2ddb4737624`, base archive SHA-256
`6dd8fe9466b068173f7aec42b7ce66100ab5aa563485ffeca55e261eb5406b7a`, and
Git-visible overlay SHA-256
`899b5ec7f1126852b6147f41f39dc900807768365979ad547a66d95874d25fdc`.
The overlay is rebuilt on every provision from modified and untracked
Git-visible files, so the hash changes as worktree changes are incorporated.

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

### Guest-local NAT44 cases

Provision the current tree first so both guests have the NAT dependencies and
test script, then run only the NAT case with:

```powershell
.\tests\hyperv\Provision-HyperV.ps1
python .\tests\hyperv\regression.py `
    --only-case tcp-nat44-single-private `
    --only-case tcp-nat44-dual-reachable
```

`tcp-nat44-single-private` is the operational NAT contract. The private client
has the public server's reachable endpoint and dials through SNAT; the public
server has no reverse endpoint, DNAT, or forwarded port. Authenticated traffic
promotes the accepted carrier for bidirectional use. The case verifies
keepalive activity, `41001` to `41002` source-port rebinding, authenticated
reacquisition, and old-carrier retirement.

The dual-reachable case executes this independent disposable topology inside
each VM:

| Role | Namespace | Outer address | WireGuard address |
|---|---|---|---|
| Private client | `wgtcp-nc-<pid>` | `10.240.0.2/24` | `10.212.0.1/32` |
| NAT router | `wgtcp-nr-<pid>` | `10.240.0.1/24`, `192.0.2.1/24` | none |
| Public server | `wgtcp-ns-<pid>` | `192.0.2.2/24` | `10.212.0.2/32` |

The router applies SNAT to the client's outbound carrier and DNATs public TCP
port `52241` to the client's configured listen port `52221`; the server listens
on `52220`. Both WireGuard peers therefore retain an explicitly reachable dial
target. On success the case proves bidirectional tunnel traffic, advancing
persistent-keepalive counters, nonzero SNAT/DNAT counters, matching conntrack
tuples, recovery after conntrack is flushed and the SNAT source port changes
from `41001` to `41002`, and preservation of the configured forwarded port
instead of learning either observed source port as the peer's listen port. A
live `FwMark` change then forces the public peer's reverse carrier to reconnect;
the router must count a new SYN through forward `52241` before traffic is
revalidated.

This is deliberately the compatibility-oriented `dual-reachable` contract.
Because both endpoints can initiate, either authenticated direction may be
retained. The test detects the winning direction and validates the matching
NAT/conntrack evidence; reverse reconnect through DNAT applies only when that
direction wins. Use `single-private` for the stronger no-forward promotion and
retirement contract.

The completed topology's veth endpoints, addresses, routes, forwarding,
nftables state, and conntrack mutation live inside PID-suffixed network
namespaces. The veth pairs are necessarily created briefly in the guest root
namespace before their endpoints are moved, but no pre-existing root
configuration is changed and cleanup leaves no test links behind. The test
records ownership before creation and removes those namespaces on `EXIT`; the
host, Multipass management NIC, and both `WGTCP-Path*` NICs are not
reconfigured. The managed-case cleanup path can remove recorded namespaces
after an interrupted command using the exact `RUN/CASE` identifiers reported
in the command log.

The `tcp-debug-hostile-stream` case selects `wireguard-fork-fault.ko` and
restores production inside one guest-side command. An `EXIT` trap covers normal
failure and catchable termination, and the host requires an explicit restore
acknowledgement from both guests. After a guest power loss or uncatchable
process termination, inspect the module variant before resuming. The fault
artifact is not a general TCP kernel variant and should not be used for
unrelated cases.

### TCP roaming and half-open cases

Provision the current worktree, then run the roaming cases independently or as
part of the focused hardening set:

```powershell
python .\tests\hyperv\regression.py `
    --keep-going `
    --only-case tcp-policy-reconnect-churn `
    --only-case tcp-nat44-single-private-address-roam `
    --only-case tcp-nat44-half-open-recovery `
    --only-case tcp-debug-hostile-stream
```

The roaming helper reserves at least 600 seconds of host command time, which
becomes a 570-second bounded guest command after the runner's cleanup margin.
The current address-roam case uses one outbound-only private peer, no DNAT, and
changes the observed NAT tuple from `192.0.2.1:41001` to
`192.0.2.129:41002`. Historical dual-router evidence below describes an older
two-device surrogate and is not the current default case.

The historical dual-router helper reserves at least 600 seconds of host command
time. It delays one old-path record for 110 seconds, requires a
12-second exact-tuple pre-stage baseline and separate 12-second
automatic-authentication gates after initial and post-`FwMark` establishment,
and retains continuous 16-second quiet windows before stale release and before
the live mark transition. Each automatic gate exceeds twice the five-second
provisional idle timeout.

The dual-router topology reports `independent-outbound-pair` and is a
same-identity, two-carrier surrogate. It creates
old and new client routers with distinct private and public paths, a public
server, two client WireGuard devices sharing one private key, and one server
peer accepting both client tunnel addresses. Both routers forward public TCP
port `52241`; old and new source translations use ports `41001` and `41002`.
Both streams are independently dialed; no accepted socket is promoted or
deduplicated. Static-key ordering selects Noise initiation only and is not
instrumented here as physical TCP-carrier arbitration.
Outer policy and inner device routes are installed before the new identity is
activated. Each inner route has a path-specific preferred source so a route
lookup cannot silently select the other device's tunnel address.

The new device is brought up with its TCP listener and `FwMark` configured but
with no private key and no peer. It must remain up during preplumb because
Linux removes its device route when the interface is brought down. After one
old encrypted echo request is submitted, the test polls both WireGuard TX and
the selective netem backlog until that single record is confirmed queued. It
then explicitly brings the old WireGuard device down and proves its exact
client-side `ESTABLISHED` tuple has disappeared before installing the shared
key and peer on the new device. This cutoff prevents new old-path handshake
records from overtaking the staged record.

After the new path becomes quiet, the delayed old record is released. The test
requires the server's authenticated endpoint to remain on the new public
address while preserving configured port `52241`, requires the old router's
reverse-SYN counter not to advance, and proves the delayed record reached the
old tunnel address with a dedicated nftables inner-ICMP counter. A subsequent
live server `FwMark` change must create a distinct marked outbound tuple through
the new DNAT and retire the old tuple from `ESTABLISHED`. An old tuple may still
appear in a terminal state such as `TIME-WAIT`; that is normal TCP lifecycle
residue and is recorded separately rather than treated as an active carrier.

The quiet-window sampler emits compact state signatures only when acquisition
fails, including first, previous, and last valid samples plus the last invalid
sample. This keeps passing logs readable without withholding endpoint, socket,
mark, handshake, NAT-counter, or transfer-counter evidence on a failure.

The half-open topology keeps the original NAT path in place and installs an
owned, drop-only nftables table that silently blackholes the established
carrier. Before the blackhole it requires a stable four-second window with no
`SYN-SENT` sockets and captures the complete accepted and outbound tuple sets.
It then correlates advancing `TCP_INFO` retransmission fields for the exact old
socket with namespace `RetransSegs`, observes a reconnect SYN, removes only the
owned drop table, and requires a distinct, conntrack-correlated replacement
tuple plus bidirectional counter movement. `tcp_retries2=5` and
`tcp_syn_retries=3` apply only inside the disposable namespaces to bound test
time; the observed recovery time is not evidence for production-default Linux
failure-detection timing.

Focused run `wg20260714T084959Z` passed
`tcp-nat44-dual-router-address-roam` on both guests for **1 PASS, 0 FAIL,
0 SKIP** in 238.500 seconds. Earlier run `wg20260714T070320Z` independently
passed policy churn and half-open recovery on both guests. Its dual-router
entry failed while the topology and queue-accounting mechanics were still
being corrected, so that entry is excluded from product evidence. A new
combined focused run and a full regression campaign for the final snapshot are
still pending.

On a managed-pair failure the runner captures both guests before cleanup. The
failure logs include public WireGuard state, listening and connected TCP
sockets, and the kernel log emitted after the per-case reset; private keys are
never collected.

The current 39-case registry includes preflight validation; all 16 combinations
of stock/fork kernels and stock/fork tools in UDP mode; focused UDP/TCP namespace,
authenticated roaming, random-port, and output tests; DEBUG initialization
selftests; stock kernel capability and live-mode-change guards, including TCP
listen-port mutation and random-port coupling; and TCP cases covering static
traffic, asymmetric listen ports, stock-tool management, configuration round
trips, configured underlay migration, full-tunnel live `FwMark` changes,
route/source/uplink reconnects, ULA and scoped link-local IPv6 carriers,
dual-stack listeners, authenticated-carrier lifetime, guest-local
dual-reachable NAT44 with source-port rebinding, and isolated
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
per-guest counter deltas were `80/4/4/437` on `wgtcp-a` and `80/4/4/442` on
`wgtcp-b` for short writes/prefixes/resyncs/drops; normal traffic recovered on
both guests after the controls were cleared.

Run `wg20260714T010310Z` passed all 36 checks registered in that historical
snapshot for **36 PASS, 0 FAIL, 0 SKIP** in 558.520 seconds, recording 541
commands. Its source identity is
HEAD `83d424cb0191bc2b90090c071728db6348f7b983`, base archive SHA-256
`2de2c670dba76cac01dd1bd35f9de99605d36b032070048d6b94f5e6f3ec0d12`, and
dirty overlay SHA-256
`40c4db67c0b9660f3589239ca85ac1870d40306075ce67617085a40b1a3d3e9a`.
Preflight passed all 107 local source-contract checks on each guest running
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
passed all 35 cases. The final NAT-expanded run above passed all 36. These were
control-client infrastructure aborts, not product failures or partial
campaigns.

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

The runtime evidence still stops short of arbitrary provider NAT behavior,
repeated hostile promotion races, a cookie-equivalent TCP pre-authentication
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
