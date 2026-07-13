# Hyper-V Regression Results

## Recorded campaign

| Field | Value |
|---|---|
| Run ID | `wg20260713T221904Z` |
| Started | 2026-07-13 22:19:04 UTC |
| Duration | 452.476 seconds |
| Host | Windows 11 Pro, Hyper-V, Multipass 1.16.3 |
| Guests | Ubuntu 24.04 (`wgtcp-a`, `wgtcp-b`) |
| Guest kernel | `6.8.0-124-generic` |
| Source HEAD | `7c398d543158b5ef77d8c822b64f90bb99229a44` |
| Base archive SHA-256 | `5133a0d1c67879de26510d242d01d198b08e71ccbe305bcd197eec13ffc15bc7` |
| Dirty overlay SHA-256 | `9d107084a83ab3778b09e1de0ef87804b1ffea16d2d474009d57e9be247262a3` |
| Result | **35 PASS, 0 FAIL, 0 SKIP** |
| Recorded commands | 533 |
| Kernel-log check failures | 0 |

The provisioner built and tested the source snapshot represented by the HEAD,
base archive, and overlay hashes above. Both guests built the production,
DEBUG, and isolated hostile-stream fault modules plus the modified tools before
the campaign. Build-time `modinfo` checks proved that the `tcp_test_*`
parameters were absent from the production and ordinary DEBUG artifacts and
present only in the fault artifact. This results record was updated afterward
with the observed outcome. Host execution used an approved brokered
administrator context after the invoking token could read the exact managed
Hyper-V VM IDs, and bounded guest-command probes succeeded before the case
loop.

## Case results

| Group or case | Count | Result | Evidence |
|---|---:|---|---|
| Preflight | 1 | PASS | Guest builds, underlays, all 100 local contract tests on each guest, artifact-isolation checks, and kernel-log checks passed |
| UDP stock/fork matrix | 16 | PASS | Every Cartesian combination of stock/fork kernel A, kernel B, tool A, and tool B carried bidirectional traffic |
| `fork-udp-netns-regression` | 1 | PASS | Fork UDP regression passed on both guests; the current case also proves a TCP tunnel over a namespace-only underlay |
| `fork-debug-initialization-selftests` | 1 | PASS | DEBUG module loaded, initialization selftests passed, and the module could be unloaded |
| `udp-roaming-path-change` | 1 | PASS | Authenticated UDP endpoint learning moved to `10.77.1.10:36686` |
| `udp-output-and-random-port` | 1 | PASS | Stock-facing output and independent random listen ports passed |
| `stock-kernel-transport-capability` | 1 | PASS | Explicit UDP remained a no-op and unsupported TCP was rejected safely |
| `fork-mode-change-rejection` | 1 | PASS | Unsafe live transport changes were rejected; live TCP listen-port mutation returned `EBUSY` without changing either listener, while down/up random-port selection produced one nonzero port shared by the TCP listener and UDP companion |
| `tcp-smoke` | 1 | PASS | Static IPv4 TCP tunnel traffic passed on port 52010 |
| `tcp-asymmetric-listen-ports` | 1 | PASS | Bidirectional tunnel traffic passed with independently configured TCP listen ports 52020 and 52021; observed carrier source ports remained ephemeral |
| `tcp-stock-tool-management` | 1 | PASS | The stock tool managed the fork kernel while the interface remained in TCP mode |
| `tcp-config-roundtrip` | 1 | PASS | `showconf`, `setconf`, `syncconf`, and `wg-quick save` preserved TCP mode and traffic; configurations containing private material remained in guest-local mode-0600 files |
| `tcp-configured-path-change` | 1 | PASS | Both configured endpoints moved to `path1`; after `path0` was disabled and both WireGuard links were cycled, forward and reverse traffic used TCP port 52012 on the replacement path |
| `tcp-full-tunnel-live-fwmark` | 1 | PASS | Full-tunnel policy routing and the recursion guard passed; established carriers reconnected after two live `FwMark` values on both guests |
| `tcp-route-change` | 1 | PASS | A live route change moved authenticated TCP carriers from `192.0.2.0/24` to `198.51.100.0/24` on both guests while tunnel traffic recovered |
| `tcp-source-address-uplink-change` | 1 | PASS | Both guests reconnected after a live local source-address change and again after moving the endpoint route to the second uplink |
| `tcp-ipv6-dual-stack` | 1 | PASS | Independent IPv4 and IPv6 listeners coexisted, asymmetric ports 52210/52211 were retained, and IPv6 outer-carrier tunnel traffic passed on both guests |
| `tcp-ipv6-link-local-scope` | 1 | PASS | Scoped link-local endpoint strings retained their interface zones, both guests established link-local IPv6 outer carriers, and tunnel traffic passed |
| `tcp-authenticated-carrier-lifetime` | 1 | PASS | An authenticated TCP carrier remained usable for 40 seconds on each guest, beyond the provisional unauthenticated lifetime |
| `tcp-debug-hostile-stream` | 1 | PASS | The isolated fault module forced real short writes, parser resynchronization, and queue drops on both guests, then recovered normal traffic; deltas were A=`80/4/4/2380` and B=`80/4/4/2378` for short writes/prefixes/resyncs/drops |

All 16 UDP matrix cells and every focused UDP, compatibility, and guard case
passed. This is the repository's evidence that UDP mode is drop-in compatible
for the tested Ubuntu/Linux stock/fork combinations. It is not a claim about
every kernel release, third-party controller, or non-Linux implementation.

The listen-port guard was exercised while TCP was live and both listeners
remained on the original port after `EBUSY`. The interface was then brought
down, configured with listen port zero, and brought up; the selected port was
greater than zero and matched between TCP and UDP. This is lifecycle evidence
for this kernel and configuration, not bind-race, namespace-churn, or
exhaustion stress coverage.

The configured TCP migration case exercised the dedicated endpoint setter in
this snapshot. `wg set ... endpoint` replaced each peer's TCP dial target,
disabled the original underlay, and then both WireGuard interfaces were cycled
down and up. Bidirectional traffic recovered over the second underlay, and both
outer TCP directions were observed on `path1`.

The new parity cases exercised automatic authenticated dial-target updates and
notifier-driven reconnects at runtime. Both guests followed authenticated
address changes, route and uplink changes, source-address replacement, and two
live `FwMark` values. The full-tunnel case verified marked endpoint routing and
the unmarked recursion guard. The IPv6 case verified independent IPv4/IPv6
listeners and an IPv6 outer carrier, while the lifetime case kept an
authenticated carrier active for 40 seconds on each guest. These results cover
the tested namespace topology and do not imply arbitrary NAT or responder-only
socket promotion behavior.

The configuration round-trip case kept all secret-bearing files inside the
guest-local mode-0700 temporary directory with mode 0600, and emitted no
secrets into host-collected output. It verified `showconf`, `setconf`,
`syncconf`, and `wg-quick save`, including preservation of `Transport = tcp`,
configured listen ports, peer sets, and tunnel traffic.
The scoped IPv6 case preserved `%interface` zones in configured and serialized
link-local endpoints and observed usable link-local outer TCP carriers on both
guests.

The hostile-stream case loaded `wireguard-fork-fault.ko`, the only artifact
that exposes the root-only fault parameters. Each guest independently observed
80 real short writes, four injected garbage prefixes, four successful parser
resynchronizations, and queue-pressure drops (2380 on `wgtcp-a`, 2378 on
`wgtcp-b`). Both recovered normal tunnel traffic after the controls were
cleared. This is deterministic fault-path evidence for the tested workload; it
is not an unbounded hostile-network or long-duration fuzzing claim.

## Follow-up hardening verification

After the 35-case campaign, the configuration case was extended from
SaveConfig serialization to a real `wg-quick` down/up reload, writer delay was
made one-shot, artifact reuse verification was strengthened, and fault-module
load/test/restore moved into one guest-side command. The rebuilt snapshot used
base archive SHA-256
`5133a0d1c67879de26510d242d01d198b08e71ccbe305bcd197eec13ffc15bc7` and
overlay SHA-256
`efe576b3c226089de2bbbd23670c599f78a45d8ec315c896cf6c6494a9692dd7`.

Focused run `wg20260713T225629Z` completed **2 PASS, 0 FAIL, 0 SKIP** in
134.149 seconds. `tcp-config-roundtrip` passed in 117.489 seconds and returned
`wg_quick_roundtrip=pass` from both guests. `tcp-debug-hostile-stream` passed
in 16.246 seconds; both guests recorded 80 short writes, four injected
prefixes, and four resynchronizations, with 434/441 queue drops, then returned
`restored_kernel_variant=fork`. Reuse-only artifact verification passed, and
all 103 source contracts passed on both guests. This focused run verifies the
hardened paths; it does not replace or change the 35-case full-campaign totals
above.

## Validation boundary

Runs `wg20260713T183821Z` and `wg20260713T184512Z` are intentionally excluded
from the campaign table. The first completed 12 passing cases before a
`wgtcp-a` collection client reached its 180-second host timeout; the second
completed nine passing cases before the same failure pattern. Seven orphaned,
CPU-spinning `multipass.exe` clients were then enumerated, inspected by exact
PID, age, and command line, and terminated by exact PID. The `multipassd`
service and both VMs were left running. Guest ownership was cleaned with the
internal case IDs recorded by each failed case's successful `prepare` command:
`m13` for `wg20260713T183821Z` and `m10` for `wg20260713T184512Z`. The next
clean 32-case campaign passed without a failure or skip, and the later expanded
campaign recorded above passed all 35 cases. The two aborts were control-client
infrastructure failures, not product regressions or partial release results.

The safe inspection, exact-PID client termination, and prepare-ID ownership
cleanup procedure is recorded in the
[Hyper-V setup guide](HYPERV_SETUP.md#orphaned-multipass-client-recovery).

This campaign establishes static and asymmetric-port TCP connectivity,
stock-tool control, configuration round trips, configured migration,
authenticated endpoint following, route/source/uplink reconnects, live
full-tunnel `FwMark` changes, ULA and scoped link-local IPv6 outer transport,
dual-stack listeners, a 40-second authenticated carrier, and deterministic
short-write/parser/queue-pressure recovery on the tested Ubuntu 24.04/Linux 6.8
guests. Remaining validation and design gaps are authenticated carrier
promotion for arbitrary NAT ephemeral-port roaming; a cookie-equivalent TCP
pre-authentication cost defense; VRF and namespace-move behavior; broader MTU
and fragmentation coverage; long-duration, multi-flow soak testing; and wider
kernel-version and distribution breadth.

The suite is functional rather than a performance campaign. It does not test
physical-carrier loss or establish TCP-over-TCP meltdown resilience. The
separate Azure application results support only the narrower hypothesis
described in the [design document](../../docs/TCP_TRANSPORT_DESIGN.md#tcp-over-tcp-behavior-and-meltdown-conditions).

Raw machine-readable results and per-command logs are intentionally ignored by
Git and remain locally under the per-run directories
`tests/hyperv/results/wg20260713T221904Z/` and
`tests/hyperv/results/wg20260713T225629Z/`. Reproduce the campaign with the
commands in [`README.md`](README.md).
