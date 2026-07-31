# Hyper-V Regression Results

## Current focused status (2026-07-31)

The latest-tree single-NAT implementation passes **213 local source contracts**.
Production, DEBUG, and fault-injection modules build on both Multipass/Hyper-V
Ubuntu guests running `6.8.0-136-generic`.

Final rebased run `wg20260731T070252Z` passed `tcp-nat44-single-private`
independently on both guests and passed the DEBUG initialization self-tests.
The topology has one private peer behind SNAT and no DNAT or forwarded port.
Both guests verified authenticated accepted-carrier promotion,
bidirectional traffic, keepalive activity, a `41001` to `41002` source-port
change, authenticated recovery, old-carrier retirement, and clean kernel logs.

Final rebased run `wg20260731T070427Z` passed hostile-stream and fault-injection recovery on
both guests, including exact fatal-send targeting and restoration of the
production module.

Final focused run `wg20260731T074807Z` passed all four current NAT/recovery
cases on both guests: single-private NAT, dual-reachable initiation with either
authenticated winner, outbound-only address-and-port roaming, and half-open
recovery. The report records **4 PASS, 0 FAIL, 0 SKIP** with clean kernel logs.

## Prior follow-up status (2026-07-15)

The integrated callback-owner and roaming-startup tree passes **205 local
source contracts** and all three guest shell harnesses pass syntax validation. Both
Ubuntu guests compiled the production tools and modules on
`6.8.0-134-generic` after the main ownership refactor. The last successful
build snapshot had overlay SHA-256
`18e3aab15eb64257e73f491849133f9a332d2467c66777214cd2481e459252a7`;
the subsequent remote writer/parser/handoff integration, callback module pin,
and device-reopen quarantine guard still need a fresh synchronized build.

Two expanded diagnostic campaigns reached 38 passing cases and one failure:
`wg20260715T180738Z` exposed an obsolete source/uplink target expectation, and
`wg20260715T183416Z` exposed the old simple-NAT 60-second acquisition boundary.
The corrected source/uplink case passed alone in `wg20260715T183342Z`. The NAT
case now uses one shared 90-second absolute acquisition deadline and records
elapsed time plus SNAT/DNAT counter deltas; isolated runs
`wg20260715T190428Z` and `wg20260715T190505Z` both passed, with the latter
making 17 seconds of startup churn visible.

The elevated child of an intentionally interrupted focused command continued
and ultimately completed run `wg20260715T214038Z` with **6 PASS, 0 FAIL**:
policy reconnect churn in 253.324 seconds, authenticated carrier lifetime in
95.334 seconds, dual-reachable NAT44 in 39.892 seconds, dual-router address
roam in 336.688 seconds, half-open recovery in 52.062 seconds, and hostile
stream recovery in 24.568 seconds. This is useful focused evidence, but that
snapshot predates the final second-stage callback-owner, quarantine, and
device-reopen guard changes. It is not a current-source acceptance result.

Two overlapping follow-up attempts are excluded as infrastructure-contaminated
runs. `wg20260715T215619Z` recorded **2 PASS, 2 FAIL** before an SSH cleanup
abort; policy setup found a missing `wgb` device and dual-router cleanup timed
out over SSH. `wg20260715T215932Z` recorded **0 PASS, 6 FAIL**, with all six
cases immediately refused because a leftover `wgb` kept module unload from
completing. Neither run is counted as product evidence or as a final-source
pass/fail result.

Restarting the managed VMs cleared the orphaned ownership, but the Multipass
daemon then stopped answering its local gRPC socket. The administrator service
restart and fresh synchronized build, focused gate, and full gate remain
pending. The current registry contains 39 cases, and no green current-source
39-case campaign exists yet. Accordingly, the historical 36-case campaign
below remains the latest complete green gate.

## Recorded campaign

| Field | Value |
|---|---|
| Run ID | `wg20260714T010310Z` |
| Started | 2026-07-14 01:03:10 UTC |
| Duration | 558.520 seconds |
| Host | Windows 11 Pro, Hyper-V, Multipass 1.16.3 |
| Guests | Ubuntu 24.04 (`wgtcp-a`, `wgtcp-b`) |
| Guest kernel | `6.8.0-124-generic` |
| Source HEAD | `83d424cb0191bc2b90090c071728db6348f7b983` |
| Base archive SHA-256 | `2de2c670dba76cac01dd1bd35f9de99605d36b032070048d6b94f5e6f3ec0d12` |
| Dirty overlay SHA-256 | `40c4db67c0b9660f3589239ca85ac1870d40306075ce67617085a40b1a3d3e9a` |
| Result | **36 PASS, 0 FAIL, 0 SKIP** |
| Recorded commands | 541 |
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

## Historical focused roaming verification

| Field | Value |
|---|---|
| Run ID | `wg20260714T084959Z` |
| Started | 2026-07-14 08:49:59 UTC |
| Duration | 238.500 seconds |
| Case | `tcp-nat44-dual-router-address-roam` |
| Result | **1 PASS, 0 FAIL, 0 SKIP** |
| Guests | `wgtcp-a`, `wgtcp-b` |
| Source HEAD | `c1d898a1f48c09c8a64c32fe76b5d2ddb4737624` |
| Base archive SHA-256 | `6dd8fe9466b068173f7aec42b7ce66100ab5aa563485ffeca55e261eb5406b7a` |
| Dirty overlay SHA-256 | `899b5ec7f1126852b6147f41f39dc900807768365979ad547a66d95874d25fdc` |

Both VM repetitions passed the same-identity, two-carrier surrogate. The new
client device remained administratively up but keyless and peerless during
preplumb because taking it down removes its device route. Both old and new
inner routes used path-specific preferred source addresses. After one old
encrypted ICMP record was submitted, the test polled WireGuard TX and selective
netem backlog without sending another record, then explicitly brought the old
device down and required its exact `ESTABLISHED` client tuple to disappear
before activating the new identity.

Both guests moved the authenticated server endpoint from
`192.0.2.1:52241` to `192.0.2.129:52241`, preserving the configured forward
port. The delayed old record was at least 59 seconds old at earliest release,
advanced the dedicated old-inner ICMP counter, and did not roll the endpoint
back or advance the old-router reverse-SYN counter. Each guest acquired the
required 16-second stable state before stale release and again before the live
server `FwMark 0x52241` transition. That transition created a distinct marked
server outbound tuple through the new DNAT and removed the prior tuple from
`ESTABLISHED`. A residual old tuple in a terminal state such as `TIME-WAIT` is
permitted and recorded separately; it is not counted as an active carrier.

The current managed Hyper-V identities were
`69fcac18-eb3f-46c1-a32f-4aa421e54e42` (`wgtcp-a`) and
`48902a17-0dfe-4bbb-ab4f-86bcfb97f96d` (`wgtcp-b`). Private-switch identities
were `a795c92c-e6d9-4ece-ad04-f835cfd70e93` (`WGTCP-Path0`) and
`2f6d2b77-2ade-42e7-af23-417eab54ec2f` (`WGTCP-Path1`). These GUIDs establish
which objects this run used; they are not portable creation parameters.

Earlier focused run `wg20260714T070320Z` passed
`tcp-policy-reconnect-churn` and `tcp-nat44-half-open-recovery` on both guests.
Policy churn completed 11 transitions with 20 distinct reconnect proofs and
eight mark-specific SYN proofs per guest. The half-open case used a drop-only
blackhole, proved exact-socket `TCP_INFO` and namespace retransmission advances,
and established a distinct conntrack-correlated replacement with bidirectional
traffic. Its namespace-only `tcp_retries2=5` and `tcp_syn_retries=3` settings
make that case bounded; its 13-14 second detection observations are not
production-default timing claims.

The `070320` dual-router entry failed while queue parsing and keyless route
preplumb were still test-mechanics work. Later isolated iterations exposed two
more topology constraints: live listener changes return `EBUSY`, and taking
the keyless new device down removes the route that must be preinstalled. These
were infrastructure/harness findings, not product failures. The corrected
`084959` pass above supersedes those failed entries as product evidence. A new
combined focused run and a full regression campaign containing the expanded
case list remain pending.

## Case results

| Group or case | Count | Result | Evidence |
|---|---:|---|---|
| Preflight | 1 | PASS | Guest builds, underlays, all 107 local contract tests on each guest, artifact-isolation checks, and kernel-log checks passed |
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
| `tcp-nat44-dual-reachable` | 1 | PASS | Each guest passed isolated SNAT, DNAT, keepalive, bidirectional traffic, `41001` to `41002` remapping, configured-port preservation, and a forced reverse dial through public forward 52241 |
| `tcp-debug-hostile-stream` | 1 | PASS | The isolated fault module forced real short writes, parser resynchronization, and queue drops on both guests, then recovered normal traffic; deltas were A=`80/4/4/437` and B=`80/4/4/442` for short writes/prefixes/resyncs/drops |

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

The NAT44 case ran separate private-peer, router, and public-peer namespaces
inside each guest. nftables SNATed the private peer to public source port 41001
and DNATed public port 52241 to private listener 52221. Both directions carried
tunnel traffic, and two-second persistent keepalive counters advanced. The
test atomically replaced the SNAT rule with source port 41002, flushed only the
router namespace's conntrack state, and recovered bidirectional traffic.
`wg show endpoints` retained configured forward 52241. A live `FwMark` change
then forced the public peer's reverse carrier to reconnect; each router counted
a new SYN through that forward. Both repetitions still saw the old accepted
41001 socket locally established, so duplicate/stale-carrier retirement remains
open. This proves only the dual-reachable topology with explicit DNAT, not
responder-only operation without a forward or general NAT parity.

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
resynchronizations, and queue-pressure drops (437 on `wgtcp-a`, 442 on
`wgtcp-b`). Both recovered normal tunnel traffic after the controls were
cleared. This is deterministic fault-path evidence for the tested workload; it
is not an unbounded hostile-network or long-duration fuzzing claim.

## Follow-up hardening verification

After the earlier 35-case campaign, the configuration case was extended from
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
all 103 source contracts passed on both guests. This focused run verified those
hardened paths. They are also included in the later 36-case full campaign
recorded above.

## NAT44 focused verification

Strengthened focused run `wg20260714T005957Z` completed **1 PASS, 0 FAIL,
0 SKIP** in 57.867 seconds before the final full campaign. Both guests passed
the same atomic remap and forced reverse-dial assertions later included in
`wg20260714T010310Z`. Its detailed counters were A keepalive
`1480->1512`/`2016->2048`, reverse SYNs `4->5`; and B keepalive
`528->560`/`436->788`, reverse SYNs `3->4`. Both reported
`old_accepted_carrier=retained`.

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
clean 32-case campaign passed without a failure or skip, the later expanded
campaign passed all 35 cases, and the final NAT-expanded campaign recorded
above passed all 36. The two aborts were control-client
infrastructure failures, not product regressions or partial release results.

The safe inspection, exact-PID client termination, and prepare-ID ownership
cleanup procedure is recorded in the
[Hyper-V setup guide](HYPERV_SETUP.md#orphaned-multipass-client-recovery).

This campaign establishes static and asymmetric-port TCP connectivity,
stock-tool control, configuration round trips, configured migration,
authenticated endpoint following, route/source/uplink reconnects, live
full-tunnel `FwMark` changes, ULA and scoped link-local IPv6 outer transport,
dual-stack listeners, a 40-second authenticated carrier, dual-reachable NAT44
with an explicit forward and one live source-port remap, and deterministic
short-write/parser/queue-pressure recovery on the tested Ubuntu 24.04/Linux 6.8
guests. Remaining validation and design gaps are authenticated carrier
promotion for responder-only/no-forward NAT; deterministic stale-carrier
retirement; arbitrary NAT/provider behavior; a cookie-equivalent TCP
pre-authentication cost defense; VRF and namespace-move behavior; broader MTU
and fragmentation coverage; long-duration, multi-flow soak testing; and wider
kernel-version and distribution breadth.

The suite is functional rather than a performance campaign. It does not test
physical-carrier loss or establish TCP-over-TCP meltdown resilience. The
separate Azure application results support only the narrower hypothesis
described in the [design document](../../docs/TCP_TRANSPORT_DESIGN.md#tcp-over-tcp-behavior-and-meltdown-conditions).

Raw machine-readable results and per-command logs are intentionally ignored by
Git and remain locally under the per-run directories
`tests/hyperv/results/wg20260714T010310Z/` and
`tests/hyperv/results/wg20260714T005957Z/`. Reproduce the campaign with the
commands in [`README.md`](README.md).
