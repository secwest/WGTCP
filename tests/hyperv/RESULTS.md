# Hyper-V Regression Results

## Recorded campaign

| Field | Value |
|---|---|
| Run ID | `wg20260713T185138Z` |
| Started | 2026-07-13 18:51:38 UTC |
| Duration | 376.109 seconds |
| Host | Windows 11 Pro, Hyper-V, Multipass 1.16.3 |
| Guests | Ubuntu 24.04 (`wgtcp-a`, `wgtcp-b`) |
| Guest kernel | `6.8.0-124-generic` |
| Source base | `e827d5f93f088dba4499e7f59d5f18c79600cc94` |
| Base archive SHA-256 | `dc743a6f917fb61aff39bdb58bfdb428d67c9788bfc78a4885c720c2b7f6d3d1` |
| Dirty overlay SHA-256 | `a2bb58930392c060843a00b2125b9e5fcbcbd3e8b13ce14c17795bf64f3ec6de` |
| Result | **32 PASS, 0 FAIL, 0 SKIP** |
| Recorded commands | 503 |
| Kernel-log check failures | 0 |

The provisioner built and tested the source snapshot represented by the base
commit and overlay hash above. Both guests built the production and DEBUG fork
modules and the modified tools before the campaign; this results record was
updated afterward with the observed outcome. Host execution used an approved
brokered administrator context after the invoking token could read the exact
managed Hyper-V VM IDs, and bounded guest-command probes succeeded before the
case loop.

## Case results

| Group or case | Count | Result | Evidence |
|---|---:|---|---|
| Preflight | 1 | PASS | Guest builds, underlays, all 89 local contract tests on each guest, and kernel-log checks passed |
| UDP stock/fork matrix | 16 | PASS | Every Cartesian combination of stock/fork kernel A, kernel B, tool A, and tool B carried bidirectional traffic |
| `fork-udp-netns-regression` | 1 | PASS | Fork UDP regression passed on both guests; the current case also proves a TCP tunnel over a namespace-only underlay |
| `fork-debug-initialization-selftests` | 1 | PASS | DEBUG module loaded, initialization selftests passed, and the module could be unloaded |
| `udp-roaming-path-change` | 1 | PASS | Authenticated UDP endpoint learning moved to `10.77.1.10:46925` |
| `udp-output-and-random-port` | 1 | PASS | Stock-facing output and independent random listen ports passed |
| `stock-kernel-transport-capability` | 1 | PASS | Explicit UDP remained a no-op and unsupported TCP was rejected safely |
| `fork-mode-change-rejection` | 1 | PASS | Unsafe live transport changes were rejected; live TCP listen-port mutation returned `EBUSY` without changing either listener, while down/up random-port selection produced one nonzero port shared by the TCP listener and UDP companion |
| `tcp-smoke` | 1 | PASS | Static IPv4 TCP tunnel traffic passed on port 52010 |
| `tcp-asymmetric-listen-ports` | 1 | PASS | Bidirectional tunnel traffic passed with independently configured TCP listen ports 52020 and 52021; observed carrier source ports remained ephemeral |
| `tcp-stock-tool-management` | 1 | PASS | The stock tool managed the fork kernel while the interface remained in TCP mode |
| `tcp-configured-path-change` | 1 | PASS | Both configured endpoints moved to `path1`; after `path0` was disabled and both WireGuard links were cycled, forward and reverse traffic used TCP port 52012 on the replacement path |
| `tcp-full-tunnel-live-fwmark` | 1 | PASS | Full-tunnel policy routing and the recursion guard passed; established carriers reconnected after two live `FwMark` values on both guests |
| `tcp-route-change` | 1 | PASS | A live route change moved authenticated TCP carriers from `192.0.2.0/24` to `198.51.100.0/24` on both guests while tunnel traffic recovered |
| `tcp-source-address-uplink-change` | 1 | PASS | Both guests reconnected after a live local source-address change and again after moving the endpoint route to the second uplink |
| `tcp-ipv6-dual-stack` | 1 | PASS | Independent IPv4 and IPv6 listeners coexisted, asymmetric ports 52210/52211 were retained, and IPv6 outer-carrier tunnel traffic passed on both guests |
| `tcp-authenticated-carrier-lifetime` | 1 | PASS | An authenticated TCP carrier remained usable for 40 seconds on each guest, beyond the provisional unauthenticated lifetime |

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

## Validation boundary

Runs `wg20260713T183821Z` and `wg20260713T184512Z` are intentionally excluded
from the campaign table. The first completed 12 passing cases before a
`wgtcp-a` collection client reached its 180-second host timeout; the second
completed nine passing cases before the same failure pattern. Seven orphaned,
CPU-spinning `multipass.exe` clients were then enumerated, inspected by exact
PID, age, and command line, and terminated by exact PID. The `multipassd`
service and both VMs were left running. Guest ownership was cleaned with the
internal case IDs recorded by each failed case's successful `prepare` command:
`m13` for `wg20260713T183821Z` and `m10` for `wg20260713T184512Z`. The fresh
run recorded above then completed all 32 cases without a failure or skip. The
two aborts were control-client infrastructure failures, not product
regressions or partial release results.

The safe inspection, exact-PID client termination, and prepare-ID ownership
cleanup procedure is recorded in the
[Hyper-V setup guide](HYPERV_SETUP.md#orphaned-multipass-client-recovery).

This campaign establishes static and asymmetric-port TCP connectivity,
stock-tool control, configured migration, authenticated endpoint following,
route/source/uplink reconnects, live full-tunnel `FwMark` changes, IPv6 outer
transport with dual-stack listeners, and a 40-second authenticated carrier on
the tested Ubuntu 24.04/Linux 6.8 guests. Remaining validation and design gaps
are authenticated socket promotion for arbitrary NAT ephemeral-port roaming;
a cookie-equivalent TCP pre-authentication cost defense; hostile short-write,
parser-resynchronization, and queue-pressure stress; complete configuration
round trips; link-local IPv6, VRF, and namespace-move behavior; and
long-duration, multi-flow soak testing.

The suite is functional rather than a performance campaign. It does not test
physical-carrier loss or establish TCP-over-TCP meltdown resilience. The
separate Azure application results support only the narrower hypothesis
described in the [design document](../../docs/TCP_TRANSPORT_DESIGN.md#tcp-over-tcp-behavior-and-meltdown-conditions).

Raw machine-readable results and per-command logs are intentionally ignored by
Git and remain locally under
`tests/hyperv/results/wg20260713T185138Z/`. Reproduce the campaign with the
commands in [`README.md`](README.md).
