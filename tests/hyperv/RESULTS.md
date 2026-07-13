# Hyper-V Regression Results

## Recorded campaign

| Field | Value |
|---|---|
| Run ID | `wg20260712T212739Z` |
| Started | 2026-07-12 21:27:39 UTC |
| Duration | 208.713 seconds |
| Host | Windows 11 Pro, Hyper-V, Multipass 1.16.3 |
| Guests | Ubuntu 24.04 (`wgtcp-a`, `wgtcp-b`) |
| Guest kernel | `6.8.0-124-generic` |
| Source base | `35c9110cac0f10a6f6481d5d25d8cc6d5989918a` |
| Base archive SHA-256 | `9f08d1ea6d36943e7ee30b32d03feeabc2431eaff004b9ac015993534d83e699` |
| Dirty overlay SHA-256 | `e19ba9759f2636849290a2773b2c5f764cd974437d94d745e837a69ee26e151c` |
| Result | **26 PASS, 0 FAIL, 0 SKIP** |
| Recorded commands | 433 |
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
| Preflight | 1 | PASS | Guest builds, underlays, contract tests, and kernel-log checks passed |
| UDP stock/fork matrix | 16 | PASS | Every Cartesian combination of stock/fork kernel A, kernel B, tool A, and tool B carried bidirectional traffic |
| `fork-udp-netns-regression` | 1 | PASS | Fork UDP regression passed on both guests; the current case also proves a TCP tunnel over a namespace-only underlay |
| `fork-debug-initialization-selftests` | 1 | PASS | DEBUG module loaded, initialization selftests passed, and the module could be unloaded |
| `udp-roaming-path-change` | 1 | PASS | Authenticated UDP endpoint learning moved to `10.77.1.10:46925` |
| `udp-output-and-random-port` | 1 | PASS | Stock-facing output and independent random listen ports passed |
| `stock-kernel-transport-capability` | 1 | PASS | Explicit UDP remained a no-op and unsupported TCP was rejected safely |
| `fork-mode-change-rejection` | 1 | PASS | Unsafe live transport changes were rejected; live TCP listen-port mutation returned `EBUSY` without changing either listener, while down/up random-port selection produced one nonzero port shared by the TCP listener and UDP companion |
| `tcp-smoke` | 1 | PASS | Static IPv4 TCP tunnel traffic passed on port 52010 |
| `tcp-stock-tool-management` | 1 | PASS | The stock tool managed the fork kernel while the interface remained in TCP mode |
| `tcp-configured-path-change` | 1 | PASS | Both configured endpoints moved to `path1`; after `path0` was disabled and both WireGuard links were cycled, forward and reverse traffic used TCP port 52012 on the replacement path |

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
outer TCP directions were observed on `path1`. This is evidence for that exact
operator-configured IPv4 migration and interface-restart sequence. It is not an
automatic authenticated-roaming or responder-only promotion test.

## Validation boundary

The earlier sandboxed run `wg20260712T200006Z` is intentionally excluded from
the campaign table. Host policy blocked TCP port 22 to both management
addresses, every bounded guest command failed, and **0 of 26 cases ran**. It
was an infrastructure failure, not a 26-case product failure or partial pass.
The runner's infrastructure gate aborts this condition even when `-KeepGoing`
is selected; that option applies only after the guest command channel is
healthy and independent cases have begun.

This campaign establishes static IPv4 TCP connectivity, stock-tool control, and
the configured two-underlay migration/interface-restart sequence for the tested
build. It does not establish responder-only promotion, automatic TCP roaming,
NAT behavior, IPv6 transport, repeated path churn, local route/address notifier
behavior, long-soak stability, IPv6 namespaces, namespace teardown/move, VRFs,
or full-tunnel policy routing. New TCP streams now use the device creation
namespace and `FwMark`; full-tunnel recursion and live routing changes still
need explicit runtime validation.

The suite is functional rather than a performance campaign. It does not test
physical-carrier loss or establish TCP-over-TCP meltdown resilience. The
separate Azure application results support only the narrower hypothesis
described in the [design document](../../docs/TCP_TRANSPORT_DESIGN.md#tcp-over-tcp-behavior-and-meltdown-conditions).

Raw machine-readable results and per-command logs are intentionally ignored by
Git and remain locally under
`tests/hyperv/results/wg20260712T212739Z/`. Reproduce the campaign with the
commands in [`README.md`](README.md).
