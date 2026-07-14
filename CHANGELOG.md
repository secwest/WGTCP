# Changelog

This file records notable user-visible, operational, compatibility, and testing
changes. Update it in the same commit as every substantive change. Architectural
rationale belongs in `DESIGNLOG.md`; both logs should be updated when a change
affects design and externally visible behavior.

## Unreleased

### Added

- Established project design and change logs as required release artifacts.
- Added complete TCP configuration round-trip coverage for `showconf`,
  `setconf`, `syncconf`, and a real `wg-quick` save/down/up reload, with all
  key-bearing files retained guest-locally at mode 0600.
- Added scoped link-local IPv6 endpoint, `showconf`, outer-carrier, and
  bidirectional tunnel validation.
- Added a separate `wireguard-fork-fault.ko` test artifact with root-only,
  DEBUG-gated controls and read-only counters for forced short writes,
  deterministic malformed prefixes, parser resynchronization, and queue
  pressure. Production and ordinary DEBUG artifacts reject those parameters.
- Added an isolated NAT44 namespace regression on both Hyper-V guests. It uses
  explicit SNAT, a differently numbered DNAT port, conntrack inspection,
  persistent-keepalive counters, and a forced translated-source-port change
  without modifying either guest's root firewall or forwarding state.

### Changed

- Refined the remaining roaming design around an atomic authenticated
  carrier-to-peer binding and promotion state machine instead of transferring
  temporary-peer state in place.
- Refined the TCP cookie design to require exact-carrier replies, MAC1
  validation before Noise work, cookie-response consumption, and a staged
  rollout before enforcing under-load MAC2 challenges.
- Moved fault-module load, test, and production restore into one guest-side
  command with `EXIT`/signal cleanup; the host requires an explicit restore
  acknowledgement from both guests.
- Made the writer-delay fault control one-shot so combining it with forced
  short writes cannot multiply the configured pause across suffix retries.
- Strengthened artifact reuse checks to compare live and saved `modinfo` and
  parameter manifests, recheck fault-parameter isolation, and validate the
  artifact manifest's kernel release.
- Defined carrier collision ordering around static-key direction preference
  and a future shared authenticated token; device-local connection IDs are
  only local locators and stale-work generations.

### Validated

- Passed 107 source contracts locally and in the final campaign preflight on
  both Ubuntu guests.
- Built production, ordinary DEBUG, and isolated fault-injection modules with
  kernel warnings enabled; `modinfo` verified fault-parameter isolation.
- Passed Hyper-V run `wg20260713T221904Z`: 35 PASS, 0 FAIL, 0 SKIP in
  452.476 seconds across 533 recorded commands with no kernel-log failures.
- On each guest, forced 80 short writes, injected and recovered from four
  malformed prefixes, forced more than 2,300 queue drops, and restored
  bidirectional traffic without stream corruption.
- Passed focused follow-up run `wg20260713T225629Z`: 2 PASS, 0 FAIL, 0 SKIP in
  134.149 seconds. Both guests completed a real `wg-quick` down/up reload; the
  one-shot hostile case recorded 80 short writes and four prefix recoveries on
  each guest, plus 434/441 queue drops, then acknowledged production-module
  restoration.
- Passed strengthened NAT44 run `wg20260714T005957Z`: 1 PASS, 0 FAIL, 0 SKIP
  in 57.867 seconds. Both guests carried bidirectional tunnel traffic through
  SNAT and DNAT, advanced keepalive counters while idle, recovered after the
  client mapping changed from port 41001 to 41002, and retained the configured
  forwarded dial port 52241. A live mark change then forced a reverse reconnect
  and each router observed a new SYN through that preserved forward.
- Passed final Hyper-V run `wg20260714T010310Z`: 36 PASS, 0 FAIL, 0 SKIP in
  558.520 seconds across 541 recorded commands with no kernel-log failures.
  The final isolated fault case restored the production module after recording
  80 short writes, four prefix recoveries, and 437/442 queue drops.

### Known limitations

- Authenticated carrier binding/promotion, ordinary responder-only NAT
  operation without a reverse port-forward, and deterministic stale-carrier
  retirement are not implemented. The passing NAT44 case requires a reachable
  configured endpoint in both directions.
- TCP handshakes still lack an enforced cookie-equivalent pre-authentication
  cost defense; accept caps do not prevent Noise CPU work.
- VRF and namespace move/teardown behavior, MTU accounting, physical-carrier
  loss, longer multi-flow soak, and broader kernel/topology coverage remain.

## 2026-07-13

### Added

- Added authenticated TCP dial-address learning while preserving the peer's
  configured remote listen port.
- Added route, address, netdevice, uplink, configured-endpoint, and live
  `FwMark` reconnect handling.
- Added independent IPv4 and IPv6 TCP listeners, IPv6 scope propagation, and
  runtime dual-stack coverage.
- Added deterministic simultaneous Noise-initiation role selection.
- Added device-wide and per-source provisional-accept caps, per-source
  throttling, authentication-aware accounting, and bounded deadlines.
- Added Hyper-V cases for asymmetric ports, configured migration, full-tunnel
  policy routing, live mark changes, route/source/uplink changes, IPv6, and a
  40-second authenticated carrier lifetime.

### Changed

- Kept UDP as the default, drop-in-compatible mode for the tested Linux stock
  and fork kernel/tool combinations.
- Separated configured TCP listen-port state from observed ephemeral source
  tuples and used stable accepted-connection IDs for authenticated observations.
- Routed reconnect requests through serialized cleanup and retry ownership.
- Serialized all TCP record writes through one bounded queue and write worker.
- Pinned one socket through each receive, resynchronization, synthetic-header,
  delivery, and requeue pass.
- Right-sized buffers retained for coalesced receive suffixes.
- Updated the README, TCP transport design, Hyper-V setup guide, and regression
  evidence with the implemented behavior and remaining parity boundaries.
- Narrowed the TCP-over-TCP performance language: real-world tests suggest
  meltdown may be a narrower condition than commonly expected, but do not prove
  general immunity.

### Fixed

- Fixed future reconnects continuing to use a stale authenticated peer address.
- Fixed accepted ephemeral TCP source ports being able to contaminate the
  configured dial target.
- Fixed live route, source-address, uplink, and `FwMark` changes leaving an
  established stream on obsolete network state.
- Fixed short-write handling so only the exact unsent record suffix is retried.
- Fixed parser lost-wakeup and buffered-record draining behavior.
- Fixed queue publication, callback, retry, removal, and device teardown races
  with explicit stop barriers and exact socket ownership.
- Fixed read-path use of a mutable peer socket by pinning the selected carrier.
- Fixed post-connect tuple caching so the kernel-selected source and ephemeral
  port are recorded after route selection.

### Validated

- Passed 89 source contract tests locally and on both Ubuntu guests.
- Built production and DEBUG modules and modified tools on Ubuntu 24.04 with
  Linux 6.8 and kernel build warnings enabled.
- Passed Hyper-V run `wg20260713T185138Z`: 32 PASS, 0 FAIL, 0 SKIP in
  376.109 seconds across 503 recorded commands.
- Passed all 16 stock/fork UDP kernel and tool combinations and every focused
  UDP/TCP compatibility and mobility case.
- Regenerated `BIG-WireguardTCP-Patch` and verified that applying it to stock
  WireGuard commit `edad0d6e99e5133b1e8e865d727a25fff6399cb4` reproduced the
  exact target Git tree, including symlink modes.

### Known limitations

- Authenticated accepted-socket promotion and general responder-only or NAT
  ephemeral-port roaming are not implemented.
- TCP handshakes still lack a cookie-equivalent pre-authentication cost defense.
- Hostile forced short-write, parser-resynchronization, malformed-stream, and
  queue-exhaustion runtime campaigns remain pending.
- Complete `showconf`, `setconf`, `syncconf`, and `wg-quick SaveConfig` round
  trips remain pending.
- Link-local IPv6, VRF, namespace-move, longer soak, and broader kernel and
  topology validation remain pending.
