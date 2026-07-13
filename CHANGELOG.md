# Changelog

This file records notable user-visible, operational, compatibility, and testing
changes. Update it in the same commit as every substantive change. Architectural
rationale belongs in `DESIGNLOG.md`; both logs should be updated when a change
affects design and externally visible behavior.

## Unreleased

### Added

- Established project design and change logs as required release artifacts.

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
