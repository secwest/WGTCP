# Design Log

This log records architectural decisions, their rationale, validation evidence,
and known limitations. Update it in the same commit as every substantive design
or behavioral change. Append a new entry when a decision changes; mark older
entries as superseded instead of silently rewriting their history.

## 2026-07-13: TCP parity and lifecycle hardening

### UDP remains the compatibility baseline

**Decision:** UDP remains the default transport when no transport is specified.
Explicit UDP configuration preserves stock-facing grammar, output, random-port
behavior, endpoint learning, and data-path semantics. In TCP mode, the companion
UDP socket and the TCP listener share the selected numeric listen port.

**Rationale:** Existing WireGuard configurations and controllers must continue
to work without opting into the experimental TCP transport.

**Evidence:** The two-VM Ubuntu 24.04/Linux 6.8 campaign
`wg20260713T185138Z` passed all 16 stock/fork kernel and tool combinations plus
the focused UDP compatibility cases.

### Configured endpoints and observed TCP tuples are separate state

**Decision:** A peer's configured TCP listen port is never replaced by an
observed ephemeral TCP source port. Noise-authenticated accepted traffic may
update the IP address used by a future dial, while device-monotonic connection
IDs prevent an older retained carrier from reverting a newer observation.
Explicit netlink endpoint changes remain authoritative.

**Rationale:** TCP source ports commonly reflect ephemeral or NAT-selected
state and are not evidence of the remote peer's listening service. Authentication
binds an address observation to a WireGuard peer, but does not advertise a new
listen port.

**Consequence:** Authenticated address learning and asymmetric configured ports
work in the tested topology. General responder-only roaming and arbitrary NAT
source-port changes still require authenticated socket promotion or an explicit
port-advertisement design.

### Network changes reconnect through one lifecycle owner

**Decision:** Route, address, netdevice, uplink, configured-endpoint, and live
`FwMark` changes request reconnection through the existing cleanup and retry
owners. Listener, accepted, and outbound socket marks are refreshed as needed.
Callbacks do not destroy or replace sockets directly.

**Rationale:** Established TCP streams retain route, source-address, and mark
state. Reusing the serialized removal path avoids concurrent socket release and
replacement from notifier, callback, and receive contexts.

**Evidence:** Full-tunnel policy routing, recursion avoidance, two live
`FwMark` changes, route replacement, source-address replacement, and uplink
migration passed on both Hyper-V guests.

### TCP stream I/O is serialized and socket lifetime is explicit

**Decision:** All encoded records enter one bounded per-peer queue and only the
write worker calls `kernel_sendmsg`. Short writes retain the exact unsent suffix
at the head of that queue. Enqueue, worker publication, retry, removal, and stop
state share the peer lifetime lock and stop barrier. Removal workers claim the
exact socket they retire and drain callbacks and work before release.

The read worker pins one selected socket for receive, parser resynchronization,
synthetic header construction, delivery, and requeue. Coalesced leftover data
uses a right-sized buffer and expands only when later parsing requires it.

**Rationale:** Stream order, partial-write recovery, and teardown correctness
must not depend on a mutable `peer_socket` pointer or on timing between callbacks
and workqueue cancellation.

**Evidence:** Production and DEBUG modules built with `W=1`; 89 source
contracts passed locally and on each guest; the complete 32-case runtime
campaign passed without kernel-log failures.

### Provisional admission is bounded but is not a cookie replacement

**Decision:** Pre-authentication TCP accepts use device-wide and per-source
caps, a fixed-size lossy source table, per-source throttling, and idle and
absolute deadlines. Valid Noise traffic releases pre-authentication accounting
for that exact connection.

**Rationale:** An unauthenticated TCP origin must not consume unbounded sockets,
tracking objects, or parser state.

**Limitation:** These controls are stateful and do not provide a stateless,
cookie-equivalent defense before cryptographic handshake work. A hostile-network
deployment still needs that design and validation.

### Dual-stack listeners are independent

**Decision:** IPv4 and IPv6 listener sockets and threads are independently
created, published, and released. Synthetic IPv6 receive metadata carries a
scope from the accepted or dialed socket so authenticated learning does not
discard link-local scope information.

**Evidence:** Independent dual-stack listeners, asymmetric listen ports, and an
IPv6 outer carrier passed at runtime. Link-local IPv6, VRF, and namespace-move
behavior remain follow-up work.

### Simultaneous Noise initiation uses a deterministic tie-break

**Decision:** When both peers initiate concurrently, the static public keys
select a deterministic Noise-handshake role under the handshake lock.

**Limitation:** This resolves handshake-role ambiguity. It is not yet a complete
authenticated physical-carrier promotion or deduplication protocol.

### Performance claims remain bounded by evidence

**Decision:** Documentation may report the observed TCP-mode throughput and
resilience results, but must not claim general TCP-over-TCP meltdown immunity.
The current evidence supports only the narrower conclusion that meltdown may
occur under a smaller set of conditions than commonly assumed.

**Follow-up:** Run controlled loss, congestion, queue, reorder, blackout,
multi-flow, forced-short-write, parser-resynchronization, and multi-hour soak
campaigns before broadening the claim.

### Hyper-V control recovery uses exact ownership

**Decision:** Host command timeouts are bounded. Orphaned `multipass.exe` client
processes are inspected by PID, age, executable, CPU use, and full command line
before only those exact stale clients are terminated. `multipassd`, VM worker
processes, and guests are not blanket-stopped. Guest cleanup uses the run ID and
internal case ID recorded by the successful `prepare` command.

**Rationale:** This preserves VM and interface ownership boundaries while
recovering from a failed host control channel. The final clean campaign passed
after seven verified stale clients and the exact `m13` and `m10` guest state
were removed.
