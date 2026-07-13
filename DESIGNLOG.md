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
IPv6 outer carrier passed at runtime. The later scoped-IPv6 campaign below
supersedes this entry's original link-local validation gap; VRF and
namespace-move behavior remain follow-up work.

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

## 2026-07-13: Persistence, scoped IPv6, and hostile-stream validation

### Configuration persistence keeps secrets inside the guest

**Decision:** TCP mode must round-trip the canonical `Transport = tcp` state
through `showconf`, `setconf`, and `syncconf`, and preserve it through
`wg-quick SaveConfig`. Runtime tests keep secret-bearing private-key material
in a mode-0700 guest temporary directory, require each configuration file to be
mode 0600, compare files without printing them, and emit only public pass/fail
fields.

**Evidence:** Both guests restored traffic and exact canonical configuration
after live `setconf` and drift-removing `syncconf`. Focused run
`wg20260713T225629Z` also used a guest-local `wg-quick` copy paired with the
modified `wg` tool to save, remove, recreate, and retest the interface; both
guests returned `wg_quick_roundtrip=pass`.

### Link-local IPv6 scope is part of the endpoint

**Decision:** A link-local IPv6 TCP endpoint is the address, numeric port, and
interface scope together. Userspace preserves the named `%interface` zone,
kernel endpoint state carries `sin6_scope_id`, and synthetic receive metadata
uses the selected socket scope rather than collapsing it to zero.

**Evidence:** Asymmetric scoped endpoints survived tool output and `showconf`,
the outer TCP tuples used the expected link-local interfaces, and bidirectional
inner IPv6 traffic passed on both guests.

### Destructive fault injection is a separate artifact

**Decision:** Forced stream faults are compiled only when both `DEBUG` and
`WG_TCP_FAULT_INJECTION` are defined. The lab builds a distinct
`wireguard-fork-fault.ko`; production and ordinary DEBUG modules expose no
`tcp_test_*` parameters. Root-only controls cap actual send requests, prepend a
bounded provably invalid byte prefix, lower the drop-newest queue cap, and pause
one writer invocation for at most one second. The delay is consumed with an
atomic exchange so partial-send suffix retries do not repeat it. Read-only
counters prove each path fired. Tests arm controls only after a clean tunnel
exists, compare counter deltas, reset every module-global control, and require
traffic recovery. Artifact reuse compares live `modinfo` output with the saved
manifests before accepting an existing build.

**Rationale:** This validates real kernel short-write, parser-resynchronization,
and backpressure paths without turning unstable destructive controls into a
production or general DEBUG interface.

### Promotion must bind an authenticated carrier before learning from it

**Decision:** The target roaming design uses a refcounted carrier object with
`PROVISIONAL`, `AUTHENTICATED`, `PROMOTING`, `ACTIVE`, `RETIRING`, and `DEAD`
states. An atomic `authenticate_candidate(connection_id, peer)` operation must
find a live ID, bind it once to exactly one configured peer while retaining a
peer reference, reject stale IDs and later identities, release admission, and
only then permit dial-IP learning or queue promotion. Promotion selects at most
one active and one bounded standby carrier and retires duplicates without
moving a partially read or written record between streams.

**Rationale:** Current connection IDs are a useful foundation, but marking a
connection authenticated does not associate it with a peer. Endpoint mutation
before a successful exact-ID claim permits stale completion and multi-identity
ambiguity. The existing public-key tie-break resolves Noise initiation state,
not physical TCP ownership.

**Compatibility:** Pre-binding parsing cannot be handshake-only. A reconnect
may carry a valid data message for an existing receiver index before a fresh
handshake, so provisional carriers need strict byte/frame budgets while allowing
exact-size handshake/cookie messages and bounded existing-key data until AEAD
authentication binds the peer.

### Carrier collision ordering needs shared authenticated input

**Decision:** Static public-key ordering selects the preferred physical
direction: the lower-key endpoint prefers outbound and the higher-key endpoint
prefers the corresponding inbound carrier. Duplicate carriers in that direction
must be ordered by a token derived from or exchanged inside their authenticated
handshake. A device-local connection ID may locate a carrier and a local
publication generation may reject stale work, but neither is shared and neither
may decide a cross-peer winner.

**Reason:** Using independent local counters can make the two endpoints publish
different streams. Direction ordering is shared already; same-direction
deduplication needs a second value both authenticated endpoints observe.

### TCP cookie enforcement requires exact-stream replies and staged rollout

**Decision:** Restore TCP pre-Noise cost defense in phases. First route
handshake and cookie replies by exact TCP connection ID, consume cookie
responses before transport branching, and enforce MAC1. Then deploy clients
that understand same-stream cookie responses. Only afterward enforce under-load
MAC2 challenges, because the current snapshot skips TCP cookie consumption and
would not be rolling-upgrade compatible with immediate challenge enforcement.

**Boundary:** Application cookies reduce pre-Noise CPU cost; they do not prevent
TCP SYN, accept-queue, or socket state. Kernel SYN cookies/backlog policy and
the existing accept caps remain separate first-layer controls.

### Final evidence for this tranche

Hyper-V run `wg20260713T221904Z` completed **35 PASS, 0 FAIL, 0 SKIP** in
452.476 seconds across 533 commands with no kernel-log failures. Each guest
observed 80 forced short writes, four injected malformed prefixes, four
successful parser resynchronizations, more than 2,300 queue-pressure drops,
and clean bidirectional recovery. The completed checks narrow the remaining
work to promotion/cookie implementation, MTU, VRF and namespace churn,
physical-carrier impairment, longer multi-flow soak, and platform breadth.

### Fault-only modules are ephemeral test state

**Decision:** One guest-side command owns the complete fault-module lifecycle.
It installs an `EXIT` cleanup before loading the fault artifact, runs the
namespace test, restores production after the namespace cleanup, and reports a
combined test/restore failure when necessary. The host runner requires each
guest to return `restored_kernel_variant=fork` before the case can pass.

**Reason:** Root-only controls and a separate build guard prevent production
parameter exposure, but leaving the instrumented artifact active after a
successful case would still make later manual testing differ from the declared
production state.

**Evidence:** The exact hardened follow-up worktree snapshot (base archive SHA-256
`5133a0d1c67879de26510d242d01d198b08e71ccbe305bcd197eec13ffc15bc7`,
overlay SHA-256
`efe576b3c226089de2bbbd23670c599f78a45d8ec315c896cf6c6494a9692dd7`)
built all three module variants on both guests. Focused run
`wg20260713T225629Z` passed the configuration and hostile-stream cases and
returned `restored_kernel_variant=fork` from each guest-side command.
Reuse-only artifact verification and all 103 contracts also passed on both
guests.
