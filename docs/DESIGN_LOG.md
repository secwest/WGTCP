# Design Log

This log records design decisions made while building and qualifying the
WireguardTCP TCP-over-TCP meltdown campaign. The transport architecture remains
described in [`TCP_TRANSPORT_DESIGN.md`](TCP_TRANSPORT_DESIGN.md); this file
captures why the investigation and its supporting changes took their current
form.

## 2026-07-12

### DL-001: Test the feedback mechanism, not random loss alone

**Status:** Accepted

The prior performance matrix primarily injected exogenous random loss. A fixed
drop probability does not rise with offered load, so it cannot by itself close
the feedback loop required for classical TCP-over-TCP meltdown.

The new campaign uses a rate-limited bottleneck and an explicit finite queue.
Offered load can therefore create queue growth, delay, overflow, outer TCP
recovery, and subsequent inner TCP congestion responses.

### DL-002: Use matched UDP WireGuard controls in every scored cell

**Status:** Accepted

Every scored WireguardTCP cell is paired with the stock UDP branch from the same
module, host state, workload, bottleneck, and named repetition. TCP degradation
below 50% of a valid exact UDP match is reported, but does not by itself prove
the meltdown mechanism.

This controls for VM capacity, WireGuard encryption cost, workload behavior,
queue construction, and unrelated path impairment.

### DL-003: Predeclare operational meltdown thresholds

**Status:** Accepted

A run is operational meltdown only when all three conditions hold:

1. at least 20% of 100 ms receiver-delivery bins have zero inner bytes;
2. fitted end-to-start goodput declines by at least 20%, with slope
   t-statistic at or below -2.0;
3. the inner RTO rate reaches one event per logical flow-minute.

Thresholds are fixed in
[`perf-test/meltdown/TESTPLAN.md`](../perf-test/meltdown/TESTPLAN.md) and must
not be changed after examining a campaign.

### DL-004: Require mechanistic attribution in addition to classification

**Status:** Accepted

Operational thresholds alone can be triggered by implementation defects.
Classical TCP-over-TCP meltdown attribution additionally requires outer
retransmission or RTO recovery and temporal coupling to inner RTO or congestion
window collapse.

Clean-path failures without outer recovery are implementation defects and are
not counted as meltdown evidence.

### DL-005: Score delivery from the receiving tunnel interface

**Status:** Accepted

Iperf interval records are retained as a cross-check, but are not the
authoritative stall signal. Multi-flow iperf can report synchronized
block-completion bursts that create false zero-delivery intervals even when
traffic is continuous.

The harness samples cumulative receive bytes on the selected tunnel interface
at 100 ms and resamples them onto exact measurement boundaries. Direction
selects the receiver:

- reverse: client receive interface;
- forward: server receive interface;
- bidirectional: both receive interfaces.

### DL-006: Separate the finite queue from propagation impairment

**Status:** Accepted

The selected egress class uses HTB for rate and a direct byte-limited `bfifo` or
`fq_codel` child for queue behavior. Selective ingress redirection to an IFB
applies half-RTT netem delay and optional exogenous loss.

This avoids a netem internal queue masking the finite bottleneck queue. Filters
select only the WireGuard carriers and optional competitor, keeping SSH and
host-control traffic outside the impairment path.

Queue size is defined in BDP units:

```text
BDP bytes = rate_mbps * RTT_ms * 125
queue bytes = BDP bytes * queue_bdp
```

### DL-007: Treat impairment and carrier verification as validity gates

**Status:** Accepted

A configured test is not evidence until runtime state is verified. The analyzer
invalidates a cell when the workload, expected sampling coverage, preflight
path, HTB rate, delay, queue kind or limit, traffic filters, clock state, kernel
health, or TCP carrier stability fails validation.

Queue overflow is reported separately. A valid run with no queue drops does not
exercise the complete loss-driven feedback loop.

### DL-008: Use the implementation's supported dual-endpoint TCP topology

**Status:** Accepted with limitation

The current implementation does not promote an accepted provisional socket into
the configured peer, so responder-only static operation is unsupported. Both
peers receive configured endpoints, normally creating two outer TCP streams.

The harness records both tuples and invalidates a TCP cell if either changes or
disappears. Results from this topology must not be generalized to a
single-carrier TCP tunnel.

### DL-009: Authenticate accepted carriers by exact stream provenance

**Status:** Accepted

Accepted TCP streams begin as bounded provisional objects. Endpoint-only
matching is insufficient because a replacement TCP connection or companion UDP
packet could otherwise authenticate the wrong provisional entry.

Each accepted stream receives a nonzero monotonic ID. TCP-derived packets carry
that ID through asynchronous handshake processing. Only successful Noise
processing can mark that exact stream authenticated.

### DL-010: Extend authenticated temporary-carrier lifetime without promotion

**Status:** Accepted

Pre-authentication controls remain:

- five-second idle deadline;
- 30-second absolute deadline;
- 128 provisional entries per device.

After the exact stream carries a valid Noise handshake, it remains a temporary
receive carrier with a 180-second activity-based idle deadline and no
pre-authentication absolute cap. Authentication does not promote or transfer
the socket.

This repairs five-second carrier rotation while preserving bounded
pre-authentication exposure and avoiding an unsynchronized ownership transfer.

### DL-011: Drain complete buffered records before another socket read

**Status:** Accepted

A bulk `recvmsg()` can contain multiple framed records. Once the first record is
delivered, a complete leftover record must be processed before another
nonblocking receive. Otherwise `EAGAIN` can strand already-buffered data until a
later callback.

The reader processes complete leftovers first and reschedules bounded work while
processable buffered records remain.

### DL-012: Gate the impairment campaign on repeatable clean controls

**Status:** Accepted

The campaign must not proceed from a single warmed-stream success. Multiple
fresh interface setups must produce zero-loss, sub-millisecond unshaped TCP
controls before throughput or impairment cells can be scored.

This gate separates transport correctness from congestion behavior and prevents
implementation stalls from being mislabeled as meltdown.

### DL-013: Keep campaign control on the operator workstation

**Status:** Accepted

The workstation directly coordinates both private test hosts through restricted
SSH forwarding. It uses one explicit key, pinned host keys, identity-only
authentication, and no agent or password fallback. No private or secondary
controller key is copied between hosts.

Host setup is ephemeral, test traffic is isolated from SSH, and qdisc state is
verified after cleanup.

### DL-014: Localize the apparent one-packet lag below the TCP reader

**Status:** Resolved without a transport change

Fresh tunnel setups can run one packet behind. BPF tracing shows:

- every `wg_tcp_data_ready()` callback promptly starts
  `wg_tcp_read_worker()`;
- `kernel_recvmsg()` reads a complete 136-byte frame and then returns
  `-EAGAIN`;
- decryption succeeds;
- endpoint reconstruction succeeds;
- the first correlated frame does not call `napi_gro_receive()`;
- the next frame reaches GRO and immediately triggers a reply.

The current evidence does not support a TCP callback or read-worker lost-wakeup
root cause. The remaining investigation is inside
`wg_packet_consume_data_done()` between endpoint reconstruction and GRO,
including protocol/size validation, trimming, keepalive handling, and allowed-IP
source lookup.

The final protocol and AllowedIPs trace showed that the apparent rejected frame
was a zero-length WireGuard keepalive. Fresh synchronized traces then showed
ordinary ping data passing endpoint reconstruction, protocol parsing,
AllowedIPs lookup, and GRO immediately. Recreating the dedicated tunnels removed
the lag. The evidence supports stale Noise/carrier state in that session, not a
repeatable pre-GRO rejection branch, so no speculative receive-path change was
made.

## 2026-07-13

### DL-015: Bind resumed evidence to source, runtime, and matrix identity

**Status:** Accepted

A cell is reusable only when `cell.json`, `cell.complete`, and
`cell.fingerprint` all exist and the fingerprint matches the current campaign.
The campaign fingerprint covers the orchestrator, analyzer and harness sources,
test plan, matrix, loaded module srcversion and hash, and `wg` tool hash. The
cell fingerprint also covers every matrix axis and repetition.

`cell.json` is published only after analysis succeeds and both endpoints verify
qdisc restoration. Campaign aggregation requires a manifest enumerating every
expected cell and fingerprint. Missing, stale, failed, or partially published
cells make the campaign incomplete rather than producing a negative result.

### DL-016: Treat interval-complete telemetry as a validity requirement

**Status:** Accepted

The BPF sampler traces a bounded child process and must exit successfully after
the requested interval. Its output must contain the header plus exactly one
summary for every inner, outer, and competitor RTO/retransmission class. A
summary must not exceed its emitted event count and may trail by at most one
final event racing tracer shutdown.

The 200 ms socket sampler writes an independent completion record. TCP carrier
validation requires enough samples to cover the workload start and end, two
unchanged carrier tuples, and no missing interval. Missing receiver-interface
samples remain missing; they are never converted into artificial zero-delivery
bins.

### DL-017: Resynchronize through the ordinary captured-socket reader

**Status:** Accepted

When buffered bytes contain no complete valid record header, the parser keeps
at most the final seven bytes that could begin a header split across TCP reads.
It then returns so the ordinary read worker can append later bytes through the
socket it captured at entry. Resynchronization does not issue a separate
one-shot `recvmsg()`.

This preserves the parallel ARM lifetime integration: complete retained records
are drained before another nonblocking read, leftover storage is sized to the
exact suffix plus header headroom, and synthetic outer headers use the live
captured socket tuple. It also prevents an invalid full header from causing a
processable-buffer requeue loop.

### DL-018: Let nonblocking send establish write-space notification

**Status:** Accepted

The write worker must not stop solely because `sk_stream_is_writeable()` reports
false before a send attempt. That check can prevent `kernel_sendmsg()` from
returning `EAGAIN`, so the stream layer never arms `SOCK_NOSPACE` and no later
write-space callback is guaranteed. Under concurrent inner flows this stranded
exactly the full 1,024-frame internal queue.

The single writer now attempts nonblocking sends until the queue is empty, a
serialized frame is partially written, or send returns zero/`EAGAIN`. A retained
exact frame or suffix is placed back at the queue head before `SOCK_NOSPACE` is
set. A memory barrier and the existing scheduler/lifetime-lock recheck close the
writable-transition race without holding a spinlock across `kernel_sendmsg()` or
busy-looping.

On matching ARM builds, the repeated 1/2/4/8/16-flow trace raised 16-flow
goodput from 2.35 to 44.67 Mb/s, changed iperf completion from failure to
success, and eliminated the 1,024-frame residue. The fixed writer observed
10,801 `EAGAIN` returns and 1,492 write-space callbacks in that run.

### DL-019: Use atomic BPF summary counters

**Status:** Accepted

Detailed RTO and retransmission events remain the analysis input, while summary
counters independently detect lost trace output. Plain
`@counter = @counter + 1` map updates lose increments when probes run
concurrently on multiple CPUs and therefore caused valid raw traces to fail
summary reconciliation.

The trace now uses atomic map increments. The ARM bpftrace compiler emitted
atomic map-add instructions, and a 16-flow stress run reconciled all 870 raw
RTO/retransmission events across both endpoints with the six summaries and no
malformed records.

### DL-020: Bound the tracer-shutdown race without rewriting original evidence

**Status:** Accepted

`interval:s:1` can print an `END` summary while one final kprobe already in
flight emits its detailed event. The detailed trace is authoritative for
scoring. Analysis permits raw count to exceed its summary by exactly one, but
still invalidates summary-greater-than-raw or any lag greater than one. This
accepts the only ordering race possible at controlled shutdown while retaining
the four-event mismatch as a failing contract.

The two original cells affected by this rule remain listed as invalid in their
published campaign. They may be reanalyzed for diagnosis, but the formal
screening inventory changes only through separate fingerprinted exact-cell
reruns.

### DL-021: Do not infer resistance from queues that did not overflow

**Status:** Accepted

The initial finite-queue and RTT-boundary stage executed all 68 cells. Sixty-one
are valid/stable, seven are invalid on evidence coverage, and no valid cell is
degraded, near-meltdown, or meltdown. No valid cell had an inner RTO or outer
recovery event.

Most nominal 50 Mb/s bottlenecks recorded no queue drops because TCP delivered
about 46.4-47.3 Mb/s. These are valid observations at the measured offered
load, but they do not test the complete loss/recovery feedback loop. The next
mechanism stage must lower the bottleneck rate or add contention before drawing
a resistance conclusion.

### DL-022: Qualify reruns as an explicit multi-fingerprint composite

**Status:** Accepted

The seven evidence-invalid screening repetitions were rerun under a new
campaign fingerprint because sampler lifetime, exact-cell selection, and the
bounded tracer-shutdown rule changed. The loaded module, userspace tool, matrix
axes, and workload definitions did not change. All seven reruns are
valid/stable with complete telemetry.

The original invalid records remain published. Qualification does not edit
their campaign or claim that both harness revisions share one fingerprint.
Instead, `merge_campaigns.py` builds a composite that:

- verifies complete source manifests, completion markers, and cell
  fingerprints;
- requires identical module srcversion, module hash, tool hash, and replacement
  axes;
- permits replacement only when the base cell is invalid and the rerun is
  valid;
- recomputes matched UDP comparisons over the selected documents;
- writes per-cell source campaign, cell fingerprint, and analyzed `cell.json`
  SHA-256 provenance.

This yields a qualified 68/68 stable screening inventory while preserving the
audit trail from the initial 61-valid/7-invalid campaign and the separate
seven-cell rerun.

### DL-023: Require observed overflow before broader mechanism testing

**Status:** Accepted

The 50 Mb/s screening bottleneck usually exceeded the transport's
46.4-47.3 Mb/s delivery and therefore did not overflow. The next matrix is
predeclared separately rather than changing the completed screening matrix.

The gate is two matched TCP/UDP repetitions at 35 Mb/s, 200 ms, and 0.25x BDP.
Broader mechanism rows add 0.5x BDP at 35 Mb/s, 0.25x BDP at 25 Mb/s, and
0.25x BDP at 35 Mb/s/400 ms. All use 16 inner flows, 60-second measurements,
no exogenous loss, and the same runtime build. The broader rows run only after
the smoke records finite-queue overflow with complete evidence and verified
cleanup.

**Gate result:** all four smoke executions were valid/stable, but none recorded
a queue drop. TCP delivered 32.80-33.08 Mb/s and UDP delivered 34.02 Mb/s.
The sampled sender-side queue peaked at 130,548 of 218,750 bytes (59.7%);
HTB recorded rate-shaper overlimits without child-queue overflow. The 12
broader rows were therefore not run. The next adaptive step requires a
separately fingerprinted smaller-queue predeclaration.

### DL-024: Adapt queue depth without changing completed evidence

**Status:** Accepted

The completed 0.25x-BDP smoke peaked above the 0.10x-BDP byte limit that the
same rate and RTT would configure. A new matrix therefore predeclares two
matched TCP/UDP repetitions at 35 Mb/s, 200 ms, 16 flows, and 0.10x BDP
(87,500 bytes). Both TCP repetitions must be valid and record finite-queue
drops before declaring a broader adaptive mechanism matrix.

If that gate does not overflow in both TCP repetitions, the same matrix
predeclares a 0.05x-BDP fallback (43,750 bytes). The fallback is not run when
the 0.10x-BDP gate passes. The analyzer now publishes measurement-window
sampled peak backlog in bytes and as a fraction of the configured queue; queue
drops remain the gate because discrete sampling can miss a transient peak.

**Gate result:** all four 0.10x-BDP cells were valid/stable. Both TCP
repetitions recorded finite-queue overflow (60 and 5 drops), satisfying the
gate; UDP controls recorded 749 and 718 drops. TCP delivered 27.75-29.05 Mb/s
versus 33.94-33.98 Mb/s for UDP. No cell produced an inner or outer RTO, outer
retransmission, outer recovery event, or negative trend. The 0.05x-BDP fallback
is therefore not run. A broader adaptive mechanism matrix may now be declared
separately; the original rows remain gated off by their failed 0.25x-BDP smoke.

### DL-025: Gate breadth on observed outer TCP recovery

**Status:** Accepted

Finite-queue drops alone establish the endogenous-loss boundary but do not
exercise nested TCP recovery. The next separately fingerprinted gate therefore
uses a 0.05x-BDP queue at 35 Mb/s, 200 ms, and 16 flows, with two matched
TCP/UDP repetitions. Broader rows run only when both TCP repetitions are valid
and overflow, and at least one records an outer retransmission or RTO.

If the gate passes, 12 predeclared executions test lower rate, doubled RTT, and
a competing CUBIC flow. If it does not, those rows remain unrun and the
investigation advances to separately fingerprinted burst-loss cells designed
to force outer RTO. This prevents spending broader-cell budget on a regime
that still lacks the recovery mechanism needed for causal meltdown evidence.

**Gate result:** the gate did not pass. TCP repetition 1 was valid/degraded at
14.54 Mb/s versus 33.18 Mb/s for UDP, with 14.3% zero-delivery bins and 273
queue drops. TCP repetition 2 fell to 2.79 Mb/s with 42.7% zero-delivery bins
and 528 drops, but its final iperf results exchange failed, making it invalid.
Neither repetition recorded an outer retransmission or RTO.

An exact retry of the invalid repetition reproduced 2.93 Mb/s, 34.5%
zero-delivery bins, 624 drops, and the final-results failure. It also exceeded
the tracer's one-event shutdown allowance by one additional event. The retry
remains invalid and does not replace the original. The 12 broader recovery
executions remain unrun; the next mechanism gate must force outer recovery
directly rather than lowering the endogenous queue again.

### DL-026: Verify exogenous burst loss before using it as evidence

**Status:** Accepted

The endogenous 0.05x-BDP gate produced severe TCP-specific degradation but no
observed outer TCP retransmission or RTO. The next separately fingerprinted
gate therefore uses the previously declared Gilbert-Elliott candidate at 50
Mb/s, 200 ms, 1x BDP, 16 inner flows, and parameters `2/25/90/99`. Two matched
TCP/UDP repetitions produce four 60-second executions.

All four executions must be valid before broader burst work is released. In
addition to the existing rate, delay, queue, filter, telemetry, workload, and
cleanup checks, the analyzer must match the live netem loss model and every
Gilbert-Elliott probability against the matrix on both endpoints. At least one
TCP repetition must record a scored outer retransmission or RTO. A validity
failure is retained and rerun only in a separate campaign; absence of outer
recovery fails the gate without tuning severity inside the completed
fingerprint.

**Gate result:** all four cells completed but failed validity before workload.
The live qdisc matched `2/25/90/99` on both endpoints in every cell, while every
tunnel preflight had 100% loss. Netem interprets the final arguments as `1-H`
and `1-K`; `1-K=99%` therefore imposes 99% loss in the good state, yielding
about 98.3% nominal stationary loss with the declared transition parameters.
No scored delivery, outer recovery, or meltdown evidence was produced.

The campaign retired one carrier per endpoint despite successful qdisc cleanup.
The preparation-only recovery path restored both dedicated tunnels, two
carriers per endpoint, and zero-loss TCP/UDP probes. The completed fingerprint
is preserved unchanged. Any semantically corrected severity must be declared
and committed as a new gate.

### DL-027: Correct good-state loss in a new burst fingerprint

**Status:** Accepted

The completed `2/25/90/99` campaign established that the shaper and analyzer
apply netem's literal `P/R/1-H/1-K` semantics. It cannot be repaired in place.
A new matrix therefore retains `P=2%`, `R=25%`, and `1-H=90%` while changing
only good-state loss to `1-K=1%`. Its nominal stationary loss is 7.59% per
impaired direction instead of 98.3%.

The new gate again consists of two matched TCP/UDP repetitions at 50 Mb/s,
200 ms, 1x BDP, 16 flows, and 60 seconds. All four executions must be valid,
with exact live loss configuration, nonzero IFB netem traffic and drops, and
realized loss between 0.5x and 2x the model's stationary expectation on each
endpoint. At least one TCP repetition must record a scored outer retransmission
or RTO. Otherwise broader burst, contention, AQM, workload, and endurance rows
remain blocked. The prior invalid cells remain part of the audit inventory and
are not replacement candidates.

**Gate result:** the exact complete campaign produced one valid/degraded UDP
cell and three invalid cells. Both TCP repetitions forced outer recovery: r1
recorded 181 retransmissions and 25 RTOs, while r2 recorded 33 retransmissions
and 13 RTOs. Their final in-band iperf results exchanges failed. TCP r1 also
missed one endpoint's realized-loss band; TCP r2 had a two-event trace-summary
discrepancy. UDP r2 had a four-event discrepancy.

Exact separate reruns remained invalid. TCP r1 then exhibited all three
meltdown conditions - 93.7% stalls, a significant negative trend, and 1.31
inner RTOs per flow-minute - plus 29 outer retransmissions and 17 outer RTOs,
but its final results exchange again failed. TCP r2 reproduced the finalization
failure, and UDP r2 reproduced a three-event trace-summary discrepancy. No
invalid record is promoted or rescored. A prospective gate must remove the
in-band final-control survivorship bias and quiesce tracer probes before summary
collection under a new source fingerprint.
