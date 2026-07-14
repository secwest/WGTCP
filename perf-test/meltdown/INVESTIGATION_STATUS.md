# WireguardTCP TCP Meltdown Investigation - Interim Status

Status cutoff: 2026-07-13 17:35 PDT (2026-07-14 00:35 UTC)

This is an interim engineering record, not the final campaign report. It
documents the repository, host, harness, implementation, measurements, and
conclusions reached so far. Clean-path qualification and the finite-queue/RTT
screening matrix are complete and qualified; stronger congestion, mechanism,
and endurance stages remain.

## 1. Executive summary

The patched transport passed clean qualification and all 14 calibration cells.
The initial screening executed all 68 scheduled finite-queue and RTT-boundary
cells, with 61 valid/stable and seven evidence-invalid. A separate exact-cell
campaign reran those seven with complete evidence; all are valid/stable. The
qualified composite is therefore 68/68 stable screening cells, and the combined
calibration/screening inventory is 82/82 valid/stable.

Four matched 0.25x-BDP mechanism-smoke cells were valid/stable, but their queue
did not overflow, so the original 12 broader rows remain intentionally unrun.
A separately predeclared 0.10x-BDP adaptive smoke then completed 4/4
valid/stable cells. Both TCP repetitions recorded finite-queue overflow (60 and
5 drops), satisfying the adaptive gate. The qualified inventory is now 90/90
valid/stable, with no degraded, near-meltdown, meltdown, or invalid cell.

The test design and most of the campaign machinery now exercise the right
mechanism: offered load fills a finite queue, queue overflow or delay stalls the
outer TCP carrier, and inner delivery, congestion control, retransmission
timers, and recovery are measured against an exact UDP WireGuard control.
Meltdown thresholds and validity rules were declared before impairment results.

Testing exposed several WireguardTCP implementation defects before the
mechanism could be evaluated:

1. accepted TCP streams were reclaimed after five seconds because they remained
   provisional;
2. complete records left in a bulk receive buffer could be stranded behind a
   subsequent nonblocking `recvmsg()` returning `EAGAIN`;
3. a stale Noise/carrier session produced an apparent one-packet receive lag;
4. the TCP writer could strand a full 1,024-frame internal queue because a
   pre-send writability check prevented `kernel_sendmsg()` from reaching
   `EAGAIN` and arming `SOCK_NOSPACE`;
5. BPF read/modify/write summary counters lost concurrent events across CPUs.

The local repairs have focused contract coverage and matching ARM builds. Three
fresh setups completed 600 bidirectional probes with zero loss and
sub-millisecond RTT. A fresh writer-fix calibration delivered approximately
47 Mb/s over TCP and 48.59 Mb/s over UDP, including 16-flow TCP. The former
1,024-frame stranded residue disappeared in direct 1/2/4/8/16-flow tracing.

The current valid evidence does not meet the predeclared meltdown definition.
It also does not rule out meltdown: most nominal 50 Mb/s finite queues did not
overflow because observed TCP delivery was only about 47 Mb/s. The next
mechanism stage must use a lower bottleneck rate or additional contention, then
force outer recovery and test temporal coupling to inner stalls and RTOs.

## 2. Objective and falsifiable definition

The question is:

> Does this WireguardTCP implementation enter classical TCP-over-TCP meltdown
> under endogenous congestion, and where is the boundary in queue depth, RTT,
> flow concurrency, and outer recovery behavior?

Every scored TCP cell has an otherwise matched UDP WireGuard control. A run is
classified as operational meltdown only when all three predeclared conditions
hold during the measurement window:

1. at least 20% of 100 ms receiver-delivery bins contain zero inner bytes;
2. fitted end-to-start goodput declines by at least 20%, with an OLS slope
   t-statistic at or below -2.0;
3. the inner TCP RTO rate is at least one event per logical flow-minute.

Those thresholds identify the operational symptom, but attribution to
TCP-over-TCP meltdown also requires outer recovery events and temporal coupling
between outer retransmission/RTO stalls and inner RTO or congestion-window
collapse. Average outer throughput is not sufficient evidence.

Classification and invalidation rules are defined in
[`TESTPLAN.md`](TESTPLAN.md). They must not be changed in response to campaign
results.

## 3. Repository and change-control state

- Repository: `secwest/WireguardTCP`
- Working branch: `dragosruiu-microsoft-tcp-meltdown-investigation`
- Current upstream `main`: `e827d5f`
- Shared ARM lifetime integration: merge `377f4af`, authored by
  `Dragos Ruiu <dr@secwest.net>`
- Git author for this investigation checkpoint:
  `Dragos Ruiu <dr@secwest.net>`
- Investigation commit policy: no Copilot tags or trailers
- Campaign infrastructure baseline: `88b7173`
- Pre-upstream experimental work is preserved in `stash@{0}` and session
  artifacts; it was not replayed blindly over the substantially changed
  upstream implementation.

The parallel ARM branch was first reconciled with current `main`, validated, and
then used as this branch's base. The campaign changes were replayed over that
shared base with manual conflict resolution in the reader and stream contracts.
Existing upstream commits retain their original authors; the author requirement
above applies to commits created for this investigation.

## 4. Azure test environment and security controls

The dedicated test pair is separate from the older lockup-reproduction pair:

| Role | Host | Private address | Platform |
|---|---|---:|---|
| Endpoint A | `wgtcp-amp-a` | `10.20.1.7` | Azure `Standard_D4ps_v5`, Ampere Neoverse-N1 |
| Endpoint B | `wgtcp-amp-b` | `10.20.1.6` | Azure `Standard_D4ps_v5`, Ampere Neoverse-N1 |

Both hosts are in Canada Central and run Ubuntu 24.04 with the Azure 6.8
kernel used for this campaign. They have private-only NICs. Existing restricted
TCP forwarding through the jump host exposes SSH only; no test service is
published directly.

Access was hardened as follows:

- authentication is public-key only;
- the campaign uses one explicit operator identity from the workstation;
- SSH agent, password, keyboard-interactive, GSSAPI, and host-based fallbacks
  are disabled by the orchestrator;
- server host keys are pinned in an isolated known-hosts file;
- root login is disabled and access is limited to `azureuser`;
- SSH forwarding, tunnels, X11, and gateway ports are disabled on the test
  hosts;
- no private key or secondary controller key is copied to either endpoint;
- SSH and Azure control traffic are excluded from impairment filters.

The user authorized starting, stopping, rebooting, deallocating, and otherwise
administering these two test hosts. A hard stop/start was used once to recover
both hosts after deleting an interface under an older module triggered matching
`wg_destruct()`/`free_netdev()` kernel faults. That lifecycle crash is a separate
implementation defect and is not meltdown evidence.

## 5. Test topology

The current upstream transport does not promote an accepted socket into the
configured peer. A responder-only TCP topology therefore does not work
reliably. Both peers are configured with endpoints, normally creating two
stable outer TCP streams, one initiated by each endpoint.

The harness samples both carrier tuples every 200 ms across each TCP workload
and writes an independent sampler-completion record. Missing interval coverage
or a tuple changing or disappearing invalidates the cell. The dual-carrier
topology is an implementation constraint and is explicitly documented so that
results are not generalized to a single outer TCP stream without further work.

Separate tunnel interfaces are used:

- stock UDP WireGuard control on the UDP test subnet;
- WireguardTCP on the TCP test subnet.

The data receiver is selected by workload direction. Interface receive-byte
counters, rather than iperf block-completion intervals, are the authoritative
source for 100 ms delivery and stall scoring.

## 6. Endogenous bottleneck construction

The shaping design separates rate/queue behavior from propagation impairment:

```text
egress:
  HTB root
    selected test class at configured rate
      bfifo with explicit byte limit, or fq_codel
    default class for unshaped control traffic

ingress:
  selective redirect to IFB
    netem half-RTT delay and optional exogenous loss
```

Only traffic between the two test addresses on UDP/51820, TCP/51821, and the
optional competing-flow port enters the shaped class.

For rate `R` Mb/s and emulated RTT `T` ms:

```text
BDP bytes = R * T * 125
queue bytes = BDP bytes * queue_bdp
```

The screening design includes 0.5x, 1x, and 4x BDP queues. `shape-link.sh`
refuses pre-existing `clsact` or IFB resources it does not own, records the
baseline qdisc signature, and verifies exact restoration. A cell is invalid if
the configured HTB rate, delay, queue type, queue limit, filters, clocks,
carrier stability, workload completion, or kernel health cannot be verified.

## 7. Campaign stages

The planned campaign is staged so expensive or destructive tests do not run
before controls and instrumentation are trustworthy:

1. clean TCP/UDP calibration with one and 16 inner flows;
2. 0.5x, 1x, and 4x BDP finite-queue sweeps;
3. a fine 50-400 ms RTT sweep around the inner-RTO transition;
4. random and burst-loss cells capable of forcing outer RTO;
5. selected 10-minute clean and high-risk endurance repetitions;
6. clean-impaired-clean and toggling epochs to measure hysteresis and recovery;
7. short-flow FCT, bidirectional traffic, Reno/CUBIC sensitivity, reverse-only
   impairment, jitter, fq_codel/AQM, ECN where supported, and competing CUBIC.

Screening cells use multiple repetitions. High-value queue, boundary, and
endurance cells require additional repetitions before conclusions.

## 8. Instrumentation and analysis implemented

The dedicated campaign under `perf-test/meltdown/` now includes:

- a secure workstation-controlled PowerShell orchestrator;
- repeatable module/tool deployment and tunnel setup;
- selective HTB, finite-queue, IFB, and netem configuration;
- 100 ms tunnel-interface counter sampling;
- 200 ms `ss -tinm` and qdisc/class/filter sampling;
- BPF tracing for inner/outer retransmission and RTO events;
- sampled congestion window, slow-start threshold, and SRTT observations;
- bounded BPF collection with six reconciled RTO/retransmission summaries;
- `nstat`, `/proc/net/snmp`, `/proc/net/netstat`, CPU, clock, module, kernel-log,
  and carrier-tuple evidence;
- monotonic-to-epoch timestamp normalization across hosts;
- outer-event to inner-RTO/cwnd-collapse coupling metrics;
- resume-safe result retrieval and per-cell JSON/CSV/Markdown output;
- source, runtime, matrix, repetition, cell, and campaign fingerprints;
- cleanup-gated cell publication and mandatory complete campaign manifests;
- automatic validity checks and matched-UDP degradation classification.

Important analysis corrections made during live testing:

1. JSON loading accepts UTF-8 BOMs and diagnostic text preceding the first JSON
   object.
2. PowerShell output is written without a BOM.
3. Multi-flow stall scoring no longer uses synchronized iperf interval
   completions, which falsely created alternating zero-delivery bins.
4. Receiver tunnel-interface counters are resampled onto exact 100 ms
   boundaries.
5. The measurement window begins with the receiver's first complete inner data
   packet.
6. RTO and retransmission events are filtered to the non-omitted workload
   window and workload ports.
7. Bidirectional RTO normalization uses twice the configured logical flow
   count.
8. Workload-window qdisc deltas are separated from setup and teardown traffic.
9. TCP cells require stable carrier tuples and complete 200 ms workload
   coverage.
10. Forward, reverse, and bidirectional receiver selection is explicit.
11. Missing receiver-counter samples remain missing rather than becoming
    artificial zero-delivery stalls.
12. BPF telemetry must complete and emit all six summaries. A summary may trail
    detailed events by one final probe at tracer shutdown; it may never exceed
    detailed events or trail by more than one.
13. Resume skips require matching campaign and cell fingerprints; stale source,
    runtime, matrix, or repetition state reruns the cell.
14. `cell.json` is not published until analysis and verified qdisc restoration
    succeed, and campaign analysis requires a complete manifest.
15. Competing-flow cells require successful, nonzero, sufficiently long
    competitor traffic.

## 9. Kernel defects found and local repairs

### 9.1 Five-second authenticated-carrier rotation

Accepted streams remain attached to provisional temporary peers. Upstream
cleanup treated them as unauthenticated forever and reclaimed them after the
five-second pre-authentication idle limit, even when the stream had carried a
valid Noise handshake. Source ports rotated on that cadence, destroying
goodput without any network congestion.

The local repair:

- assigns every accepted TCP stream a monotonic nonzero stream ID;
- carries the ID through asynchronous receive processing;
- marks only the exact stream that carried a successfully consumed Noise
  handshake as authenticated;
- keeps the five-second idle, 30-second absolute, and 128-entry
  pre-authentication limits unchanged;
- gives authenticated temporary receive carriers a 180-second activity-based
  idle deadline;
- does not promote the temporary stream into the configured peer;
- protects listener initialization from cleanup during callback installation
  and first read scheduling.

Focused lifecycle and roaming contract tests cover provenance, authentication
ordering, deadlines, and listener ownership.

### 9.2 Complete records stranded behind `EAGAIN`

A bulk `recvmsg()` can contain more than one framed record. The reader delivered
the first record, retained the complete leftover record, then attempted another
nonblocking receive before processing the leftover. If that call returned
`EAGAIN`, the complete record remained buffered until unrelated later traffic
caused another callback.

The local reader now:

- processes a complete buffered record before calling `recvmsg()` again;
- preserves and immediately drains complete leftover frames;
- bounds work per invocation and reschedules processable buffered work;
- coordinates reader scheduling with stream teardown.

Focused stream contract coverage guards the ordering.

### 9.3 Split-header resynchronization and ARM lifetime integration

The former resynchronizer performed a separate one-shot socket read after
rejecting buffered framing bytes. That design could discard the beginning of a
valid header split across callbacks and complicated socket-retirement identity.

The merged reader now:

- scans every complete eight-byte candidate with the full framing validator;
- retains at most the final seven bytes that could prefix a split header;
- returns so the ordinary reader appends later bytes using its socket captured
  at worker entry;
- drains complete retained records before another nonblocking read;
- sizes leftover storage to the exact suffix plus reserved header headroom;
- derives outbound synthetic headers from the live captured socket tuple,
  including connected source ports and IPv6 addresses.

These semantics combine the campaign's split-header repair with the parallel
ARM branch's captured-socket and exact-leftover fixes. Focused contracts guard
the combined behavior.

### 9.4 Apparent receive lag resolved as stale state

The protocol/AllowedIPs trace showed that the first correlated post-idle frame
was a legitimate zero-length WireGuard keepalive. Fresh synchronized traces
showed ordinary ping data passing framing, decryption, endpoint reconstruction,
protocol parsing, AllowedIPs lookup, and GRO immediately. Recreating the
dedicated tunnels removed the approximately 104 ms one-packet lag. It did not
reproduce across three fresh setups and is not treated as a remaining receive
pipeline defect.

### 9.5 TCP writer lost wakeup

The first calibrated 16-flow TCP runs collapsed to 0.07-0.17 Mb/s with 98-99%
zero-delivery bins. Function-level 1/2/4/8/16-flow tracing showed:

- successful enqueue count exceeded send count by exactly 1,024 frames;
- the internal queue then rejected new frames with `-ENOBUFS`;
- no physical-qdisc drops, outer retransmissions, or outer RTOs occurred;
- no write-space callback arrived.

The writer checked `sk_stream_is_writeable()` before `kernel_sendmsg()`. That
could bypass the `EAGAIN` path which retains the frame and arms
`SOCK_NOSPACE`, leaving queued work with no future callback. The repair:

- keeps the write worker as the only `kernel_sendmsg()` caller;
- attempts nonblocking sends until empty, partial, or `EAGAIN`;
- retains the exact serialized frame or unsent suffix before notification
  arming;
- holds no spinlock across `kernel_sendmsg()`;
- uses the existing memory barrier and scheduler/lifetime-lock recheck so a
  concurrent writable transition cannot be missed.

The repeated concurrency trace delivered 44.25-44.67 Mb/s at 1/2/4/8/16 flows.
At 16 flows, 10,801 sends returned `EAGAIN`, 1,492 write-space callbacks ran,
all iperf workloads completed, and no 1,024-frame residue remained.

### 9.6 Concurrent BPF summary accounting

Plain BPF map read/modify/write summaries lost updates when probes ran on
different CPUs. The trace now uses atomic increments. ARM compiler output
contained atomic map additions, and a 16-flow stress trace reconciled all
870 raw RTO/retransmission events.

Tracer shutdown can still race one final detailed probe after an `END` summary.
Analysis therefore permits a summary to trail raw events by exactly one. A
summary greater than raw events, or a lag greater than one, remains invalid.

## 10. Qualified measured results

Results from superseded implementation states are not pooled with the current
campaign.

### 10.1 Runtime identity

Calibration, screening, rerun qualification, and the 0.25x-BDP smoke used:

- kernel: `6.8.0-1062-azure`;
- module srcversion: `01DA86291E0FBD2CD3C940C`;
- module SHA-256:
  `05d0d5830adb04dfb16d80797b891a9cb1b45cc36bc6fd5eb82790aa372bbd6a`;
- userspace tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`.

The adaptive smoke was built independently on both endpoints from committed
checkpoint `2b9513f` and currently runs:

- module srcversion: `01DA86291E0FBD2CD3C940C`;
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`;
- the same userspace tool hash above.

The adaptive campaign has its own source/runtime fingerprint and is not merged
into an earlier single-fingerprint campaign.

### 10.2 Clean calibration

All 14 calibration cells are valid/stable:

| Workload | Repetitions | Median authoritative goodput | Stalls | Scored inner/outer RTOs |
|---|---:|---:|---:|---:|
| TCP, one flow | 3 reverse plus 1 forward | 46.979 Mb/s | 0 | 0 |
| TCP, 16 flows | 3 | 47.260 Mb/s | 0 | 0 |
| UDP control, one flow | 3 reverse plus 1 forward | 48.594 Mb/s | 0 | not applicable |
| UDP control, 16 flows | 3 | 48.594 Mb/s | 0 | not applicable |

Every calibration cell had stable dual TCP carriers where applicable, complete
telemetry, zero finite-queue drops, and verified qdisc restoration. The
16-flow TCP repetitions recorded 1,118-1,205 inner retransmissions without
timeout, stalls, or delivery collapse.

### 10.3 Qualified finite-queue and RTT-boundary screening

All 68 scheduled cells executed without an execution failure. Seven initial
evidence-window failures were rerun in a separate fingerprinted campaign. The
qualified composite retains per-cell source provenance and contains:

| Classification | Cells |
|---|---:|
| valid/stable | 68 |
| valid/degraded | 0 |
| valid/near-meltdown | 0 |
| valid/meltdown | 0 |
| invalid | 0 |

Together with calibration, all 82 scheduled cells are valid/stable.

Valid TCP cells generally delivered 46.4-47.3 Mb/s versus approximately
48.59 Mb/s for UDP controls. No valid cell produced an inner RTO or an outer
recovery event. One 250 ms TCP cell had a 0.9% stall fraction but remained
stable. One 0.5x-BDP/40 ms TCP cell recorded 12 queue drops without stalls,
RTOs, or recovery.

Most configured 50 Mb/s bottlenecks did not overflow because observed TCP
delivery remained below the bottleneck rate. Those cells validate operation at
their measured load but do not close the endogenous congestion feedback loop.

### 10.4 Initial invalid evidence and qualification rerun

The seven invalid repetitions are:

- `boundary-rtt100-16f-tcp-r2` and
  `boundary-rtt175-16f-tcp-r2`: one final raw BPF event beyond an `END`
  summary;
- `boundary-rtt300-16f-tcp-r2`: server carrier sampling ended before the full
  workload boundary;
- `boundary-rtt300-16f-udp-r2`: qdisc sampling ended before the full workload
  boundary;
- `boundary-rtt400-16f-tcp-r2`: both carrier and qdisc coverage ended early;
- `boundary-rtt400-16f-udp-r1` and
  `boundary-rtt400-16f-udp-r2`: qdisc coverage ended early, so the shaped-class
  usage requirement also could not be proven.

These were evidence-window failures, not observed transport collapse. The
initial campaign remains published unchanged with all seven invalid records.

The exact-cell rerun used the same module srcversion/hash, tool hash, and matrix
axes, plus a 30-second sampler margin. All seven cells are valid/stable with
complete BPF, qdisc, workload, and carrier evidence. A fail-closed composite
generator selected only those seven replacements, recomputed matched UDP
comparisons, and recorded the selected source campaign and cell fingerprint for
all 68 rows, together with each analyzed cell document's SHA-256. It refuses to
replace valid evidence or merge different runtime identities or axes.

### 10.5 Lower-rate mechanism smoke

The predeclared mechanism gate ran two TCP and two UDP repetitions at 35 Mb/s,
200 ms, 0.25x BDP, and 16 inner flows:

| Transport | Valid/stable | Goodput range | Queue drops | Inner/outer RTO |
|---|---:|---:|---:|---:|
| TCP | 2/2 | 32.80-33.08 Mb/s | 0 | 0 / 0 |
| UDP control | 2/2 | 34.02 Mb/s | 0 | 0 / 0 |

All four had zero 100 ms stalls, no negative trend, complete telemetry, stable
dual carriers, and verified cleanup. Across 1,077,876 shaped packets, the
sender-side queue peaked at 130,548 of 218,750 bytes (59.7%). HTB overlimits
confirmed active rate shaping, but the finite child queue did not overflow.
The predeclared gate therefore stopped the remaining 12 mechanism rows.

### 10.6 Adaptive finite-queue smoke

The separately predeclared adaptive gate used the same rate, RTT, flow count,
duration, and no-loss model with a 0.10x-BDP (87,500-byte) queue:

| Transport | Valid/stable | Goodput range | Queue drops | Peak sampled backlog | Inner/outer RTO |
|---|---:|---:|---:|---:|---:|
| TCP | 2/2 | 27.75-29.05 Mb/s | 60, 5 | 75.9-76.3% | 0 / 0 |
| UDP control | 2/2 | 33.94-33.98 Mb/s | 749, 718 | 97.3% | 0 / 0 |

Both TCP repetitions satisfied the overflow gate. No cell recorded an outer
retransmission or recovery event, and all fitted goodput trends were positive.
The first TCP repetition had 4.0% zero-delivery bins with a 100 ms longest
stall, below the 20% threshold; the others had none. The 0.05x-BDP fallback was
not run.

## 11. What can be concluded about TCP meltdown now

### Supported conclusions

- None of the 90 valid calibration, screening, or mechanism-smoke cells meets
  even one component of the predeclared full-meltdown definition.
- No valid cell has an inner RTO or outer recovery event, so there is no
  cross-layer recovery coupling to attribute to classical TCP-over-TCP
  meltdown.
- The severe pre-fix 16-flow collapse was a deterministic writer-notification
  defect with no outer loss or recovery, not classical meltdown.
- The writer repair restores clean 16-flow throughput and remains responsive
  through thousands of `EAGAIN`/write-space cycles.
- The current dual-carrier build is stable across the qualified calibration and
  screening evidence collected so far.

### Conclusions not yet supported

- The campaign does not rule out meltdown under heavier sustained overflow that
  forces outer retransmission/RTO, bidirectional contention, AQM/ECN, or
  endurance load.
- The current results should not be generalized from two outer streams to a
  single-carrier or responder-only design.
- The seven records in the initial campaign remain invalid and are not used as
  transport evidence; only their separate complete reruns enter the qualified
  composite.

The current assessment is: **no meltdown was observed in 90 qualified cells.
The adaptive smoke now proves finite-queue overflow, but it did not trigger
outer TCP recovery, so the full nested recovery feedback mechanism remains to
be exercised.**

## 12. Validation completed

- 91 repository source-contract, analysis, matrix, and composite-integrity
  tests pass;
- Python compilation, Bash syntax, PowerShell parsing, and diff whitespace
  checks pass;
- disposable-veth shaping produced parseable single-line qdisc JSON, accounted
  only handle `20:`, rate-limited traffic, and restored the baseline;
- the writer-fix module built independently on both ARM endpoints with matching
  srcversion and SHA-256;
- ARM BPF bytecode uses atomic counter updates;
- 870/870 raw stress-trace events reconcile;
- clean 1/2/4/8/16-flow writer traces completed without stranded frames;
- all 14 calibration, 68 initial screening, and seven qualification-rerun
  executions completed;
- all four mechanism-smoke executions completed valid/stable; the 12 broader
  rows were gated off because no queue overflow occurred;
- all four adaptive-smoke executions completed valid/stable; both TCP
  repetitions overflowed and the 0.05x-BDP fallback was gated off;
- the qualified composite contains 68/68 valid/stable rows, 61 initial cell
  fingerprints, and seven rerun fingerprints under an identical runtime
  identity;
- post-campaign cleanup restored physical qdiscs and left no sampler or
  competitor unit running;
- each endpoint retained two established carriers and the matching module
  srcversion;
- a fresh post-adaptive-smoke TCP probe delivered 10/10 packets at 0.319 ms
  mean;
- the temporary restricted access gateway is limited to its two forwarding
  sockets while mechanism testing remains active.

## 13. Repository changes in this investigation

Major changed or added surfaces include:

- `kernel/socket.c`: authenticated carrier lifetime, complete retained-record
  draining, split-header preservation, captured-socket handling, exact
  left-over storage, and writer notification repair;
- `kernel/socket.h`, `kernel/queueing.h`, and `kernel/receive.c`: exact stream
  provenance and post-Noise authentication;
- `tests/test_tcp_*_contract.py`: stream lifetime, framing, captured-socket,
  single-writer, suffix replay, and notification invariants;
- `perf-test/meltdown/harness/`: selective shaping, endpoint/interface samples,
  atomic TCP-event telemetry, fail-closed analysis, and provenance-preserving
  campaign composition;
- `perf-test/meltdown/orchestrator/run-campaign.ps1`: secure execution,
  fingerprints, exact-cell reruns, and cleanup-gated publication;
- `tests/test_meltdown_analysis.py` and `tests/test_meltdown_merge.py`: campaign
  analysis and composite-integrity coverage;
- `docs/TCP_TRANSPORT_DESIGN.md`, `docs/DESIGN_LOG.md`, and `CHANGELOG.md`:
  implementation and evidence history;
- `perf-test/meltdown/results/`: compact reviewable calibration and screening
  inventories.

## 14. Evidence retention

Raw per-cell artifacts, diagnostic traces, synchronized host captures, and
host-specific access files remain outside Git. They include:

- writer concurrency traces and BPF atomic-validation evidence;
- complete 14-cell calibration, 68-cell initial screening, seven-cell rerun,
  four-cell mechanism-smoke, and four-cell adaptive-smoke directories;
- per-endpoint BPF, socket, qdisc, interface, nstat, CPU, clock, and kernel-log
  evidence;
- source/runtime/cell/campaign fingerprints and completion markers.

Git contains compact calibration, initial-screening, rerun, qualified composite,
mechanism-smoke, and adaptive-smoke inventories. The qualified directory
includes a source fingerprint for every selected cell. No credentials, private
keys, or host-specific connection files are included.

## 15. Current host state at cutoff

- Both dedicated test hosts are running the matching writer-fix module.
- UDP and TCP test interfaces are configured.
- Two TCP carrier streams are established.
- Physical qdiscs are restored; no campaign impairment is active.
- No sampler or competitor unit is running.
- A fresh TCP probe passed with zero loss and 0.319 ms mean RTT.
- The temporary restricted access gateway is running only for the active
  mechanism investigation and exposes only two restricted forwarding sockets.
- Restricted test access/services and tunnel state still require final
  closeout cleanup after the remaining campaign.

## 16. Remaining work

Mechanism and breadth:

1. run the predeclared 0.05x-BDP recovery smoke and require valid overflow plus
   outer retransmission or RTO before the 12 broader recovery rows;
2. run burst-loss and outer-RTO cells and measure temporal coupling;
3. run fq_codel/AQM and ECN arms, competing CUBIC, and bidirectional traffic;
4. add Reno/BBR sensitivity, short-flow FCT, jitter, reverse-only impairment,
   dynamics, and selected 10-minute endurance tests.

Closeout:

1. generate final compact tables and plots and document every completed,
   invalid, and unrun cell;
2. rotate credentials exposed by historical commits;
3. verify qdisc/tunnel restoration, remove transient services/access state, and
   deallocate both Azure hosts;
4. restore private-repository authorization and push the investigation commits.

## 17. Reading order

1. [`README.md`](README.md) - campaign purpose, layout, and invocation
2. [`TESTPLAN.md`](TESTPLAN.md) - immutable definitions and validity rules
3. this document - interim engineering state and evidence
4. [`results/2026-07-13-wakeup-calibration/REPORT.md`](results/2026-07-13-wakeup-calibration/REPORT.md)
5. [`results/2026-07-13-wakeup-screening-initial/REPORT.md`](results/2026-07-13-wakeup-screening-initial/REPORT.md)
6. [`results/2026-07-13-wakeup-screening-rerun/REPORT.md`](results/2026-07-13-wakeup-screening-rerun/REPORT.md)
7. [`results/2026-07-13-wakeup-screening-qualified/REPORT.md`](results/2026-07-13-wakeup-screening-qualified/REPORT.md)
8. [`results/2026-07-13-mechanism-smoke/REPORT.md`](results/2026-07-13-mechanism-smoke/REPORT.md)
9. [`results/2026-07-13-adaptive-smoke/REPORT.md`](results/2026-07-13-adaptive-smoke/REPORT.md)
