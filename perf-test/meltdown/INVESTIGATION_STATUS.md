# WireguardTCP TCP Meltdown Investigation - Interim Status

Status cutoff: 2026-07-13 01:57 PDT (2026-07-13 08:57 UTC)

This is an interim engineering record, not the final campaign report. It
documents the repository, host, harness, implementation, measurements, and
conclusions reached so far. The impairment matrix is intentionally paused until
the TCP tunnel passes repeatable clean-path controls.

## 1. Executive summary

The campaign is not yet in a position to claim either that WireguardTCP melts
down or that it is resistant to meltdown.

The test design and most of the campaign machinery now exercise the right
mechanism: offered load fills a finite queue, queue overflow or delay stalls the
outer TCP carrier, and inner delivery, congestion control, retransmission
timers, and recovery are measured against an exact UDP WireGuard control.
Meltdown thresholds and validity rules were declared before impairment results.

Testing exposed several WireguardTCP implementation defects before that
mechanism could be evaluated:

1. accepted TCP streams were reclaimed after five seconds because they remained
   provisional;
2. complete records left in a bulk receive buffer could be stranded behind a
   subsequent nonblocking `recvmsg()` returning `EAGAIN`;
3. fresh tunnel setups can still run one packet behind, producing approximately
   104 ms ping RTT at 100 ms probe spacing and losing the final outstanding
   packet.

The first two defects have local fixes and focused contract coverage. The
patched build has demonstrated long clean intervals, including 0.322 ms mean
RTT with 0/1780 packets lost over 370 seconds and successful Noise rekeys.
However, that behavior is not repeatable after every fresh interface setup.

The newest BPF evidence changes the diagnosis of the remaining one-packet lag.
`wg_tcp_data_ready()`, `wg_tcp_read_worker()`, and `kernel_recvmsg()` all run
promptly. A complete 136-byte frame is read, decrypted successfully, and has a
valid reconstructed endpoint. The first correlated packet is then discarded
before `napi_gro_receive()`. The next packet, approximately one probe interval
later, reaches GRO and immediately triggers a reply. The immediate blocker is
therefore later in the authenticated receive pipeline, not a demonstrated
socket-callback or read-worker lost wakeup.

No poor TCP result collected so far is valid evidence of classical
TCP-over-TCP meltdown. The collapses occurred with no outer queue loss,
retransmission, RTO, or recovery event. They are implementation failures on a
clean path. Conversely, the successful clean-path soaks do not prove resistance
to meltdown because the high-risk endogenous finite-queue and endurance matrix
has not yet run on a repeatably correct build.

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
12. BPF telemetry must complete and emit all six summaries, with counts matching
    detailed RTO/retransmission events.
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

### 9.4 Remaining fresh-setup one-packet lag

After the prior fixes, a fresh strict preparation can still exhibit one-packet
lag:

- approximately 104 ms RTT with 100 ms probes;
- the final outstanding ping is often lost, producing roughly 2-25% loss in
  short probes;
- two outer carriers remain established and stable;
- no impairment qdisc is active.

This behavior originally looked like a receive-worker lost wakeup because the
delay follows the next packet's arrival. BPF tracing now localizes it further
downstream.

## 10. Measured results so far

Results from different implementation states are not pooled. The table is a
diagnostic history, not a scored campaign summary.

| Build/context | Test | Observation | Interpretation |
|---|---|---|---|
| Upstream `74a68d7` | UDP, 50 Mb/s/40 ms calibration | about 45.7-45.9 Mb/s | Healthy control |
| Upstream `74a68d7` | TCP, one flow | about 0.66 Mb/s | Carrier cleanup defect; not meltdown |
| Upstream `74a68d7` | TCP, 16 flows | about 3.43 and 4.91 Mb/s in valid repetitions | No outer loss/RTO; not classical meltdown |
| Earlier diagnostic build | TCP clean smoke | about 0.03-0.074 Mb/s, about 99% apparent stalls, repeated inner RTOs | Handshake/carrier/read defects; not meltdown |
| Patched authenticated-carrier build | 45-second carrier check | unchanged carrier tuples; 0.303 ms mean ping | Former five-second rotation removed |
| Patched reader build | 370-second ping/rekey soak | 0/1780 lost, 0.322 ms mean, three successful Noise rekeys | Strong clean-path success for one setup |
| Patched reader build | 250-second idle/rekey check | 20/20 probes, 0.298 ms mean after rekey | Idle/rekey path succeeded once |
| Same deployed build after fresh setup | 100 ms ping train | about 104 ms RTT and final-packet loss | Remaining deterministic one-packet pipeline lag |

The module still loaded during the latest tracing is:

- srcversion: `FA765AD5F9F65E0768CADA6`
- SHA-256:
  `ccf693af58eda5e109d80b51f5643b661824e47f2aad493f1f0cc3d54734843d`

The exact merged candidate was then built independently on both ARM hosts,
without loading it:

- kernel: `6.8.0-1062-azure`
- srcversion: `2C69667F330A67B0D720BB8`
- SHA-256:
  `0be3a49888aa36f8a708bdba3f8e937a9d3e9c40a97629634dcb36e764d8bb6c`

Both hosts produced the same identity. Keeping the candidate unloaded preserves
the traced failure state for the final protocol/allowed-IP discriminating run.

## 11. Latest BPF receive-pipeline evidence

Tracing was performed on both the requester and responder with 100 ms ping
spacing.

### 11.1 TCP callback and read worker

For each correlated arrival:

1. `wg_tcp_data_ready()` ran;
2. `wg_tcp_read_worker()` began tens of microseconds later;
3. `kernel_recvmsg()` returned one complete 136-byte frame;
4. a second nonblocking `kernel_recvmsg()` returned `-EAGAIN`;
5. the worker exited promptly.

There was one worker invocation per callback. The observed 104 ms delay was not
spent waiting for the callback, workqueue, or socket read.

### 11.2 Decryption and NAPI delivery

The first correlated post-idle frame followed this path:

```text
wg_tcp_data_ready
  -> wg_tcp_read_worker
  -> wg_packet_receive
  -> decrypt_packet returns success
  -> wg_packet_rx_poll
  -> wg_socket_endpoint_from_skb returns success
  -> no napi_gro_receive
  -> no immediate TCP reply
```

The next 136-byte frame arrived approximately 104 ms later and followed:

```text
wg_tcp_data_ready
  -> wg_tcp_read_worker
  -> wg_packet_receive
  -> decrypt_packet returns success
  -> wg_packet_rx_poll
  -> wg_socket_endpoint_from_skb returns success
  -> napi_gro_receive
  -> reply queued and written within tens of microseconds
```

This pattern repeated across short probes. It explains why reply `N` appears
only after request `N+1`, while also showing that the earlier lost-wakeup
hypothesis is not supported by the latest trace.

The remaining candidate branches are inside
`wg_packet_consume_data_done()` between endpoint reconstruction and
`napi_gro_receive()`, including keepalive handling, inner network-header
type/size validation, trimming, and allowed-IP source routing. A trace program
has been extended to instrument `ip_tunnel_parse_protocol()` and
`wg_allowedips_lookup_src()`, but that final discriminating run had not been
executed at this status cutoff.

## 12. What can be concluded about TCP meltdown now

### Supported conclusions

- The original random-loss results were not sufficient to test classical
  meltdown because loss was exogenous and the harmed inner quantities and
  cross-layer timing were not measured.
- Several severe TCP results in this investigation are definitively
  implementation defects, not congestion-induced meltdown.
- Accepted-carrier lifetime and framed-stream receive ordering materially affect
  apparent performance and can mimic meltdown metrics.
- The patched transport can sustain sub-millisecond clean traffic and Noise
  rekeys for several minutes in at least some fresh setups.
- The current harness is substantially closer to a defensible mechanistic test:
  finite queues, matched UDP controls, receiver delivery, timer separation,
  carrier validity, and temporal coupling are all represented.

### Conclusions not yet supported

- No valid high-risk endogenous-congestion cell has yet demonstrated full
  meltdown under the predeclared definition.
- No valid high-risk campaign has yet ruled meltdown out.
- There is not yet enough repeatable clean-path stability to publish throughput,
  queue-boundary, RTT-boundary, short-flow, or endurance comparisons.
- The current dual-outer-stream topology should not be generalized to every
  TCP tunnel design.

The honest current assessment is: **WireguardTCP is not yet being measured
against meltdown; implementation correctness remains the gating issue.**

## 13. Validation completed

For the merged checkpoint:

- 79 repository tests passed;
- Python compilation passed;
- Bash syntax checks passed;
- PowerShell parsing passed;
- diff whitespace checks passed;
- disposable-veth shaping apply/rollback restored the baseline;
- the complete endpoint sampler ran on both ARM hosts;
- each real sampler produced successful BPF and socket status records, the BPF
  header and all six reconciled summaries, and a completion marker;
- 22-23 socket samples per endpoint showed two unchanged carrier tuples;
- the exact candidate built independently on both ARM hosts with matching
  srcversion and module SHA-256;
- the candidate was not loaded over the preserved tracing build;
- isolated identity-only, pinned-host SSH authentication passed;
- clean-path carrier stability and rekey soaks passed in selected setups.

Additional protocol/allowed-IP trace programs remain session artifacts rather
than repository sources.

## 14. Repository changes in this investigation

Major changed or added surfaces include:

- `kernel/socket.c`
  - accepted-stream identity and authenticated lifetime;
  - listener initialization handoff protection;
  - buffered-record drain ordering and bounded rescheduling;
  - split-header suffix preservation;
  - captured-socket tuple reconstruction and exact leftover allocation;
  - reader/teardown scheduling coordination.
- `kernel/socket.h`
  - authenticated pending-stream API.
- `kernel/queueing.h`
  - TCP stream provenance in packet metadata.
- `kernel/receive.c`
  - exact-stream authentication after successful Noise processing.
- `tests/test_tcp_lifecycle_contract.py`
  - stream provenance, deadlines, and listener ownership.
- `tests/test_tcp_roaming_contract.py`
  - authentication ordering.
- `tests/test_tcp_stream_contract.py`
  - buffered-leftover drain, split-header resynchronization, and captured-socket
    behavior.
- `tests/test_meltdown_analysis.py`
  - JSON tolerance, interface delivery, telemetry completion, carrier coverage,
    campaign fingerprints/manifests, competitor validity, and matched-control
    analysis.
- `perf-test/meltdown/harness/analyze.py`
  - fail-closed validity, timing, delivery, telemetry reconciliation, RTO,
    queue, carrier, fingerprint, manifest, and coupling analysis.
- `perf-test/meltdown/harness/sample-endpoint.sh`
  - endpoint evidence, bounded BPF lifecycle, socket completion, and
    tunnel-counter collection.
- `perf-test/meltdown/harness/sample-interface.py`
  - stable 100 ms interface sampling.
- `perf-test/meltdown/harness/shape-link.sh`
  - selective endogenous bottleneck construction and verified restoration.
- `perf-test/meltdown/orchestrator/run-campaign.ps1`
  - secure two-host deployment, strict controls, execution, retrieval, and
    cleanup-gated publication with source/runtime/cell fingerprints.
- `perf-test/meltdown/matrix-screening.csv`
  - matched calibration, queue, and RTT-boundary cells.
- `docs/TCP_TRANSPORT_DESIGN.md`
  - authenticated temporary carriers and buffered-record draining.

## 15. Evidence retained outside Git

Raw campaigns and diagnostic traces are intentionally not committed. Principal
artifact groups include:

- upstream `74a68d7` calibration;
- authenticated-carrier patched preparation;
- patched clean baselines;
- reader-fix preparation;
- strict fresh-setup preparation;
- smoke matrices and per-cell data;
- BPF callback, read, decrypt, NAPI, and transmit traces.
- final full-sampler evidence from both endpoints, including status, summary,
  and carrier-coverage records.

Generated campaign cell directories remain gitignored. Final reviewable output
will consist of compact summaries, plots, environment manifests, completed and
invalid cell inventories, and the final dated report.

## 16. Current host state at cutoff

- Both dedicated test hosts are running.
- The earlier tracing module is loaded on both.
- The final merged candidate is built identically on both but is not loaded.
- UDP and TCP test interfaces are configured.
- Two TCP carrier streams are established.
- No campaign impairment qdisc was present in the latest clean-path checks.
- Short-lived BPF and sampler processes completed normally.
- Restricted SSH proxying, transient test services, and tunnel state still need
  final cleanup after the campaign.

## 17. Remaining work

Immediate correctness work:

1. run the prepared protocol/allowed-IP trace and identify the exact
   pre-`napi_gro_receive()` branch;
2. repair the root cause without weakening authentication, source validation,
   provisional-stream limits, or teardown safety;
3. reconcile any new upstream or parallel-debug changes before modifying the
   shared transport code;
4. rebuild and deploy identical modules;
5. repeat multiple cold/fresh interface setup cycles;
6. require zero loss and sub-millisecond unshaped TCP controls each time.

Campaign qualification:

1. run a matched TCP/UDP two-cell smoke;
2. verify receiver timing, 100 ms bins, BPF filtering, qdisc-window deltas,
   carrier stability, and exact qdisc restoration;
3. run matched clean calibration;
4. run finite-queue and RTT-boundary screening with repetitions;
5. select and run burst, workload, dynamic, and endurance cells.

Closeout:

1. generate compact result tables and plots from raw evidence;
2. document every completed, invalid, and unrun cell;
3. state whether the predeclared meltdown definition was met and whether outer
   coupling supports attribution;
4. restore host qdiscs and tunnel state;
5. remove transient services and restricted proxies;
6. deallocate idle Azure hosts.

## 18. Reading order

1. [`README.md`](README.md) - campaign purpose, layout, and invocation
2. [`TESTPLAN.md`](TESTPLAN.md) - immutable definitions and validity rules
3. this document - interim engineering state and evidence
4. generated `results/<campaign>/REPORT.md` - final scored results, when the
   qualified campaign completes
