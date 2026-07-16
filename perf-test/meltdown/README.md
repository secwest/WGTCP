# TCP-over-TCP Meltdown Campaign

This campaign tests the mechanism that the baseline random-loss campaign could
not exercise: offered load fills a finite carrier queue, overflow loss stalls
the outer TCP connection, and those stalls trigger congestion responses in
inner TCP flows.

This is a causal stress campaign, not a prevalence study. All 82 clean
calibration and finite-queue/RTT screening cells were valid/stable. Severe
behavior appeared only in the deliberately harsh breadth envelope: 16
saturated CUBIC flows, a 50 Mb/s 1x-BDP FIFO, 200-400 ms RTT, and persistent
random or burst loss. No valid execution was formal meltdown. The lowest
demonstrated severe profile used 4.42% nominal stationary burst loss at 200 ms;
the unrun 0.3% random-loss row means the lower onset is unknown. See
[`../../docs/TCP_MELTDOWN.md`](../../docs/TCP_MELTDOWN.md) for the calibrated
operator-facing conclusion.

The existing [`../REPORT.md`](../REPORT.md) remains useful application-level
evidence, but it does not establish or exclude meltdown. It used exogenous
random loss and aggregate averages. This directory adds:

- a rate-limited carrier bottleneck with finite queues measured in BDP;
- matched TCP and UDP WireGuard controls;
- 100 ms inner-delivery bins and a predeclared meltdown definition;
- per-layer TCP retransmission and RTO events;
- timestamped socket, qdisc, CPU, and TCP-counter samples;
- single- and multi-flow bulk tests, RTT-boundary sweeps, AQM/ECN, burst,
  dynamics, short-flow, bidirectional, CC, and contention stages.

Read [`TESTPLAN.md`](TESTPLAN.md) before running. The thresholds in that file
must not be changed after inspecting a campaign. The current implementation,
environment, evidence, and blockers are recorded in
[`INVESTIGATION_STATUS.md`](INVESTIGATION_STATUS.md).

## Current evidence

The fixed campaign has completed its clean, finite-queue, recovery, qualified
burst, and 20-execution burst-breadth stages. The pre-breadth released selection
is 106/106 complete: 98 valid (92 stable, five degraded, one near-meltdown),
zero meltdown, and eight invalid.

The breadth base completed 20/20 executions; six evidence-invalid cells were
rerun exactly once. The resulting 26 raw executions contain 19 valid outcomes
(10 degraded and nine near-meltdown), zero meltdown, and seven invalid. One
random-loss TCP cell remained invalid after its sole rerun, so the all-valid
breadth composite is stopped rather than repaired by changing a gate or adding
another retry.

The full post-repair raw-execution audit is 162 executions: 122 valid
(92 stable, 17 degraded, 13 near-meltdown), zero meltdown, and 40 invalid.
Severe nested stalls and outer recovery are established, but no valid execution
simultaneously meets the predeclared stall, declining-goodput, and inner-RTO
conditions. See
[`results/2026-07-14-final-audit/`](results/2026-07-14-final-audit/).

The active boundary strategy and all results released so far are summarized in
[`BOUNDARY_STATUS.md`](BOUNDARY_STATUS.md).

The timed packet-correlation stage is now frozen incomplete. It selected 23
valid logical cells across the 1-, 2-, 4-, and partial 8-packet residence
points, retained eight invalid originals, and safety-stopped one exact rerun
during external package-service interference. Residence 16 is unrun, no
correlation onset threshold is claimed, and Stage 3 is not released. Compact
attempt, logical-cell, profile, source-manifest, and audit provenance is in
[`results/2026-07-16-boundary-stage2-correlation/`](results/2026-07-16-boundary-stage2-correlation/).

Across the nine valid logical TCP breadth cells, longest continuous
zero-delivery runs were 0.7-40.2 seconds (median 6.3 seconds) in 60-second
workloads. At the lowest severe profile, repetitions stalled for at most 0.7
and 6.3 seconds while spending 52.8% and 62.2% of the full measurement window
with no delivery.

## Layout

```text
meltdown/
  TESTPLAN.md
  INVESTIGATION_STATUS.md
  matrix-screening.csv
  matrix-mechanism.csv
  matrix-mechanism-adaptive.csv
  matrix-mechanism-recovery.csv
  matrix-mechanism-burst.csv
  matrix-mechanism-burst-recovery.csv
  matrix-mechanism-burst-qualified.csv
  matrix-mechanism-burst-transport-qualified.csv
  matrix-mechanism-burst-breadth.csv
  BOUNDARY_TESTPLAN.md
  BOUNDARY_STATUS.md
  matrix-boundary-smoke.csv
  matrix-boundary-correlation.csv
  harness/
    install-host.sh
    setup-tunnels.sh
    shape-link.sh
    sample-endpoint.sh
    tcp-events.bt
    analyze.py              # cell/campaign analysis and raw stall timelines
    compose_campaigns.py    # sharded/stopped campaign audit composition
  orchestrator/
    run-campaign.ps1
  results/<campaign>/
    campaign-status.json
    cells.csv
    REPORT.md
    cells/                 # raw local artifacts, gitignored
      <cell>/
        cell.json
        cell.fingerprint
        cell.complete
  results/<qualified-composite>/
    composite-status.json
    provenance.csv
    cells.csv
    REPORT.md
  results/2026-07-14-final-audit/
    campaigns.csv          # raw-execution inclusion/exclusion ledger
    README.md
  results/2026-07-16-boundary-stage1-smoke/
    cells.csv              # compact cross-pair smoke summary
    README.md
  results/2026-07-16-boundary-stage2-correlation/
    attempts.csv           # every valid, invalid, failed, or stopped attempt
    logical-cells.csv      # selected, unresolved, and unrun matrix state
    profiles.csv           # correlation-point release summary
    README.md
```

## Safety model

`shape-link.sh` classifies only test traffic between the peer addresses on
WireGuard ports 51820/51821 and the optional competing-flow port 5202. The
egress HTB class feeds a byte-limited FIFO or fq_codel queue directly, so
overflow is load-dependent. Selective ingress redirection to an IFB applies
one-way delay and optional exogenous loss without putting SSH, Azure agent,
DNS, or NTP traffic in the impairment path. The script refuses to replace an
unknown root qdisc, records a marker under `/run/wgtcp-meltdown`, and verifies
that cleanup restores the normalized baseline qdisc state.

The workstation orchestrates both endpoints directly. SSH uses one explicit
operator key, password and agent fallback are disabled, server host keys must
exist in a caller-supplied pinned known-hosts file, and no private or secondary
controller key is copied to either VM. Host setup is intentionally ephemeral:
it loads the repository module with `insmod`, creates only `wg-mt-udp` and
`wg-mt-tcp`, and uses transient systemd services.

## Run

The two test hosts need SSH endpoints reachable by the operator. They may be
direct addresses, Bastion/native-client forwards, or restricted TCP proxies.
No address or credential is stored in this repository.

```powershell
.\orchestrator\run-campaign.ps1 `
  -HostA <ssh-host> -PortA <ssh-port-a> `
  -HostB <ssh-host> -PortB <ssh-port-b> `
  -PrivateIpA <carrier-ip-a> -PrivateIpB <carrier-ip-b> `
  -SshKey <operator-key> -KnownHostsFile <pinned-known-hosts> `
  -RemoteSourceDir /home/azureuser/WireguardTCP-build `
  -Stage calibration,queue,boundary `
  -ResultsDir .\results\2026-07-11-ampere
```

Use `-PrepareOnly` to build the control path and tunnels without running cells.
Use one or more exact matrix cell names with `-Cell` to rerun only selected
repetitions without replacing already-qualified evidence:

```powershell
.\orchestrator\run-campaign.ps1 <connection-and-topology-arguments> `
  -SkipPrepare `
  -Cell boundary-rtt300-16f-tcp-r2,boundary-rtt300-16f-udp-r2 `
  -ResultsDir .\results\2026-07-13-targeted-rerun
```

### Reanalyze a reproduced campaign

Raw campaign directories contain `cell.env`, `iperf3.json`, per-endpoint
`interface-series.csv`, qdisc/socket/BPF data, and the completion markers needed
by the fail-closed analyzer.

```powershell
python .\harness\analyze.py cell `
  .\results\<campaign>\cells\<cell>

python .\harness\analyze.py campaign `
  .\results\<campaign> `
  --csv .\results\<campaign>\cells.csv `
  --report .\results\<campaign>\REPORT.md
```

### Explore zero-delivery stalls

The `stalls` command reuses the analyzer's exact receiver selection, first-data
anchor, warm-up exclusion, 100 ms alignment, and coverage rules. It refuses to
join runs across missing delivery samples. JSON and CSV rows include exact
start/end nanoseconds and mark runs touching either measurement boundary as
censored.

```powershell
# JSON summary plus every contiguous zero-delivery interval.
python .\harness\analyze.py stalls `
  .\results\<campaign>\cells\<cell>

# CSV interval timeline for plotting or correlation with BPF/qdisc events.
python .\harness\analyze.py stalls `
  .\results\<campaign>\cells\<cell> `
  --csv .\results\<campaign>\<cell>-stalls.csv
```

Committed compact summaries can be explored without raw artifacts:

```powershell
Import-Csv .\results\2026-07-14-burst-breadth\cells.csv |
  Where-Object { $_.tunnel -eq 'tcp' } |
  Sort-Object { [int]$_.longest_stall_ms } -Descending |
  Format-Table cell_id,valid,classification,goodput_mbps,
  stall_fraction_100ms,longest_stall_ms,outer_recovery_events
```

Raw `cells/` artifacts remain gitignored because socket and qdisc series can be
large. Reproducing a campaign creates those files locally for event-level
analysis; published `cells.csv` files retain the comparable stall fraction,
longest stall, loss, recovery, validity, and classification fields.

Campaign execution is resume-safe only across identical evidence identities. A
cell is skipped when `cell.json`, `cell.complete`, and a matching
`cell.fingerprint` all exist. Changes to campaign sources, test plan, matrix
axes, repetition, module, tool, or common fixed-path endpoint iperf version and
executable hash make the prior cell stale. Campaign analysis also requires a
complete manifest listing every expected fingerprint. Before impairment, the
runner also binds each controller endpoint to its declared physical address and
fixed local/peer TCP and UDP tunnel addresses, so reversed host roles fail
closed. Targeted `-Cell` runs
retain exact cell fingerprints but their manifests set
`targeted_selection=true` and `qualifying_complete=false`; they cannot
constitute a complete gate. Raw artifacts stay under the gitignored `cells/`
directory; generated `cells.csv` and the dated report are the reviewable
evidence.

Historical matrices use the implicit `strict` workload-completion policy:
nonzero iperf exit status is invalid. The prospective
`matrix-mechanism-burst-qualified.csv` opts into `interval_complete`, which can
accept only an allowlisted final-control failure after exact flow count,
near-full continuous interval output, and complete independent interface
delivery are all proven. Bidirectional workloads must prove both interval
directions independently. It does not rescore prior artifacts. See
[`TESTPLAN.md`](TESTPLAN.md) for the fixed thresholds and error allowlist.
Current traces attach monotonic sequence numbers to every event/layer/CPU stream
and require each detailed stream to contain exactly `1..N` through its terminal
map value. Missing, duplicated, skipped, reordered, wrong-CPU, or mixed-format
evidence therefore fails closed. Legacy scalar and per-CPU-count summaries
retain their original compatibility semantics only when reanalyzing historical
evidence.

The separately fingerprinted
`matrix-mechanism-burst-transport-qualified.csv` keeps the exact
`2/25/90/1` severity but opts into `impairment_validation=transport_aware`.
Every cell must first pass an unshaped zero-loss, at-most-20-ms tunnel
preflight. After shaping, UDP retains the existing RTT and 0.5x-2x stationary
loss bands. TCP must retain liveness, at least 0.7x configured RTT, exact live
qdisc parameters, monotonic counters, and nonzero netem traffic and drops, but
post-loss RTT amplification and the realized loss fraction are measured
outcomes rather than upper-bounded validity controls. Historical and
policy-absent cells remain strict and are never rescored.

When a separate fingerprinted campaign reruns evidence-invalid cells, build an
auditable qualified composite rather than copying over the original cells:

```powershell
python .\harness\merge_campaigns.py `
  --base <raw-initial-campaign> `
  --replacement <raw-exact-cell-rerun> `
  --output .\results\<qualified-composite>
```

The merger requires explicit full-matrix qualification metadata, so legacy,
targeted, or incomplete campaigns cannot serve as a base. It refuses to replace
valid evidence and refuses to combine different runtime identities, including
prospectively recorded iperf versions and executable
hashes, or matrix axes. It retains both source campaign fingerprints and writes
the selected fingerprint and analyzed `cell.json` SHA-256 for every cell to
`provenance.csv`.

For a matrix split across many pair-specific shards, or one that stops before a
fully valid selection exists, compose a chronological audit instead:

```powershell
python .\harness\compose_campaigns.py `
  --matrix .\matrix-boundary-correlation.csv `
  --campaign <first-shard> `
  --campaign <next-shard-or-exact-rerun> `
  --audit-evidence stopped-cell=<preserved-audit-directory> `
  --output .\results\<stopped-composition>
```

Campaign arguments declare chronological attempt order. For every repeated
cell, the compositor requires the later shard's hash-bound `updated_at` to be
strictly newer; disjoint shard order must still be reconciled with the campaign
audit timeline before publication. The compositor requires every shard to bind
the exact full matrix, enforces identical runtime identity and matrix axes,
permits a rerun only after evidence-invalid execution, requires exact cell and
pair campaign fingerprints, and permits at most two attempts per logical cell.
Matched TCP/UDP controls must also share that pair fingerprint. It emits
separate ledgers for all attempts and all matrix cells, so invalid originals,
valid replacements, failed or stopped attempts, and unrun cells remain visible
rather than being copied over. Safety-stop events are latched independently
from analyzable attempt outcomes, and unmanifested on-disk cell evidence is
rejected. The stop cell must be the final manifested attempt and no later shard
may add evidence. Timed endpoint metrics and conditions also require their exact
numeric or boolean types before matched-control scoring.
