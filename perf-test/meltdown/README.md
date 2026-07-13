# TCP-over-TCP Meltdown Campaign

This campaign tests the mechanism that the baseline random-loss campaign could
not exercise: offered load fills a finite carrier queue, overflow loss stalls
the outer TCP connection, and those stalls trigger congestion responses in
inner TCP flows.

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

## Layout

```text
meltdown/
  TESTPLAN.md
  INVESTIGATION_STATUS.md
  matrix-screening.csv
  harness/
    install-host.sh
    setup-tunnels.sh
    shape-link.sh
    sample-endpoint.sh
    tcp-events.bt
    analyze.py
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

Campaign execution is resume-safe only across identical evidence identities. A
cell is skipped when `cell.json`, `cell.complete`, and a matching
`cell.fingerprint` all exist. Changes to campaign sources, test plan, matrix
axes, repetition, module, or tool identity make the prior cell stale. Campaign
analysis also requires a complete manifest listing every expected fingerprint.
Raw artifacts stay under the gitignored `cells/` directory; generated
`cells.csv` and the dated report are the reviewable evidence.

When a separate fingerprinted campaign reruns evidence-invalid cells, build an
auditable qualified composite rather than copying over the original cells:

```powershell
python .\harness\merge_campaigns.py `
  --base <raw-initial-campaign> `
  --replacement <raw-exact-cell-rerun> `
  --output .\results\<qualified-composite>
```

The merger refuses to replace valid evidence or combine different runtime
identities or matrix axes. It retains both source campaign fingerprints and
writes the selected fingerprint and analyzed `cell.json` SHA-256 for every cell
to `provenance.csv`.
