# WireguardTCP Performance

## Executive summary

WireguardTCP provides a TCP carrier for WireGuard without changing WireGuard's
encryption, keys, peer identity, or `AllowedIPs` model. The measured and
functional results show seven practical advantages:

1. **Competitive clean-path speed.** On low- and medium-latency test paths,
   TCP mode matched or exceeded UDP mode in several bulk-transfer and HTTPS
   workloads.
2. **Lower CPU utilization in selected clean-path workloads.** On clean LAN
   cells, TCP-WG used 6.7%-10.9% less mean CPU for bulk transfer and
   11.7%-16.6% less for sequential HTTPS across x64 and arm64.
3. **Much stronger application delivery in selected lossy-path tests.** The
   outer TCP stream retransmitted missing data instead of exposing every outer
   loss directly to the inner workload.
4. **No formally classified TCP-over-TCP meltdown.** Across 122 valid
   post-repair executions in the dedicated mechanistic campaign, no execution
   met all three predeclared meltdown conditions, including runs in a
   deliberately extreme laboratory envelope.
5. **Outbound-only NAT traversal.** A private peer established through SNAT
   without DNAT or a forwarded inbound port, then roamed across source-address
   and source-port changes.
6. **Kernel-native operation.** The persistent carrier needs no proxy, relay,
   or extra userspace encapsulation process, while retaining normal WireGuard
   keys, AllowedIPs, keepalives, and configuration tools.
7. **Bounded and recoverable stream handling.** Capped queues, exact
   short-write continuation, parser resynchronization, fatal-send retirement,
   and replacement-carrier recovery passed focused destructive tests.

TCP mode is not universally faster than UDP. At clean 195-227 ms RTT, some
bulk-TCP results were 14%-23% lower, and the harshest persistent-loss tests
produced severe TCP-specific stalls even though they did not meet the complete
formal meltdown definition. The useful conclusion is therefore not that
TCP-over-TCP can never degrade. It is that **broad or inevitable meltdown was
not observed, normal controls remained stable, and TCP mode delivered major
advantages in several tested deployment conditions.**

## Headline application results

The application campaign used eight isolated Azure VM pairs across x64 and
arm64, four latency tiers, and configured carrier loss from 0% through 20%.
Each cell was the mean of three end-to-end application runs through otherwise
matched TCP-WG and UDP-WG tunnels.

### Clean-path performance

| Workload and path | TCP-WG | UDP-WG | TCP-mode difference |
|---|---:|---:|---:|
| Bulk TCP, LAN x64, 0% loss | 2789.4 Mbps | 2588.2 Mbps | **+7.8%** |
| Bulk TCP, LAN arm64, 0% loss | 2918.4 Mbps | 2777.2 Mbps | **+5.1%** |
| Bulk TCP, 56 ms x64, 0% loss | 519.3 Mbps | 428.9 Mbps | **+21.1%** |
| Bulk TCP, 56 ms arm64, 0% loss | 1058.3 Mbps | 1008.9 Mbps | **+4.9%** |
| Sequential HTTPS, LAN x64, 0% loss | 152.55 requests/s | 131.14 requests/s | **+16.3%** |
| Sequential HTTPS, LAN arm64, 0% loss | 156.41 requests/s | 143.18 requests/s | **+9.2%** |

These results show that adding the TCP carrier did not impose an automatic
throughput penalty. On these clean low- and medium-latency cells, it was
competitive and often faster.

CPU utilization was also lower in the clean LAN comparisons. Bulk transfer
used 73.5% versus 78.8% mean CPU on x64 (**6.7% lower**) and 64.2% versus
72.1% on arm64 (**10.9% lower**). Sequential HTTPS used 53.5% versus 60.6%
on x64 (**11.7% lower**) and 51.2% versus 61.3% on arm64 (**16.6% lower**).

The clean-path result is workload- and latency-dependent. At approximately
195 ms RTT, clean x64 bulk TCP measured 244.8 Mbps over TCP-WG versus
286.1 Mbps over UDP-WG, a 14.4% reduction. At approximately 227 ms RTT, it
measured 160.3 Mbps versus 209.2 Mbps, a 23.4% reduction. Operators should
benchmark their actual path rather than infer a universal winner.

### Delivery under synthetic carrier loss

Selected application-level results were especially favorable to TCP mode when
uniform random loss was injected in the legacy carrier test:

| Workload and path | Loss | TCP-WG | UDP-WG |
|---|---:|---:|---:|
| Bulk TCP, LAN x64 | 0.5% | 2764.6 Mbps | 2080.0 Mbps |
| Bulk TCP, LAN x64 | 1% | 2731.2 Mbps | 1590.6 Mbps |
| Bulk TCP, LAN x64 | 10% | 2751.2 Mbps | 28.8 Mbps |
| Sequential HTTPS, LAN x64 | 10% | 154.54 requests/s | 6.01 requests/s |
| Inner UDP, LAN x64 | 10% | 968.6 Mbps | 880.6 Mbps |
| Inner UDP, LAN arm64 | 20% | 999.7 Mbps | 798.4 Mbps |

The advantage comes from the carrier behavior. With UDP-WG, an outer datagram
lost by the path is gone and the inner protocol must absorb or recover from
that loss. With TCP-WG, the outer stream retransmits missing bytes and restores
record order before WireGuard processes the encrypted message. This can greatly
improve completeness and application goodput when recovery is more valuable
than minimum latency.

The very large loss-test differences are real measurements from that harness,
but they are not predictions for arbitrary networks. The legacy campaign
impaired the tunnel-facing path and did not instrument a physical outer
bottleneck deeply enough to establish a TCP-over-TCP failure boundary. The
newer mechanistic campaign described below was created specifically to test
that boundary.

## TCP-over-TCP meltdown result

### No formal meltdown was established

The dedicated campaign defined a formal meltdown before analyzing results. A
valid execution had to meet all three conditions:

1. at least 20% of 100 ms receiver-delivery bins contained zero inner bytes;
2. fitted goodput declined by at least 20%, with a slope t statistic at or
   below -2; and
3. inner TCP recorded at least one retransmission timeout per flow-minute.

**None of 122 valid post-repair executions met all three conditions.** Some
executions were classified as degraded or near-meltdown, but the campaign did
not produce a valid formal meltdown result.

### Stable high-RTT and finite-queue controls

The campaign completed 82 clean calibration and finite-queue/RTT screening
cells as valid and stable.

| Carrier condition | Observed result |
|---|---|
| 50 Mb/s, 200 ms RTT, 0.5x/1x/4x-BDP FIFO, no induced loss | 46.74-47.28 Mbps with no zero-delivery stalls |
| 50 Mb/s, 400 ms RTT, 1x-BDP FIFO, no induced loss | 47.20-47.23 Mbps with no zero-delivery stalls |
| 100-400 ms no-loss RTT sweep | Stable; one 250 ms repetition had isolated 100 ms zero-delivery bins |

High RTT, a finite FIFO, and 16 continuously active inner TCP flows were
therefore not sufficient by themselves to trigger the measured pathology.

### What happened in the deliberately extreme envelope

Severe TCP-specific degradation did appear, but only after combining all of
the following:

- 16 continuously backlogged inner CUBIC flows;
- a 50 Mb/s carrier and 1x-BDP FIFO;
- 200-400 ms configured RTT;
- persistent random or Gilbert-Elliott burst loss; and
- 60-second reverse-direction bulk workloads.

The lowest demonstrated severe profile used 200 ms RTT and 4.42% nominal
stationary burst loss. Its two valid TCP repetitions delivered 1.09 and
0.73 Mbps, with longest continuous stalls of 0.7 and 6.3 seconds. More severe
breadth cells produced longer stalls, up to 40.2 seconds, but still did not
satisfy every formal meltdown condition.

This matters for an accurate interpretation:

- **Positive result:** even the extreme campaign did not establish formal
  meltdown under its fixed definition.
- **Operational caution:** severe head-of-line amplification is possible when
  persistent outer loss, long RTT, a constrained queue, and many saturated
  inner flows occur together.
- **Scope:** those conditions are not representative of a healthy datacenter or
  well-managed wired path, though they may occur transiently on congested
  mobile, interfered Wi-Fi, satellite, or overloaded tunnel paths.

The campaign did not run the planned lower-loss onset sweep, so it does not
prove universal immunity or identify an exact transition threshold.

## Why TCP mode can perform well

### Recovery is handled once at the carrier

The TCP carrier delivers a complete ordered record stream to WireGuard. For
bulk transfers, APIs, package downloads, backups, and reliable inner UDP
payloads, this can prevent each application from independently reacting to
outer packet loss.

### Persistent kernel connections avoid an extra userspace hop

WireguardTCP maintains per-peer connections. Once established, ordinary
encrypted WireGuard messages flow over the existing stream; applications do
not need a proxy, relay, or separate userspace encapsulation process. Framing
and stream handling remain in the kernel module.

### Authenticated roaming keeps identity separate from location

The WireGuard public key remains the peer identity while the outer TCP address
and ephemeral source port may change. Authenticated accepted-carrier promotion
lets a reachable peer adopt the private peer's outbound stream, and generation
ordering prevents an older carrier from rolling back the current path. This
passed both source-port rebinding and source-address roaming.

### Exact recovery avoids replaying uncertain stream prefixes

Terminal send and receive paths retire only the exact failed socket. A partially
emitted frame is not replayed onto a replacement stream, while a short write
continues from the exact unsent suffix. The focused fault gate passed parser
resynchronization, queue pressure, exact fatal-send selection, carrier
replacement, and restoration of the production module.

### Stateful network compatibility improves practical availability

Performance is irrelevant if the tunnel cannot connect. TCP mode can traverse
networks that block raw UDP but permit the selected TCP port. Its persistent
flows and keepalives also fit common stateful firewall and NAT policies.

The functional regression passed a single-private NAT44 topology with no DNAT
or inbound port forward. The private peer initiated through SNAT; the public
peer authenticated and promoted the accepted carrier for bidirectional traffic.
Idle keepalives, translated source-port rebinding, source-address roaming,
authenticated reacquisition, and old-carrier retirement passed on both Hyper-V
guests. This is operational evidence for the tested Linux/nftables topology,
not a claim about every provider NAT or hostile middlebox.

### The operational model remains simple

TCP mode uses the normal WireGuard configuration model. The primary addition
is:

```ini
Transport = tcp
```

Keys, peers, `AllowedIPs`, endpoints, `PersistentKeepalive`, `wg`, `wg-quick`,
and systemd management retain their familiar roles. See
[`QUICKSTART.md`](QUICKSTART.md) for installation and tunnel templates.

## Choosing TCP mode

TCP mode is a strong candidate for:

- UDP-blocked or UDP-hostile networks;
- file transfer, backup, synchronization, package distribution, and API
  traffic where completeness matters;
- reliable carriage of inner UDP payloads where late delivery is preferable
  to loss;
- dual-reachable stateful firewall or explicitly port-forwarded NAT layouts;
  and
- deployments that can benchmark their real path and choose TCP or UDP per
  interface.

Prefer UDP mode for:

- voice, gaming, and real-time media where a late packet may be worse than a
  lost packet;
- paths where stock WireGuard already performs well and minimal state is the
  priority; and
- heavily congested, persistently lossy, high-RTT paths carrying many saturated
  inner TCP flows without active queue management or capacity planning.

Use separate WireGuard interfaces when a deployment needs both modes. There is
no automatic TCP/UDP negotiation or fallback.

## Evidence and reproducibility

The numbers above are summaries, not standalone benchmark claims. Full
methodology, tables, caveats, matrices, and reproduction instructions are in:

- [`perf-test/REPORT.md`](perf-test/REPORT.md) for end-to-end application
  results across x64/arm64, four latency tiers, five workloads, and configured
  loss levels;
- [`docs/TCP_MELTDOWN.md`](docs/TCP_MELTDOWN.md) for the calibrated meltdown
  conclusion and stable-control results;
- [`perf-test/meltdown/`](perf-test/meltdown/README.md) for the physical-carrier
  impairment harness, fixed validity rules, and campaign ledger; and
- [`tests/hyperv/RESULTS.md`](tests/hyperv/RESULTS.md) for functional regression
  evidence.

Results belong to their recorded VM sizes, kernels, source revisions,
topologies, and impairment models. They establish useful observed behavior,
not a universal performance guarantee or production service-level objective.
