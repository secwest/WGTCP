# Timed Boundary Stage 2 Correlation

Stage 2 is frozen **incomplete and safety-stopped**. The campaign qualified the
1-, 2-, and 4-packet residence points, reached the 8-packet point, and did not
run the 16-packet point. It therefore does not establish a packet-correlation
onset threshold and does not release Stage 3.

## Frozen inventory

| Inventory | Count |
|---|---:|
| Planned logical cells | 30 |
| Logical cells reached | 24 |
| Selected valid logical cells | 23 |
| Unresolved logical cells | 1 |
| Unrun logical cells | 6 |
| Analyzable raw executions | 31 |
| Valid raw executions | 23 |
| Invalid raw executions | 8 |
| Safety-stopped attempts without analyzable cell evidence | 1 |

The eight original invalid executions are retained. Seven received their one
allowed exact rerun and produced valid replacements. The eighth, 8-packet UDP
r3, consumed its exact rerun in the safety stop and remains unresolved.

## Correlation results

| Mean bad-state residence | Selected valid | Qualified matched pairs | TCP quasi-meltdown episodes | Formal meltdowns | State |
|---:|---:|---:|---:|---:|---|
| 1 packet | 6/6 | 3/3 | 0/3 | 0 | Qualified |
| 2 packets | 6/6 | 3/3 | 1/3 | 0 | Qualified; below the two-of-three onset rule |
| 4 packets | 6/6 | 3/3 | 0/3 | 0 | Qualified |
| 8 packets | 5/6 | 2/3 | 0/2 | 0 | Incomplete; UDP r3 unresolved |
| 16 packets | 0/6 | 0/3 | N/A | 0 | Unrun |

All 23 selected valid cells retain the whole-run `stable` classification. The
episode endpoint is intentionally separate. At two packets, TCP r2 had a
1.8-second zero-delivery stall, a 0.139 Mb/s minimum rolling five-second
delivery rate versus 4.605 Mb/s for its matched UDP control, 162 outer-recovery
events, and 11.551-second recovery to 90%. It is the only qualified
quasi-meltdown episode.

The 1- and 4-packet points had no quasi-meltdown in three repetitions. Their TCP
maximum stalls were 0.2-0.3 seconds and 0.3-0.7 seconds respectively. At eight
packets, TCP r1/r2 had 0.4/0.7-second stalls. The valid TCP r3 replacement had a
1.4-second stall, 1.996 Mb/s minimum five-second delivery, 126 outer-recovery
events, and 12.451-second recovery, but it has no valid matched UDP r3 control
and therefore cannot receive a qualified quasi-meltdown label.

The non-monotonic 0/3, 1/3, 0/3 sequence is retained as observed. It must not be
converted into an onset threshold.

## Safety stop

The UDP r3 exact rerun scheduled its 16-second loss epoch for
`1784185268769450000` ns. Ubuntu `apt-daily-upgrade` began on the server at
06:59:59 UTC. After upgrading Python, package service-restart handling restarted
the active Python impairment helper and endpoint sampler at 07:01:12 UTC. The
restarted helper correctly rejected its absolute start time because it was then
in the past. The controller stopped the workload and latched
`timed_impairment`.

This is external execution interference, not a positive or negative transport
result. The prospective rule permits no additional UDP r3 retry. Residence 16
and Stage 3 remain unrun.

Afterward, all four hosts passed exact runtime, qdisc, clock, carrier, package
manager, and residue checks. They delivered 40/40 TCP and 40/40 UDP tunnel
control probes with zero loss.

## Provenance

The composition binds the exact 30-cell matrix at SHA-256
`b95a85d0a9df2ad4ef757be665b0512f631de1dbac96513c04870aa47be79d7e`.
The original pair uses campaign fingerprint
`3e340f5d617ef81d4e6d3afd2a309bbbc4a85cb19c387178989320cd733c11b0`;
the secondary pair uses
`44551711fc8dbab373ad4ebfcafd7860bb4f19c4bad704a9ef2ba6c367e7c362`.

- [`attempts.csv`](attempts.csv) retains every valid, invalid, and stopped
  attempt in chronological source order. `raw_classification` is the immutable
  source-cell value; `selected_classification` is the matched-control-adjusted
  value only for a selected attempt. `safety_stop` is independent of outcome so
  an analyzed stop cannot disappear into an invalid or valid classification.
- [`logical-cells.csv`](logical-cells.csv) records the selected, unresolved, and
  unrun state of all 30 logical cells.
- [`selected-cells.csv`](selected-cells.csv) contains compact metrics and exact
  source hashes for the 23 selected valid cells.
- [`profiles.csv`](profiles.csv) summarizes the five residence points and onset
  rule.
- [`source-campaigns.csv`](source-campaigns.csv) binds all 14 shard manifests
  and the safety-stop record.
- [`audit-evidence.csv`](audit-evidence.csv) binds the preserved stopped-cell
  raw/journal bundle and the four-host post-stop validation bundle.
- [`composition-status.json`](composition-status.json) is the machine-readable
  frozen inventory.
- [`sha256-manifest.txt`](sha256-manifest.txt) hashes the committed composition
  files.

Raw endpoint telemetry remains outside Git because of its size. The preserved
stopped-cell audit tree is bound at
`9d39d0f143d857922b87d48854ff72fd4960bc34214d4d068adeb59205a240db`;
the post-stop validation tree is bound at
`c798e8a60468163bff28eb0d212e2f62b700c38122255c5527bb1fbc5e19d2d4`.
