# Qualified Transport-Aware Burst Composite

This is the qualified four-cell burst gate: three valid cells from the complete
base campaign plus the one allowed valid exact replacement for TCP r1. All four
selected cells use the same campaign fingerprint, runtime identity, matrix
axes, and exact cell fingerprints.

The composite contains three degraded cells and one near-meltdown cell, with no
stable, meltdown, or invalid cells. Both TCP cells record outer recovery (143
and 129 events), so the fixed release rule of four valid cells plus observed TCP
outer recovery is satisfied. Neither TCP cell meets all three formal meltdown
conditions.

`provenance.csv` records each selected source campaign, campaign and cell
fingerprints, analyzed `cell.json` SHA-256, and the sole replacement.
`composite-status.json` records the runtime identity and source counts. The
selected traces contain 5,264 exactly reconciled sequence-bearing event rows
across 89 event/layer/CPU streams.
