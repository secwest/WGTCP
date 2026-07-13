# Initial Writer-Wakeup Screening Evidence

This directory is the compact, reviewable output from the 68-cell finite-queue
and RTT-boundary screening completed on 2026-07-13. The formal initial
inventory is 61 valid/stable and seven invalid, with no degraded,
near-meltdown, or meltdown cells.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `05d0d5830adb04dfb16d80797b891a9cb1b45cc36bc6fd5eb82790aa372bbd6a`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `c9d47c429a3df821aadc74d933f0ff002c685deb4f59163176ed0f261c1e10f1`

`cells.csv` contains the scored inventory, `REPORT.md` is generated from that
inventory, and `campaign-status.json` binds the expected cell fingerprints.
The seven invalid cells are retained rather than silently dropped and are
scheduled for exact-cell reruns. Raw host and per-cell evidence is retained
outside Git.
