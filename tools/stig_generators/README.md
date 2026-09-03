# STIG module generators

The quarterly-update mechanism for `benchmarks/stig/`. Not shipped policy
content — tooling that regenerates it from DISA's own XCCDF data.

## Quarterly update procedure (ties to `STANDARDS_UPDATE_REGISTRY.md`)

1. Download the current compilation (~370 MB):
   `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_<Month>_<Year>.zip`
   (browser User-Agent required; probe the month names — DISA uses e.g.
   `U_SRG-STIG_Library_July_2026.zip`.)
2. Extract per-platform `*_Manual-xccdf.xml` files and parse to
   `catalogs/<platform>.json` — see the parse loop in any generator's history;
   fields: benchmark, version, release, rules[{vuln_id, stig_id, severity,
   title, check}] with FULL check text (no truncation — that bug cost a
   derivation round).
3. Run the generators (they write straight into `benchmarks/stig/`):
   - `gen_windows.py` — auto-derives registry rules from check-content
     blocks (exact / or-less / or-greater / multi-block-AND / absent).
   - `gen_linux.py`, `gen_k8s.py`, `gen_apps.py` — hand-authored logic
     tables; **catalog ID hard-gate**: a rule ID missing from the current
     XCCDF aborts generation.
4. `opa test benchmarks/stig/` must be green (green-fixture tests regenerate
   with the modules).
5. **Spot-check semantics, not just IDs**: diff titles for rules whose logic
   you didn't change — the ID gate cannot catch a rule whose meaning moved.
   This caught three rounds of drift during the 2026-09-03 build.

## Lessons encoded

- Platforms leave the library (Win 10, Server 2016/2019, Ubuntu 20.04 in
  July 2026) — absence means SUNSET.md, never silence.
- Hand-written stub IDs rot: the pre-2026-09 Server 2022 stub misattributed
  WN22-SO-000050. Generated-with-verification replaces trusted-from-memory.
