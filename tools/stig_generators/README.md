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

## Scripts added 2026-10-13

- `parse_xccdf.py <key>=<Manual-xccdf.xml> …` — the parse loop as a script: writes
  `catalogs/<key>.json` (benchmark, version, release date, rules with full check
  text and CCI idents). Catalogs are gitignored; regenerate from the compilation.
- `gen_oracle_linux.py` — derives `oracle_linux_9` from the RHEL 9 modules and
  `oracle_linux_8` from those, by DISA rule title (never by the library's own
  stig_id — see the RHEL 9 id defect in `benchmarks/stig/README.md`). Every
  fuzzy pair is printed; reviewed overrides and refusals live in `PLATFORMS`.
- `gen_oracle_db.py` — Oracle Database 19c and MySQL 8.0, every rule in the
  catalog (query-backed facts or named attestations).
- **Move `catalogs/` out of the tree before `opa test .`** — OPA loads every JSON file it finds, and two
  catalogs at the same data path fail with a merge error. CI never sees them (gitignored). Aborts if a catalog rule
  has no logic entry or a logic entry has no catalog rule.
- `gen_k8s.py [kubernetes] [rke2]` (rewritten 2026-10-21) — every rule of Kubernetes V2R6 and RGS RKE2 V2R7,
  with the same two-way gate. Each logic entry carries its evidence paths, a pass fixture and a fail
  mutation, so the tests (pass / fail / evidence-missing per rule) are generated with the module.
  `openshift_4` is no longer generated (hand-maintained; its old table is in git history).
- `gen_crosswalk.py <U_CCI_List.xml> <key> …` — stig_id → CCI → 800-53 Rev 5
  join for the given catalogs, merged into `crosswalk/stig_800_53/data.json`.

## Lessons encoded

- Platforms leave the library (Win 10, Server 2016/2019, Ubuntu 20.04 in
  July 2026) — absence means SUNSET.md, never silence.
- Hand-written stub IDs rot: the pre-2026-09 Server 2022 stub misattributed
  WN22-SO-000050. Generated-with-verification replaces trusted-from-memory.
