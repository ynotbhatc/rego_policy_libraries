# Standards Update Registry

**Version:** v1.0
**Date:** 2026-09-02
**Authors:** Tim Coulter (Red Hat) with Claude (Anthropic)
**Purpose:** Every framework this library implements tracks an upstream standard that
*will* change. This registry records what version we implement, how often the upstream
revises, and where to watch — so Rego gets regenerated when the standard updates instead
of drifting silently.

**Why this exists (the motivating incident):** on 2026-09-02, the CISA CPG module was
nearly written against v1.0.1 goal IDs — but CISA had shipped **CPG 2.0 in October 2025**
with a complete renumbering (old 2.H MFA became 3.F, three goals deleted, four added).
A one-fetch check caught it. This registry is that check, systematized.

## Update process

1. **Monthly sweep** (scheduled): for each row, check the watch URL for a release newer
   than "Implemented version." Takes minutes; most months find nothing.
2. **On a new release:** open an issue titled `update: <framework> <old> → <new>` with the
   changelog link. Triage: renumbering/new controls → regenerate the module; editorial →
   bump the version comment only.
3. **Regeneration rule:** new benchmark versions get a **new directory** (existing
   convention — do not mutate the old version). Framework modules revise in place with the
   version pinned in the header and this registry updated in the same PR.
4. **Rows marked "verify"** carry cadence/next-expected values from general knowledge, to
   be confirmed on their first sweep.

## Registry

| Framework / benchmark | Implemented version | Upstream owner | Revision cadence | Next expected | Watch |
|---|---|---|---|---|---|
| CISA CPG | **2.0** — module tagged Oct 2025, official pub 2025-12-11; **diff vs final pending (#173)** | CISA | 24–36 months (stated in the 2.0 report) | 2027–2028 | cisa.gov/cross-sector-cybersecurity-performance-goals |
| CIS MCP Server Benchmark | **v1.0.0 (Sep 2026) — PARTIAL: 46/55 recs, sections 6/8/9 pending PDF** | CIS | first release; expect fast minor revs while MCP spec moves | watch closely | workbench.cisecurity.org / cisecurity.org/cis-benchmarks |
| NIST CSF | 2.0 (Feb 2024) — verified current 2026-10-06; draft Cyber AI Profile (Dec 2025) pending | NIST | ~10 years major; concept papers precede | no major expected soon | nist.gov/cyberframework |
| NIST SP 800-53 | r5 (+ r5.2 patch releases) | NIST | continuous "patch release" model since 2024 — **watch quarterly** (verify) | rolling | csrc.nist.gov/pubs/sp/800/53 |
| NIST SP 800-171 | r3 (May 2024) | NIST | multi-year | — | csrc.nist.gov/pubs/sp/800/171 |
| CIS Benchmarks (per-OS dirs) | pinned per directory (e.g. RHEL 9 v2.0.0) | CIS | **rolling, roughly annual per benchmark** — the highest-churn family in the library | continuous | workbench.cisecurity.org (per-benchmark) |
| DISA STIGs | per-platform pins — July 2026 library verified 2026-09-03 (see `benchmarks/stig/README.md`) | DISA | **quarterly release cycle**; compilation zip `U_SRG-STIG_Library_<Month>_<Year>.zip` | October 2026 library | dl.dod.cyber.mil (compilation) / public.cyber.mil/stigs |
| NSA/CISA K8s Hardening | v1.2 (Aug 2022) — current, no newer revision exists | NSA/CISA | irregular (v1.0→1.1→1.2 within a year, then stable) | — | media.defense.gov / cisa.gov alerts |
| K8s Pod Security Standards | kubernetes.io page, field lists as of 2026-09 | Kubernetes SIG Auth | evolves with K8s minor releases (new fields/sysctls gain version gates) | per K8s release | kubernetes.io/docs/concepts/security/pod-security-standards |
| PCI DSS | 4.0.1 (sole active; v4.0 retired 2024-12-31, future-dated reqs mandatory since 2025-03-31) | PCI SSC | v5.0 in development — two RFC cycles done (Dec 2025, Jun–Jul 2026), no date | watch v5.0 quarterly | pcisecuritystandards.org/document_library |
| ISO/IEC 27001 | 2022 (+ Amd 1:2024 climate) | ISO | ~5–9 year cycle | verify | iso.org/standard (27001) |
| ISO/IEC 42001 | **2023 (first edition)** — verified current 2026-10-06; EN ISO/IEC 42001:2026 is identical-text CEN adoption (not an AI Act harmonised standard) | ISO | no amendment or 2nd ed. in ballot | — | iso.org/standard/44545 |
| SOC 2 (TSC) | 2017 TSC, 2022 revised points of focus | AICPA | irregular; points-of-focus revisions | verify | aicpa-cima.com (TSC) |
| HIPAA Security Rule | current rule (NPRM RIN 0945-AA22 NOT finalized; moved to Long-Term Actions, final projected **Jul 2027**) | HHS OCR | final rule will require full module regeneration | watch through 2027 | hhs.gov/hipaa |
| GLBA Safeguards Rule | 16 CFR 314 as amended (breach notif. May 2024) — verified no newer amendment 2026-10-06 | FTC | amendment-driven | — | ftc.gov/legal-library (Safeguards Rule) |
| CCPA/CPRA | current regs | Cal. AG / CPPA | **CPPA rulemaking is ongoing (ADMT, cybersecurity audits) — watch actively** (verify) | rolling | cppa.ca.gov/regulations |
| GDPR | 2016/679 | EU | stable text; guidance evolves (EDPB) | — | edpb.europa.eu |
| EU AI Act | Reg. 2024/1689 **as amended by Digital Omnibus Reg. 2026/1744** (in force 2026-07-27): Annex III high-risk → 2027-12-02, Annex I → 2028-08-02, Art.50 live since 2026-08-02, +2 new Art.5 prohibitions — **module update pending (#168)** | EU | omnibus-driven | 2027-12-02 gate | artificialintelligenceact.eu |
| EU CRA | Reg. 2024/2847 | EU | phased applicability through 2027 | phase dates | eur-lex (2024/2847) |
| NIS2 | Directive 2022/2555 | EU | member-state transposition ongoing | rolling | enisa.europa.eu |
| DORA | Reg. 2022/2554 + RTS 2025/532 (subcontracting, in force 2025-07-22) + RTS 2025/1190 (TLPT, applicable 2025-07-08) — **module update pending (#169)** | EU | remaining RTS/ITS — watch ESAs | rolling | eiopa/eba/esma joint |
| NERC CIP | per-standard (incl. CIP-015-1 INSM) | NERC/FERC | **rolling per-standard with staged effective dates — track effective dates, not versions** | per standard | nerc.com/pa/Stand |
| IEC 62443 | per-part | IEC | rolling per-part | verify | iec.ch |
| NIST AI RMF | 1.0 (+ GenAI profile 2024) | NIST | profile additions | verify | nist.gov/itl/ai-risk-management-framework |
| CMMC | 2.0 (final rule Dec 2024, phased) | DoD | phased rollout through ~2028 | phase dates | dodcio.defense.gov/cmmc |
| NY DFS | 23 NYCRR 500 2nd amendment — **final tranche enforceable 2025-11-01** (universal MFA §500.12, full asset inventory §500.13(a)); **date-gate audit pending (#171)** | NYDFS | no 3rd amendment as of 2026-10 | — | dfs.ny.gov |
| ITAR | 22 CFR 120–130 — **4 substantive final rules 2025–26** (USML eff. 2025-09-15, Cyprus §126.1 2025-10-01, AUKUS 2025-12-30, Syria §126.1 removal 2026-10-01); **regeneration pending (#170)** | State/DDTC | rolling; Part 130 NPRM proposed 2026-06-15 | rolling | pmddtc.state.gov |
| COBIT | 2019 (current as of 2026-10-06) — **COBIT 7 imminent**: Foundations cert cutover 2026-10-27, framework content "later this year" | ISACA | ~7 years | re-check after 2026-10-27 | isaca.org/resources/cobit |
| SWIFT CSP | CSCF v-year | SWIFT | **annual CSCF release, attestation deadline each December** | annual | swift.com (CSP) |
| HITRUST CSF | pinned in module | HITRUST | ~annual minor releases (verify) | annual | hitrustalliance.net |
| TISAX | pinned in module | ENX/VDA | ISA catalog updates (verify) | verify | enx.com/tisax |
| CFR Part 11 | 21 CFR 11 | FDA | stable; guidance-driven | — | fda.gov |
| FERPA | 34 CFR Part 99 (current per eCFR 2026-09) | ED | amendment-driven; **ED signaled intent (Fall 2024) to propose amendments — watch** | rolling | ecfr.gov (34 CFR 99) |
| COPPA | 16 CFR Part 312 as amended 90 FR 16918 (eff. 2025-06-23; compliance 2026-04-22) | FTC | amendment-driven (first update since 2013) | — | ftc.gov/legal-library (COPPA Rule) |
| FedRAMP | rev5 baselines — **20x is GA** (Consolidated Rules 2026-06-25): rules mandatory for all 2027-01-01, no new rev5 certs after 2027-06-11, Class D stays rev5 pending FY27 pilot; **20x/KSI module scoped (#172)** | GSA | 20x cadence | 2027-01-01 | fedramp.gov |
| ISO/IEC 42005 | 2025 (first edition, 2025-05-28) | ISO/IEC | first-edition — watch for early amendment | — | iso.org/standard/44545 (42005) |
| OWASP LLM Top 10 | 2026 edition (2026-08-04) | OWASP GenAI Security Project | ~annual; 2026 renumbered 8 of 10 vs 2025 | 2027 | genai.owasp.org |
| MITRE ATLAS (crosswalk) | atlas-data v2026.09 (16 tactics, 101+69 techniques, 35 mitigations) | MITRE | monthly releases — crosswalk metadata only, not checks | continuous | github.com/mitre-atlas/atlas-data |
| FedRAMP 20x KSI | Consolidated Rules datafile (46 KSIs, stable since 2026-06-24) | GSA/FedRAMP | datafile-versioned; regenerate module from fedramp-consolidated-rules.json | rolling | github.com/FedRAMP/rules |
| UK MoD DCC / DEF STAN 05-138 | Issue 4 (14 May 2024); DCC scheme live 2025, L0 mandate 2026-12-31 | UK MoD DStan / IASME | issue-driven (Iss 3→4 ~4 yrs); scheme guidance revs faster | watch | gov.uk (DStan) + iasme.co.uk (DCC) |
| PQC Readiness | FIPS 203/204/205 (Aug 2024) + NIST IR 8547 (draft ipd) + EO 14412 (2026-06-22) / OMB M-26-15 + CNSA 2.0 | NIST / OMB / NSA | **IR 8547 final expected — watch; CNSA 2.0 FAQ revs; EO-driven FAR rule in progress** | rolling | csrc.nist.gov/pubs/ir/8547 + nsa.gov (CNSA 2.0 FAQ) |
| CIS M365 (saas/) | pinned per module | CIS | rolling ~annual | continuous | workbench.cisecurity.org |
| CISA SCuBA M365 (scuba/) | per-policy IDs (v-suffix) pinned in modules; 104 policies | CISA | rolling per-policy revisions in cisagov/ScubaGear — watch the baselines/ directory | continuous | github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines |
| CIS EKS | v1.8.0 | CIS | rolling ~annual | continuous | workbench.cisecurity.org |
| CIS AKS | v1.8.0 | CIS | rolling ~annual | continuous | workbench.cisecurity.org |
| CIS GKE | v1.9.0 | CIS | rolling ~annual | continuous | workbench.cisecurity.org |

## Maintenance

- Update a row **in the same PR** that updates its module.
- The monthly sweep updates "Next expected" and clears "verify" flags as they're confirmed.
- New framework added to the library → new row here, in the same PR (checked in review).
