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
| CISA CPG | **2.0 (Oct 2025)** | CISA | **24–36 months (stated in the 2.0 report)** | 2027–2028 | cisa.gov/cross-sector-cybersecurity-performance-goals |
| NIST CSF | 2.0 (Feb 2024) | NIST | ~10 years major; concept papers precede | no major expected soon | nist.gov/cyberframework |
| NIST SP 800-53 | r5 (+ r5.2 patch releases) | NIST | continuous "patch release" model since 2024 — **watch quarterly** (verify) | rolling | csrc.nist.gov/pubs/sp/800/53 |
| NIST SP 800-171 | r3 (May 2024) | NIST | multi-year | — | csrc.nist.gov/pubs/sp/800/171 |
| CIS Benchmarks (per-OS dirs) | pinned per directory (e.g. RHEL 9 v2.0.0) | CIS | **rolling, roughly annual per benchmark** — the highest-churn family in the library | continuous | workbench.cisecurity.org (per-benchmark) |
| DISA STIGs | per-platform pins — July 2026 library verified 2026-09-03 (see `benchmarks/stig/README.md`) | DISA | **quarterly release cycle**; compilation zip `U_SRG-STIG_Library_<Month>_<Year>.zip` | October 2026 library | dl.dod.cyber.mil (compilation) / public.cyber.mil/stigs |
| PCI DSS | 4.x | PCI SSC | ~3–4 year majors + interim revisions (4.0.1 model) | verify | pcisecuritystandards.org/document_library |
| ISO/IEC 27001 | 2022 (+ Amd 1:2024 climate) | ISO | ~5–9 year cycle | verify | iso.org/standard (27001) |
| ISO/IEC 42001 | **2023 (first edition)** | ISO | first-edition standards often amend early — **watch closely** (verify) | verify | iso.org/standard/44545 |
| SOC 2 (TSC) | 2017 TSC, 2022 revised points of focus | AICPA | irregular; points-of-focus revisions | verify | aicpa-cima.com (TSC) |
| HIPAA Security Rule | current rule | HHS OCR | **NPRM for a major Security Rule update is in flight (proposed Dec 2024) — final rule will require module regeneration** (verify status) | watch actively | hhs.gov/hipaa |
| GLBA Safeguards Rule | 16 CFR 314 as amended (breach notif. May 2024) | FTC | amendment-driven | — | ftc.gov/legal-library (Safeguards Rule) |
| CCPA/CPRA | current regs | Cal. AG / CPPA | **CPPA rulemaking is ongoing (ADMT, cybersecurity audits) — watch actively** (verify) | rolling | cppa.ca.gov/regulations |
| GDPR | 2016/679 | EU | stable text; guidance evolves (EDPB) | — | edpb.europa.eu |
| EU AI Act | Reg. 2024/1689 | EU | **phased applicability: prohibitions Feb 2025, GPAI Aug 2025, high-risk Aug 2026–2027 — module obligations activate on those dates** | phase dates | artificialintelligenceact.eu |
| EU CRA | Reg. 2024/2847 | EU | phased applicability through 2027 | phase dates | eur-lex (2024/2847) |
| NIS2 | Directive 2022/2555 | EU | member-state transposition ongoing | rolling | enisa.europa.eu |
| DORA | Reg. 2022/2554 (applies Jan 2025) | EU | RTS/ITS technical standards still landing — watch ESAs | rolling | eiopa/eba/esma joint |
| NERC CIP | per-standard (incl. CIP-015-1 INSM) | NERC/FERC | **rolling per-standard with staged effective dates — track effective dates, not versions** | per standard | nerc.com/pa/Stand |
| IEC 62443 | per-part | IEC | rolling per-part | verify | iec.ch |
| NIST AI RMF | 1.0 (+ GenAI profile 2024) | NIST | profile additions | verify | nist.gov/itl/ai-risk-management-framework |
| CMMC | 2.0 (final rule Dec 2024, phased) | DoD | phased rollout through ~2028 | phase dates | dodcio.defense.gov/cmmc |
| NY DFS | 23 NYCRR 500 v2 (Nov 2023) | NYDFS | amendment had phased effective dates through Nov 2025 — final phases just landed (verify) | — | dfs.ny.gov |
| ITAR | 22 CFR 120–130 | State/DDTC | rule amendments; consolidation rulemaking recurring | rolling | pmddtc.state.gov |
| COBIT | 2019 | ISACA | ~5–7 year majors (verify) | verify | isaca.org/resources/cobit |
| SWIFT CSP | CSCF v-year | SWIFT | **annual CSCF release, attestation deadline each December** | annual | swift.com (CSP) |
| HITRUST CSF | pinned in module | HITRUST | ~annual minor releases (verify) | annual | hitrustalliance.net |
| TISAX | pinned in module | ENX/VDA | ISA catalog updates (verify) | verify | enx.com/tisax |
| CFR Part 11 | 21 CFR 11 | FDA | stable; guidance-driven | — | fda.gov |
| FedRAMP | current baselines (rev5) | GSA | **FedRAMP 20x modernization in progress — watch actively** (verify) | rolling | fedramp.gov |
| CIS M365 (saas/) | pinned per module | CIS | rolling ~annual | continuous | workbench.cisecurity.org |

## Maintenance

- Update a row **in the same PR** that updates its module.
- The monthly sweep updates "Next expected" and clears "verify" flags as they're confirmed.
- New framework added to the library → new row here, in the same PR (checked in review).
