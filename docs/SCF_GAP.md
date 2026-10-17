# Secure Controls Framework (SCF) coverage gap and expansion plan

**Version:** v1.7
**Date:** 2026-10-13
**Authors:** Tim Coulter (ynotbha@aisle-five.com), Claude (Anthropic)
**Measured against:** SCF 2026.3 workbook (released 2026-09-21), `SCF 2026.3` sheet; this library at v2.4.2 plus the Phase 1 batch of 2026-10-13

## Why this document exists

The SCF is the free metaframework most GRC teams reach for when they need one control set mapped to many laws.
It is the breadth benchmark for this library. We already exceed it on depth (executable checks) and lose to it on
breadth (documents mapped). This document measures the gap document by document and sets the order in which we
close it, so that the README claim of "broadest regulatory coverage of any machine-readable policy library" holds
against SCF by count and not only by kind.

## The two libraries, same day

| Measure | SCF 2026.3 | Rego Policy Libraries v2.4.2 |
|---|---|---|
| Unit | one catalogue control, mapped to external documents | one executable Rego check, grouped by document |
| Controls / checks | 1,591 controls in 34 domains | 19,728 control-level checks (`make count`) |
| Documents mapped | 270 mapping columns, 234 distinct documents once profile variants collapse | 174 framework catalogs, 130+ framework directories |
| Executable | no (Excel, JSON, OSCAL catalog) | yes (OPA / EOPA, fail-closed) |
| Technical benchmarks (CIS, STIG) | none | 30+ CIS platforms, 23 STIG platforms |
| Licence | Creative Commons BY-ND, free | open |

"Profile variants" are rows SCF lists separately but that are one source document with a selection applied: the
CIS Controls implementation groups, GovRAMP and FedRAMP impact levels, the nine PCI DSS SAQs, the DEF STAN 05-138
risk levels, the NIST 800-53B baselines, the 800-82 OT overlays, the 800-161 levels and the CMMC levels. We model
those as profile gates inside one module (as `dcc`, `cis_controls_v8` and `pqc` already do), so the honest unit of
comparison is the distinct document.

## Where we stand against SCF's 234 documents

| Status | Count | Meaning |
|---|---|---|
| covered | 83 | a module exists for that document, same or newer edition |
| partial | 8 | the document is covered inside another module, or we carry an older edition |
| gap | 143 | nothing in the library |

By region:

| Region | Documents | Covered | Partial | Gap |
|---|---|---|---|---|
| General and international standards | 67 | 32 | 6 | 29 |
| United States, federal | 43 | 30 | 2 | 11 |
| United States, state | 27 | 2 | 0 | 25 |
| EMEA | 50 | 14 | 0 | 36 |
| APAC | 36 | 5 | 0 | 31 |
| Americas | 11 | 0 | 0 | 11 |

The region totals are distinct documents, so they add to 234 and differ from the 270 raw columns.

What SCF does not have and we do: every CIS Benchmark and DISA STIG, CISA SCuBA M365, NSA/CISA Kubernetes
Hardening, Pod Security Standards, SLSA, S2C2F, FedRAMP 20x KSI, HITRUST, FISMA, CISA ZTMM, PQC readiness,
ISO/IEC 42005, OWASP LLM Top 10, GEISA, MCP tool-call governance, HKMA TM-G-1/TM-C-1, CERT-In Directions,
METI Cybersecurity Management Guidelines, ITAR, NIST IR 7628 (AMI) and the digital sovereignty suite. None of
those count toward the 237, so our 174 catalogs and SCF's "83 covered" are different lists.

## How we close it

The order below weights customer demand (federal, financial, Oracle and database estates, regulated industry),
reuse (one engine that serves many documents) and effort. Each phase is a release train of its own; counts move
the README on every merge because `make count --check-readme` enforces it.

### Phase 1. Re-stamp and profile the 8 partials

Cheapest breadth: the controls exist, the document label or edition is what is missing.

- Edition bumps: CSA CCM 4.0 to 4.1.0, ISO/IEC 27701:2019 to 2025, PCI DSS 4.0 to 4.0.1, SWIFT CSP 2024 to 2025
  (all need a licensed or login-gated document).
- Profile gates on existing modules: nine PCI DSS SAQ profiles, NIST SP 800-53 Rev 4 beside Rev 5 (pending the
  decision on attested 800-53 modules).
- Split-outs: the DoD Zero Trust Reference Architecture 2.0 and Execution Roadmap on the zero-trust module (source
  PDFs refuse automated download; waiting on a copy).
- Done 2026-10-13/14: 800-53B and FedRAMP baselines as OSCAL profiles; 800-171 Rev 2, 800-171A (both revisions),
  800-172/172A, DFARS 7012, EO 14028, SSDAF, CSF 2.0, 800-82 overlays, 800-161 levels, C5:2026, HIPAA
  Administrative Simplification with 800-66 Rev 2 numbering, DORA RTS 2024/1774, UK DPA 2018, ISO 27002:2022
  numbering on ISO 27001, CSWP 39-upd1.

Outcome: 91 of 234 covered, no partials.

### Phase 2. International standards with the widest reuse (29 gaps)

- ISO family: 22301, 27017, 27018, 29100, 31000, 31010.
- IEC 62443-2-1, 4-1 and 4-2 to complete the series beside 3-3; IEC TR 60601-4-5 for medical devices.
- NIST: Privacy Framework 1.0, SP 800-37 R2, SP 800-39, SP 800-160 Vol 2, AI 600-1 (generative AI profile).
- OWASP Top 10 2025 and a MITRE ATT&CK v16 crosswalk off the existing STIG-to-800-53 map.
- Governance and privacy principles: COSO 2013, AICPA Privacy Management Framework, APEC and OECD privacy
  principles, CR-CMM, Shared Assessments SIG 2025, NAIC MDL-668, MPA Content Security 5.3.1.
- Sector: ISO/SAE 21434 with UN R155 and WP.29 (automotive), UL 2900-1 and 2900-2-2, IMO maritime cyber risk,
  SPARTA 4.0 (space), CSA IoT Security Controls Framework, GovRAMP (an 800-53 baseline family: cheap after Phase 1).

Outcome: 120 of 234.

### Phase 3. United States federal remainder (11 gaps)

TIC 3.0, CMS MARS-E 2.0, FAR 52.204-21/25/27, FFIEC IT Examination Handbook, NISPOM, NRC 10 CFR 73.54,
33 CFR Part 101 Subpart F, TSA rail directive 1580/82-2022-01, FTC Act Section 5, FACTA and FCRA, FIPPS,
45 CFR 155.260, FINRA, FCA, NSF Research Infrastructure Guide, DoW Brilliant at the Basics (IT and OT),
CERT RMM 1.2, NNPI, C2M2 2.1, US Data Privacy Framework.

Outcome: 131 of 234.

### Phase 4. United States state law (25 gaps) with one engine

The comprehensive state privacy acts (Colorado, Virginia, Texas, Oregon, Montana, Tennessee, Nevada) share a
structure: controller duties, consumer rights, sensitive data consent, data protection assessments, universal
opt-out. One parameterised module with a per-state table covers them the way `dcc` covers four risk profiles.
Separate modules for Illinois BIPA, New York SHIELD, Massachusetts 201 CMR 17.00, California SB 1386 and SB 327,
Texas BC 521, SB 820, SB 2610 and TRAIGA, Texas DIR SCSC 2.2 and TX-RAMP Level 1 and 2 (another 800-53
baseline family), Nevada SB 220 and the Nevada gaming regulation, Vermont Act 171, Alaska PIPA.

Outcome: 156 of 234.

### Phase 5. EMEA (36 gaps)

- Gulf cluster, high demand and well-structured control catalogues: Saudi NCA ECC-1, CSCC-1, OTCC-1, CGIoT-1,
  SACS-002, SAMA CSF 1.0, Saudi PDPL; UAE NIAF; Qatar PDPPL.
- Financial regulators: FINMA Circular 2023/1, BaFin BAIT, EBA GL/2019/04, PSD2, CSSF 20/750 and 22/806.
- National baselines: Spain ENS (Royal Decree 311/2022) with CCN-STIC 825, UK CAP 1850, Israel CDMO 2.0.
- GDPR-derivative national acts with one engine and a per-country table: Austria, Belgium, Germany FDPA, Greece,
  Hungary, Ireland, Italy, Norway, Poland, Serbia, Switzerland FADP, Israel PPL, Turkey, Russia 152-FZ,
  Kenya, Nigeria, South Africa POPIA.

Outcome: 192 of 234.

### Phase 6. APAC and Americas (42 gaps)

- Australia: ISM (June 2026), Cloud Controls Matrix, Privacy Principles, CPS 230, SOCI Act, IoT Code of Practice.
- New Zealand: NZISM 3.9, Privacy Act 2020, the three HISF profiles.
- Singapore: CCOP for CII, Cyber Hygiene Practice, PDPA. Japan: APPI, ISMAP. South Korea PIPA. Taiwan PDPA.
  Philippines DPA. Hong Kong PDO. Malaysia PDPA.
- India: IT Rules 2011, SEBI CSCRF, the four RBI directions (data localisation, digital payments, PA, PPI).
- China: Cybersecurity Law, Data Security Law, PIPL, DNSIP decision.
- Americas: Canada PIPEDA, OSFI B-13 and self-assessment guidance, ITSP.10.171; Brazil LGPD; Mexico FDPA;
  Argentina, Chile, Colombia, Bahamas, Bermuda BMA code.

Outcome: 234 of 234, plus everything SCF does not carry.

## Rules that do not bend while we expand

- **Source text or nothing.** Every control row is written from the document itself, with its own identifier,
  never from SCF's paraphrase. SCF mappings are a checklist of what exists, not a source.
- **No fabricated facts.** Privacy and governance law is attestation-heavy. Those modules stay attestation
  modules with OSCAL catalogs, as the financial regulators already are, and the collector contract says so.
- **Every number moves together.** README, `docs/metrics.json`, COMPARISON.md and this document are updated in
  the same PR as the count change; CI fails the README on drift.
- **Fail closed.** A new framework with no facts reports non-compliant with a reason on day one.

## Appendix: every SCF 2026.3 document, with our status

Profile counts in brackets are the number of SCF columns collapsed into that document.

### General and international standards

67 documents: 32 covered, 6 partial, 29 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| AICPA \| Privacy Management Framework (PMF) | gap |  |
| AICPA \| TSC 2017:2022 (used for SOC 2) | covered | frameworks/management/soc2 |
| APEC \| Privacy Framework \| 2015 | gap |  |
| BSI \| Standard 200-1 | gap |  |
| CIS \| CSC \| 8.1 | covered | frameworks/management/cis_controls_v8 (IG1/IG2/IG3 scoring) |
| CIS \| CSC 8.1 (3 profiles) | covered | frameworks/management/cis_controls_v8 (IG1/IG2/IG3 scoring) |
| COBIT \| 2019 | covered | frameworks/management/cobit |
| COSO \| 2013 | gap |  |
| CR \| CMM \| 2026 | gap |  |
| CSA \| CCM \| 4.1.0 | partial | frameworks/management/csa_ccm is v4.0; SCF maps v4.1.0 |
| CSA \| IoT SCF \| 2 | gap |  |
| GovRAMP (6 profiles) | gap |  |
| IEC 62443-2-1 \| 2024 | gap | only 62443-3-3 covered |
| IEC 62443-3-3 \| 2013 | covered | frameworks/critical_infrastructure/iec_62443 |
| IEC 62443-4-1 \| 2018 | gap | only 62443-3-3 covered |
| IEC 62443-4-2 \| 2019 | gap | only 62443-3-3 covered |
| IEC TR 60601-4-5 \| 2021 | gap |  |
| IMO \| Maritime Cyber Risk Management | gap |  |
| ISO/SAE \| 21434 \| 2021 | gap |  |
| ISO \| 22301 \| 2019 | gap |  |
| ISO \| 27001 \| 2022 | covered | frameworks/management/iso27001 (93 Annex A controls, 2022 numbering) |
| ISO \| 27002 \| 2022 | covered | frameworks/management/iso27001: all 93 Annex A controls under the 2022 numbering with an iso27002 view (titles and attributes only; 35 fact-decided, 58 attested) |
| ISO \| 27017 \| 2015 | gap |  |
| ISO \| 27018 \| 2025 | gap |  |
| ISO \| 27701 \| 2025 | partial | frameworks/privacy/iso27701 is 2019; SCF maps 2025 |
| ISO \| 29100 \| 2024 | gap |  |
| ISO \| 31000 \| 2018 | gap |  |
| ISO \| 31010 \| 2009 | gap |  |
| ISO \| 42001 \| 2023 | covered | governance/iso_42001 |
| MITRE \| ATT&CK \| 16 | covered | crosswalk/attack_800_53 (ATT&CK 16.1 to 800-53 Rev 5 mapping, data only) |
| MPA \| Content Security Program \| 5.3.1 | gap |  |
| NAIC \| Insurance Data Security Model Law (MDL-668) | gap |  |
| NIST \| AI 100-1 (AI RMF) \| 1.0 | covered | frameworks/federal/nist/ai_rmf (all 72 subcategories) |
| NIST \| AI 600-1 | covered | frameworks/federal/nist/ai_rmf/nist_ai_600_1_main.rego (212 actions) |
| NIST \| 800-37 \| R2 | covered | frameworks/federal/nist/risk_management_framework (all 47 RMF tasks) |
| NIST \| 800-39 | covered | frameworks/federal/nist/sp_800_39 (12 tasks) |
| NIST \| 800-53 \| R4 | partial | Rev 5 module only |
| NIST \| 800-53 \| R5.2 | covered | frameworks/federal/nist/sp_800_53 (Rev 5) |
| NIST \| 800-53B R5 (4 profiles) | covered | converters/exports/oscal/dist/profiles: the four NIST baselines as OSCAL profiles, imported from NIST's own files |
| NIST \| SP 800-66 R2 | covered | frameworks/privacy/hipaa: 800-66 Rev 2 section numbers on every Security Rule row |
| NIST \| 800-82 R3 (4 profiles) | covered | frameworks/critical_infrastructure/nist_800_82: Appendix F OT overlay table (424 controls, Low/Moderate/High) as a profile gate |
| NIST \| 800-160 Vol2 R1 | covered | frameworks/federal/nist/sp_800_160v2 (50 approaches) |
| NIST \| 800-161 \| R1 | covered | benchmarks/supply_chain/scrm_800_161: Appendix B tailoring table (297 controls; baseline, flow-down, levels 1-3) as a profile gate |
| NIST \| 800-161 R1 (5 profiles) | partial | scrm_800_161 without the baseline/flow-down/level profiles |
| NIST \| 800-171 \| R2 | covered | frameworks/federal/nist/sp_800_171_r2 (110 requirements from NIST CPRT) |
| NIST \| 800-171 \| R3 | covered | frameworks/federal/nist/sp_800_171 (97 requirements, 349 statements, NIST CPRT ids) |
| NIST \| 800-171A | covered | frameworks/federal/nist/sp_800_171a_r2 (320 assessment objectives under the 110 Rev 2 requirements) |
| NIST \| 800-171A \| R3 | covered | frameworks/federal/nist/sp_800_171a (422 determination statements) |
| NIST \| 800-172 R3 | covered | frameworks/federal/nist/sp_800_172 (137 statements from NIST CPRT) |
| NIST \| 800-172A R3 | covered | frameworks/federal/nist/sp_800_172 (199 determination statements) |
| NIST \| 800-207 | covered | frameworks/federal/zero_trust |
| NIST \| 800-218 | covered | frameworks/federal/nist_ssdf + benchmarks/supply_chain/ssdf |
| NIST \| CSF \| 2.0 | covered | frameworks/federal/nist/cybersecurity_framework_2.0 (all 106 subcategories from NIST CPRT; 29 fact-decided, 77 attested) |
| NIST \| CSWP 39 | covered | frameworks/federal/pqc/cswp39_crypto_agility.rego: 67 practice rows from CSWP 39-upd1 (June 2026) |
| NIST Privacy Framework \| 1.0 | covered | frameworks/privacy/nist_privacy_framework (100 subcategories from NIST CPRT) |
| OECD \| Privacy Principles | gap |  |
| OWASP \| Top 10 \| 2025 | covered | governance/owasp_top10 (10 categories, 249 CWEs) |
| PCI DSS \| 4.0.1 (10 profiles) | partial | frameworks/financial/pci_dss is v4.0; 4.0.1 re-stamp needed |
| SCF \| DPMP \| 2026 | gap |  |
| Shared Assessments SIG \| 2025 | gap |  |
| SPARTA \| 4.0 | gap |  |
| SWIFT \| CSF \| 2025 | partial | frameworks/financial/swift_csp is v2024; SCF maps 2025 |
| TISAX \| ISA \| 6.0.3 | covered | frameworks/management/tisax (6.0.3) |
| UL \| 2900-1 \| 2017 | gap |  |
| UL \| 2900-2-2 \| 2016 | gap |  |
| UN \| R155 | gap |  |
| UN \| ECE WP.29 | gap |  |

### United States, federal

43 documents: 30 covered, 2 partial, 11 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| CMS MARS-E \| 2.0 | covered | frameworks/privacy/cms_mars_e (352 controls; superseded by ARC-AMPE, recorded) |
| CISA \| CPG 2022 | covered | frameworks/federal/cisa_cpg (2.0, newer than SCF's 2022) |
| DHS CISA \| SSDAF | covered | frameworks/federal/cisa_ssdaf (the form's 15 items with scope gates) |
| DHS CISA \| TIC 3.0 | covered | frameworks/federal/cisa_tic3 (116 capabilities, catalog v3.3) |
| Data Privacy Framework \| 2023 | gap |  |
| C2M2 \| 2.1 | covered | frameworks/critical_infrastructure/c2m2 (356 practices, MIL gate) |
| DoW BaTB IT \| 2026 | gap |  |
| DoW BaTB OT \| 2026 | gap |  |
| CERT RMM \| 1.2 | covered | frameworks/management/cert_rmm (248 specific practices, titles + own summaries) |
| CMMC 2.0 (4 profiles) | covered | frameworks/federal/cmmc |
| DFARS \| 252.204-7012 | covered | frameworks/federal/dfars_7012 (25 obligations from acquisition.gov) |
| NNPI (unclass) \| 2010 | gap |  |
| DoD Zero Trust Reference Architecture 2.0 | partial | zero_trust is CISA ZTMM + 800-207, not the DoD RA/roadmap |
| DoD Zero Trust Execution Roadmap v1.1 | partial | zero_trust is CISA ZTMM + 800-207, not the DoD RA/roadmap |
| EO 14028 | covered | frameworks/federal/eo_14028 (43 directive rows by role, from the Federal Register text) |
| FAR \| 52.204-21 | covered | frameworks/federal/far_cyber |
| FAR \| 52.204-25 | covered | frameworks/federal/far_cyber |
| FAR \| 52.204-27 | covered | frameworks/federal/far_cyber |
| CJIS Security Policy \| 6.0 | covered | frameworks/federal/cjis |
| 21 CFR Part 11 \| 2025 | covered | frameworks/regulatory/cfr_part_11 |
| FFIEC ITEH \| 2016 | gap |  |
| FedRAMP R5 (4 profiles) | covered | frameworks/federal/fedramp; the four Rev 5 baselines as OSCAL profiles in dist/profiles (+ fedramp_20x, which SCF lacks) |
| 45 CFR 155.260 | covered | frameworks/privacy/aca_155_260 (35 rows) |
| IRS 1075 \| 2021 | covered | frameworks/federal/irs_1075 |
| 33 CFR \| Part 101 Subpart F | covered | frameworks/critical_infrastructure/maritime_33cfr101f (105 rows) |
| COPPA \| 2024 | covered | frameworks/privacy/coppa |
| FACTA & FCRA \| 2023 | covered | frameworks/financial/ftc_red_flags (16 CFR 681 Red Flags + 682 disposal) |
| FERPA \| 2010 | covered | frameworks/privacy/ferpa |
| FTC Act \| 1938 | gap |  |
| GLBA CFR 314 \| 2023 | covered | frameworks/financial/glba |
| HIPAA Security Rule \| NIST SP 800-66 R2 | covered | frameworks/privacy/hipaa Security Rule rows carry the 800-66 Rev 2 section and key-activity numbers |
| HIPAA Administrative Simplification 2013 | covered | frameworks/privacy/hipaa: Parts 160, 162 and 164 Subparts C/D/E keyed to CFR citations (246 rows) |
| SOX \| 2002 | covered | frameworks/financial/sox |
| NERC CIP \| 2024 | covered | frameworks/critical_infrastructure/nerc_cip |
| NISPOM \| 2020 | covered | frameworks/federal/nispom (32 CFR 117, 599 rows) |
| NRC 10 CFR 73.54 \| 2015 | covered | frameworks/critical_infrastructure/nrc_73_54 (34 rows) |
| NSF \| RIG 2025 | gap |  |
| FIPPS \| 1973 | gap |  |
| SEC Cybersecurity Rule \| 2023 | covered | frameworks/financial/sec_cyber |
| FCA CRM \| 2023 | gap |  |
| FINRA \| 2007 | gap |  |
| TSA \| SDP 2021-02F | covered | frameworks/critical_infrastructure/tsa_pipeline (01G/02G, newer) |
| TSA / DHS \| 1580/82-2022-01 | gap |  |

### United States, state

27 documents: 2 covered, 0 partial, 25 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| Alaska \| PIPA \| 2029 | gap |  |
| California \| CCPA \| 2025 | covered | frameworks/privacy/ccpa |
| California \| SB1386 \| 2002 | gap |  |
| California \| SB327 \| 2018 | gap |  |
| Colorado \| Colorado Privacy Act \| 2021 | gap |  |
| Illinois \| BIPA \| 2008 | gap |  |
| Illinois \| IPA \| 2009 | gap |  |
| Illinois \| PIPA \| 2006 | gap |  |
| Massachusetts \| 201 CMR 17.00 \| 2008 | gap |  |
| Montana \| CDPA \| 2025 | gap |  |
| Nevada \| Privacy Law \| 2023 | gap |  |
| Nevada \| NOGE Reg 5 \| 2024 | gap |  |
| Nevada \| SB220 \| 2019 | gap |  |
| New York \| DFS 23 NYCRR500 \| 2023 Amd 2 | covered | frameworks/financial/ny_dfs |
| New York \| SHIELD Act \| 2019 | gap |  |
| Oregon \| CPA \| 2023 | gap |  |
| Oregon \| 646A \| 2025 | gap |  |
| Tennessee \| TIPA \| 2025 | gap |  |
| Texas \| BC521 \| 2009 | gap |  |
| Texas \| CDPA \| 2025 | gap |  |
| Texas \| DIR SCSC 2.2 \| 2025 | gap |  |
| Texas \| SB 2610 \| 2025 | gap |  |
| Texas \| SB 820 \| 2019 | gap |  |
| Texas \| TRAIGA \| 2025 | gap |  |
| Texas \| TX-RAMP (2 profiles) | gap |  |
| Virginia \| CDPA \| 2023 | gap |  |
| Vermont \| Act 171 \| 2018 | gap |  |

### EMEA

50 documents: 14 covered, 0 partial, 36 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| Austria \| FAPPD \| 2000 | gap |  |
| Belgium \| Act 8 \| 1992 | gap |  |
| Switzerland \| FADP \| 2025 | gap |  |
| CHE \| FINMA \| Circular 2023/1 | gap |  |
| Germany \| BAIT \| 2017 | gap |  |
| Germany \| C5 \| 2026 | covered | frameworks/regional/bsi_c5 re-keyed to C5:2026 (168 criteria, 17 subject areas, BSI ids) |
| Germany \| FDPA \| 2017 | gap |  |
| Spain \| CCN-STIC 825 | gap |  |
| Spain \| Royal Decree 311 \| 2022 | gap |  |
| EU \| AI Act | covered | governance/eu_ai_act |
| EU \| Cyber Resiliency Act \| 2024 | covered | frameworks/compliance/cra (17 modules, Annex I included) |
| EU \| Cyber Resiliency Act Annex I \| 2024 | covered | frameworks/compliance/cra (17 modules, Annex I included) |
| EU \| DORA \| 2023 | covered | frameworks/financial/dora |
| EU \| DORA RTS \| 2024 | covered | frameworks/financial/dora/dora_rts_ict_risk.rego: Delegated Regulation (EU) 2024/1774, 308 rows (Title II 228, Title III 80), simplified-framework and entity-role gates |
| EU \| EBA \| GL/2019/04 | gap |  |
| EU \| GDPR \| 2016 | covered | frameworks/privacy/gdpr |
| EU \| NIS2 \| 2022 | covered | frameworks/compliance/nis2 (directive + 2024 implementing annex) |
| EU \| NIS2 Annex \| 2024 | covered | frameworks/compliance/nis2 (directive + 2024 implementing annex) |
| EU \| PSD2 \| 2015 | gap |  |
| UK \| CAF 4.0 | covered | frameworks/compliance/ncsc_caf |
| UK \| CAP 1850 \| 2020 | gap |  |
| UK \| Cyber Essentials 3.3 | covered | frameworks/regional/cyber_essentials (Willow 2025) |
| UK \| DEFSTAN 05-138 \| 2024 | covered | frameworks/regional/dcc (all four risk profiles) |
| UK \| DEFSTAN 05-138 (4 profiles) | covered | frameworks/regional/dcc (all four risk profiles) |
| UK \| DPA \| 2018 | covered | frameworks/privacy/uk_dpa_2018 (151 duty rows from the legislation.gov.uk XML, point in time 2026-09-30; Part 3 gated by competent_authority) |
| Greece \| PIRPPD \| 1997 | gap |  |
| Hungary \| Act CXII \| 2011 | gap |  |
| Ireland \| DPA \| 2018 | gap |  |
| Israel \| CDMO \| 2.0 | gap |  |
| Israel \| PPL \| 2025 | gap |  |
| Italy \| PDPC \| 2018 | gap |  |
| Kenya \| DPA \| 2019 | gap |  |
| LUX \| CCSF 20/750 \| 2020 | gap |  |
| LUX \| CCSF 22/806 \| 2022 | gap |  |
| Nigeria \| DPR \| 2019 | gap |  |
| Norway \| DPA \| 2018 | gap |  |
| Poland \| Act 10 \| 2018 | gap |  |
| Qatar \| PDPPL \| 2020 | gap |  |
| Russia \| 152-FZ \| 2025 | gap |  |
| Saudi Arabia \| IoT CGIoT-1 \| 2024 | gap |  |
| Saudi Arabia \| CSCC-1 \| 2019 | gap |  |
| Saudi Arabia \| ECC-1 \| 2018 | gap |  |
| Saudi Arabia \| OTCC-1 \| 2022 | gap |  |
| Saudi Arabia \| PDPL | gap |  |
| Saudi Arabia \| SACS-002 \| 2022 | gap |  |
| Saudi Arabia \| SAMA CSF 1.0 \| 2017 | gap |  |
| Serbia \| 87/2018 | gap |  |
| Turkey \| LDDP \| 2016 | gap |  |
| UAE \| NIAF \| 2023 | gap |  |
| South Africa \| POPIA \| 2013 | gap |  |

### APAC

36 documents: 5 covered, 0 partial, 31 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| Australia \| CCM \| 2026 | gap |  |
| Australia \| IoT Code of Practice \| 2024 | gap |  |
| Australia \| Essential 8 \| 2024 | covered | frameworks/regional/essential_eight |
| Australia \| ISM \| June 2026 | gap |  |
| Australian Privacy Principles \| 2026 | gap |  |
| Australia \| Prudential Standard CPS230 \| 2023 | gap |  |
| Australia \| Prudential Standard CPS234 \| 2019 | covered | frameworks/financial/apra_cps234 |
| Australia \| SOCI \| 2028 | gap |  |
| China \| DNSIP \| 2012 | gap |  |
| China \| Cybersecurity Law \| 2017 | gap |  |
| China \| Data Security Law \| 2021 | gap |  |
| China \| Privacy Law \| 2021 | gap |  |
| Hong Kong \| PDO \| 2022 | gap |  |
| India \| DPDPA \| 2023 | covered | frameworks/privacy/dpdp_india |
| India \| ITR \| 2011 | gap |  |
| India \| RBI Data Localization \| 2018 | gap |  |
| India \| RBI Digital Payments \| 2021 | gap |  |
| India \| RBI PA \| 2025 | gap |  |
| India \| RBI PPI \| 2025 | gap |  |
| India \| SEBI CSCRF \| 2024 | gap |  |
| Japan \| APPI \| 2020 | gap |  |
| Japan \| ISMAP | gap |  |
| South Korea \| PIPA \| 2011 | gap |  |
| Malaysia \| RMiT \| 2025 | covered | frameworks/financial/bnm_rmit |
| Malaysia \| PDPA \| 2010 | gap |  |
| New Zealand \| HISF Microsmall \| 2023 | gap |  |
| New Zealand \| HISF MLHSP \| 2023 | gap |  |
| New Zealand \| HISF Suppliers \| 2023 | gap |  |
| New Zealand \| NZISM 3.9 | gap |  |
| New Zealand \| Privacy Act of 2020 | gap |  |
| Philippines \| DPA \| 2012 | gap |  |
| Singapore \| CCOP CII \| 2026 | gap |  |
| Singapore \| Cyber Hygiene Practice \| 2019 | gap |  |
| Singapore \| MAS TRM \| 2021 | covered | frameworks/financial/mas_trm |
| Singapore \| PDPA \| 2012 | gap |  |
| Taiwan \| PDPA \| 2025 | gap |  |

### Americas

11 documents: 0 covered, 0 partial, 11 gap.

| SCF document | Status | Our module / note |
|---|---|---|
| Argentina \| Reg 132 \| 2018 | gap |  |
| Bahamas \| DPA \| 2003 | gap |  |
| Bermuda \| BMACCC \| 2020 | gap |  |
| Brazil \| LGPD \| 2018 | gap |  |
| Canada \| ITSP-10-171 \| 2025 | gap |  |
| Canada \| OSFI B-13 \| 2022 | gap |  |
| Canada \| OSFI Self-Assessment Guidance | gap |  |
| Canada \| PIPEDA \| 2000 | gap |  |
| Chile \| Act 19628 \| 1999 | gap |  |
| Colombia \| Law 1581 \| 2012 | gap |  |
| Mexico \| FDPA \| 2010 | gap |  |
