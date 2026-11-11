# Frameworks and benchmarks in the library

<!-- Moved out of README.md on 2026-11-11 so the front page stays short. Content unchanged except headings. -->

Every implemented standard is tracked in [`../STANDARDS_UPDATE_REGISTRY.md`](../STANDARDS_UPDATE_REGISTRY.md): pinned version, upstream revision cadence and watch URL.

## Coverage at a glance

| Standard / Framework | Path | Controls / Requirements |
|---------------------|------|------------------------|
| **CIS RHEL 9 v2.0.0** | `benchmarks/cis/rhel_9/` | 17 modules · **224+ control IDs** ✅ |
| CIS RHEL 8 | `benchmarks/cis/rhel_8/` | Full |
| CIS RHEL 10 | `benchmarks/cis/rhel_10/` | Full |
| CIS Ubuntu 22.04/24.04/20.04 | `benchmarks/cis/ubuntu_*/` | Full |
| CIS Rocky Linux 8/9 | `benchmarks/cis/rocky_linux_*/` | Full |
| CIS Debian 11 | `benchmarks/cis/debian_11/` | Full |
| CIS Amazon Linux 2023 | `benchmarks/cis/amazon_linux_2023/` | Full |
| CIS Windows Server 2022 v5.1.0 | `benchmarks/cis/windows_server_2022_modular/` | Full: all 408 recommendations (406 evaluated, 2 Manual by attestation), member server and domain controller, Level 1/2 and Next Generation profiles |
| CIS Windows Server 2019 | `benchmarks/cis/windows_server_2019_modular/` | IDs unverified: a copy of the old 2022 module's numbering, not checked against the CIS Windows Server 2019 benchmark |
| CIS Windows 10 Enterprise v5.0.0 | `benchmarks/cis/windows_10_modular/` | Full: all 501 recommendations (499 evaluated, 2 Manual by attestation), Level 1/2, BitLocker and Next Generation profiles |
| CIS Windows 11 Enterprise v5.1.0 | `benchmarks/cis/windows_11_modular/` | Full: all 535 recommendations (533 evaluated, 2 Manual by attestation), Level 1/2 and BitLocker profiles |
| CIS Microsoft 365 Foundations v7 (SaaS) | `benchmarks/cis/saas/m365_v7/` | 9 sections: Entra, Exchange, Defender, Purview, SharePoint, Teams, Intune, Fabric, Admin Center |
| CIS PostgreSQL | `benchmarks/cis/postgresql/` | Full |
| Network devices — Cisco, Juniper, Palo Alto, Fortinet, Arista, VyOS, pfSense | `benchmarks/cis/network_devices/` | Full |
| CIS AWS / Azure / GCP | `benchmarks/cis/cloud/` | Foundations |
| CIS Docker / Kubernetes / OpenShift | `benchmarks/cis/containers/` | Full |
| **DISA STIGs — 25 platforms** (RHEL 8/9, **Oracle Linux 8/9**, Windows Server 2016/2019/2022/**2025**, Windows 10/11, Ubuntu 20.04/22.04, Amazon Linux 2023, SLES 15, **Kubernetes (all 92 rules, V2R6)**, **RGS RKE2 (all 21 rules, V2R7)**, OpenShift 4, Crunchy Postgres 16, SQL 2016, **Oracle Database 19c**, **Oracle MySQL 8.0**, Apache 2.4, Cisco IOS-XE, vSphere 8 ESXi) | `benchmarks/stig/` | Per-rule findings with XCCDF-verified IDs (July 2026 library; Oracle from October 2026; Kubernetes V2R6 and RKE2 V2R7 verified 2026-10-21); every rule of the two Oracle database STIGs, Kubernetes and RKE2; all CAT I on new platforms; fail-closed entrypoints; coverage-of-total stated per aggregator |
| NIST 800-53 rev5 | `frameworks/federal/nist/sp_800_53/` | All control families |
| NIST 800-82 (OT) | `frameworks/critical_infrastructure/nist_800_82/` | Full |
| FISMA / FedRAMP / CMMC | `frameworks/federal/` | Full |
| ISO 27001:2022 Annex A / ISO 27002:2022 (all 93 controls, 2022 numbering, titles and attributes only; 35 fact-decided) | `frameworks/management/iso27001/` | Full |
| SOC 2 Type II | `frameworks/management/soc2/` | All TSCs |
| PCI-DSS v4.0 | `frameworks/financial/pci_dss/` | All 12 requirements |
| SOX ITGC | `frameworks/financial/sox/` | Full |
| HIPAA Administrative Simplification (45 CFR Parts 160, 162, 164 Subparts C/D/E, CFR-cited; 800-66 Rev 2 numbering) | `frameworks/privacy/hipaa/` | Full |
| GDPR | `frameworks/privacy/gdpr/` | Full |
| NERC-CIP (CIP-002 – CIP-015) | `frameworks/critical_infrastructure/nerc_cip/` | 14 standards |
| IEC 62443 (all parts) | `frameworks/critical_infrastructure/iec_62443/` | 51 SRs, SL 1–4 |
| NIST IR 7628 (AMI / Smart Grid) | `frameworks/critical_infrastructure/ami/` | Full |
| DORA / NIS2 (DORA incl. RTS 2024/1774 ICT risk management framework, 308 rows, simplified-framework gate) | `frameworks/financial/dora/`, `frameworks/compliance/nis2/` | Full |
| NCSC CAF 4.0 | `frameworks/compliance/ncsc_caf/` | 23 Cyber Outcomes |
| Digital Sovereignty | `frameworks/sovereignty/` | 7 domains |
| **CSA CCM v4.0** | `frameworks/management/csa_ccm/` | 16 domains, 197 controls |
| **ISO/IEC 27701:2019** | `frameworks/privacy/iso27701/` | PIMS, PII Controller, PII Processor, DSR |
| **NIST SP 800-171 Rev 3** | `frameworks/federal/nist/sp_800_171/` | 17 families, all 97 requirements with their 349 statements, ids and text from NIST's CPRT export; 79 decided by facts, 18 attested; 33 withdrawn listed with reasons |
| **NIST SP 800-171A Rev 3** | `frameworks/federal/nist/sp_800_171a/` | all 422 assessment determination statements, rolled up per requirement; examine / interview / test methods carried as data |
| **NIST SP 800-171 Rev 2** | `frameworks/federal/nist/sp_800_171_r2/` | the 110 requirements DFARS 7012 and CMMC 2.0 Level 2 still assess, basic / derived classification from CPRT |
| **NISPOM (32 CFR 117)** | `frameworks/federal/nispom/` | 599 contractor obligations from the CFR text, 18 programme gates (FOCI, classified IS, SAP, SCI, RD, NNPI, NATO …) |
| **FAR 52.204-21 / -25 / -27** | `frameworks/federal/far_cyber/` | basic safeguarding (15 requirements), covered telecom (Section 889) reporting clocks, ByteDance prohibition; per-clause gates |
| **CISA TIC 3.0 Security Capabilities Catalog v3.3** | `frameworks/federal/cisa_tic3/` | 116 capabilities, universal + 12 PEP groups, group gate |
| **DOE C2M2 v2.1** | `frameworks/critical_infrastructure/c2m2/` | all 356 practices in 10 domains, target-MIL gate and cumulative MIL scoring |
| **NRC 10 CFR 73.54 + USCG 33 CFR 101 Subpart F** | `frameworks/critical_infrastructure/nrc_73_54/`, `frameworks/critical_infrastructure/maritime_33cfr101f/` | nuclear licensee cyber rule (34 paragraphs) and the 2025 maritime cybersecurity rule (105 obligations, compliance dates as data) |
| **CERT-RMM v1.2** | `frameworks/management/cert_rmm/` | 248 specific practices in 26 process areas (ids and titles; summaries are our own) |
| **CMS MARS-E 2.0, 45 CFR 155.260, FTC Red Flags / Disposal** | `frameworks/privacy/cms_mars_e/`, `frameworks/privacy/aca_155_260/`, `frameworks/financial/ftc_red_flags/` | 352 MARS-E controls (superseded by ARC-AMPE, recorded), 35 ACA Exchange PII obligations, 12 Red Flags / FACTA disposal obligations |
| **NIST SP 800-37 Rev 2 RMF + SP 800-39** | `frameworks/federal/nist/risk_management_framework/`, `frameworks/federal/nist/sp_800_39/` | all 47 RMF tasks across the seven steps (P-1 … M-7, optional P-4 / P-6 gated) and the 12 SP 800-39 risk-management tasks |
| **NIST AI RMF 1.0 + AI 600-1 Generative AI Profile** | `frameworks/federal/nist/ai_rmf/` | all 72 Core subcategories (14 fact-decided) and the 212 suggested actions of the GAI profile on their parent subcategories, rolled up per GAI risk; profile gated by `generative_ai` |
| **NIST SP 800-160 Vol 2 Rev 1** | `frameworks/federal/nist/sp_800_160v2/` | the 50 cyber-resiliency implementation approaches under 14 techniques, with objectives, design principles and the Table E-1 SP 800-53 mapping as data |
| **OWASP Top 10:2025** | `governance/owasp_top10/` | the 10 categories with their 249 mapped CWEs (titles and CWE lists only; summaries are our own) |
| **NIST SP 800-171A (June 2018)** | `frameworks/federal/nist/sp_800_171a_r2/` | all 320 assessment objectives under the 110 Rev 2 requirements, examine / interview / test lists as data |
| **NIST SP 800-172 Rev 3 + 172A** | `frameworks/federal/nist/sp_800_172/` | 137 enhanced security requirement statements and all 199 determination statements; a statement is satisfied only when attested and every determination holds |
| **DFARS 252.204-7012 (May 2024, change of 2026-05-07)** | `frameworks/federal/dfars_7012/` | 25 contractor obligations by paragraph: 800-171 implementation, FedRAMP Moderate-equivalent cloud, 72-hour reporting, malware submission, 90-day media preservation, flow-down |
| **EO 14028 Improving the Nation's Cybersecurity** | `frameworks/federal/eo_14028/` | 43 directive rows from Secs. 2, 3, 4, 6, 7, 8 by role (agency, FCEB agency, supplier); the 15 Sec. 4(e) supplier practices |
| **CISA Secure Software Development Attestation Form v1.0** | `frameworks/federal/cisa_ssdaf/` | the 15 attestation items with their scope gates; each item carries its EO 4(e) subsection and SSDF tasks |
| **CCPA / CPRA** | `frameworks/privacy/ccpa/` | Consumer rights, sensitive PI, data practices |
| **EU AI Act (2024/1689)** | `governance/eu_ai_act/` | Prohibited, High-Risk, Transparency, GPAI, Governance |
| **TSA Pipeline Security Directives** | `frameworks/critical_infrastructure/tsa_pipeline/` | SD Pipeline-2021-01G + 02G, 12 sections, 112 requirements |
| **GLBA Safeguards Rule (16 CFR 314)** | `frameworks/financial/glba/` | All §314.4 elements + §314.5 breach notification (2024), small-institution exemption modeled |
| **CISA CPG 2.0 (Oct 2025)** | `frameworks/federal/cisa_cpg/` | All 34 goals, six CSF-2.0 functions incl. GOVERN, per-function rollup |
| **ISO/IEC 42001:2023 (AIMS)** | `governance/iso_42001/` | Clauses 4–10 + Annex A groups — completes the AI trio with EU AI Act + NIST AI RMF |
| **ITAR (22 CFR 120–130)** | `frameworks/regulatory/itar/` | Data-safeguarding slice: deemed exports, §120.54 encryption carve-out, DDTC hygiene — legal/licensing scoped out honestly |
| **COBIT 2019** | `frameworks/management/cobit/` | Governance-system attestation across EDM/APO/BAI/DSS/MEA — maturity assessment explicitly disclaimed |
| **CISA SCuBA M365** | `benchmarks/scuba/m365/` | All 104 baseline policies across 7 products (Entra ID, Defender, EXO, Power BI, Power Platform, SharePoint/OneDrive, Teams); SHALL/SHOULD criticality reported; BOD 25-01 |
| **CIS Amazon EKS v1.8.0** | `benchmarks/cis/eks/` | 49 controls (kubescape-mapped coverage; gaps stated in header) |
| **CIS Azure AKS v1.8.0** | `benchmarks/cis/aks/` | 56 controls (kubescape-mapped coverage; gaps stated in header) |
| **CIS Google GKE v1.9.0** | `benchmarks/cis/gke/` | 40 controls (partial cover of the official benchmark — stated in header) |
| **NSA/CISA Kubernetes Hardening v1.2** | `benchmarks/nsa_cisa/kubernetes/` | 43 controls across the guide's 5 sections |
| **SAP Security Baseline Template v2.6 (ABAP)** | `benchmarks/sap/abap/` | Registry of all 355 ABAP checks SAP publishes (SAP-samples, Apache-2.0); 138 decided from host facts (profile, transport and kernel parameters, gateway and message-server ACL files), the rest listed not-assessable with the store named; projections onto the Baseline requirements, the DSAG S/4HANA audit guide sections and NIST CSF 2.0 |
| **Kubernetes Pod Security Standards** | `benchmarks/pss/kubernetes/` | 12 baseline + 6 restricted controls, evaluated against an actual Pod manifest |
| **FERPA (34 CFR Part 99)** | `frameworks/privacy/ferpa/` | 32 controls: notification, access/amendment, consent, exception conditions, directory info, disclosure recordkeeping |
| **COPPA (16 CFR Part 312, 2025 amendments)** | `frameworks/privacy/coppa/` | 21 controls incl. separate third-party-disclosure consent, retention policy, written infosec program |
| **CIS Controls v8.1** | `frameworks/management/cis_controls_v8/` | 18 Critical Security Controls, 153 safeguards, cumulative IG1 ⊆ IG2 ⊆ IG3 scoring — distinct from the CIS *Benchmarks* above |
| **Zero Trust — CISA ZTMM v2.0 + NIST SP 800-207** | `frameworks/federal/zero_trust/` | 83 criteria across the 5 pillars + 3 cross-cutting capabilities |
| **PQC Readiness (FIPS 203/204/205, EO 14412, CNSA 2.0) + NIST CSWP 39-upd1 crypto agility** | `frameworks/federal/pqc/` | 67 CSWP 39 practice rows (June 2026 update, implementer and cloud gates) beside 15 profile-gated controls (general/federal/nss) + data-driven algorithm classification over a supplied crypto inventory (HNDL, IR 8547 deprecation, CNSA 2.0) |
| **BNM Risk Management in Technology (Malaysia, Sep 2026)** | `frameworks/financial/bnm_rmit/` | 99 mandatory S paragraphs of Part B §§8–15; cloud, third-party, NCII and digital-services paragraphs gated by declared flags; 2027 dated obligations and the 4-hour / 120-minute availability targets in the report |
| **HKMA SPM TM-G-1 + TM-C-1 (Hong Kong)** | `frameworks/financial/hkma_trm/` | 67 controls: TM-G-1 §§2–7 technology risk management plus the TM-C-1 cyber duties (incident reporting, C-RAF, STDB, CISP); WLAN, outsourcing and overseas-IT paragraphs gated by declared flags |
| **APRA CPS 234 Information Security (Australia, 2019)** | `frameworks/financial/apra_cps234/` | one control per requirement paragraph 13–36; third-party paragraphs gated by a declared flag; 72-hour incident and 10-business-day weakness clocks in the report |
| **METI Cybersecurity Management Guidelines Ver. 3.0 (Japan, 2023)** | `frameworks/regional/meti_csm/` | Appendix A check sheets: 3 principles (9 items) + 10 directions (40 items), each with its NIST CSF subcategory refs; per-direction report |
| **India DPDP Act 2023 + DPDP Rules 2025** | `frameworks/privacy/dpdp_india/` | Data Fiduciary duties: lawful basis, notice, consent, Rule 6 safeguards, 72-hour breach reporting, retention and erasure, children, Significant Data Fiduciary, rights, transfers; four declared scope flags; penalty tiers in the report |
| **CERT-In Directions under s.70B(6) IT Act (Apr 2022)** | `frameworks/regional/cert_in/` | India: 6-hour incident reporting, all 20 Annexure I incident types, 180-day in-country logs, NIC/NPL time sync, PoC; provider and VASP duties by declared sector flag |
| **MAS Technology Risk Management Guidelines (Jan 2021)** | `frameworks/financial/mas_trm/` | 237 controls across chapters 3–15, per-chapter report; chapter 14 (online financial services) scoped by flag |
| **ACSC Essential Eight (Nov 2023)** | `frameworks/regional/essential_eight/` | 8 mitigation strategies, 96 requirements; overall maturity = lowest strategy level |
| **FBI CJIS Security Policy** | `frameworks/federal/cjis/` | All 13 Policy Areas, 98 requirements, NIST 800-53-mapped |
| **NIST SSDF (SP 800-218 v1.1)** | `frameworks/federal/nist_ssdf/` | 42 secure-software-development controls |
| **NIST CSF 2.0** | `frameworks/federal/nist/cybersecurity_framework_2.0/` | all 106 subcategories (6 functions, 22 categories) with ids, text and the 363 implementation examples from NIST's CPRT export; 29 decided by facts, 77 attested; 79 withdrawn CSF 1.1 subcategories listed with their destination |
| **NIST Privacy Framework 1.0** | `frameworks/privacy/nist_privacy_framework/` | all 100 subcategories (5 functions, 18 categories) from NIST's CPRT export, with each row's CSF relationship (identical / adapted / none) |
| **NIST SP 800-82 Rev 3 OT overlay** | `frameworks/critical_infrastructure/nist_800_82/` | Appendix F Table 22 transcribed: 424 SP 800-53 controls with Low / Moderate / High OT baseline membership (verified against the 800-53B sizes), 24 additions and 3 removals, impact gate |
| **NIST SP 800-161 Rev 1 C-SCRM tailoring** | `benchmarks/supply_chain/scrm_800_161/` | Appendix B Table 6 transcribed: 297 controls with Baseline / Flow Down / Level 1-3 membership, level gate |
| **IRS Publication 1075 (Rev. 11-2021)** | `frameworks/federal/irs_1075/` | 8 safeguard areas, 57 requirements — IRC 6103(p)(4)(A)–(F), §9 computer security (800-53 Rev 5 tailoring), §10 incident response |
| **UK Cyber Essentials (Willow, April 2025)** | `frameworks/regional/cyber_essentials/` | 5 technical control themes, 28 requirements |
| **UK Data Protection Act 2018 (as at 2026-09-30)** | `frameworks/privacy/uk_dpa_2018/` | 151 controller / processor duties beyond the UK GDPR: Part 2 supplementary provisions and Schedule 1 policy document, Part 3 law-enforcement processing (gated), s.164A; Parts 4–7 out of scope with citations |
| **BSI C5:2026** (all 168 criteria, 17 subject areas, BSI's ids; binding for periods from 2027-06-01), **MAS TRM (Singapore, Jan 2021)**, **CERT-In Directions (India, 2022)**, **India DPDP Act 2023 + Rules 2025**, **METI CSM Guidelines (Japan)**, **APRA CPS 234**, **HKMA TM-G-1/TM-C-1**, **BNM RMiT (Malaysia)** | `frameworks/regional/bsi_c5/` | All 17 criteria domains, 61 requirements — incl. Portability/Interoperability (export + confirmed deletion) and Government Investigation Requests (INQ) |
| **ISO/IEC 42005:2025 (AI impact assessment)** | `governance/iso_42005/` | 22 attestation checks across the AIIA process (Clause 5) and per-system records (Clause 6), wired to the ISO 42001 AIMS integration |
| **OWASP LLM Top 10 (2026)** | `governance/owasp_llm/` | 30 controls (3 per risk, LLM01–LLM10:2026) with a MITRE ATLAS mitigation crosswalk (atlas-data v2026.09) |
| **FedRAMP 20x KSI** | `frameworks/federal/fedramp_20x/` | All 46 Key Security Indicators, Class B/C profiles, generated from the Consolidated Rules datafile; rev5 module retained for existing/High |
| **UK MoD DCC — DEF STAN 05-138 Issue 4** | `frameworks/regional/dcc/` | All 148 controls, 4 Cyber Risk Profiles (L0 Basic → L3 Expert) with exact per-control level sets incl. the non-cumulative supersession pairs |
| **SAE AS9100D (IAQG 9100:2016) aerospace QMS** | `frameworks/management/as9100d/` | 70 clause rows of clauses 4–10 in seven clause packages incl. every aerospace addition (8.1.1–8.1.4, 8.4 flow-down, 8.5.1.1–8.5.1.3, 8.5.6, 8.7, 9.1.2 on-time delivery/conformity, 10.2 root cause + human factors); 18 decided from collected evidence, 52 attested; clause numbers and titles only — no standard text |

## CIS Benchmark coverage

| Platform | Path | Controls |
|----------|------|----------|
| **RHEL 9** | `benchmarks/cis/rhel_9/` | 17 modules · **224+ control IDs** ✅ |
| RHEL 8 | `benchmarks/cis/rhel_8/` | Full |
| Ubuntu 22.04 | `benchmarks/cis/ubuntu_22_04/` | Full |
| Ubuntu 20.04 / 24.04 | `benchmarks/cis/ubuntu_20_04/` | Full |
| Debian 11 | `benchmarks/cis/debian_11/` | Full |
| Rocky Linux 8 / 9 | `benchmarks/cis/rocky_linux_8/` | Full |
| Amazon Linux 2023 | `benchmarks/cis/amazon_linux_2023/` | Full |
| Windows Server 2022 | `benchmarks/cis/windows_server_2022_modular/` | Full (v5.1.0, 408 recommendations) |
| Windows Server 2019 | `benchmarks/cis/windows_server_2019_modular/` | IDs unverified |
| AWS / Azure / GCP | `benchmarks/cis/cloud/` | Foundations |
| Docker / Kubernetes / OpenShift | `benchmarks/cis/containers/` | Full |
| MySQL / Oracle / PostgreSQL | `benchmarks/cis/databases/` | Full |
| Cisco / Juniper / Palo Alto / Fortinet / Arista | `benchmarks/cis/network/` | Full |

## IEC 62443 Coverage

Full library for IEC 62443 Industrial Automation and Control Systems (IACS) Security — all 51 System Requirements (SRs) from Part 3-3 plus Part 2 management requirements.

| File | Part | Title | SRs |
|------|------|-------|-----|
| `fr1_identification_authentication.rego` | 3-3 FR 1 | Identification & Authentication Control (IAC) | SR 1.1–1.13 (13) |
| `fr2_use_control.rego` | 3-3 FR 2 | Use Control (UC) | SR 2.1–2.12 (12) |
| `fr3_system_integrity.rego` | 3-3 FR 3 | System Integrity (SI) | SR 3.1–3.9 (9) |
| `fr4_data_confidentiality.rego` | 3-3 FR 4 | Data Confidentiality (DC) | SR 4.1–4.3 (3) |
| `fr5_restricted_data_flow.rego` | 3-3 FR 5 | Restricted Data Flow / Zone & Conduit (RDF) | SR 5.1–5.4 (4) |
| `fr6_timely_response.rego` | 3-3 FR 6 | Timely Response to Events (TRE) | SR 6.1–6.2 (2) |
| `fr7_resource_availability.rego` | 3-3 FR 7 | Resource Availability (RA) | SR 7.1–7.8 (8) |
| `part2_security_management.rego` | 2-1 | Security Management System (CSMS) | — |
| `part2_patch_management.rego` | 2-3 | Patch Management in IACS Environments | — |
| `part2_service_provider.rego` | 2-4 | Security Program for IACS Service Providers (SP.01–SP.10) | — |
| `part3_risk_assessment.rego` | 3-2 | Security Risk Assessment (ZCR 1–5) | — |
| `iec_62443_main.rego` | All | Main orchestrator — aggregates all parts | 51 total |

**Security Level (SL) tiering:** All FR modules enforce SL-differentiated requirements — violations are tagged with the SL at which they apply (SL 1 baseline through SL 4 state-sponsored threat protection).

**OPA endpoint:** `POST /v1/data/iec_62443_main/iec_62443_compliance_report`

```json
{
  "standard": "IEC 62443",
  "target_sl": 2,
  "compliant": false,
  "fr_compliance_score": 71,
  "sr_compliance_score": 84,
  "passing_frs": 5,
  "total_frs": 7,
  "passing_srs": 43,
  "total_srs": 51,
  "part3_3_foundational_requirements": {
    "FR1_identification_authentication": { "compliant": true, "passing_srs": 13 },
    "FR5_restricted_data_flow": { "compliant": false, "violations": ["..."] }
  }
}
```

---

## TSA Pipeline Security Directives Coverage

Both currently-effective TSA pipeline cybersecurity directives, in
`frameworks/critical_infrastructure/tsa_pipeline/` — 12 section modules plus an
orchestrator, covering 112 directive subparagraphs.

| Directive | Effective | Sections covered |
|---|---|---|
| **SD Pipeline-2021-01G** — *Enhancing Pipeline Cybersecurity* | 2026-01-16 → 2027-01-15 | II.B Cybersecurity Coordinator · II.C Incident reporting to CISA · II.D Vulnerability assessment |
| **SD Pipeline-2021-02G** — *Pipeline Cybersecurity Mitigation Actions, Contingency Planning, and Testing* | 2026-05-03 → 2027-05-02 | II.A/III.A Critical Cyber Systems · II.B/VI Implementation Plan + amendments · III.B Network segmentation · III.C Access control · III.D Continuous monitoring · III.E Patch management · III.F Incident Response Plan · III.G Assessment Plan · IV/V Records + SSI |

**OPA endpoint:** `POST /v1/data/tsa_pipeline/main/compliance_report`

The directives are largely deadline-driven, and the deadlines are what these
policies assert — each is pinned by a test in
`tests/test_tsa_pipeline_deadlines.rego`:

| Clock | Directive |
|---|---|
| 72 hours — report incident to CISA | SD-01G II.C.3 |
| 24 hours — supplemental information | SD-01G II.C.5.f |
| 7 days — Coordinator info change | SD-01G II.B.1.e |
| 60 days — "no Critical Cyber Systems" notice | SD-02G II.A.5 |
| 45 / 50 / 30 days — permanent change · amendment filing · reconsideration petition | SD-02G VI.C / VI.D / VI.F |
| 12 months, ≥ 2 objectives — Incident Response Plan exercise | SD-02G III.F.1.e |
| 24 months — cybersecurity architecture design review | SD-02G III.G.2.b |
| ⅓ per year, 100% over 3 years — assessment coverage | SD-02G III.G.2.d |
| 12 months — Assessment Plan and report submission | SD-02G III.G.3–4 |
| 24 hours — maximum packet capture period | SD-02G IV.C.2.e.ii |

> **No fact source exists yet.** Both directives are overwhelmingly plan-,
> attestation-, and recordkeeping-driven ("is there a TSA-approved Cybersecurity
> Implementation Plan", "was the Assessment Plan submitted within 12 months").
> None of that comes from host fact-gathering, and nothing currently emits the
> `input` documented in each module header. On absent input this framework
> reports **fully non-compliant across all 12 sections** — correct fail-closed
> behavior for an audit framework, but not a working assessment until an
> attestation intake or GRC export is wired up. Don't demo it as one.

---

## NERC-CIP Coverage

Full library covering all active CIP standards (CIP-002 through CIP-015) in `frameworks/critical_infrastructure/nerc_cip/`.

**OPA endpoint:** `POST /v1/data/nerc_cip_main`

**Data sources:** Every `input.*` field used by the 14 CIP policies is documented in [`frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md`](frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md) — each entry lists the real-world source system (GRC, CMDB, LMS, PACS, SIEM, INSM platform, vulnerability scanner, etc.), the collection method (Ansible module or REST endpoint), and whether the integration is currently live or stubbed.
