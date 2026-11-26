# Frameworks and benchmarks in the library

<!-- Moved out of README.md on 2026-11-11 so the front page stays short. Content unchanged except headings. -->

Every implemented standard is tracked in [`../STANDARDS_UPDATE_REGISTRY.md`](../STANDARDS_UPDATE_REGISTRY.md): pinned version, upstream revision cadence and watch URL. What moved upstream each month, and what the library did about it, is written up in [`sweeps/`](sweeps/README.md).

## Coverage at a glance

Each framework key is labelled validated, partial or experimental in [`scripts/coverage_labels.json`](../scripts/coverage_labels.json); the table is in [COVERAGE.md](../COVERAGE.md). Only CIS RHEL 9, CIS Windows Server 2022 and CIS M365 v7 are validated today; a row below says what a module holds, not that it has been run on real evidence.

This page is written by hand and is not the full list: the [site catalog](https://ynotbhatc.github.io/rego_policy_libraries/) is generated from the tree and lists every directory, and [`standards.yaml`](../standards.yaml) records the version each framework key implements. `make check-standards` fails when a path below does not exist, when a version quoted below differs from `standards.yaml`, when a recommendation count differs from the total the module declares, or when a cell says only "Full".

| Standard / Framework | Path | Controls / Requirements |
|---------------------|------|------------------------|
| **CIS RHEL 9 v3.0.0** | `benchmarks/cis/rhel_9/` | All 352 recommendations, generated from the benchmark's workbook (20 modules, including three STIG/NIST extension modules that are not benchmark recommendations); the deprecated first-release `cis.rhel_9` package was removed |
| CIS RHEL 8 v4.0.0 | `benchmarks/cis/rhel_8/` | All 322 recommendations (17 modules) |
| CIS RHEL 10 v1.0.1 (draft) | `benchmarks/cis/rhel_10/` | A first subset: 25 checks in one module, not the whole benchmark |
| CIS Ubuntu 22.04 v3.0.0, 24.04 v2.0.1, 20.04 v3.0.0, 26.04 v1.0.0 | `benchmarks/cis/ubuntu_*/` | 22.04: all 306 recommendations; 24.04: all 332 recommendations; 26.04: all 350 recommendations; 20.04: 17 section modules with no declared total (163 distinct recommendation ids) |
| CIS Rocky Linux 8 v3.0.0, 9 v3.0.0 | `benchmarks/cis/rocky_linux_*/` | Rocky 8: all 322 recommendations; Rocky 9: all 352 recommendations |
| CIS Debian 11 (derived from the Ubuntu 20.04 benchmark v3.0.0), Debian 12 v2.0.1, Debian 13 v1.1.1 | `benchmarks/cis/debian_*/` | Debian 11: 16 section modules, no declared total (168 distinct ids); Debian 12: all 331 recommendations; Debian 13: all 350 recommendations |
| CIS Amazon Linux 2023 v1.0.0 | `benchmarks/cis/amazon_linux_2023/` | All 243 recommendations (17 modules) |
| CIS Windows Server 2022 v5.1.0 | `benchmarks/cis/windows_server_2022_modular/` | All 408 recommendations (406 evaluated, 2 Manual by attestation), member server and domain controller, Level 1/2 and Next Generation profiles |
| CIS Windows Server 2019 v5.0.0 | `benchmarks/cis/windows_server_2019_modular/` | All 400 recommendations (398 evaluated, 2 Manual by attestation), generated from the benchmark's workbook; Level 1/2 and Next Generation profiles |
| CIS Windows 10 Enterprise v5.0.0 | `benchmarks/cis/windows_10_modular/` | All 501 recommendations (499 evaluated, 2 Manual by attestation), Level 1/2, BitLocker and Next Generation profiles |
| CIS Windows 11 Enterprise v5.1.0 | `benchmarks/cis/windows_11_modular/` | All 535 recommendations (533 evaluated, 2 Manual by attestation), Level 1/2 and BitLocker profiles |
| CIS Microsoft 365 Foundations v7 (SaaS) | `benchmarks/cis/saas/m365_v7/` | 9 sections: Entra, Exchange, Defender, Purview, SharePoint, Teams, Intune, Fabric, Admin Center |
| CIS PostgreSQL 13 v1.3.0, 14 v1.3.0, 15 v1.2.0, 17 v1.1.0 (16 v1.1.0 and 18 v1.0.0 in their own directories) | `benchmarks/cis/postgresql/`, `benchmarks/cis/postgresql_16/`, `benchmarks/cis/postgresql_18/` | One module per major version; each declares its own total in its report |
| CIS network devices: Arista EOS v1.0.0, Cisco IOS v4.1.0, Cisco IOS XE 17.x v2.2.2, FortiGate 7.4.x v1.0.1, Juniper JunOS v2.1.0, OPNsense v1.0.0, Palo Alto Firewall 11 v1.2.1, pfSense v1.1.1, VyOS v1.0.1 | `benchmarks/cis/network_devices/` | One module per platform. Arista (33), IOS XE 17 (84), FortiGate (64) and Palo Alto (79) declare the benchmark's recommendation count; the Juniper module is a 9-check subset; the others declare no total |
| CIS AWS Foundations v7.1.0, Azure Foundations v7.0.0, GCP Foundation v5.0.0 | `benchmarks/cis/aws/`, `benchmarks/cis/azure/`, `benchmarks/cis/gcp/` | AWS: all 94 recommendations; Azure: all 128 recommendations; GCP: Level 1 and Level 2 modules with no declared total. `benchmarks/cis/cloud/` holds the older unversioned AWS and Azure modules |
| CIS Docker v1.9.0, Kubernetes v2.1.0, OpenShift Container Platform v2.0.0 | `benchmarks/cis/docker/`, `benchmarks/cis/kubernetes/`, `benchmarks/cis/openshift/` | Docker: all 117 recommendations; Kubernetes: all 134 recommendations; OpenShift: all 115 recommendations. `benchmarks/cis/containers/` holds the older unversioned Docker and Kubernetes modules |
| **DISA STIGs — 25 platforms** (RHEL 8/9/10, **Oracle Linux 8/9**, Windows Server 2016/2019/2022/**2025**, Windows 11, Ubuntu 20.04/22.04/24.04, Amazon Linux 2023, SLES 15, **Kubernetes (all 92 rules, V2R6)**, **RGS RKE2 (all 21 rules, V2R7)**, OpenShift 4, Crunchy Data Postgres 16, SQL Server 2016, **Oracle Database 19c**, **Oracle MySQL 8.0**, Apache 2.4, Cisco IOS-XE, vSphere 8 ESXi) | `benchmarks/stig/` | Per-rule findings with XCCDF-verified IDs; the STIG release each platform implements is in [`standards.yaml`](../standards.yaml); every rule of the two Oracle database STIGs, Kubernetes and RKE2; all CAT I on new platforms; fail-closed entrypoints; coverage-of-total stated per aggregator; **RHEL 9 V2R10**: all 445 rules written against DISA's check text, 104 of them run on a real RHEL 9.6 host, the other 341 unit-tested only with most of their fact paths not collected yet, so the key is labelled partial ([README](../benchmarks/stig/rhel_9/README.md)) |
| NIST 800-53 Rev 5 | `frameworks/federal/nist/sp_800_53/` | All 20 families; 546 controls and enhancements of the 1,014 active in the Rev 5 catalog (release 5.2.0): all 300 base controls plus 246 enhancements, each its own finding, covering every control of the 800-53B Low (149), Moderate (287) and High (370) baselines and the FedRAMP Rev 5 Low (156), Moderate (323) and High (410) baselines, plus AC-17(9) and SA-10(1) (TX-RAMP Level 2, in no NIST baseline); Privacy baseline 96 of 96. Organizational controls with no machine-checkable evidence require a signed attestation. Per-control results (pass, fail, evidence missing, not attested) and per-baseline results for 800-53B Low/Moderate/High/Privacy and FedRAMP Low/Moderate/High (evaluated, passed, not evaluated), not a baseline authorization; withdrawn controls not assessed; organization-defined parameters supplied as input |
| FISMA | `frameworks/federal/fisma/` | Three modules (system security plan, authority to operate, continuous monitoring) and an orchestrator; 8 checks, not a full FISMA assessment |
| FedRAMP Rev 5 | `frameworks/federal/fedramp/` | Partial: authorization status plus 10–12 FedRAMP Rev 5 baseline controls with FedRAMP parameter values (CA-2, CA-6, CA-7, CA-8, IR-8, PS-3, RA-2, RA-5, SC-13, SR-2; CP-7 at Moderate/High; SA-9(5) at High). Not a baseline assessment: the Rev 5 baselines select 156 (Low), 323 (Moderate) and 410 (High) controls, reported as `baseline_size` beside the evaluated `total_controls`; LI-SaaS selects the same 156 ids as Low in FedRAMP's OSCAL profile and is not evaluated separately. With benchmark results supplied, technical controls take their verdict from the benchmark-to-control crosswalk (`crosswalk/`) |
| CMMC (32 CFR Part 170): Level 1 = the 15 FAR 52.204-21(b)(1) requirements (AC.L1-b.1.i … SI.L1-b.1.xv), Level 2 = the 110 NIST SP 800-171 Rev 2 requirements (AC.L2-3.1.1 …) | `frameworks/federal/cmmc/` | Levels 1 and 2 scored per practice (15 / 110); Level 3 (24 NIST SP 800-172 requirements) not evaluated |
| ISO 27001:2022 Annex A / ISO 27002:2022 (2022 numbering, titles and attributes only) | `frameworks/management/iso27001/` | All 93 controls: 35 decided by sub-module checks, many of which read attested flags rather than observed values; 58 attested |
| SOC 2 (AICPA Trust Services Criteria 2017, points of focus 2022) | `frameworks/management/soc2/` | all 33 common criteria with per-criterion results (`control_results`: pass / fail / evidence_missing / not_attested): 10 decided from evidence (CC6.1-CC6.3, CC6.5-CC6.8, CC7.1, CC7.2, CC8.1), 23 by signed attestation (`input.soc2.attestations`); idle timeout, log retention and review interval compared with the entity's own commitments; for the optional categories in scope, all 28 criteria scored by id (A1.1-A1.3, C1.1-C1.2, PI1.1-PI1.5, P1.1-P8.1; 21 from evidence, 7 by attestation) with entity commitments for retention, recovery-test interval, breach-notice times, reconciliation interval and data-subject response time; category-module verdicts are advisory |
| PCI DSS v4.0.1 | `frameworks/financial/pci_dss/` | All 12 requirements (one roll-up per requirement; numeric parameters checked against PCI SSC public SAQ D and FAQs; superseded 6.4.1 not gating) |
| SOX ITGC | `frameworks/financial/sox/` | Sections 302, 404 and 409, management assessment, IT general controls and financial application controls: 31 scored checks in the orchestrator (`sox.main`), four unscored advisories. Facts are posted as the input document under `input.sox.<area>.<control>.<field>`; `data.sox` is read only when the input has no `sox` key, never merged, and the report states the source in `evidence_source` |
| HIPAA Administrative Simplification (45 CFR Parts 160, 162, 164 Subparts C/D/E, CFR-cited; 800-66 Rev 2 numbering) | `frameworks/privacy/hipaa/` | 246 CFR-cited requirements declared across five modules: Security Rule 68, Privacy Rule 110, Part 160 8, Part 162 43, Breach Notification Rule and HITECH 17; five topic modules (access control, audit controls, authentication, integrity, transmission security) beside them |
| GDPR (Regulation (EU) 2016/679) | `frameworks/privacy/gdpr/` | Five modules: a general compliance module, controller and processor duties, international transfers, cookies and tracking, and an aggregator; a subset of the Regulation's articles, no declared total |
| NERC-CIP (CIP-002 – CIP-015) | `frameworks/critical_infrastructure/nerc_cip/` | 14 standards |
| IEC 62443 (all parts) | `frameworks/critical_infrastructure/iec_62443/` | 51 SRs, SL 1–4, plus the four process modules (Part 2-1, 2-3, 2-4, 3-2): 55 controls in the report |
| NIST IR 7628 Rev 1 (AMI / Smart Grid) | `frameworks/critical_infrastructure/ami/` | 12 modules in three groups (NIST IR 7628 requirements, AMI device compliance, head-end); no declared total |
| DORA (Regulation (EU) 2022/2554 with RTS 2024/1774 on the ICT risk management framework) / NIS2 (Directive (EU) 2022/2555) | `frameworks/financial/dora/`, `frameworks/compliance/nis2/` | DORA: the Regulation's ICT articles plus the RTS rows, with the simplified-framework gate; NIS2: Article 20, the Article 21(2) measures and the Article 23(4) reporting steps in one module. Each module reports the number it evaluates as `total_controls` |
| NCSC CAF 4.0 | `frameworks/compliance/ncsc_caf/` | 23 contributing outcomes as the module lists them (16 technical, 7 organisational), in seven section modules; not checked against the outcome count of the published CAF 4.0 |
| Digital Sovereignty | `frameworks/sovereignty/` | 7 domains |
| **CSA CCM v4.0** | `frameworks/management/csa_ccm/` | 16 domains, 197 controls |
| **ISO/IEC 27701:2019** (**experimental, not validated**: control list compiled from public secondary sources, not checked against the purchased standard, never run on real evidence; [README](../frameworks/privacy/iso27701/README.md)) | `frameworks/privacy/iso27701/` | 108 controls: clause 5 (23), clause 6 (36), Annex A controllers (31), Annex B processors (18); 8 from system facts, 100 attested |
| **NIST SP 800-171 Rev 3** | `frameworks/federal/nist/sp_800_171/` | 17 families, all 97 requirements with their 349 statements, ids and text from NIST's CPRT export; 79 decided by facts, 18 attested; 33 withdrawn listed with reasons |
| **NIST SP 800-171A Rev 3** | `frameworks/federal/nist/sp_800_171a/` | all 422 assessment determination statements, rolled up per requirement; examine / interview / test methods carried as data |
| **NIST SP 800-171 Rev 2** | `frameworks/federal/nist/sp_800_171_r2/` | the 110 requirements DFARS 7012 and CMMC 2.0 Level 2 still assess, basic / derived classification from CPRT |
| **NISPOM (32 CFR 117)** | `frameworks/federal/nispom/` | 599 contractor obligations from the CFR text, 18 programme gates (FOCI, classified IS, SAP, SCI, RD, NNPI, NATO …) |
| **FAR 52.204-21 / -25 / -27** | `frameworks/federal/far_cyber/` | basic safeguarding (the 15 paragraph (b)(1) requirements), covered telecom (Section 889) reporting clocks, ByteDance prohibition; per-clause gates |
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
| **TSA Pipeline Security Directives** | `frameworks/critical_infrastructure/tsa_pipeline/` | SD Pipeline-2021-01G + 02G, 12 sections, 112 directive subparagraphs (34 in 01G, 78 in 02G) decided by 175 checks |
| **GLBA Safeguards Rule (16 CFR 314)** | `frameworks/financial/glba/` | All §314.4 elements + §314.5 breach notification (2024), small-institution exemption modeled; 34 checks |
| **CISA CPG 2.0 (Oct 2025)** | `frameworks/federal/cisa_cpg/` | All 34 goals, six CSF-2.0 functions incl. GOVERN, per-function rollup |
| **ISO/IEC 42001:2023 (AIMS)** | `governance/iso_42001/` | Clauses 4–10 + Annex A groups — completes the AI trio with EU AI Act + NIST AI RMF |
| **ITAR (22 CFR 120–130)** | `frameworks/regulatory/itar/` | Data-safeguarding slice: deemed exports, §120.54 encryption carve-out, DDTC hygiene — legal/licensing explicitly scoped out |
| **COBIT 2019** | `frameworks/management/cobit/` | Governance-system attestation across EDM/APO/BAI/DSS/MEA — maturity assessment explicitly disclaimed |
| **CISA SCuBA M365** | `benchmarks/scuba/m365/` | All 109 active policies of the ScubaGear v2.0.0 baselines across 7 products (Entra ID, EXO, Power BI, Power Platform, Security Suite, SharePoint/OneDrive, Teams); SHALL/SHOULD criticality reported; BOD 25-01 |
| **CIS Amazon EKS v2.0.0** | `benchmarks/cis/eks/` | All 47 recommendations (29 Automated from evidence, 18 Manual by attestation) |
| **CIS Azure AKS v2.1.0**, **AKS Automatic v1.0.0** | `benchmarks/cis/aks/`, `benchmarks/cis/aks_automatic/` | AKS: all 50 recommendations (30 decided from collected facts, 20 by attestation), Level 1 and Level 2 profiles; AKS Automatic: all 33 recommendations |
| **CIS Google GKE v1.9.0** | `benchmarks/cis/gke/` | 40 controls (partial cover of the official benchmark — stated in header) |
| **NSA/CISA Kubernetes Hardening v1.2** | `benchmarks/nsa_cisa/kubernetes/` | 43 controls across the guide's 5 sections |
| **SAP Security Baseline Template v2.6 (ABAP)** | `benchmarks/sap/abap/` | Registry of all 355 ABAP checks SAP publishes (SAP-samples, Apache-2.0); 138 decided from host facts (profile, transport and kernel parameters, gateway and message-server ACL files), the rest listed not-assessable with the store named; projections onto the Baseline requirements, the DSAG S/4HANA audit guide sections and NIST CSF 2.0 |
| **Kubernetes Pod Security Standards** | `benchmarks/pss/kubernetes/` | 12 baseline + 6 restricted controls, evaluated against an actual Pod manifest |
| **FERPA (34 CFR Part 99)** | `frameworks/privacy/ferpa/` | 32 controls: notification, access/amendment, consent, exception conditions, directory info, disclosure recordkeeping |
| **COPPA (16 CFR Part 312, 2025 amendments)** | `frameworks/privacy/coppa/` | 21 controls incl. separate third-party-disclosure consent, retention policy, written infosec program |
| **CIS Controls v8.1** | `frameworks/management/cis_controls_v8/` | 18 Critical Security Controls, 153 safeguards, cumulative IG1 ⊆ IG2 ⊆ IG3 scoring — distinct from the CIS *Benchmarks* above |
| **Zero Trust — CISA ZTMM v2.0 + NIST SP 800-207** | `frameworks/federal/zero_trust/` | 83 criteria across the 5 pillars + 3 cross-cutting capabilities |
| **PQC Readiness (FIPS 203/204/205, EO 14412, CNSA 2.0) + NIST CSWP 39-upd1 crypto agility** | `frameworks/federal/pqc/` | 67 CSWP 39 practice rows (June 2026 update, implementer and cloud gates) beside 15 profile-gated controls (general/federal/nss) + data-driven classification of every row of a required, non-empty crypto inventory as quantum-vulnerable, post-quantum (FIPS 203/204/205, SP 800-208, pre-standard Kyber/Dilithium/SPHINCS+, pending FN-DSA/HQC), hybrid, identifiable-but-not-NIST (sntrup761 hybrid, ChaCha20, UMAC, Camellia: reported in general, a finding under federal/nss per FIPS 140-3 / CNSA 2.0), symmetric/hash or unrecognised (unrecognised, missing and empty inventories are findings; IR 8547 deprecation, SP 800-131A undersized keys, 112-bit legacy and SHA-1 status); report carries total_controls/failed_controls per control (13/18/22 by profile) |
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
| **BSI C5:2026** | `frameworks/regional/bsi_c5/` | All 168 criteria in 17 subject areas, under BSI's ids, incl. Portability/Interoperability (export + confirmed deletion) and Government Investigation Requests (INQ); binding for periods from 2027-06-01 |
| **ISO/IEC 42005:2025 (AI impact assessment)** | `governance/iso_42005/` | 22 attestation checks across the AIIA process (Clause 5) and per-system records (Clause 6), wired to the ISO 42001 AIMS integration |
| **OWASP LLM Top 10 (2026)** | `governance/owasp_llm/` | 30 controls (3 per risk, LLM01–LLM10:2026) with a MITRE ATLAS mitigation crosswalk (atlas-data v2026.10) |
| **OWASP ASVS 5.0.0** | `governance/owasp_asvs/` | One result per requirement of the declared level: Level 1 70, Level 2 253, Level 3 345 requirements (17 chapters, 80 sections; levels are cumulative). Each requirement is a verifier's attested result keyed by its id (`V1.2.3`), only boolean `true` passes; a requirement may be marked not applicable with a written reason. Ids, chapter and section numbers and levels only, no requirement text (CC BY-SA 4.0, attribution in NOTICE); a missing or unknown level assesses Level 3 |
| **FedRAMP 20x KSI** | `frameworks/federal/fedramp_20x/` | All 46 Key Security Indicators, Class B/C profiles, generated from the Consolidated Rules datafile; rev5 module retained for existing/High |
| **GovRAMP (formerly StateRAMP)** | `frameworks/federal/govramp/` | Per-control results for the baseline of the declared impact level and verified status: Low 153, Moderate 319, High 406 controls (Authorized and Provisionally Authorized); Ready 29 / 80 / 90; Core 60 (Moderate only). The control lists are GovRAMP's own Controls Matrices, not FedRAMP's 156 / 323 / 410 (GovRAMP does not select IA-2(12), IA-8(1), SA-4(10), nor CA-8(2) at Moderate and High). Each control takes its result from the NIST SP 800-53 module (with that module's parameter values; controls where the GovRAMP Federal Overlay differs from FedRAMP are flagged on their rows); status attestations: PMO or 3PAO assessment, sponsor approval, 12-month validity, quarterly (Core) or monthly continuous monitoring. Benchmark results go through the same crosswalk as FedRAMP. Not a GovRAMP verification |
| **TX-RAMP (Texas Risk and Authorization Management Program)** | `frameworks/federal/txramp/` | Per-control results for the declared certification level: Level 1 117 controls, Level 2 223 (the publisher's TX-RAMP Control Baselines 2.0, counts as in Program Manual 4.0 Appendix A). Each control takes its result from the NIST SP 800-53 module (with that module's parameter values; AC-17(9) and SA-10(1), which only Level 2 selects, were added to that module for this). Attestations: Acknowledgment and Inventory, assessment questionnaire, Security Plan Workbook, POA&M, three-year validity, annual (Level 1) or quarterly (Level 2) vulnerability reports, 48-hour breach and 30-day significant-change notices. An accepted FedRAMP or GovRAMP equivalence (explicit boolean facts, the external status earning at least the declared level) replaces the assessment and shows as `basis: "equivalence"` on every row and in the report. Provisional is a finding, never a pass. Not a TX-RAMP certification |
| **UK MoD DCC — DEF STAN 05-138 Issue 4** | `frameworks/regional/dcc/` | All 148 controls, 4 Cyber Risk Profiles (L0 Basic → L3 Expert) with exact per-control level sets incl. the non-cumulative supersession pairs |
| **SAE AS9100D (IAQG 9100:2016) aerospace QMS** | `frameworks/management/as9100d/` | 71 clause rows of clauses 4–10 in seven clause packages incl. every aerospace addition (8.1.1–8.1.4, 8.3.4.1 V&V testing, 8.4 flow-down, 8.5.1.1–8.5.1.3, 8.5.6, 8.7, 9.1.2 on-time delivery/conformity KPIs + customer feedback, 10.2 root cause + human factors); 18 decided from collected evidence (malformed, blank or empty evidence never passes), 53 attested; clause numbers and titles only — no standard text |

## CIS Benchmark coverage

| Platform | Path | Controls |
|----------|------|----------|
| **RHEL 9** | `benchmarks/cis/rhel_9/` | v3.0.0, all 352 recommendations (20 modules) |
| RHEL 8 | `benchmarks/cis/rhel_8/` | v4.0.0, all 322 recommendations |
| Ubuntu 22.04 | `benchmarks/cis/ubuntu_22_04/` | v3.0.0, all 306 recommendations |
| Ubuntu 24.04 | `benchmarks/cis/ubuntu_24_04/` | v2.0.1, all 332 recommendations |
| Ubuntu 20.04 | `benchmarks/cis/ubuntu_20_04/` | v3.0.0, 17 section modules, no declared total |
| Debian 11 | `benchmarks/cis/debian_11/` | Derived from the Ubuntu 20.04 benchmark v3.0.0; 16 section modules, no declared total |
| Rocky Linux 8 | `benchmarks/cis/rocky_linux_8/` | v3.0.0, all 322 recommendations |
| Rocky Linux 9 | `benchmarks/cis/rocky_linux_9/` | v3.0.0, all 352 recommendations |
| Amazon Linux 2023 | `benchmarks/cis/amazon_linux_2023/` | v1.0.0, all 243 recommendations |
| Windows Server 2022 | `benchmarks/cis/windows_server_2022_modular/` | v5.1.0, all 408 recommendations |
| Windows Server 2019 | `benchmarks/cis/windows_server_2019_modular/` | v5.0.0, all 400 recommendations |
| AWS / Azure / GCP | `benchmarks/cis/aws/`, `benchmarks/cis/azure/`, `benchmarks/cis/gcp/` | AWS v7.1.0 (all 94 recommendations), Azure v7.0.0 (all 128 recommendations), GCP v5.0.0 (no declared total) |
| Docker / Kubernetes / OpenShift | `benchmarks/cis/docker/`, `benchmarks/cis/kubernetes/`, `benchmarks/cis/openshift/` | Docker v1.9.0 (all 117 recommendations), Kubernetes v2.1.0 (all 134 recommendations), OpenShift v2.0.0 (all 115 recommendations) |
| MySQL / Oracle / PostgreSQL | `benchmarks/cis/mysql/`, `benchmarks/cis/oracle/`, `benchmarks/cis/postgresql/` | MySQL 8.0 v1.2.0; Oracle Database 19c v2.0.0, 23ai v1.0.0, 26ai v1.0.0; PostgreSQL 13, 14, 15 and 17 (16 and 18 in `postgresql_16/`, `postgresql_18/`) |
| Cisco / Juniper / Palo Alto / Fortinet / Arista / OPNsense / pfSense / VyOS | `benchmarks/cis/network_devices/` | One module per platform; versions in the table above |

## IEC 62443 Coverage

Modules for IEC 62443 Industrial Automation and Control Systems (IACS) Security — all 51 System Requirements (SRs) from Part 3-3 plus Part 2 management requirements.

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
| `iec_62443_main.rego` | All | Main orchestrator — aggregates all parts | 51 SRs; `total_controls` 55 with the four process modules |

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
orchestrator, covering 112 directive subparagraphs (34 in 01G, 78 in 02G; each
section module declares its own figure as `requirements_evaluated`). The 175
checks that decide them are reported as `total_checks` / `total_controls`; one
subparagraph can take several checks.

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

Modules for CIP-002 through CIP-015 (14 standards, one module each, plus an orchestrator) in `frameworks/critical_infrastructure/nerc_cip/`. The version of each standard the modules implement is recorded in [`standards.yaml`](../standards.yaml).

**OPA endpoint:** `POST /v1/data/nerc_cip_main`

**Data sources:** Every `input.*` field used by the 14 CIP policies is documented in [`frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md`](../frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md) — each entry lists the real-world source system (GRC, CMDB, LMS, PACS, SIEM, INSM platform, vulnerability scanner, etc.), the collection method (Ansible module or REST endpoint), and whether the integration is currently live or stubbed.
