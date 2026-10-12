# Bank Negara Malaysia — Risk Management in Technology (RMiT) policy document
# BNM/RH/PD 028-98, issued 25 September 2026 (supersedes the June 2023 RMiT).
#
# Source: bnm.gov.my/documents/20124/938039/pd-rmit-sep26.pdf. Applies to
# licensed banks, investment banks, Islamic banks, insurers and takaful
# operators, prescribed development financial institutions, approved e-money
# issuers, designated payment system operators, registered merchant acquirers
# and intermediary remittance institutions (Part A §2).
#
# Shape: one control per "S" (Standard — mandatory) paragraph of Part B,
# sections 8–15. "G" (Guidance) paragraphs are not controls and are not
# here. Attested from the institution's evidence as
# input.bnm_rmit.standards["10.55"] == true. Paragraphs that apply only when
# the institution does the thing (cloud 10.50/10.52, third-party service
# providers 10.46–10.49 and 10.12, NCII designation 11.4, digital services
# 12.x) are gated by flags that MUST be declared true or false.
#
# Dated obligations carried in the report: early-warning and stand-in
# processing for key digital services by 30 September 2027 (10.31);
# quarterly availability disclosure from 15 October 2027 (10.35(e)).
#
# Fail-closed: non-true attestation, unknown id, malformed container or an
# undeclared flag are violations. Per-section gap report.
#
# Query: POST /v1/data/bnm_rmit/main/compliance_report

# METADATA
# title: "BNM Risk Management in Technology (RMiT), September 2026 — Part B standards"
# custom:
#   class: compliance
#   framework: bnm_rmit
#   source: bnm
#   domains: [financial, malaysia]
#   coverage:
#     checks: 107
#     cited: 103
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.2
package bnm_rmit.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"8": "§8 Governance",
	"9": "§9 Technology Risk Management",
	"10": "§10 Technology Operations Management",
	"11": "§11 Cybersecurity Management",
	"12": "§12 Digital Services",
	"13": "§13 Technology Audits",
	"14": "§14 External Party Assurance",
	"15": "§15 Security Awareness and Education",
}

_flags := {
	"uses_cloud_services": "RMiT 10.50/10.52 — whether the institution uses cloud services must be declared true or false",
	"engages_third_party_service_providers": "RMiT 10.12, 10.46–10.49 — whether third-party service providers are engaged for technology functions must be declared true or false",
	"designated_ncii_entity": "RMiT 11.4 — whether the institution is designated a National Critical Information Infrastructure entity under the Cyber Security Act 2024 must be declared true or false",
	"provides_digital_services": "RMiT §12 — whether the institution provides digital services or delivery channels to customers must be declared true or false",
}

standards := {
	# ── 8 Governance ─────────────────────────────────────────────────────
	"8.1": {"s": "8", "gate": "", "text": "The board establishes and approves a technology risk appetite aligned with the institution's risk appetite: risk tolerances for technology events, a risk owner and residual-risk acceptance criteria and authority, key risk indicators, sufficient resources, and regular review"},
	"8.2": {"s": "8", "gate": "", "text": "The board approves and reviews IT and cybersecurity strategic plans of at least three years, endorses and oversees the TRMF and CRF, requires robust risk assessments for critical systems and emerging technology, has IT frameworks and policies reviewed at least every three years, and ensures the framework supports technology applications to the Bank"},
	"8.3": {"s": "8", "gate": "", "text": "A board-level committee with at least one member with technology experience and competencies oversees technology matters"},
	"8.4": {"s": "8", "gate": "", "text": "The board obtains regular updates on technology and cyber threats, allocates time to discuss cyber risks including extreme-incident impacts with external expert input where appropriate, and participates in cybersecurity awareness and training"},
	"8.5": {"s": "8", "gate": "", "text": "The board audit committee ensures the effectiveness of the internal technology audit function: competent audit staff, appropriate scope, procedures and frequency, and prompt closure of corrective actions"},
	"8.6": {"s": "8", "gate": "", "text": "Senior management implements the TRMF and CRF as policies and procedures consistent with risk appetite, ensures the crisis management plan escalates recovery considering duration, customers affected and transactions impacted, and reports KPIs and risk controls to the board regularly"},
	"8.7": {"s": "8", "gate": "", "text": "A cross-functional committee of cyber, technology and business senior management oversees the strategic technology plan and policies, updates the board on key technology matters, and approves policy deviations after risk assessment, reporting material deviations to the board"},
	# ── 9 Technology Risk Management ─────────────────────────────────────
	"9.1": {"s": "9", "gate": "", "text": "The technology risk management framework (TRMF) is an integral part of the enterprise risk management framework"},
	"9.2": {"s": "9", "gate": "", "text": "The TRMF defines technology risk, assigns responsibilities with governance and reporting, identifies risks including emerging technology, classifies all information assets by criticality, sets measurement and assessment methods, controls and mitigations, continuous monitoring, an accurate risk profile, key resources and interdependencies including critical third parties and their connected parties, scenario analysis for severe conditions, and incident management to restore services to a secure and stable state"},
	"9.3": {"s": "9", "gate": "", "text": "An independent enterprise-wide technology risk management function implements the TRMF and CRF, advises on critical technology projects and escalates critical issues, and gives independent views on third-party assessments"},
	"9.4": {"s": "9", "gate": "", "text": "A designated CISO with sufficient authority, independence and resources is independent of day-to-day operations, apprises the board and senior management of current and emerging technology risks, has the requisite technical, audit, governance, risk, strategic and third-party-risk skills, and is appropriately certified"},
	"9.5": {"s": "9", "gate": "", "text": "The CISO formulates policies implementing the TRMF and CRF, enforces compliance with them and with technology regulatory requirements, and advises senior management on technology risk and security matters"},
	# ── 10 Technology Operations Management ──────────────────────────────
	"10.1": {"s": "10", "gate": "", "text": "Technology project governance is commensurate with risk and complexity: oversight roles, authority and reporting structures, and risk assessments throughout the project life cycle"},
	"10.2": {"s": "10", "gate": "", "text": "Project risk assessments address resource adequacy including vendors and concurrent projects, system complexity and integration, security controls through the life cycle, completeness of user requirements, robustness of testing, deployment and fallback strategies, and disaster recovery readiness"},
	"10.3": {"s": "10", "gate": "", "text": "The board and senior management receive and review timely reports on significant project risks throughout implementation"},
	"10.4": {"s": "10", "gate": "", "text": "An enterprise technology architecture framework gives a comprehensive view of technology and baseline components, a technical design showing infrastructure, interconnectivity, dependencies and security controls (to find single points of failure), mappings to business functions, units, applications and data, principles for network and security design, and longer-term priorities"},
	"10.5": {"s": "10", "gate": "", "text": "An SDLC methodology covers requirement, design, development, testing, deployment, change management, maintenance and decommissioning, integrated with enterprise architecture, risk management and security principles including segregation of duties"},
	"10.6": {"s": "10", "gate": "", "text": "Rapid development (DevOps) meets enterprise security, governance and compliance requirements, with automated IT security compliance review and automated vulnerability discovery and testing before release"},
	"10.7": {"s": "10", "gate": "", "text": "Production is physically segregated from development and testing; on cloud, these environments do not run on the same virtual host"},
	"10.8": {"s": "10", "gate": "", "text": "Rigorous system testing precedes deployment, verifying user requirements and robustness; sensitive test data requires authorisation and disclosure safeguards"},
	"10.10": {"s": "10", "gate": "", "text": "Changes to source code of critical systems undergo source code review for security and recognised coding practices before introduction"},
	"10.11": {"s": "10", "gate": "", "text": "System changes are independently reviewed and approved; contingency plans for unsuccessful material changes are established and tested"},
	"10.12": {"s": "10", "gate": "engages_third_party_service_providers", "text": "Contracts for critical systems developed or maintained by third parties require sufficient notice of impacting changes, demonstrated secure-by-design development, and continued accessibility of source code for business continuity"},
	"10.13": {"s": "10", "gate": "", "text": "Decommissioning of critical systems minimises customer and business impact, with contingency plans established and tested for unsuccessful decommissioning"},
	"10.16": {"s": "10", "gate": "", "text": "Robust policies identify and reduce shadow IT risks"},
	"10.17": {"s": "10", "gate": "", "text": "No system or digital service runs with known security vulnerabilities, on outdated platforms or end-of-life technology: a current security hardening baseline, timely patching, remedial plans for approaching EOL, and management-approved, risk-assessed, annually reviewed exceptions with phase-out timelines"},
	"10.18": {"s": "10", "gate": "", "text": "A patch and EOL management framework covers asset identification and risk assessment, deployment criteria, priority and turnaround by severity, compatibility testing, an end-to-end approval, testing, monitoring and tracking workflow, and end-user awareness"},
	"10.19": {"s": "10", "gate": "", "text": "The effectiveness and security of technology in use is monitored against disruptive developments (e.g. quantum computing): board advice on impact, a long-term strategy with competent resources, and a migration roadmap"},
	"10.20": {"s": "10", "gate": "", "text": "A cryptography policy requires industry-standard algorithms, message authentication, hashes, signatures and random number generation; secure key life-cycle management; at least annual review of standards and algorithms for critical and customer-facing systems; an asset inventory of cryptographic tools and algorithms with rationale and mappings; and tested compromise-recovery plans"},
	"10.21": {"s": "10", "gate": "", "text": "Cryptographic controls are evaluated with due diligence; the institution retains ownership and control of encryption keys (or with an independent custodian) except for non-critical systems without customer information, manages externally generated keys to industry standards, weighs reliance on third-party assessments against risk appetite, and considers resource impact and reduced traffic visibility"},
	"10.22": {"s": "10", "gate": "", "text": "Cryptographic protocols for secret and public keys follow recognised international standards and are tested; secret and private key storage and computation occur in a protected environment (HSM, TEE or equivalent) commensurate with risk"},
	"10.23": {"s": "10", "gate": "", "text": "Public keys are stored in certificates from a Certificate Authority (recognised CAs for customers); authentication and signature protocols protect private keys so their use is legally binding; issuance and renewal follow industry and legal specifications"},
	"10.24": {"s": "10", "gate": "", "text": "Resilience and availability objectives of data centres are specified to support business recovery objectives"},
	"10.25": {"s": "10", "gate": "", "text": "Data centres have redundant capacity components and multiple distribution paths with no single point of failure"},
	"10.26": {"s": "10", "gate": "", "text": "Critical systems are hosted in dedicated, physically secured production data centre space not in a disaster-prone area, with no single point of failure in hardware, electrical, thermal and infrastructure design, and with adequate maintenance and continuous monitoring with timely alerts"},
	"10.27": {"s": "10", "gate": "", "text": "Data centre operations have control procedures including automated batch management, production change procedures, error handling and exception management"},
	"10.28": {"s": "10", "gate": "", "text": "Incompatible activities in data centre operations are segregated (development from operations); necessary vendor or programmer access to production is authorised and monitored"},
	"10.29": {"s": "10", "gate": "", "text": "System capacity is planned and managed for peak periods, growth plans and architecture changes"},
	"10.30": {"s": "10", "gate": "", "text": "Real-time monitoring tracks capacity utilisation and performance of key processes and services with actionable alerts; scope, metrics and thresholds are updated periodically"},
	"10.31": {"s": "10", "gate": "provides_digital_services", "text": "Key digital services and delivery channels are made resilient: early-warning mechanisms by 30 September 2027 (detect failed transactions and measure availability, monitor affected customers and volumes, escalate immediately when 5% or more of expected daily customers or transactions are affected), regular reviews of vulnerable interdependencies, and stand-in processing arrangements by 30 September 2027 prioritised for the least substitutable channels with customers informed of terms, risks and responsibilities"},
	"10.32": {"s": "10", "gate": "", "text": "Critical systems with an expectation of immediate customer or counterparty service are designed for high availability: cumulative unplanned downtime at the customer interface of not more than 4 hours on a rolling 12 months and a maximum tolerable downtime of 120 minutes per incident"},
	"10.34": {"s": "10", "gate": "", "text": "Diversity in technology is prioritised so critical systems infrastructure is not excessively exposed to similar technology risks"},
	"10.35": {"s": "10", "gate": "provides_digital_services", "text": "During digital service interruptions the institution escalates and decides promptly to resume via alternatives within the 10.32 timeframe, defines accountabilities and third-party arrangements for degradation, runs a communication plan with immediate customer notice, feedback handling, frequent updates and alternatives, offers a convenient availability-status check (e.g. real-time status on the website), and discloses its quarterly availability track record within 15 calendar days of quarter-end from 15 October 2027"},
	"10.36": {"s": "10", "gate": "", "text": "A reliable, scalable and secure enterprise network supports business activities and growth plans"},
	"10.37": {"s": "10", "gate": "", "text": "Network services for critical systems are reliable with no single point of failure against network faults and cyber threats"},
	"10.39": {"s": "10", "gate": "", "text": "Real-time bandwidth monitoring and network resilience metrics flag over-utilisation and disruptions from congestion and faults, including traffic analysis for trends and anomalies"},
	"10.40": {"s": "10", "gate": "", "text": "Network services supporting critical systems ensure confidentiality, integrity and availability of data"},
	"10.41": {"s": "10", "gate": "", "text": "A maintained network design blueprint identifies all internal and external interfaces and connectivity, physical and logical, with segmentation"},
	"10.42": {"s": "10", "gate": "", "text": "Sufficient network device logs are retained for investigation and forensics for at least three years"},
	"10.43": {"s": "10", "gate": "", "text": "Safeguards (e.g. logical network segmentation from other group entities) minimise the risk of a compromise in one entity affecting others in the group"},
	"10.44": {"s": "10", "gate": "", "text": "A backup strategy and procedures manage the backup life cycle, keep adequate copies of critical data, OS, programs, utilities, master and transaction files and event logs, store media in an environmentally secure access-controlled site, secure removable media per Appendix 1, test restoration periodically with prompt root-cause remediation, and have an independent risk assessment of end-to-end backup storage and delivery"},
	"10.45": {"s": "10", "gate": "", "text": "A tamper-proof backup arrangement and an isolated recovery environment enable resumption of critical banking and payment services within tolerance after destructive cyber attacks such as ransomware"},
	"10.46": {"s": "10", "gate": "engages_third_party_service_providers", "text": "The board and senior management exercise effective oversight of third-party service providers for critical technology functions; the institution remains accountable for all resulting risks"},
	"10.47": {"s": "10", "gate": "engages_third_party_service_providers", "text": "Due diligence on third-party service providers is conducted before on-boarding and throughout the engagement, considering at least the Appendix 8 risks"},
	"10.48": {"s": "10", "gate": "engages_third_party_service_providers", "text": "Service level agreements with third-party providers include regulator and institution access rights to records and decision minutes, prior notice of substantial sub-contracting, a secrecy undertaking surviving the engagement, disaster recovery and backup, uptime objectives, exit and termination continuity with timely data recovery, prompt disclosure of disruptions and cyber incidents in the provider's or sub-contractors' environment, compliance with international standards and staff certification, and participation in security awareness programmes"},
	"10.49": {"s": "10", "gate": "engages_third_party_service_providers", "text": "A roadmap achieves continuous monitoring of third-party cybersecurity posture: measuring the infrastructure footprint and customer information accessible to third parties, leading product-specific controls, incident response protocols with providers for software-update vulnerabilities, a priority set of controls with frequent assurance assertions, higher-frequency monitoring of disclosed incidents, automated metric testing, and response to breached thresholds"},
	"10.50": {"s": "10", "gate": "uses_cloud_services", "text": "A comprehensive risk assessment precedes cloud adoption, addressing deployment model sophistication, migration, infrastructure location and geopolitical and legal risk, multi-tenancy and data co-mingling, lock-in and portability, security configurability, exposure via the provider, termination and data recovery, demarcation of responsibilities and liability, and continuing regulatory and standards compliance"},
	"10.52": {"s": "10", "gate": "uses_cloud_services", "text": "Customer, counterparty and proprietary data on cloud services are safeguarded against unauthorised disclosure and access, with ownership, control and management of all such data and services retained, including cryptographic key management"},
	"10.53": {"s": "10", "gate": "", "text": "An access control policy governs identification, authentication and authorisation of all users to IT assets and data, with granularity commensurate with unauthorised-access risk"},
	"10.54": {"s": "10", "gate": "", "text": "Access control adheres to deny-all by default, least privilege on a need-to-have basis, time-bound access, segregation of incompatible functions (development vs operations, security vs system administration, network operation vs network security, IT operations), dual-authorisation criteria, and authentication by criticality: stronger for critical activities and remote access, robust identity verification at provisioning, and credentials uniquely linked to one user"},
	"10.55": {"s": "10", "gate": "", "text": "Multi-factor authentication resistant to social engineering, combining two or more of knowledge, inherent and possession factors, authenticates user access to critical systems"},
	"10.56": {"s": "10", "gate": "", "text": "A user access matrix outlines access rights, roles or profiles and the authorising and approving authorities, reviewed and updated periodically"},
	"10.57": {"s": "10", "gate": "", "text": "Access controls to enterprise-wide systems are managed and monitored, anomalies are flagged for prompt investigation, and user activities in critical systems are logged, retained at least three years and reviewed in a timely manner"},
	# ── 11 Cybersecurity Management ──────────────────────────────────────
	"11.1": {"s": "11", "gate": "", "text": "Cyber risk management has an enterprise-wide focus reflecting the collective responsibility of business and technology lines"},
	"11.2": {"s": "11", "gate": "", "text": "A cyber resilience framework (CRF) articulates governance, resilience objectives and risk tolerance against the evolving threat environment, targets operational resilience against extreme but plausible attacks, and supports identification, protection, detection, response and recovery of on-premises and third-party-hosted systems and data"},
	"11.3": {"s": "11", "gate": "", "text": "The CRF includes institutional understanding of cyber risk context and posture; identification, classification and prioritisation of critical systems, information, assets and interconnectivity; threats, vulnerabilities and countermeasures; layered defence with zero-trust, micro-segmentation and security by design; continuous surveillance for timely detection; incident handling procedures and a crisis response playbook; secure information sharing with other institutions and FMIs; a centralised automated technology asset inventory; and a cyber risk management function escalating high-risk threats to senior management and the board"},
	"11.4": {"s": "11", "gate": "designated_ncii_entity", "text": "As a designated National Critical Information Infrastructure entity, the institution complies with the Cyber Security Act 2024 requirements, guidelines and NACSA directives and standards"},
	"11.5": {"s": "11", "gate": "", "text": "The Appendix 5 control measures are adopted to enhance resilience to cyber attacks"},
	"11.6": {"s": "11", "gate": "", "text": "A realistic red-team simulation attack on the infrastructure is conducted at least once every three years"},
	"11.8": {"s": "11", "gate": "", "text": "Cybersecurity operations have clear responsibilities with mitigating measures for each phase of the attack life cycle: reconnaissance, weaponisation, delivery, exploitation, installation, command and control, exfiltration"},
	"11.9": {"s": "11", "gate": "", "text": "Continuous proactive monitoring and timely detection of anomalies via a Security Operations Centre with competent resources and tools, covering all critical systems and supporting infrastructure, with regular vulnerability assessment and penetration testing per Appendix 5"},
	"11.10": {"s": "11", "gate": "", "text": "A cyber threat intelligence process collects, analyses and evaluates threat information including data breaches and misleading information about the institution on the Internet, social media and dark web"},
	"11.11": {"s": "11", "gate": "", "text": "Flagged anomalous activities are investigated and responded to according to their complexity"},
	"11.12": {"s": "11", "gate": "", "text": "Cyber crisis management policies and procedures incorporate attack scenarios and responses into the crisis management plan, escalation, BCP and DR, with a communication plan for shareholders, regulators, customers and employees"},
	"11.13": {"s": "11", "gate": "", "text": "A Cyber Incident Response Plan covers preparedness (CERT governance, reporting, roles, invocation and escalation), detection and analysis (points of compromise, damage assessment including threat-actor claims, evidence preservation), containment and eradication, recovery with contingency strategies, and post-incident review with lessons learned"},
	"11.14": {"s": "11", "gate": "", "text": "CERT members are conversant with the incident response plan and procedures and remain contactable at all times"},
	"11.15": {"s": "11", "gate": "", "text": "A secure, reliable out-of-band communication infrastructure for internal and external stakeholders operates if primary communications are compromised"},
	"11.16": {"s": "11", "gate": "", "text": "An annual cyber drill tests the CIRP and out-of-band communications on current and emerging scenarios with the board, senior management and relevant third parties, covering escalation, communication and decision-making at different impact levels and the readiness of CERT and third parties; results are reported to the board"},
	"11.17": {"s": "11", "gate": "", "text": "Loss provision arrangements are reviewed against scenario analysis of extreme cyber events; any cyber insurance adequately covers the events and liabilities, its warranties and obligations are reflected in crisis procedures without unintended exclusions, and insurer obligations do not impair acting in the institution's and customers' best interests"},
	"11.18": {"s": "11", "gate": "", "text": "Cyber incidents are notified to the Bank per the Operational Risk Reporting, Business Continuity Management and Merchant Acquiring Services policy documents and any other specified policy"},
	"11.19": {"s": "11", "gate": "", "text": "Cyber threat intelligence is shared with the industry on a timely basis via the Bank's, industry's or law enforcement platforms, with resources allocated to industry-wide intelligence initiatives"},
	"11.20": {"s": "11", "gate": "", "text": "The institution collaborates and cooperates closely with relevant stakeholders and authorities in combating cyber threats"},
	# ── 12 Digital Services ──────────────────────────────────────────────
	"12.1": {"s": "12", "gate": "provides_digital_services", "text": "The CRF implements robust security controls for digital services: minimum controls per delivery channel assessed regularly (Appendices 2, 3, 4, 11), proper user and device authentication and transaction authorisation against impersonation and fraud (Appendix 3), and strong physical and logical controls"},
	"12.2": {"s": "12", "gate": "provides_digital_services", "text": "Where the §12 digital services controls are not yet implemented, documented explanation shows alternatives are at least as effective and the institution assumes liability for fraud arising from the gap"},
	"12.3": {"s": "12", "gate": "provides_digital_services", "text": "The CRF extends to customers' mobile devices and access points: layered controls protecting the mobile application and its data, continuous surveillance of exploitation with swift control upgrades, incident handling to help customers contain damage, coordinated rapid countermeasure upgrades across functions, senior management review with escalation thresholds, and board apprisal of outcomes"},
	"12.4": {"s": "12", "gate": "provides_digital_services", "text": "Fraud detection capabilities and rules are updated promptly on new modus operandi, supported by risk analytics and continuous upgrade per Appendix 11 Fraud Detection Standards"},
	"12.5": {"s": "12", "gate": "provides_digital_services", "text": "Digital service delivery risks are mitigated: secure communication channels with compensating controls for phishing-prone channels (no clickable links in SMS), advance customer information on new controls, and practical ways for customers to verify calls from the institution or its outsourced providers"},
	"12.6": {"s": "12", "gate": "provides_digital_services", "text": "Customers can manage activation and de-activation of payment cards for card-not-present and overseas transactions, without diminishing the institution's liabilities and duty of care"},
	"12.7": {"s": "12", "gate": "provides_digital_services", "text": "Customer awareness programmes are continuously reviewed for effectiveness: timely practical fraud-identification information including new modus operandi, clear explanation of security measures and how to verify genuine sites and apps, real-time alerts when measures are absent, and measures such as interactive simulations"},
	"12.8": {"s": "12", "gate": "provides_digital_services", "text": "Customers can conveniently report, suspend and re-activate accounts on suspected fraud: a secure self-service kill switch, an adequately resourced contact centre, and restoration of access within a reasonable time after validation"},
	"12.9": {"s": "12", "gate": "provides_digital_services", "text": "Incidents involving potential fraud or compromised customer data trigger heightened monitoring of affected accounts, notification of affected customers with mitigation information, and revocation and re-issue of affected credentials or payment instruments where exploitation risk exists"},
	# ── 13 Technology Audits ─────────────────────────────────────────────
	"13.1": {"s": "13", "gate": "", "text": "Scope, frequency and intensity of technology audits are commensurate with the complexity, sophistication and criticality of systems and applications"},
	"13.2": {"s": "13", "gate": "", "text": "The technology audit plan is reviewed annually with appropriate frequency and coverage of critical services, third-party providers, material external interfaces, delayed or terminated critical projects, and post-implementation reviews of new or material enhancements"},
	"13.3": {"s": "13", "gate": "", "text": "Internal audit has dedicated, specialised, professionally certified technology audit resources conversant with the institution's systems and delivery channels"},
	# ── 14 External Party Assurance ──────────────────────────────────────
	"14.1": {"s": "14", "gate": "", "text": "A technically competent external provider performs a production data centre resilience and risk assessment (DCRA) at least every three years or on material change, covering paragraphs 10.24–10.28; reliance on third-party reports for provider-managed data centres is consistent with risk appetite and meets the same requirements; the board-level committee deliberates the outcome"},
	"14.2": {"s": "14", "gate": "", "text": "A technically competent external provider performs network resilience and risk assessments (NRA) at least every three years or on material network design change, covering paragraphs 10.36–10.43; the board-level committee deliberates the outcome"},
	# ── 15 Security Awareness and Education ──────────────────────────────
	"15.1": {"s": "15", "gate": "", "text": "Regular technology and cybersecurity awareness education for all staff is conducted at least annually, reflects the evolving threat landscape, is measured for effectiveness, and includes third-party providers where appropriate"},
	"15.2": {"s": "15", "gate": "", "text": "Staff in technology operations, cybersecurity and risk management receive adequate continuous training and are competent and suitably certified"},
	"15.3": {"s": "15", "gate": "", "text": "Board members receive regular training and information on technology developments to discharge their oversight role"},
}

dated_obligations := {
	"10.31_early_warning_and_stand_in_processing": "2027-09-30",
	"10.35e_quarterly_availability_disclosure_from": "2027-10-15",
}

_in := object.get(input, "bnm_rmit", {})

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (bnm_rmit.%v undeclared)", [text, key])
}

_gate_open(g) if g == ""

_gate_open(g) if _in[g] == true

applicable[id] := c if {
	some id, c in standards
	_gate_open(c.gate)
}

_attested(id) if _in.standards[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("RMiT S %v (%v): %v — not attested", [id, sections[c.s], c.text])
}

violations contains msg if {
	some id, _ in _in.standards
	not standards[id]
	msg := sprintf("RMiT Input Contract: attestation for unknown paragraph %v — not an S paragraph of Part B §§8–15", [id])
}

violations contains msg if {
	_in.standards
	not is_object(_in.standards)
	msg := "RMiT Input Contract: input.bnm_rmit.standards must be an object of {\"<paragraph>\": true}"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id, c in applicable; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "standards": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

compliance_report := {
	"framework": "Bank Negara Malaysia — Risk Management in Technology (RMiT)",
	"standard": "BNM/RH/PD 028-98, issued 25 September 2026 — Part B policy requirements, S paragraphs §§8–15",
	"source": "bnm.gov.my — pd-rmit-sep26.pdf",
	"flags": {k: object.get(_in, k, "undeclared") | some k, _ in _flags},
	"dated_obligations": dated_obligations,
	"availability_targets": {"max_cumulative_unplanned_downtime_hours_rolling_12m": 4, "max_tolerable_downtime_minutes_per_incident": 120},
	"standards_total": count(standards),
	"standards_evaluated": count(applicable),
	"standards_attested": count([id | some id, _ in applicable; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
