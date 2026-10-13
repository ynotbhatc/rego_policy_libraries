# HKMA Supervisory Policy Manual — TM-G-1 "General Principles for Technology
# Risk Management" (V.1, 24 June 2003; the module HKMA still cites in 2024)
# and TM-C-1 "Supervisory Approach on Cyber Risk Management" (V.1,
# 29 November 2024, statutory guideline under Banking Ordinance §7(3)).
#
# Sources: brdr.hkma.gov.hk — TM-G-1.pdf (20030624-2-EN) and TM-C-1.pdf
# (20241202-2-EN). Applies to all authorized institutions (AIs) in Hong Kong.
#
# Shape: one control per TM-G-1 paragraph that sets an expectation
# (sections 2–7), plus the four duties TM-C-1 places on AIs: report
# significant cyber incidents (2.4), conduct regular C-RAF assessments
# (3.5.2), adopt Secure Tertiary Data Backup (4.3) and exchange intelligence
# through CISP (5.1). Attested from the AI's evidence as
# input.hkma_trm.controls["3.2.3"] == true. Paragraphs that only apply when
# the AI uses the thing (WLAN 6.3.x, technology outsourcing 7.1.1, overseas
# IT support 2.6.1) are gated by flags that MUST be declared true or false.
#
# Fail-closed: non-true attestation, unknown id, malformed container or an
# undeclared flag are violations. Per-section gap report.
#
# Query: POST /v1/data/hkma_trm/main/compliance_report

# METADATA
# title: "HKMA SPM TM-G-1 Technology Risk Management + TM-C-1 Cyber Risk (Hong Kong)"
# custom:
#   class: compliance
#   framework: hkma_trm
#   source: hkma
#   domains: [financial, hong-kong]
#   coverage:
#     checks: 74
#     cited: 70
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package hkma_trm.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"2": "TM-G-1 §2 IT governance",
	"3": "TM-G-1 §3 Security management",
	"4": "TM-G-1 §4 System development and change management",
	"5": "TM-G-1 §5 Information processing",
	"6": "TM-G-1 §6 Communications networks",
	"7": "TM-G-1 §7 Management of technology service providers",
	"C": "TM-C-1 duties of AIs (cyber risk)",
}

_flags := {
	"uses_wireless_lan": "TM-G-1 6.3 — whether the AI deploys wireless LANs must be declared true or false",
	"outsources_technology_services": "TM-G-1 7.1 — whether the AI outsources technology services must be declared true or false",
	"relies_on_overseas_offices_for_it": "TM-G-1 2.6 — whether the AI relies on overseas offices for IT controls or support must be declared true or false",
}

controls := {
	# ── 2 IT governance ────────────────────────────────────────────────────
	"2.1.1": {"s": "2", "gate": "", "text": "IT control policies setting the ground rules for IT controls are developed by senior management, formally approved by the Board or its committee, and implemented across IT functions and business units"},
	"2.1.2": {"s": "2", "gate": "", "text": "IT control policies cover at least security management, system development and change management, information processing, communications networks and service providers, and are reviewed regularly and updated"},
	"2.1.3": {"s": "2", "gate": "", "text": "Processes to verify compliance with IT control policies and to seek approval for dispensation are specified, with defined consequences for non-adherence"},
	"2.1.4": {"s": "2", "gate": "", "text": "Mechanisms (periodic reminders, orientation for new recruits) promote regular awareness of IT control policies"},
	"2.2.1": {"s": "2", "gate": "", "text": "An IT organisation structure and job descriptions for IT functions are documented and approved by senior management"},
	"2.2.2": {"s": "2", "gate": "", "text": "Segregation of duties within and among IT functions is enforced (developers have no production access; security management has no conflicting duties), with compensating controls such as peer review where segregation is impractical"},
	"2.2.3": {"s": "2", "gate": "", "text": "An IT planning or steering committee of senior management, business units and IT meets regularly and reports major technology initiatives and material IT issues to senior management and the Board"},
	"2.2.4": {"s": "2", "gate": "", "text": "A documented IT strategy covering long- and short-term initiatives is endorsed by the Board and senior management and reviewed at least annually"},
	"2.3.2": {"s": "2", "gate": "", "text": "The function responsible for the technology risk management (TRM) process is clearly established"},
	"2.3.3": {"s": "2", "gate": "", "text": "The TRM function assists business units and IT in identifying, measuring, monitoring and controlling technology risks, promotes policy compliance and supports investigation of technology-related frauds and incidents"},
	"2.3.4": {"s": "2", "gate": "", "text": "A formal technology risk acknowledgement and acceptance process reviews, evaluates and approves major non-compliance with IT control policies: risk description and assessment, mitigating controls, remedial plan, approval by the risk owner and senior management"},
	"2.4.1": {"s": "2", "gate": "", "text": "Technology audits periodically assess the TRM process and IT controls under an annual technology audit plan; audit issues are recorded, followed up and rectified"},
	"2.4.2": {"s": "2", "gate": "", "text": "Where in-house technology audit expertise is insufficient it is supplemented by external specialists or group technology auditors"},
	"2.5.1": {"s": "2", "gate": "", "text": "Staff of IT functions, the TRM function and technology audit are competent, with sufficient staffing for present and expected demand and turnover"},
	"2.5.2": {"s": "2", "gate": "", "text": "A process identifies material skill gaps against a skill matrix and an adequate training programme is in place; professional qualifications are encouraged for security, TRM and audit staff"},
	"2.6.1": {"s": "2", "gate": "relies_on_overseas_offices_for_it", "text": "Respective responsibilities of local and overseas offices for IT controls and support are clearly set out in policies, procedures or service agreements"},
	# ── 3 Security management ──────────────────────────────────────────────
	"3.1.1": {"s": "3", "gate": "", "text": "Each application system has an assigned information owner accountable for confidentiality and integrity, working with the TRM and IT functions"},
	"3.1.2": {"s": "3", "gate": "", "text": "Information is classified by sensitivity with guidelines, definitions and protection procedures for each class"},
	"3.1.3": {"s": "3", "gate": "", "text": "Confidentiality is protected regardless of media; secure disposal and destruction processes exist for sensitive paper and electronic media"},
	"3.1.4": {"s": "3", "gate": "", "text": "Cryptography uses industry-accepted solutions with sound key management: secure generation, distribution, storage, entry, use and archiving (tamper-resistant storage recommended) and off-site backup of keys under equivalent controls"},
	"3.2.1": {"s": "3", "gate": "", "text": "Access to information and application systems is restricted by authentication and access control rules; every user has a unique ID with an appropriate authentication method"},
	"3.2.2": {"s": "3", "gate": "", "text": "Effective password rules avoid easy-to-guess passwords and enforce periodic change; multi-factor authentication is used for higher-risk transactions and activities (payments, financial messages, mobile computing)"},
	"3.2.3": {"s": "3", "gate": "", "text": "Privileged and emergency IDs are granted only necessary authorities, formally approved before release, monitored (peer review of logs), safeguarded, and have passwords changed immediately on return"},
	"3.3.1": {"s": "3", "gate": "", "text": "A security administration function grants, changes and removes access with information-owner approval, removes rights on leaving or role change, re-certifies user access periodically (e.g. annually), reviews security logs and violation reports timely, and performs incident analysis, reporting and investigation"},
	"3.3.2": {"s": "3", "gate": "", "text": "Segregation of duties or compensating controls within the security administration function mitigate unauthorised activity by that function"},
	"3.3.3": {"s": "3", "gate": "", "text": "Incident response and reporting procedures handle security incidents during and outside office hours and include timely reporting to the HKMA of confirmed IT-related fraud or major security breaches"},
	"3.4.1": {"s": "3", "gate": "", "text": "Baseline security requirements safeguard applications, operating systems, system software and databases: authenticated and authorised access, periodic static-data integrity checks, secure configuration with unnecessary services removed, timely vendor patching with clear responsibility, documented configurations with periodic certification, and protected logging and monitoring of system and user activity"},
	"3.5.1": {"s": "3", "gate": "", "text": "End-user computing is controlled: data security, documentation, storage and backup, recovery, audit responsibilities and training"},
	"3.5.2": {"s": "3", "gate": "", "text": "Mobile computing controls cover user approval, remote-access authentication, protection of devices against theft and malware, encryption of sensitive data in the mobile environment and in transit, and backup of mobile data"},
	"3.5.3": {"s": "3", "gate": "", "text": "Malicious-software controls prohibit unauthorised downloads and doubtful sites, keep reputable anti-virus current, block executables and mobile code with known vulnerabilities, and scan all devices regularly with recovery procedures"},
	"3.6.1": {"s": "3", "gate": "", "text": "Critical information processing facilities sit in secure areas with security barriers and entry controls; access is restricted to authorised personnel and reviewed regularly; buildings give minimum indication of purpose"},
	"3.6.2": {"s": "3", "gate": "", "text": "Data centre sites consider environmental threats; environmental monitoring (fire, smoke, temperature, water, dust) and protection from power failure (UPS, backup generator) are in place"},
	"3.6.3": {"s": "3", "gate": "", "text": "Third-party access to secure areas is approved and monitored; recruitment of permanent and temporary technology staff and contractors includes verification and background checks"},
	# ── 4 System development and change management ────────────────────────
	"4.1.1": {"s": "4", "gate": "", "text": "A project management framework specifies the methodology for major technology projects: responsibilities, activity breakdown, time and resource budgets, milestones, checkpoints, dependencies, quality assurance, risk assessment and approvals"},
	"4.2.1": {"s": "4", "gate": "", "text": "A full project life-cycle methodology governs development, implementation and maintenance of major systems from initiation through feasibility, requirements, design, development, testing, training, implementation, operation and maintenance"},
	"4.2.2": {"s": "4", "gate": "", "text": "The life-cycle methodology defines roles and deliverables per phase and ensures security requirements are identified with business requirements, built, tested and implemented"},
	"4.2.3": {"s": "4", "gate": "", "text": "An independent party (QA, TRM or technology audit) conducts a quality assurance review of major projects for compliance with the methodology, policies, control requirements, regulations and law"},
	"4.2.4": {"s": "4", "gate": "", "text": "A formal acceptance process promotes only tested and approved systems to production; testing is in a separate environment; production data is not used in testing unless de-sensitised and approved by the information owner; performance testing precedes promotion"},
	"4.2.5": {"s": "4", "gate": "", "text": "A formal software package acquisition process evaluates the package (licence, functionality, performance, security) and the supplier (financial condition, reputation, technical capability)"},
	"4.2.6": {"s": "4", "gate": "", "text": "Ongoing maintenance and support of software packages are specified in formal contracts; escrow is considered for mission-critical packages"},
	"4.3.1": {"s": "4", "gate": "", "text": "A formal change management process covers classification and impact, roles with segregation of duties so no one person can change production unreviewed, version control and audit trails, scheduling and tracking, rollback, and post-implementation verification"},
	"4.3.2": {"s": "4", "gate": "", "text": "Emergency changes follow formal procedures and are approved by the information owner and relevant parties at the time, or endorsed by the information owner as soon as practicable afterwards"},
	"4.3.3": {"s": "4", "gate": "", "text": "Emergency changes are logged and backed up (previous and changed versions and data), reviewed by independent personnel, and replaced by proper fixes through normal change management"},
	# ── 5 Information processing ──────────────────────────────────────────
	"5.1.1": {"s": "5", "gate": "", "text": "Service level agreements with business units cover availability, performance, capacity for growth and user support, with procedures to manage delivery"},
	"5.1.2": {"s": "5", "gate": "", "text": "An IT operations manual documents operator tasks, job scheduling and execution, and on-site and off-site backup of data and software (frequency, scope, retention) for production and development"},
	"5.1.3": {"s": "5", "gate": "", "text": "A problem management system responds to IT operational incidents, escalates to IT management, and records, analyses and tracks incidents to rectification; a helpdesk provides front-line support"},
	"5.2.1": {"s": "5", "gate": "", "text": "Application performance is continuously monitored with timely exception reporting and forecasting to identify problems early and feed capacity planning"},
	"5.2.2": {"s": "5", "gate": "", "text": "Capacity planning covers backup systems and related facilities as well as production"},
	"5.3.1": {"s": "5", "gate": "", "text": "IT facilities and equipment are maintained per industry practice and supplier intervals, with fault and maintenance records and a hardware and facility inventory of purchased and leased assets"},
	"5.4.1": {"s": "5", "gate": "", "text": "An IT disaster recovery plan ensures critical application systems and technology services resume per business recovery requirements (TM-G-2), with adequate insurance of IT resources"},
	# ── 6 Communications networks ─────────────────────────────────────────
	"6.1.2": {"s": "6", "gate": "", "text": "Network management responsibility is assigned to skilled, resourced individuals; network standards, design, diagrams and procedures are documented, current, communicated and reviewed periodically"},
	"6.1.3": {"s": "6", "gate": "", "text": "Critical communications facilities are identified and single points of failure minimised by automatic re-routing, multiple exchanges and alternate telecommunications providers"},
	"6.1.4": {"s": "6", "gate": "", "text": "The network is monitored continuously: services and performance against targets, traffic volumes and bottlenecks, and detection of unusual activity based on attack characteristics"},
	"6.1.5": {"s": "6", "gate": "", "text": "Powerful network analysis and monitoring tools are protected from unauthorised use and restricted to authorised staff under approval and review"},
	"6.2.1": {"s": "6", "gate": "", "text": "Procedures for use of networks and network services define available services, authorisation of who may access them, and protection of access points, connections and services"},
	"6.2.2": {"s": "6", "gate": "", "text": "Internal networks are segregated by access-control need; production systems sit in dedicated segments separated from internet, extranet and market-data traffic; sensitive inter-segment traffic is controlled and tamper-protected"},
	"6.2.3": {"s": "6", "gate": "", "text": "Security parameter settings of routers, firewalls and network servers are reviewed regularly; audit trails of critical network devices are maintained and reviewed; operations staff are alerted in real time to potential breaches"},
	"6.2.4": {"s": "6", "gate": "", "text": "Network certification assesses LAN/WAN additions or changes (dial ports, switches, terminal servers, gateways, routers, extranets, internet) for vulnerabilities and documents approval or required controls"},
	"6.3.1": {"s": "6", "gate": "uses_wireless_lan", "text": "WLAN policies cover approval, installation, operation and administration; a risk assessment of accessible information precedes implementation; a standard WLAN security configuration and network certification apply"},
	"6.3.2": {"s": "6", "gate": "uses_wireless_lan", "text": "Stronger encryption and mutual authentication protect wireless-to-wired traffic where needed; WLANs are segregated from the corporate network (e.g. firewalls)"},
	# ── 7 Management of technology service providers ──────────────────────
	"7.1.1": {"s": "7", "gate": "outsources_technology_services", "text": "Technology outsourcing follows SA-2 plus: providers have resources and expertise to meet IT control policies; critical services get an independent assessment of the provider's IT control environment with the report provided to the HKMA; agreements specify performance standards, obligations, ownership and sub-contracting notification or approval; an annual assessment confirms the control environment of critical providers; excessive reliance on a single provider is avoided; a contingency and exit plan exists for critical outsourced services"},
	"7.2.1": {"s": "7", "gate": "", "text": "Guidelines govern other major technology service providers (telecommunications, network operators): selection, approval of material exceptions and avoidance of over-reliance on a single provider for critical services"},
	# ── TM-C-1 duties of AIs ──────────────────────────────────────────────
	"C.2.2": {"s": "C", "gate": "", "text": "A technology and cyber risk management framework proportionate to the nature, scale and complexity of operations is in place, consistent with IC-1 and TM-G-1"},
	"C.2.4": {"s": "C", "gate": "", "text": "Significant cyber incidents are reported promptly to the HKMA and, where appropriate, other relevant authorities (e.g. PCPD, CSTCB) under prevailing legal and regulatory obligations"},
	"C.3.5.2": {"s": "C", "gate": "", "text": "Regular Cyber Resilience Assessment Framework (C-RAF) assessments are conducted — inherent risk assessment, maturity assessment, and iCAST for medium or high inherent risk — raising cyber defence maturity to the assessed exposure"},
	"C.4.3": {"s": "C", "gate": "", "text": "Secure Tertiary Data Backup (STDB) is adopted so critical data can be recovered if a cyber attack compromises both production and backup environments"},
	"C.5.1": {"s": "C", "gate": "", "text": "The AI exchanges cyber threat intelligence through the Cyber Intelligence Sharing Platform (CISP) under the Cybersecurity Fortification Initiative"},
}

_in := object.get(input, "hkma_trm", {})

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("HKMA %v (hkma_trm.%v undeclared)", [text, key])
}

_gate_open(g) if g == ""

_gate_open(g) if _in[g] == true

applicable[id] := c if {
	some id, c in controls
	_gate_open(c.gate)
}

_attested(id) if _in.controls[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("HKMA %v %v: %v — not attested", [sections[c.s], id, c.text])
}

violations contains msg if {
	some id, _ in _in.controls
	not controls[id]
	msg := sprintf("HKMA Input Contract: attestation for unknown paragraph %v — not in TM-G-1 §§2–7 or the TM-C-1 duties", [id])
}

violations contains msg if {
	_in.controls
	not is_object(_in.controls)
	msg := "HKMA Input Contract: input.hkma_trm.controls must be an object of {\"<paragraph>\": true}"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id, c in applicable; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "controls": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

compliance_report := {
	"framework": "HKMA Supervisory Policy Manual — TM-G-1 General Principles for Technology Risk Management + TM-C-1 Supervisory Approach on Cyber Risk Management",
	"standard": "TM-G-1 V.1 (24 June 2003); TM-C-1 V.1 (29 November 2024, statutory guideline)",
	"source": "brdr.hkma.gov.hk — TM-G-1.pdf, TM-C-1.pdf",
	"flags": {k: object.get(_in, k, "undeclared") | some k, _ in _flags},
	"controls_total": count(controls),
	"controls_evaluated": count(applicable),
	"controls_attested": count([id | some id, _ in applicable; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
