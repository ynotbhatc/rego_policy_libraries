# MAS Technology Risk Management Guidelines (Monetary Authority of Singapore,
# 18 January 2021) — chapters 3–15.
#
# Source: mas.gov.sg → Regulation → Guidelines → Technology Risk Management
# Guidelines (January 2021). The Guidelines are MAS's expectations for
# financial institutions in Singapore; they are not legally binding on their
# own but MAS assesses compliance in supervision, and the Notices on
# Technology Risk Management (e.g. MAS Notice 644 / 655 / 1114 / CMG-N02)
# make parts of them binding for their respective sectors.
#
# Shape: one control per Guidelines paragraph that states a "should".
# 237 controls across 13 chapters, each attested by the FI from its own
# evidence: input.mas_trm.controls["9.1.5"] == true. Nothing here measures a
# host; this is the attestation layer that a MAS-regulated FI's compliance
# team maintains, and the per-chapter report is what a TRM self-assessment
# or MAS inspection questionnaire asks for.
#
# Fail-closed: a control not attested true is a violation (absent or any
# non-true value); an attestation for an unknown id is a violation (typo
# guard); a non-object controls container is a violation. Chapter 14 (Online
# Financial Services) can be declared not applicable with
# online_financial_services=false — an FI that offers none — in which case
# its 23 controls are not evaluated and the report says so. Nothing else can
# be excluded.
#
# Query: POST /v1/data/mas_trm/main/compliance_report
#
# Input contract — input.mas_trm.*
#   controls                   object: {"<paragraph id>": true, ...}
#   online_financial_services  bool, default true (chapter 14 applies)

# METADATA
# title: "MAS Technology Risk Management Guidelines (January 2021)"
# custom:
#   class: compliance
#   framework: mas_trm
#   source: mas
#   domains: [financial, singapore]
#   coverage:
#     checks: 109
#     cited: 106
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.3.5
package mas_trm.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

controls_b := {
	# ── 9 Access Control ─────────────────────────────────────────────────
	"9.1.1": {"ch": "9", "text": "'Never alone', segregation of duties and least privilege apply to access to information assets; rights follow roles for staff, contractors and service providers"},
	"9.1.2": {"ch": "9", "text": "A user access management process provisions, changes and revokes access, with authorisation by the information asset owner or equivalent"},
	"9.1.3": {"ch": "9", "text": "User access and user-management activities are uniquely identified and logged for audit and investigation"},
	"9.1.4": {"ch": "9", "text": "A password policy enforces strong controls: change on first logon, minimum length, history and complexity"},
	"9.1.5": {"ch": "9", "text": "Multi-factor authentication is implemented for users with access to sensitive system functions"},
	"9.1.6": {"ch": "9", "text": "Periodic user access reviews by asset owners identify dormant, redundant and inappropriate access; exceptions are resolved promptly"},
	"9.1.7": {"ch": "9", "text": "Access is granted need-to-use and revoked or disabled promptly on role change, transfer or termination"},
	"9.1.8": {"ch": "9", "text": "Service providers with access to information assets are subject to the same monitoring and access restrictions as personnel"},
	"9.2.1": {"ch": "9", "text": "Privileged access is granted need-to-use; privileged account activity is logged and reviewed as part of ongoing monitoring"},
	"9.2.2": {"ch": "9", "text": "System and service accounts are managed and monitored for suspicious or unauthorised activity"},
	"9.3.1": {"ch": "9", "text": "Remote connections are encrypted and remote users authenticate with strong (multi-factor) authentication"},
	"9.3.2": {"ch": "9", "text": "Remote access is allowed only from devices secured to the FI's security standards"},
	# ── 10 Cryptography ──────────────────────────────────────────────────
	"10.1.2": {"ch": "10", "text": "Cryptographic algorithms come from well-established international standards, with algorithm and key length meeting security objectives"},
	"10.1.3": {"ch": "10", "text": "Random seeds or numbers underpinning algorithm security are of sufficient length and randomness"},
	"10.1.4": {"ch": "10", "text": "All cryptographic algorithms in use have been rigorously tested or vetted against the security objectives"},
	"10.1.5": {"ch": "10", "text": "Cryptanalysis developments are monitored; algorithms or key lengths are updated to stay resilient"},
	"10.2.1": {"ch": "10", "text": "Key management policy, standards and procedures cover generation, distribution, installation, renewal, revocation, recovery and expiry"},
	"10.2.2": {"ch": "10", "text": "Keys are securely generated and protected from disclosure; key-derivation material is protected or securely destroyed"},
	"10.2.3": {"ch": "10", "text": "Each key has a lifespan based on data sensitivity, system criticality and threat exposure, and is replaced securely before expiry"},
	"10.2.4": {"ch": "10", "text": "Sensitive keys are managed, processed and stored in hardened, tamper-resistant systems such as an HSM"},
	"10.2.5": {"ch": "10", "text": "Sensitive keys are not exposed in transmission; distribution uses out-of-band or other secure means"},
	"10.2.6": {"ch": "10", "text": "Keys are single-purpose (e.g. encryption keys differ from signing keys)"},
	"10.2.7": {"ch": "10", "text": "A compromised key is revoked and replaced together with every key its exposure could compromise"},
	"10.2.8": {"ch": "10", "text": "Expired or revoked keys are destroyed by a secure, non-recoverable method"},
	"10.2.9": {"ch": "10", "text": "Replacement keys are generated so that knowledge of the previous key cannot derive the new one"},
	"10.2.10": {"ch": "10", "text": "Backups of cryptographic keys are maintained for recovery and accorded a high level of protection"},
	# ── 11 Data and Infrastructure Security ──────────────────────────────
	"11.1.1": {"ch": "11", "text": "Data loss prevention policies and measures cover confidential data in motion, at rest (endpoints, servers, databases, backups, cloud) and in use"},
	"11.1.2": {"ch": "11", "text": "Measures prevent and detect data theft and unauthorised modification on systems and endpoints, including provider-managed systems held to the same standard"},
	"11.1.3": {"ch": "11", "text": "Confidential data on systems and endpoints is encrypted and protected by strong access controls"},
	"11.1.4": {"ch": "11", "text": "Only authorised storage media, systems and endpoints are used to communicate, transfer or store confidential data"},
	"11.1.5": {"ch": "11", "text": "Use of unauthorised internet services (social media, cloud storage, file sharing, email, messaging) for confidential data is prevented and detected"},
	"11.1.6": {"ch": "11", "text": "Sensitive production data in non-production is restricted, needs senior management approval, is access-controlled and masked where possible"},
	"11.1.7": {"ch": "11", "text": "Confidential data is irrevocably deleted from media, systems and endpoints before disposal or redeployment"},
	"11.2.1": {"ch": "11", "text": "Firewalls or equivalent secure the network boundary with the Internet and with third parties"},
	"11.2.2": {"ch": "11", "text": "Information assets are segmented by criticality, functional role or data sensitivity to limit lateral movement and insider threat"},
	"11.2.3": {"ch": "11", "text": "Network intrusion prevention systems detect and block malicious traffic"},
	"11.2.4": {"ch": "11", "text": "Network access controls detect and prevent unauthorised devices connecting to the network"},
	"11.2.5": {"ch": "11", "text": "Network device access-control rules are reviewed regularly; obsolete rules and insecure protocols are removed promptly"},
	"11.2.6": {"ch": "11", "text": "Internet web browsing is isolated from endpoints by physical or logical controls, or equivalent"},
	"11.2.7": {"ch": "11", "text": "DoS protection detects and responds to distributed, volumetric and application-layer attacks"},
	"11.2.8": {"ch": "11", "text": "Network architecture, security design and interconnections are reviewed periodically for vulnerabilities"},
	"11.3.1": {"ch": "11", "text": "Hardware and software security configuration standards exist and are reviewed periodically"},
	"11.3.2": {"ch": "11", "text": "A process verifies uniform application of the standards, identifies deviations and addresses their risk in a timely manner"},
	"11.3.3": {"ch": "11", "text": "Endpoint protection (behavioural and signature-based) addresses malware and its delivery channels"},
	"11.3.4": {"ch": "11", "text": "Anti-malware signatures are kept current and systems are scanned regularly"},
	"11.3.5": {"ch": "11", "text": "Detection and response mechanisms scan for indicators of compromise and monitor system and endpoint processes for anomalies"},
	"11.3.6": {"ch": "11", "text": "Application white-listing or equivalent ensures only authorised software is installed"},
	"11.3.7": {"ch": "11", "text": "BYOD is preceded by a comprehensive risk assessment and secured per Annex B (MDM/MAM or virtualisation, jailbreak/root checks, encryption, lock-and-wipe)"},
	"11.4.1": {"ch": "11", "text": "Security standards exist for all virtualisation components (hypervisor, host OS, guest OS)"},
	"11.4.2": {"ch": "11", "text": "Strong access controls restrict administrative access to the hypervisor and host operating system"},
	"11.4.3": {"ch": "11", "text": "Policies and standards govern the security, creation, distribution, storage, use, retirement and destruction of virtual images and snapshots"},
	"11.5.1": {"ch": "11", "text": "An inventory of IoT devices records their networks and physical locations"},
	"11.5.2": {"ch": "11", "text": "Processes and controls mitigate risks arising from IoT devices"},
	"11.5.3": {"ch": "11", "text": "IoT devices are hosted in a separate network segment with access controls restricting their traffic"},
	"11.5.4": {"ch": "11", "text": "Controls prevent unauthorised access to IoT devices"},
	"11.5.5": {"ch": "11", "text": "IoT devices are monitored for suspicious activity so compromised devices can be isolated promptly"},
	# ── 12 Cyber Security Operations ─────────────────────────────────────
	"12.1.1": {"ch": "12", "text": "A process collects, processes and analyses cyber events, threat intelligence and vulnerability information for relevance and impact"},
	"12.1.2": {"ch": "12", "text": "Cyber intelligence monitoring services are procured and the FI participates in threat information-sharing arrangements"},
	"12.1.3": {"ch": "12", "text": "A process detects and responds to online misinformation about the FI"},
	"12.2.1": {"ch": "12", "text": "A security operations centre or managed security service provides continuous monitoring, with defined processes, roles and responsibilities"},
	"12.2.2": {"ch": "12", "text": "Security, application, database, network and OS logs are collected, reviewed, retained and protected from unauthorised access"},
	"12.2.3": {"ch": "12", "text": "Baseline profiles of each system's routine activity are established, maintained and used to identify anomalies"},
	"12.2.4": {"ch": "12", "text": "User behavioural analytics are considered to enhance security monitoring"},
	"12.2.5": {"ch": "12", "text": "Events across system logs are correlated to identify suspicious activity patterns"},
	"12.2.6": {"ch": "12", "text": "Suspicious or anomalous activity is escalated to relevant stakeholders in a timely manner"},
	"12.3.1": {"ch": "12", "text": "A cyber incident response and management plan covers communication, coordination and response for plausible threat scenarios"},
	"12.3.2": {"ch": "12", "text": "Breaches are investigated to identify the control deficiencies and the full extent of impact"},
	"12.3.3": {"ch": "12", "text": "Cyber intelligence and lessons learnt from incidents feed back into controls and the incident plan"},
	# ── 13 Cyber Security Assessment ─────────────────────────────────────
	"13.1.1": {"ch": "13", "text": "Regular vulnerability assessments are conducted at a frequency commensurate with system criticality and exposure, with timely remediation"},
	"13.1.2": {"ch": "13", "text": "VA scope minimally covers vulnerability discovery, weak configurations, open ports and application vulnerabilities, including common web vulnerabilities"},
	"13.2.1": {"ch": "13", "text": "Penetration testing is carried out; online financial services get a combination of blackbox and greybox testing"},
	"13.2.3": {"ch": "13", "text": "Penetration testing is conducted on the production environment with proper safeguards"},
	"13.2.4": {"ch": "13", "text": "Internet-facing systems are penetration-tested at least annually and after major changes"},
	"13.3.1": {"ch": "13", "text": "Regular scenario-based cyber exercises (social engineering, table-top, cyber range) validate response, recovery and communication plans"},
	"13.3.2": {"ch": "13", "text": "Exercises involve senior management, business, communications, crisis management, service providers and technical responders as objectives require"},
	"13.4.1": {"ch": "13", "text": "Adversarial attack simulation (red team) exercises test cyber defence and response against prevalent threats"},
	"13.4.2": {"ch": "13", "text": "Red-team objectives, scope and rules of engagement are defined and the exercise is closely supervised to protect production"},
	"13.5.1": {"ch": "13", "text": "Assessment scenarios are designed on challenging but plausible threats"},
	"13.6.1": {"ch": "13", "text": "A remediation process tracks and resolves assessment findings with severity classification, remediation timeframes by severity, and risk-assessed deviations"},
	# ── 14 Online Financial Services ─────────────────────────────────────
	"14.1.1": {"ch": "14", "text": "Security and control measures for online financial services are commensurate with the risk involved"},
	"14.1.2": {"ch": "14", "text": "Communication channels are secured to protect customer data through encryption and digital signatures"},
	"14.1.3": {"ch": "14", "text": "Exposure to code injection, cross-site scripting, man-in-the-middle, DNS hijacking, DDoS, malware and spoofing attacks is minimised"},
	"14.1.4": {"ch": "14", "text": "Mobile application risks are addressed with the Annex C measures (no local caching of data, key protection, anti-tampering, integrity checks and obfuscation, certificate pinning, secure keypad, device binding)"},
	"14.1.5": {"ch": "14", "text": "Mobile applications are distributed only through official stores or other secure delivery channels"},
	"14.1.6": {"ch": "14", "text": "Phishing campaigns against the FI and its customers are actively monitored, reported for takedown, and customers are alerted"},
	"14.1.7": {"ch": "14", "text": "Rooted or jailbroken devices are blocked from transacting unless the app is sandboxed or containerised against tampering"},
	"14.2.1": {"ch": "14", "text": "Multi-factor authentication is deployed at login for online financial services"},
	"14.2.2": {"ch": "14", "text": "Customer passwords are end-to-end encrypted in transit and verified only in a hardened or tamper-resistant system"},
	"14.2.3": {"ch": "14", "text": "Transaction signing protects high-risk activities: sensitive data changes, new payees, high-value transfers, limit revisions"},
	"14.2.5": {"ch": "14", "text": "Time-based OTP validity periods are as short as practicable"},
	"14.2.6": {"ch": "14", "text": "Biometric data and authentication credentials are encrypted in storage and transmission"},
	"14.2.7": {"ch": "14", "text": "Biometric FAR and FRR are calibrated to the risk of the online activity"},
	"14.2.8": {"ch": "14", "text": "Soft-token provisioning verifies customer identity, blocks rooted/jailbroken devices and performs device binding"},
	"14.2.9": {"ch": "14", "text": "Authenticated sessions and their encryption stay intact; hijacked sessions are detected and terminated; sessions time out on inactivity"},
	"14.2.10": {"ch": "14", "text": "Alternate authorisation controls for corporate customers (e.g. maker-checker) are security-risk-assessed against the activity's risk"},
	"14.2.11": {"ch": "14", "text": "Authentication credentials (biometric templates, passwords) are stored resistant to reverse engineering, with procedures to revoke and replace compromised credentials"},
	"14.3.1": {"ch": "14", "text": "Real-time fraud monitoring identifies and blocks suspicious or fraudulent online transactions"},
	"14.3.2": {"ch": "14", "text": "Suspicious transactions are investigated and issues addressed promptly"},
	"14.3.3": {"ch": "14", "text": "Customers are notified of suspicious activity and transfers above a defined threshold, with transaction details and reporting instructions"},
	"14.4.1": {"ch": "14", "text": "Customers are informed of security best practices, including securing the devices they use"},
	"14.4.2": {"ch": "14", "text": "Customers are alerted to new cyber threats on a timely basis"},
	"14.4.3": {"ch": "14", "text": "Customers are advised how to detect unauthorised transactions and report security issues or suspected fraud"},
	# ── 15 IT Audit ──────────────────────────────────────────────────────
	"15.1.1": {"ch": "15", "text": "IT audit provides the board and senior management an independent, objective opinion on risk management, governance and controls for existing and emerging technology risks"},
	"15.1.2": {"ch": "15", "text": "A comprehensive set of auditable areas covers all IT operations, functions and processes for audit planning"},
	"15.1.3": {"ch": "15", "text": "IT audit frequency is commensurate with the criticality and risk of the asset, function or process"},
	"15.1.4": {"ch": "15", "text": "IT auditors have the competency and skills to assess IT policies, procedures, processes and controls"},
}

controls := object.union(controls_a, controls_b)

chapters := {
	"3": "Technology Risk Governance and Oversight",
	"4": "Technology Risk Management Framework",
	"5": "IT Project Management and Security-by-Design",
	"6": "Software Application Development and Management",
	"7": "IT Service Management",
	"8": "IT Resilience",
	"9": "Access Control",
	"10": "Cryptography",
	"11": "Data and Infrastructure Security",
	"12": "Cyber Security Operations",
	"13": "Cyber Security Assessment",
	"14": "Online Financial Services",
	"15": "IT Audit",
}

default _ofs := true

_ofs := false if input.mas_trm.online_financial_services == false

# Chapter 14 is the only chapter that can be out of scope (an FI with no
# online financial services); every other control always applies.
applicable[id] := c if {
	some id, c in controls
	c.ch != "14"
}

applicable[id] := c if {
	some id, c in controls
	c.ch == "14"
	_ofs
}

_attested(id) if input.mas_trm.controls[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("MAS TRM %v (ch. %v %v): %v — not attested", [id, c.ch, chapters[c.ch], c.text])
}

violations contains msg if {
	some id, _ in input.mas_trm.controls
	not controls[id]
	msg := sprintf("MAS TRM Input Contract: attestation for unknown paragraph id %v — not a control in the January 2021 Guidelines", [id])
}

violations contains msg if {
	input.mas_trm.controls
	not is_object(input.mas_trm.controls)
	msg := "MAS TRM Input Contract: input.mas_trm.controls must be an object of {\"<paragraph id>\": true}"
}

chapter_reports[ch] := r if {
	some ch, name in chapters
	ids := {id | some id, c in applicable; c.ch == ch}
	passed := {id | some id in ids; _attested(id)}
	r := {
		"chapter": ch,
		"name": name,
		"applicable": count(ids) > 0,
		"controls": count(ids),
		"attested": count(passed),
		"gaps": sort([id | some id in ids; not id in passed]),
	}
}

compliance_report := {
	"framework": "MAS Technology Risk Management Guidelines (January 2021)",
	"standard": "Monetary Authority of Singapore — TRM Guidelines, 18 January 2021, chapters 3–15",
	"source": "mas.gov.sg — Technology Risk Management Guidelines (January 2021)",
	"online_financial_services_in_scope": _ofs,
	"controls_total": count(controls),
	"controls_evaluated": count(applicable),
	"controls_attested": count([id | some id, _ in applicable; _attested(id)]),
	"chapters": chapter_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
