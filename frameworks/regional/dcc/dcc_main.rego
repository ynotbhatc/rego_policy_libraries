# UK MoD Defence Cyber Certification (DCC) — DEF STAN 05-138 Issue 4
# "Cyber Security Standard for Suppliers" (14 May 2024)
#
# The DCC scheme (MOD + IASME, launched 2025) certifies defence suppliers
# against the 148 controls in DEF STAN 05-138 Issue 4 Table 1, at four
# Cyber Risk Profiles assigned by the CSM risk assessment:
#   Level 0 "Basic"        —   3 controls
#   Level 1 "Foundational" — 101 controls
#   Level 2 "Advanced"     — 139 controls
#   Level 3 "Expert"       — 144 controls
# All MOD supply-chain suppliers are expected to hold DCC Level 0 by
# 31 Dec 2026. Certification: 3 years, annual attestation; CE required
# at every level (control 0001), CE Plus at Levels 2-3 (control 0002).
#
# Levels are NOT strictly cumulative: a few controls are superseded by a
# stronger variant at higher levels and drop out of the higher profiles —
# 2300 (L1 only), 2502/2504 (L1 only; replaced by 2503/2505 at L2-L3),
# 3101 (L1-L2; replaced by 3102 at L3). The table therefore records the
# exact level set per control, transcribed from Table 1 of the standard
# (level tallies verified against the declared 3/101/139/144).
#
# The standard's own acknowledgements cite NIST SP 800-171/800-172,
# MITRE ATT&CK and NCSC — DCC obligations correlate onto the same 800-53
# spine the public crosswalk (docs/CONTROL_CORRELATION_PATTERN.md)
# already carries, so one assessment can discharge DCC alongside
# 800-171-derived frameworks.
#
# Query: POST /v1/data/dcc/main/compliance_report
#
# Fail-closed:
#   - every attestation must be the boolean true — absent, false, or any
#     non-boolean value is a violation for an applicable control
#   - absent target_level evaluates the STRICTEST profile (Level 3)
#   - unrecognized target_level is itself a violation and evaluates L3
#   - attestations for unknown control ids are violations (typo guard);
#     attesting a KNOWN control that is not applicable at the target level
#     is accepted without effect (suppliers may attest beyond their level,
#     and superseded ids remain valid at their own levels)
#
# Input contract — input.dcc.*
#
#   target_level             — 0 | 1 | 2 | 3 (number). The CRP level being
#                              certified against. Absent → 3.
#   controls                 — object: {"<control id>": true, ...}
#                              attestation per DEF STAN 05-138 control id,
#                              e.g. {"0001": true, "2402": true}. Source:
#                              supplier assessment records / portal
#                              attestation workflow.

# METADATA
# title: "UK MoD Defence Cyber Certification (DCC) — DEF STAN 05-138 Issue 4"
# custom:
#   class: compliance
#   framework: dcc
#   source: uk-mod
#   domains: [uk, defense]
package dcc.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

_level_names := {0: "Basic", 1: "Foundational", 2: "Advanced", 3: "Expert"}

_objectives := {
	"CE": "Certification prerequisites",
	"A": "Managing security risk",
	"B": "Protecting against cyber attack",
	"C": "Detecting cyber security events",
	"D": "Minimising the impact of cyber security incidents",
}

# Target CRP level — absent evaluates Level 3 (strictest, fail-closed).
default _target := 3

_target := input.dcc.target_level if input.dcc.target_level in {0, 1, 2, 3}

# An attestation counts only as the boolean true.
_attested(id) if input.dcc.controls[id] == true

# Controls applicable at the target level (exact per-control level sets).
applicable contains id if {
	some id, m in controls
	_target in m.levels
}

violations contains msg if {
	lvl := input.dcc.target_level
	not lvl in {0, 1, 2, 3}
	msg := sprintf(
		"DCC Input Contract: unrecognized target_level %v — must be 0, 1, 2 or 3 (evaluated at Level 3)",
		[lvl],
	)
}

violations contains msg if {
	some id in applicable
	not _attested(id)
	m := controls[id]
	msg := sprintf(
		"DCC %s (%s, Objective %s — %s): the Supplier shall %s — not attested",
		[id, m.lvls, m.obj, m.name, m.req],
	)
}

# The attestation container must be an object keyed by control id — an
# array/string/number here still fails closed above, but gets an explicit
# contract message instead of 144 misleading "not attested" diagnostics.
violations contains msg if {
	ctrls := input.dcc.controls
	not is_object(ctrls)
	msg := "DCC Input Contract: controls must be an object of {\"<control id>\": true} attestations"
}

# Typo guard: an attestation keyed by an id that is not in the standard is
# an input-contract violation, not a silent no-op. Object shape only —
# iterating an array here would bind indices and report them as bogus ids.
violations contains msg if {
	is_object(input.dcc.controls)
	some id, _ in input.dcc.controls
	not controls[id]
	msg := sprintf(
		"DCC Input Contract: attestation for unknown control id %v — not a DEF STAN 05-138 Issue 4 control",
		[id],
	)
}

_attested_count := count([id | some id in applicable; _attested(id)])

# Per-objective violation rollup.
_obj_violations(obj) := count([id |
	some id in applicable
	not _attested(id)
	controls[id].obj == obj
])

compliance_report := {
	"framework": "UK MoD Defence Cyber Certification (DCC)",
	"standard": "DEF STAN 05-138 Issue 4 (14 May 2024)",
	"target_level": _target,
	"level_name": _level_names[_target],
	"controls_evaluated": count(applicable),
	"controls_attested": _attested_count,
	"objectives": {obj: {
		"title": title,
		"open_violations": _obj_violations(obj),
	} |
		some obj, title in _objectives
	},
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}

# ── DEF STAN 05-138 Issue 4, Table 1 — all 148 controls ─────────────────────

controls := {
	"0001": {
		"levels": {0, 1, 2, 3}, "lvls": "L0-L3", "obj": "CE",
		"name": "Cyber Essentials",
		"req": "hold Cyber Essentials certification covering the contract scope, maintained for the contract duration",
	},
	"0002": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "CE",
		"name": "Cyber Essentials Plus",
		"req": "hold Cyber Essentials Plus certification covering the contract scope, maintained for the contract duration",
	},
	"1100": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Governance",
		"req": "have management policies and processes governing security of network and information systems supporting Functions and protection of Data",
	},
	"1101": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Board direction",
		"req": "have organisational security management led at board level and articulated in corresponding policies",
	},
	"1102": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Roles and responsibilities",
		"req": "establish security roles and responsibilities at all levels with clear channels for communicating and escalating risks",
	},
	"1103": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Decision-making",
		"req": "have senior-level accountability with appropriately delegated decision-making authority, considering security risks alongside other organisational risks",
	},
	"1200": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Risk management",
		"req": "identify, assess, understand and remediate security risks to network and information systems, with an organisational approach to risk management",
	},
	"1201": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Risk management process",
		"req": "have effective internal processes for managing risks and communicating associated activities and solutions",
	},
	"1202": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Periodically assess risk",
		"req": "periodically assess risk to operations, assets and individuals resulting from system operation and Data processing, storage or transmission",
	},
	"1203": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Network diagrams",
		"req": "create and maintain up-to-date network diagrams detailing boundaries, internal and external connections, and systems",
	},
	"1204": {
		"levels": {3}, "lvls": "L3", "obj": "A",
		"name": "Threat intelligence capabilities",
		"req": "implement threat intelligence capabilities informing security architecture, monitoring, threat hunting, advisories, response and recovery",
	},
	"1205": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Assurance",
		"req": "gain validation of the effectiveness of security across technology, people and processes supporting Functions and Data",
	},
	"1206": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Internal controls assurance",
		"req": "monitor security controls on an ongoing basis, recording deficiencies, reporting to leadership and mitigating within agreed timeframes",
	},
	"1300": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Asset management",
		"req": "determine and understand everything required to deliver and support Functions and protect Data, including people, systems and supporting infrastructure",
	},
	"1301": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "A",
		"name": "Automated asset inventory management",
		"req": "employ automated discovery and management tools maintaining an up-to-date, complete inventory of data, people, systems and infrastructure",
	},
	"1400": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Supply chain",
		"req": "understand and manage security risks arising from dependencies on external suppliers, with appropriate measures where third-party services are used",
	},
	"1401": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "External provider trusted relationships",
		"req": "establish, document and maintain trust relationships with external service providers based on defined security and privacy requirements",
	},
	"1500": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Physical access controls",
		"req": "restrict and monitor physical access to facilities where Data is stored or processed using industry-standard controls, with regular log review",
	},
	"1501": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Physical access device management",
		"req": "maintain an inventory of physical access devices with unique identifiers and named assignees",
	},
	"1502": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Physical access restrictions",
		"req": "restrict physical access to sensitive areas to authorised staff and maintain an inventory of privileged physical access",
	},
	"1503": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "A",
		"name": "Visitor access management",
		"req": "log visitor access and exit, require distinct visitor badges, escort visitors, and recover badges at day end",
	},
	"2100": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Resilience policy and process development",
		"req": "develop, enact and regularly review cyber security and resilience policies and processes managing risk of adverse impact",
	},
	"2101": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Policy and process implementation",
		"req": "implement security policies and processes demonstrating continuing security benefit to Functions and Data",
	},
	"2200": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Identity and access control",
		"req": "understand, document and manage access to networks, information systems and removable media, with all accounts verified, authenticated and authorised",
	},
	"2201": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Access control - multi-factor authentication",
		"req": "implement MFA mechanisms controlling access to critical or sensitive systems and organisational operations",
	},
	"2202": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Device management",
		"req": "fully understand and trust the devices used to access networks and systems supporting Functions and processing Data",
	},
	"2203": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Privileged user management",
		"req": "closely manage privileged user access and actions on networks and information systems",
	},
	"2204": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Principle of least functionality",
		"req": "configure systems to provide only essential capabilities, prohibiting or restricting non-essential ports, protocols, programmes and services",
	},
	"2205": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Least privilege",
		"req": "closely manage all user accounts and apply least privilege across networks and information systems",
	},
	"2206": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Least privilege - audit system",
		"req": "limit access to audit and security logging data to privileged user groups with a confirmed requirement",
	},
	"2207": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Separation of duties",
		"req": "develop a policy and implement separation-of-duties methodology for standard and privileged accounts",
	},
	"2208": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Identity and Access Management (IdAM)",
		"req": "closely manage identity and access control for users, admins, devices and systems",
	},
	"2209": {
		"levels": {3}, "lvls": "L3", "obj": "B",
		"name": "Limit access to authorised entities",
		"req": "implement automated mechanisms supporting management of system accounts, including processes acting for authorised users",
	},
	"2210": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Limit to authorised transactions",
		"req": "issue, manage, verify, revoke and audit identities and credentials for authorised transactions, users and processes",
	},
	"2211": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Secure first-time password management",
		"req": "securely store, transmit and manage first-time and one-time passwords, requiring immediate change after first logon",
	},
	"2212": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Automated password management",
		"req": "employ automated mechanisms for generation, protection, storage, rotation and cryptographic management of passwords",
	},
	"2213": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Automated password quality check",
		"req": "deploy technical controls managing credential quality reflecting industry standards for length, complexity, reuse history and insecure patterns",
	},
	"2214": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Repeated unsuccessful logon handling",
		"req": "lock accounts after at most ten failed logons for a minimum of 15 minutes, increasing on repeat lockouts",
	},
	"2215": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Replay-resistant authentication",
		"req": "enforce technical control protecting against capture and retransmission of authentication information",
	},
	"2216": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Privilege failure handling",
		"req": "prevent non-privileged users executing privileged functions and capture such attempts in audit logs",
	},
	"2217": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Service accounts",
		"req": "inventory all generic, service and system accounts, each owned by a single named accountable individual",
	},
	"2218": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "System users and processes",
		"req": "identify system users, processes acting on behalf of users, and devices",
	},
	"2300": {
		"levels": {1}, "lvls": "L1", "obj": "B",
		"name": "Data security",
		"req": "appropriately protect data stored or transmitted electronically from unauthorised access, modification or deletion",
	},
	"2301": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Understanding data",
		"req": "understand and classify data important to Functions, including storage, movement, protective markings and impact of compromise",
	},
	"2302": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Data in transit",
		"req": "protect and control data in transit, using encryption where appropriate, including transfers to third parties",
	},
	"2303": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Management of established network connections",
		"req": "terminate network connections at session end or after a defined period of inactivity",
	},
	"2304": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Wireless network access control",
		"req": "require authorisation and authentication of all users and devices on trusted wireless networks, encrypted with WPA2 or above",
	},
	"2305": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Remote Access - VPN",
		"req": "enforce MFA, encryption of all transmitted data, and disabled split-tunnelling for staff VPN remote access",
	},
	"2306": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Remote access sessions",
		"req": "employ cryptographic mechanisms protecting the confidentiality of remote access sessions",
	},
	"2307": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Managed access control points",
		"req": "route remote access via managed access control points",
	},
	"2308": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Stored data",
		"req": "appropriately protect the confidentiality of soft and hard copies of stored data for all Functions",
	},
	"2309": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Mobile data",
		"req": "protect, such as through encryption, data important to Functions and all Data on mobile devices",
	},
	"2310": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Removable media",
		"req": "inventory, encrypt and restrict removable storage media to corporately owned or authorised devices",
	},
	"2311": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Authorised working locations",
		"req": "maintain and communicate a list of authorised off-premise working locations",
	},
	"2312": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Security at alternate working locations",
		"req": "employ technical controls and user education reducing security risk of off-premise working",
	},
	"2313": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Media/equipment sanitisation",
		"req": "appropriately sanitise devices, equipment and removable media holding important data before reuse or disposal",
	},
	"2314": {
		"levels": {0, 1, 2, 3}, "lvls": "L0-L3", "obj": "B",
		"name": "Ensure UK GDPR compliance",
		"req": "ensure processing of personal data complies with the General Data Protection Regulation",
	},
	"2315": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Email authentication methods",
		"req": "implement DMARC, DKIM and SPF to verify email source authenticity",
	},
	"2316": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "PII processing/transparency - control flow",
		"req": "monitor and control the flow of all PII and government information per approved authorisations, legislation and contract",
	},
	"2317": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Endpoint encryption",
		"req": "implement and maintain full disk encryption on all endpoints to industry standards such as AES-256 or FIPS equivalent",
	},
	"2318": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Approved cryptographic methods",
		"req": "employ nationally or departmentally approved cryptography when protecting all Data (e.g. FIPS 140-2 or comparable)",
	},
	"2319": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Securely manage cryptographic keys",
		"req": "establish and manage cryptographic keys using approved solutions (e.g. FIPS 140-2 or comparable)",
	},
	"2320": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Data Loss Prevention (DLP)",
		"req": "implement tooling to monitor and restrict access to and use of removable media, external websites and email",
	},
	"2321": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Publicly accessible data",
		"req": "designate and train authorised individuals and review content so publicly accessible systems contain no non-public information",
	},
	"2322": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Mobile devices/BYOD",
		"req": "ensure mobile devices accessing the corporate environment are configured and managed using industry-recognised solutions such as MDM",
	},
	"2323": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Secure destruction",
		"req": "securely destroy all Data no longer needed or at Agreement end, with confirmed erasure and attestation where contracted",
	},
	"2400": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "System security",
		"req": "protect from cyber attack the networks, systems and technology critical to Functions and Data, informed by organisational risk",
	},
	"2401": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Secure configuration",
		"req": "securely configure the network and information systems supporting business Functions and protecting Data",
	},
	"2402": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Vulnerability management",
		"req": "implement a vulnerability and patch management process with monthly scans, CVSS v3-prioritised patching, and a Risk Treatment Plan",
	},
	"2403": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Penetration testing",
		"req": "conduct penetration testing at least every 12 months against externally facing systems, remediating deficiencies and retaining records",
	},
	"2404": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Change management",
		"req": "document, publish and review change control procedures at least every 12 months, with approval and audit trail before changes",
	},
	"2405": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Patch management",
		"req": "maintain a patch management programme addressing known vulnerabilities within industry best-practice timelines, including emergency out-of-band patching",
	},
	"2406": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Privacy warning notices - prior to access",
		"req": "require users to accept warning notices before system access covering monitoring, prohibited use, penalties and consent to recording",
	},
	"2407": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Privacy warning notices - specific handling",
		"req": "require authenticated users to accept warning notices before accessing systems with specific handling requirements",
	},
	"2408": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Screen locking/timeouts",
		"req": "automatically lock user sessions after a predefined period, with the lock screen concealing previously displayed information",
	},
	"2409": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Identify allowed programs",
		"req": "identify software authorised to execute, blocking all other programs by default with permit-by-exception",
	},
	"2410": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Review the list of approved software",
		"req": "review and manage the list of authorised software programs at least every 90 days",
	},
	"2411": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Secured Internet access",
		"req": "enforce endpoint internet controls preventing malware, blocking undesirable sites, sandboxing downloads and terminating idle sessions",
	},
	"2412": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Voice over Internet Protocol (VoIP)",
		"req": "establish usage restrictions and guidance for VoIP with controls to authorise, monitor and control its use",
	},
	"2413": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Mobile code management",
		"req": "define acceptable and unacceptable mobile code and control its identification, authorisation, monitoring and use",
	},
	"2414": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Communication authenticity protection",
		"req": "use secure network management and communication protocols protecting session authenticity",
	},
	"2415": {
		"levels": {3}, "lvls": "L3", "obj": "B",
		"name": "Automatically identify and address misconfigurations and unauthorised components",
		"req": "employ automated mechanisms detecting misconfigured or unauthorised system components",
	},
	"2416": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Shared system resources",
		"req": "prevent unauthorised and unintended information transfer via shared system resources",
	},
	"2417": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Authorise remote execution of privileged commands",
		"req": "ensure all remote users acquire appropriate authorisation before accessing or executing privileged functions",
	},
	"2418": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Baseline configurations and inventories",
		"req": "implement and document system hardening procedures and baseline configurations, restricting unsupported software and hardware",
	},
	"2419": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Obscure authentication information",
		"req": "configure systems so credentials such as passwords are not displayed as cleartext during input",
	},
	"2420": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Authentication feedback",
		"req": "configure systems to minimise failed-logon feedback that could aid compromise of authentication mechanisms",
	},
	"2421": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Network Time Protocol (NTP)",
		"req": "implement NTP to a recognised authoritative source, synchronising every network device clock for consistent audit timestamps",
	},
	"2422": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Physical and logical access restrictions",
		"req": "define, document, approve and enforce physical and logical access restrictions for changes to organisational systems",
	},
	"2423": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Trusted source repository",
		"req": "maintain an automated asset register of system components, including data location and ownership",
	},
	"2424": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Implement audit for stored credentials outside policy",
		"req": "store administrator credentials via an approved secured mechanism with quarterly audits confirming the control functions",
	},
	"2425": {
		"levels": {3}, "lvls": "L3", "obj": "B",
		"name": "Use integrity verification tools",
		"req": "implement an integrity verification tool detecting unauthorised changes to web-facing and critical software and firmware, auto-triggering incident response",
	},
	"2426": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Anti-malware capabilities",
		"req": "regularly audit anti-malware capabilities verifying they are current, functional, managed, and updating signatures and software",
	},
	"2427": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Monitor/protect communications at boundaries",
		"req": "monitor, control and protect communications at external and key internal boundaries, including all remote workers",
	},
	"2428": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Verify/limit access to external system connections",
		"req": "control and limit connections to external systems by an allow-list on the network boundary",
	},
	"2429": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Verify/limit access from external system connections",
		"req": "block unauthorised inbound connections by default, with firewall rules approved, documented and justified by business need",
	},
	"2430": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "External system connection review",
		"req": "promptly remove or disable firewall rules no longer required or fulfilling no business need",
	},
	"2500": {
		"levels": {0, 1, 2, 3}, "lvls": "L0-L3", "obj": "B",
		"name": "Resilient networks and systems",
		"req": "build resilience against cyber attack and system failure into design, implementation, operation and management of systems",
	},
	"2501": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Design for resilience",
		"req": "design networks and systems to be resilient and appropriately segregated, with resource limitations mitigated",
	},
	"2502": {
		"levels": {1}, "lvls": "L1", "obj": "B",
		"name": "Resilience preparation",
		"req": "develop recovery plans for all systems that deliver Functions and protect Data",
	},
	"2503": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Resilience preparation with testing",
		"req": "develop recovery plans for all delivering systems, tested at least annually with deficiencies recorded and resolved within timelines",
	},
	"2504": {
		"levels": {1}, "lvls": "L1", "obj": "B",
		"name": "Backups",
		"req": "hold accessible, secured current backups needed to recover Functions and protect Data, with encryption and integrity validation",
	},
	"2505": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Resilient backups",
		"req": "hold secured current backups with encryption, integrity validation, secure offsite storage, and regular recovery testing",
	},
	"2506": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Physical transport of backups",
		"req": "protect physical movement of backup media using locked containers, certified couriers, chain of custody and cryptographic protection",
	},
	"2507": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Deny traffic by default at interfaces",
		"req": "ensure firewalls block every network path and service not explicitly CAB-authorised, removing unsupported exceptions",
	},
	"2508": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Separate public and internal subnetworks",
		"req": "implement network segmentation separating publicly accessible components from internal network components",
	},
	"2509": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Managed email filtering",
		"req": "implement tooling to detect, block and report malicious or spam emails entering the network",
	},
	"2510": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Diagnostic programmes",
		"req": "check all media containing diagnostic or test programs for malicious code before use on the organisational network",
	},
	"2511": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Maintenance activities",
		"req": "ensure good-practice tooling, techniques and mechanisms are authorised or provided to maintenance personnel",
	},
	"2512": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "MFA for remote maintenance activities",
		"req": "require MFA for nonlocal maintenance sessions via external connections, terminating connections when maintenance completes",
	},
	"2513": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Maintenance personnel supervision",
		"req": "designate authorised, qualified personnel to supervise maintenance personnel lacking required physical access authorisations",
	},
	"2600": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Staff awareness and training",
		"req": "ensure staff have appropriate awareness, knowledge and skills to perform their roles securely",
	},
	"2601": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Cyber security culture",
		"req": "develop and maintain a positive cyber security culture making information security part of day-to-day activity",
	},
	"2602": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Cyber security training",
		"req": "train supporting personnel in cyber security with awareness training at least every 12 months covering phishing, APTs and breaches",
	},
	"2603": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Staff risk awareness",
		"req": "make managers, administrators and users aware of security risks and policies, reviewed at least every 12 months",
	},
	"2604": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Acceptable Use Policy",
		"req": "enforce an Acceptable Use Policy covering social media, public posting, clear desk/screen and asset handling",
	},
	"2605": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "B",
		"name": "Annual threat focused training feedback",
		"req": "conduct practical awareness-training exercises aligned with current threat scenarios, with feedback to participants and supervisors",
	},
	"2700": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Personnel pre-employment checks",
		"req": "perform background verification on Personnel accessing Data, including credentials, employment history and BPSS",
	},
	"2701": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Personnel security vetting",
		"req": "define and implement a policy applying BPSS and National Security Vetting checks as appropriate",
	},
	"2702": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Joiners, movers and leavers",
		"req": "define and implement a joiners, movers and leavers policy securing organisational hardware, software and systems",
	},
	"2703": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Whistleblowing",
		"req": "implement training and processes for reporting suspicious activity without fear of recrimination, with a disciplinary process for violations",
	},
	"2704": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "B",
		"name": "Environmental controls",
		"req": "implement and maintain fire suppression, temperature and humidity controls, and backup power where appropriate",
	},
	"3100": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Security monitoring",
		"req": "monitor the security status of networks and systems to detect problems and track protective-measure effectiveness",
	},
	"3101": {
		"levels": {1, 2}, "lvls": "L1-L2", "obj": "C",
		"name": "Monitor security controls",
		"req": "establish and document security event monitoring covering events, frequency, roles and an escalation matrix",
	},
	"3102": {
		"levels": {3}, "lvls": "L3", "obj": "C",
		"name": "Continuously monitor security controls",
		"req": "document 24x7x365 security event monitoring of all information systems with correlation tools, roles and escalation matrix",
	},
	"3103": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Securing logs",
		"req": "hold logging data securely with business-need-only read access, protected audit tools and a documented retention period",
	},
	"3104": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Security event triage",
		"req": "provide evidence from monitoring tooling verifying the reliability of identified and triggered alerts for triage",
	},
	"3105": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Identifying security incidents",
		"req": "contextualise alerts with threat and system knowledge, engaging Incident Response when an incident is identified",
	},
	"3106": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Monitoring tools and skills",
		"req": "ensure monitoring staff skills, tools and roles reflect governance requirements, expected threats and system complexity",
	},
	"3107": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Create, retain and correlate audit logs",
		"req": "generate event logs archived 12 months minimum, capturing key security events, reviewed weekly with 6-monthly event-type reviews",
	},
	"3108": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Audit reduction and report generation",
		"req": "implement audit record reduction and report generation supporting on-demand review without altering content or time ordering",
	},
	"3109": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Integration of records with incident management",
		"req": "integrate audit record review, triage, analysis and reporting with governance and incident management",
	},
	"3110": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Monitor alerts/advisories and take action",
		"req": "monitor system security alerts and advisories and take action in response",
	},
	"3200": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Proactive security event discovery",
		"req": "detect malicious activity even when it evades standard signature-based solutions or such solutions are undeployable",
	},
	"3201": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "System abnormalities for attack detection",
		"req": "define examples of abnormal system behaviour to aid detection of hard-to-identify malicious activity",
	},
	"3202": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "C",
		"name": "Proactive attack discovery",
		"req": "implement reasonable and proportionate measures detecting malicious activity affecting Functions and Data protection",
	},
	"3203": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Use indicators of compromise from alerts",
		"req": "monitor security alerts and advisories and respond using agreed and managed indicators of compromise",
	},
	"3204": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "C",
		"name": "Presence of unauthorised system components",
		"req": "detect unauthorised hardware, software and firmware, then disable network access, isolate components and notify security operations",
	},
	"4100": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "D",
		"name": "Response and recovery planning",
		"req": "implement well-defined, tested incident management processes ensuring continuity of Functions and Data protection",
	},
	"4101": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "D",
		"name": "Response plan",
		"req": "have an up-to-date incident response plan grounded in risk assessment, covering a range of incident scenarios",
	},
	"4102": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "D",
		"name": "Response and recovery capability",
		"req": "be capable of enacting the incident response plan, limiting impact and coordinating incident handling with contingency planning",
	},
	"4103": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "D",
		"name": "Testing and exercising",
		"req": "exercise response plans at least every 12 months using past incidents and threat-intelligence-informed scenarios",
	},
	"4104": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "D",
		"name": "Incident handling capability",
		"req": "establish an operational incident handling capability covering preparation, detection, forensic analysis, containment, recovery and reporting",
	},
	"4105": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "D",
		"name": "Exfiltration tests",
		"req": "conduct data exfiltration tests at network boundaries at least every 12 months against authorised and covert channels",
	},
	"4106": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "D",
		"name": "Attempted unauthorised connections from staff",
		"req": "audit the identity of internal users associated with denied communications",
	},
	"4200": {
		"levels": {1, 2, 3}, "lvls": "L1-L3", "obj": "D",
		"name": "Lessons learned",
		"req": "incorporate root cause analysis and lessons learned into response procedures, with improvements implemented within 30 days of analysis",
	},
	"4201": {
		"levels": {2, 3}, "lvls": "L2-L3", "obj": "D",
		"name": "Business Continuity Risk Assessments",
		"req": "perform Business Continuity Risk Assessments for outage or Data Breach risks, recorded in a risk register with mitigating controls",
	},
	"4202": {
		"levels": {3}, "lvls": "L3", "obj": "D",
		"name": "Operation resilience for equipment",
		"req": "assess the requirement for redundant networking and telecommunication systems, implementing and protecting them where required",
	},
}
