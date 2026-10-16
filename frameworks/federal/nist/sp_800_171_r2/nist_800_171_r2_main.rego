# NIST SP 800-171 Revision 2 — Protecting Controlled Unclassified Information in
# Nonfederal Systems and Organizations: the 110 security requirements (3.1.1–3.14.7).
#
# Source of truth: NIST CPRT JSON export of SP_800_171_2_0_0, retrieved 2026-10-13
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_2_0_0/export/json?element=all
#   sha256 7e4bae9b7df6ea0724416057a2ea1b972c03475c9fef066e0cb0568a9436597a
# Every requirement id, requirement text, family title and the basic/derived
# classification below is generated verbatim from that export (NIST text is
# public domain; family titles are upper-case because the export spells them so).
# Measured in the export: 110 `requirement` elements, 14 `family` elements,
# 2 `requirement_type` elements (RT_basic: 31 requirements, RT_derived: 79),
# 110 `discussion` elements (not carried). Rev 2 has no withdrawn requirements
# and the export defines no profiles or levels, so none are modelled here.
#
# Why Rev 2 is kept beside Rev 3: Rev 3 is the current NIST revision (the CPRT
# export SP_800_171_3_0_0 lists 130 requirement elements, 33 withdrawn: 97 active,
# numbered 03.xx.yy), and it lives in frameworks/federal/nist/sp_800_171/. But
# DFARS 252.204-7012 and CMMC 2.0 Level 2 still assess these 110 Rev 2
# requirements, so defense contractors are assessed against Rev 2 until the
# clause moves. This module is the Rev 2 catalogue as an attestation table,
# generated from NIST's own export.
#
# Shape (like frameworks/financial/bnm_rmit): one control per requirement,
# attested from the organization's assessment evidence (SSP / assessment
# record) as input.nist_sp_800_171_r2.requirements["3.1.1"] == true.
#
# Fail-closed:
#   - absent or non-object input.nist_sp_800_171_r2 is an explicit FAIL-CLOSED violation
#   - every requirement must be attested with the boolean true; absent, false,
#     "true" or any other value is a violation naming the requirement
#   - attestation for an id that is not a Rev 2 requirement is a violation (typo guard,
#     also catches Rev 3 ids such as "03.01.01")
#   - a non-object requirements container is a violation
#
# Input contract — input.nist_sp_800_171_r2.*
#   requirements — object: {"<requirement id>": true, ...}, e.g. {"3.1.1": true}
#
# Report: per-family attestation totals and gaps, basic/derived split.
# Query: POST /v1/data/nist/sp800_171_r2/main/compliance_report

# METADATA
# title: "NIST SP 800-171 Rev 2 — 110 security requirements (DFARS 252.204-7012 / CMMC 2.0 Level 2)"
# custom:
#   class: compliance
#   framework: nist_sp_800_171_r2
#   source: nist
#   domains: [us-federal, cui]
#   coverage:
#     checks: 114
#     cited: 112
#     expected: 110
#     found: 112
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171_r2.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

source := {
	"document": "NIST SP 800-171 Revision 2",
	"cprt_export": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_2_0_0/export/json?element=all",
	"sha256": "7e4bae9b7df6ea0724416057a2ea1b972c03475c9fef066e0cb0568a9436597a",
	"retrieved": "2026-10-13",
}

# family id -> title (CPRT `family` elements)
families := {
	"3.1": "ACCESS CONTROL",
	"3.2": "AWARENESS AND TRAINING",
	"3.3": "AUDIT AND ACCOUNTABILITY",
	"3.4": "CONFIGURATION MANAGEMENT",
	"3.5": "IDENTIFICATION AND AUTHENTICATION",
	"3.6": "INCIDENT RESPONSE",
	"3.7": "MAINTENANCE",
	"3.8": "MEDIA PROTECTION",
	"3.9": "PERSONNEL SECURITY",
	"3.10": "PHYSICAL PROTECTION",
	"3.11": "RISK ASSESSMENT",
	"3.12": "SECURITY ASSESSMENT",
	"3.13": "SYSTEM AND COMMUNICATIONS PROTECTION",
	"3.14": "SYSTEM AND INFORMATION INTEGRITY",
}

# requirement id -> family, CPRT requirement_type (basic | derived), text
requirements := {
	# ── 3.1 ACCESS CONTROL (22)
	"3.1.1": {"family": "3.1", "type": "basic", "text": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems)."},
	"3.1.2": {"family": "3.1", "type": "basic", "text": "Limit system access to the types of transactions and functions that authorized users are permitted to execute."},
	"3.1.3": {"family": "3.1", "type": "derived", "text": "Control the flow of CUI in accordance with approved authorizations."},
	"3.1.4": {"family": "3.1", "type": "derived", "text": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion."},
	"3.1.5": {"family": "3.1", "type": "derived", "text": "Employ the principle of least privilege, including for specific security functions and privileged accounts."},
	"3.1.6": {"family": "3.1", "type": "derived", "text": "Use non-privileged accounts or roles when accessing nonsecurity functions."},
	"3.1.7": {"family": "3.1", "type": "derived", "text": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs."},
	"3.1.8": {"family": "3.1", "type": "derived", "text": "Limit unsuccessful logon attempts."},
	"3.1.9": {"family": "3.1", "type": "derived", "text": "Provide privacy and security notices consistent with applicable CUI rules."},
	"3.1.10": {"family": "3.1", "type": "derived", "text": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity."},
	"3.1.11": {"family": "3.1", "type": "derived", "text": "Terminate (automatically) a user session after a defined condition."},
	"3.1.12": {"family": "3.1", "type": "derived", "text": "Monitor and control remote access sessions."},
	"3.1.13": {"family": "3.1", "type": "derived", "text": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions."},
	"3.1.14": {"family": "3.1", "type": "derived", "text": "Route remote access via managed access control points."},
	"3.1.15": {"family": "3.1", "type": "derived", "text": "Authorize remote execution of privileged commands and remote access to security-relevant information."},
	"3.1.16": {"family": "3.1", "type": "derived", "text": "Authorize wireless access prior to allowing such connections."},
	"3.1.17": {"family": "3.1", "type": "derived", "text": "Protect wireless access using authentication and encryption."},
	"3.1.18": {"family": "3.1", "type": "derived", "text": "Control connection of mobile devices."},
	"3.1.19": {"family": "3.1", "type": "derived", "text": "Encrypt CUI on mobile devices and mobile computing platforms."},
	"3.1.20": {"family": "3.1", "type": "derived", "text": "Verify and control/limit connections to and use of external systems."},
	"3.1.21": {"family": "3.1", "type": "derived", "text": "Limit use of portable storage devices on external systems."},
	"3.1.22": {"family": "3.1", "type": "derived", "text": "Control CUI posted or processed on publicly accessible systems."},
	# ── 3.2 AWARENESS AND TRAINING (3)
	"3.2.1": {"family": "3.2", "type": "basic", "text": "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems."},
	"3.2.2": {"family": "3.2", "type": "basic", "text": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities."},
	"3.2.3": {"family": "3.2", "type": "derived", "text": "Provide security awareness training on recognizing and reporting potential indicators of insider threat."},
	# ── 3.3 AUDIT AND ACCOUNTABILITY (9)
	"3.3.1": {"family": "3.3", "type": "basic", "text": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity."},
	"3.3.2": {"family": "3.3", "type": "basic", "text": "Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions."},
	"3.3.3": {"family": "3.3", "type": "derived", "text": "Review and update logged events."},
	"3.3.4": {"family": "3.3", "type": "derived", "text": "Alert in the event of an audit logging process failure."},
	"3.3.5": {"family": "3.3", "type": "derived", "text": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity."},
	"3.3.6": {"family": "3.3", "type": "derived", "text": "Provide audit record reduction and report generation to support on-demand analysis and reporting."},
	"3.3.7": {"family": "3.3", "type": "derived", "text": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records."},
	"3.3.8": {"family": "3.3", "type": "derived", "text": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion."},
	"3.3.9": {"family": "3.3", "type": "derived", "text": "Limit management of audit logging functionality to a subset of privileged users."},
	# ── 3.4 CONFIGURATION MANAGEMENT (9)
	"3.4.1": {"family": "3.4", "type": "basic", "text": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles."},
	"3.4.2": {"family": "3.4", "type": "basic", "text": "Establish and enforce security configuration settings for information technology products employed in organizational systems."},
	"3.4.3": {"family": "3.4", "type": "derived", "text": "Track, review, approve or disapprove, and log changes to organizational systems."},
	"3.4.4": {"family": "3.4", "type": "derived", "text": "Analyze the security impact of changes prior to implementation."},
	"3.4.5": {"family": "3.4", "type": "derived", "text": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems."},
	"3.4.6": {"family": "3.4", "type": "derived", "text": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities."},
	"3.4.7": {"family": "3.4", "type": "derived", "text": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services."},
	"3.4.8": {"family": "3.4", "type": "derived", "text": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software."},
	"3.4.9": {"family": "3.4", "type": "derived", "text": "Control and monitor user-installed software."},
	# ── 3.5 IDENTIFICATION AND AUTHENTICATION (11)
	"3.5.1": {"family": "3.5", "type": "basic", "text": "Identify system users, processes acting on behalf of users, and devices."},
	"3.5.2": {"family": "3.5", "type": "basic", "text": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems."},
	"3.5.3": {"family": "3.5", "type": "derived", "text": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts."},
	"3.5.4": {"family": "3.5", "type": "derived", "text": "Employ replay-resistant authentication mechanisms for network access to privileged and nonprivileged accounts."},
	"3.5.5": {"family": "3.5", "type": "derived", "text": "Prevent reuse of identifiers for a defined period."},
	"3.5.6": {"family": "3.5", "type": "derived", "text": "Disable identifiers after a defined period of inactivity."},
	"3.5.7": {"family": "3.5", "type": "derived", "text": "Enforce a minimum password complexity and change of characters when new passwords are created."},
	"3.5.8": {"family": "3.5", "type": "derived", "text": "Prohibit password reuse for a specified number of generations."},
	"3.5.9": {"family": "3.5", "type": "derived", "text": "Allow temporary password use for system logons with an immediate change to a permanent password."},
	"3.5.10": {"family": "3.5", "type": "derived", "text": "Store and transmit only cryptographically-protected passwords."},
	"3.5.11": {"family": "3.5", "type": "derived", "text": "Obscure feedback of authentication information."},
	# ── 3.6 INCIDENT RESPONSE (3)
	"3.6.1": {"family": "3.6", "type": "basic", "text": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities."},
	"3.6.2": {"family": "3.6", "type": "basic", "text": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization."},
	"3.6.3": {"family": "3.6", "type": "derived", "text": "Test the organizational incident response capability."},
	# ── 3.7 MAINTENANCE (6)
	"3.7.1": {"family": "3.7", "type": "basic", "text": "Perform maintenance on organizational systems."},
	"3.7.2": {"family": "3.7", "type": "basic", "text": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance."},
	"3.7.3": {"family": "3.7", "type": "derived", "text": "Ensure equipment removed for off-site maintenance is sanitized of any CUI."},
	"3.7.4": {"family": "3.7", "type": "derived", "text": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems."},
	"3.7.5": {"family": "3.7", "type": "derived", "text": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete."},
	"3.7.6": {"family": "3.7", "type": "derived", "text": "Supervise the maintenance activities of maintenance personnel without required access authorization."},
	# ── 3.8 MEDIA PROTECTION (9)
	"3.8.1": {"family": "3.8", "type": "basic", "text": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital."},
	"3.8.2": {"family": "3.8", "type": "basic", "text": "Limit access to CUI on system media to authorized users."},
	"3.8.3": {"family": "3.8", "type": "basic", "text": "Sanitize or destroy system media containing CUI before disposal or release for reuse."},
	"3.8.4": {"family": "3.8", "type": "derived", "text": "Mark media with necessary CUI markings and distribution limitations."},
	"3.8.5": {"family": "3.8", "type": "derived", "text": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas."},
	"3.8.6": {"family": "3.8", "type": "derived", "text": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards."},
	"3.8.7": {"family": "3.8", "type": "derived", "text": "Control the use of removable media on system components."},
	"3.8.8": {"family": "3.8", "type": "derived", "text": "Prohibit the use of portable storage devices when such devices have no identifiable owner."},
	"3.8.9": {"family": "3.8", "type": "derived", "text": "Protect the confidentiality of backup CUI at storage locations."},
	# ── 3.9 PERSONNEL SECURITY (2)
	"3.9.1": {"family": "3.9", "type": "basic", "text": "Screen individuals prior to authorizing access to organizational systems containing CUI."},
	"3.9.2": {"family": "3.9", "type": "basic", "text": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers."},
	# ── 3.10 PHYSICAL PROTECTION (6)
	"3.10.1": {"family": "3.10", "type": "basic", "text": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals."},
	"3.10.2": {"family": "3.10", "type": "basic", "text": "Protect and monitor the physical facility and support infrastructure for organizational systems."},
	"3.10.3": {"family": "3.10", "type": "derived", "text": "Escort visitors and monitor visitor activity."},
	"3.10.4": {"family": "3.10", "type": "derived", "text": "Maintain audit logs of physical access."},
	"3.10.5": {"family": "3.10", "type": "derived", "text": "Control and manage physical access devices."},
	"3.10.6": {"family": "3.10", "type": "derived", "text": "Enforce safeguarding measures for CUI at alternate work sites."},
	# ── 3.11 RISK ASSESSMENT (3)
	"3.11.1": {"family": "3.11", "type": "basic", "text": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI."},
	"3.11.2": {"family": "3.11", "type": "derived", "text": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified."},
	"3.11.3": {"family": "3.11", "type": "derived", "text": "Remediate vulnerabilities in accordance with risk assessments."},
	# ── 3.12 SECURITY ASSESSMENT (4)
	"3.12.1": {"family": "3.12", "type": "basic", "text": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application."},
	"3.12.2": {"family": "3.12", "type": "basic", "text": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems."},
	"3.12.3": {"family": "3.12", "type": "basic", "text": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls."},
	"3.12.4": {"family": "3.12", "type": "basic", "text": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems."},
	# ── 3.13 SYSTEM AND COMMUNICATIONS PROTECTION (16)
	"3.13.1": {"family": "3.13", "type": "basic", "text": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems."},
	"3.13.2": {"family": "3.13", "type": "basic", "text": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems."},
	"3.13.3": {"family": "3.13", "type": "derived", "text": "Separate user functionality from system management functionality."},
	"3.13.4": {"family": "3.13", "type": "derived", "text": "Prevent unauthorized and unintended information transfer via shared system resources."},
	"3.13.5": {"family": "3.13", "type": "derived", "text": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks."},
	"3.13.6": {"family": "3.13", "type": "derived", "text": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception)."},
	"3.13.7": {"family": "3.13", "type": "derived", "text": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling)."},
	"3.13.8": {"family": "3.13", "type": "derived", "text": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards."},
	"3.13.9": {"family": "3.13", "type": "derived", "text": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity."},
	"3.13.10": {"family": "3.13", "type": "derived", "text": "Establish and manage cryptographic keys for cryptography employed in organizational systems."},
	"3.13.11": {"family": "3.13", "type": "derived", "text": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI."},
	"3.13.12": {"family": "3.13", "type": "derived", "text": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device."},
	"3.13.13": {"family": "3.13", "type": "derived", "text": "Control and monitor the use of mobile code."},
	"3.13.14": {"family": "3.13", "type": "derived", "text": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies."},
	"3.13.15": {"family": "3.13", "type": "derived", "text": "Protect the authenticity of communications sessions."},
	"3.13.16": {"family": "3.13", "type": "derived", "text": "Protect the confidentiality of CUI at rest."},
	# ── 3.14 SYSTEM AND INFORMATION INTEGRITY (7)
	"3.14.1": {"family": "3.14", "type": "basic", "text": "Identify, report, and correct system flaws in a timely manner."},
	"3.14.2": {"family": "3.14", "type": "basic", "text": "Provide protection from malicious code at designated locations within organizational systems."},
	"3.14.3": {"family": "3.14", "type": "basic", "text": "Monitor system security alerts and advisories and take action in response."},
	"3.14.4": {"family": "3.14", "type": "derived", "text": "Update malicious code protection mechanisms when new releases are available."},
	"3.14.5": {"family": "3.14", "type": "derived", "text": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed."},
	"3.14.6": {"family": "3.14", "type": "derived", "text": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks."},
	"3.14.7": {"family": "3.14", "type": "derived", "text": "Identify unauthorized use of organizational systems."},
}

_supplied if is_object(input.nist_sp_800_171_r2)

_in := object.get(input, "nist_sp_800_171_r2", {})

_attested(id) if _in.requirements[id] == true

violations contains msg if {
	not _supplied
	msg := "NIST SP 800-171 Rev 2: FAIL-CLOSED - facts 'input.nist_sp_800_171_r2' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant"
}

violations contains msg if {
	some id, r in requirements
	not _attested(id)
	msg := sprintf("NIST SP 800-171 Rev 2 %v (%v %v, %v): %v — not attested", [id, r.family, families[r.family], r.type, r.text])
}

violations contains msg if {
	_supplied
	is_object(_in.requirements)
	some id, _ in _in.requirements
	not requirements[id]
	msg := sprintf("NIST SP 800-171 Rev 2 Input Contract: attestation for unknown id %v — not one of the 110 Rev 2 requirements (Rev 3 ids 03.xx.yy belong to frameworks/federal/nist/sp_800_171)", [id])
}

violations contains msg if {
	_supplied
	_in.requirements
	not is_object(_in.requirements)
	msg := "NIST SP 800-171 Rev 2 Input Contract: input.nist_sp_800_171_r2.requirements must be an object of {\"<requirement id>\": true}"
}

family_reports[f] := r if {
	some f, name in families
	ids := {id | some id; req := requirements[id]; req.family == f}
	passed := {id | some id in ids; _attested(id)}
	r := {
		"family": name,
		"requirements": count(ids),
		"basic": count({id | some id in ids; requirements[id].type == "basic"}),
		"derived": count({id | some id in ids; requirements[id].type == "derived"}),
		"attested": count(passed),
		"gaps": sort([id | some id in ids; not id in passed]),
	}
}

compliance_report := {
	"framework": "NIST SP 800-171 Revision 2",
	"standard": "Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations — 110 security requirements",
	"applies_via": "DFARS 252.204-7012 and CMMC 2.0 Level 2 assess the Rev 2 requirements",
	"source": source,
	"standard_total": 110,
	"requirements_attested": count([id | some id; _ = requirements[id]; _attested(id)]),
	"basic_attested": count([id | some id; r := requirements[id]; r.type == "basic"; _attested(id)]),
	"derived_attested": count([id | some id; r := requirements[id]; r.type == "derived"; _attested(id)]),
	"families": family_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
