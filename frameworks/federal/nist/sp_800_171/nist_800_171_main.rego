# NIST SP 800-171 Rev 3 — Protecting Controlled Unclassified Information in Nonfederal Systems and
# Organizations. Main entry point: one control per Rev 3 requirement.
#
# Source of truth: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export of
# SP 800-171 Rev 3 (doc_identifier SP_800_171_3_0_0, version 3.0.0),
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all
#   sha256 19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa, retrieved 2026-10-13.
# NIST text is public domain. Every id and every text string below is copied verbatim from that export by
# a generator; nothing is paraphrased. Parentage (family -> requirement -> statement -> determination)
# is taken from the export's `projection` relationships and was checked against the id spelling: zero
# disagreements.
#
# Id scheme (exactly the CPRT element_identifier values):
#   family        03.01 … 03.17                     (17)
#   requirement   03.01.01 … 03.17.03               (130 in the text: 97 active controls + 33 withdrawn)
#   statement     SR-03.01.01, SR-03.01.01.a, SR-03.01.01.c.01   (349 security_requirement elements)
# Statements keep CPRT's `SR-` prefix. The 349 are 97 requirement roots (29 carry the whole requirement
# text, 68 are empty containers for lettered items), 193 lettered items (.a, .b, …) and 59 numbered
# sub-items (.c.01, …). The numbered sub-items are list fragments of their lettered parent (for example
# SR-03.01.01.c.01 "Authorized users of the system,") — the export keeps them as separate elements and so
# does this table; they are not joined into sentences.
#
# Families:
#   03.01 Access Control                                16 requirements,  6 withdrawn
#   03.02 Awareness and Training                         2 requirements,  1 withdrawn
#   03.03 Audit and Accountability                       8 requirements,  1 withdrawn
#   03.04 Configuration Management                      10 requirements,  2 withdrawn
#   03.05 Identification and Authentication              8 requirements,  4 withdrawn
#   03.06 Incident Response                              5 requirements,  0 withdrawn
#   03.07 Maintenance                                    3 requirements,  3 withdrawn
#   03.08 Media Protection                               7 requirements,  2 withdrawn
#   03.09 Personnel Security                             2 requirements,  0 withdrawn
#   03.10 Physical Protection                            5 requirements,  3 withdrawn
#   03.11 Risk Assessment                                3 requirements,  1 withdrawn
#   03.12 Security Assessment and Monitoring             4 requirements,  1 withdrawn
#   03.13 System and Communications Protection          10 requirements,  6 withdrawn
#   03.14 System and Information Integrity               5 requirements,  3 withdrawn
#   03.15 Planning                                       3 requirements,  0 withdrawn
#   03.16 System and Services Acquisition                3 requirements,  0 withdrawn
#   03.17 Supply Chain Risk Management                   3 requirements,  0 withdrawn
#
# Withdrawn requirements (33) are not controls. They are listed in `withdrawn` with CPRT's withdraw_reason
# and the incorporated_into / addressed_by relationships, and an attestation that names one is rejected.
#
# How a requirement is evaluated (fail-closed); `basis` in the report says which applies:
#   facts         79 requirements are decided by the fact checks of the family modules in this
#                 directory (data.nist.sp800_171.<family>, written against Rev 2 statements, facts under
#                 input.nist_800_171.<family> and input.cui_access). Each Rev 2 check is keyed to the Rev 3
#                 requirement in the same slot (Rev 3 keeps the Rev 2 numbering; the CPRT withdraw reasons cite
#                 those slots); a Rev 2 slot withdrawn in Rev 3 as "Incorporated into X" is keyed to X. Every
#                 mapped check must pass. An attestation for one of these ids is accepted but does not decide it.
#   attestation   18 requirements have no fact check and are attested, the way bnm_rmit is:
#                 input.nist_sp_800_171.requirements["<id>"] == true. They are:
#                 03.04.10, 03.04.11, 03.04.12, 03.05.12, 03.06.04, 03.06.05, 03.10.08, 03.11.04, 03.12.05, 03.14.08,
#                 03.15.01, 03.15.03, 03.16.01, 03.16.02, 03.16.03, 03.17.01, 03.17.02, 03.17.03.
#   retired       11 Rev 2 fact checks whose slot is withdrawn as "Addressed by", "Recategorized as NCO",
#                 "Technology-specific" or "Consistency with SP 800-53" gate nothing:
#                 3.1.13, 3.4.9, 3.5.6, 3.5.8, 3.5.9, 3.7.1, 3.13.2, 3.13.3, 3.13.7, 3.13.14, 3.14.5.
# Missing or non-object input.nist_sp_800_171.requirements is a FAIL-CLOSED violation (the 18 attested
# requirements cannot be evaluated without it); a failed fact check, a non-true attestation, an unknown id
# or a withdrawn id is a violation. Caveat: a Rev 2-shaped fact check is narrower than its Rev 3 requirement
# (03.01.01 has parts a-h; its check is three Rev 2 booleans), so a passing fact basis is not a full Rev 3
# determination — SP 800-171A (frameworks/federal/nist/sp_800_171a) is the statement-level assessment.
#
# Query: POST /v1/data/nist_800_171/main/compliance_report

# METADATA
# title: "NIST SP 800-171 Rev 3 — 97 requirements (CPRT ids), fact-evaluated or attested"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 50
#     cited: 47
#     expected: 97
#     found: 124
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist_800_171.main

import rego.v1

source := {
	"publication": "NIST SP 800-171 Rev 3",
	"doc_identifier": "SP_800_171_3_0_0",
	"version": "3.0.0",
	"website": "https://csrc.nist.gov/pubs/sp/800/171/r3/final",
	"export_url": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all",
	"export_sha256": "19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa",
	"retrieved": "2026-10-13",
}

families := {
	"03.01": "Access Control",
	"03.02": "Awareness and Training",
	"03.03": "Audit and Accountability",
	"03.04": "Configuration Management",
	"03.05": "Identification and Authentication",
	"03.06": "Incident Response",
	"03.07": "Maintenance",
	"03.08": "Media Protection",
	"03.09": "Personnel Security",
	"03.10": "Physical Protection",
	"03.11": "Risk Assessment",
	"03.12": "Security Assessment and Monitoring",
	"03.13": "System and Communications Protection",
	"03.14": "System and Information Integrity",
	"03.15": "Planning",
	"03.16": "System and Services Acquisition",
	"03.17": "Supply Chain Risk Management",
}

requirements := {
	"03.01.01": {
		"family": "03.01",
		"title": "Account Management",
		"statements": {
			"SR-03.01.01": "",
			"SR-03.01.01.a": "Define the types of system accounts allowed and prohibited.",
			"SR-03.01.01.b": "Create, enable, modify, disable, and remove system accounts in accordance with policy, procedures, prerequisites, and criteria.",
			"SR-03.01.01.c": "Specify:",
			"SR-03.01.01.c.01": "Authorized users of the system,",
			"SR-03.01.01.c.02": "Group and role membership, and",
			"SR-03.01.01.c.03": "Access authorizations (i.e., privileges) for each account.",
			"SR-03.01.01.d": "Authorize access to the system based on:",
			"SR-03.01.01.d.01": "A valid access authorization and",
			"SR-03.01.01.d.02": "Intended system usage.",
			"SR-03.01.01.e": "Monitor the use of system accounts.",
			"SR-03.01.01.f": "Disable system accounts when:",
			"SR-03.01.01.f.01": "The accounts have expired,",
			"SR-03.01.01.f.02": "The accounts have been inactive for [Assignment: organization-defined time period],",
			"SR-03.01.01.f.03": "The accounts are no longer associated with a user or individual,",
			"SR-03.01.01.f.04": "The accounts are in violation of organizational policy, or",
			"SR-03.01.01.f.05": "Significant risks associated with individuals are discovered.",
			"SR-03.01.01.g": "Notify account managers and designated personnel or roles within:",
			"SR-03.01.01.g.01": "[Assignment: organization-defined time period] when accounts are no longer required.",
			"SR-03.01.01.g.02": "[Assignment: organization-defined time period] when users are terminated or transferred.",
			"SR-03.01.01.g.03": "[Assignment: organization-defined time period] when system usage or the need-to-know changes for an individual.",
			"SR-03.01.01.h": "Require that users log out of the system after [Assignment: organization-defined time period] of expected inactivity or when [Assignment: organization-defined circumstances].",
		},
	},
	"03.01.02": {
		"family": "03.01",
		"title": "Access Enforcement",
		"statements": {"SR-03.01.02": "Enforce approved authorizations for logical access to CUI and system resources in accordance with applicable access control policies."},
	},
	"03.01.03": {
		"family": "03.01",
		"title": "Information Flow Enforcement",
		"statements": {"SR-03.01.03": "Enforce approved authorizations for controlling the flow of CUI within the system and between connected systems."},
	},
	"03.01.04": {
		"family": "03.01",
		"title": "Separation of Duties",
		"statements": {
			"SR-03.01.04": "",
			"SR-03.01.04.a": "Identify the duties of individuals requiring separation.",
			"SR-03.01.04.b": "Define system access authorizations to support separation of duties.",
		},
	},
	"03.01.05": {
		"family": "03.01",
		"title": "Least Privilege",
		"statements": {
			"SR-03.01.05": "",
			"SR-03.01.05.a": "Allow only authorized system access for users (or processes acting on behalf of users) that is necessary to accomplish assigned organizational tasks.",
			"SR-03.01.05.b": "Authorize access to [Assignment: organization-defined security functions] and [Assignment: organization-defined security-relevant information].",
			"SR-03.01.05.c": "Review the privileges assigned to roles or classes of users [Assignment: organization-defined frequency] to validate the need for such privileges.",
			"SR-03.01.05.d": "Reassign or remove privileges, as necessary.",
		},
	},
	"03.01.06": {
		"family": "03.01",
		"title": "Least Privilege – Privileged Accounts",
		"statements": {
			"SR-03.01.06": "",
			"SR-03.01.06.a": "Restrict privileged accounts on the system to [Assignment: organization-defined personnel or roles]..",
			"SR-03.01.06.b": "Require that users (or roles) with privileged accounts use non-privileged accounts when accessing non-security functions or non-security information.",
		},
	},
	"03.01.07": {
		"family": "03.01",
		"title": "Least Privilege – Privileged Functions",
		"statements": {
			"SR-03.01.07": "",
			"SR-03.01.07.a": "Prevent non-privileged users from executing privileged functions.",
			"SR-03.01.07.b": "Log the execution of privileged functions.",
		},
	},
	"03.01.08": {
		"family": "03.01",
		"title": "Unsuccessful Logon Attempts",
		"statements": {
			"SR-03.01.08": "",
			"SR-03.01.08.a": "Enforce a limit of [Assignment: organization-defined number] consecutive invalid logon attempts by a user during a [Assignment: organization-defined time period].",
			"SR-03.01.08.b": "Automatically [Selection (one or more): lock the account or node for an [Assignment: organization-defined time period]; lock the account or node until released by an administrator; delay next logon prompt; notify system administrator; take other action] when the maximum number of unsuccessful attempts is exceeded.",
		},
	},
	"03.01.09": {
		"family": "03.01",
		"title": "System Use Notification",
		"statements": {"SR-03.01.09": "Display a system use notification message with privacy and security notices consistent with applicable CUI rules before granting access to the system."},
	},
	"03.01.10": {
		"family": "03.01",
		"title": "Device Lock",
		"statements": {
			"SR-03.01.10": "",
			"SR-03.01.10.a": "Prevent access to the system by [Selection (one or more): initiating a device lock after [Assignment: organization-defined time period] of inactivity; requiring the user to initiate a device lock before leaving the system unattended].",
			"SR-03.01.10.b": "Retain the device lock until the user reestablishes access using established identification and authentication procedures.",
			"SR-03.01.10.c": "Conceal, via the device lock, information previously visible on the display with a publicly viewable image.",
		},
	},
	"03.01.11": {
		"family": "03.01",
		"title": "Session Termination",
		"statements": {"SR-03.01.11": "Terminate a user session automatically after [Assignment: organization-defined conditions or trigger events requiring session disconnect]."},
	},
	"03.01.12": {
		"family": "03.01",
		"title": "Remote Access",
		"statements": {
			"SR-03.01.12": "",
			"SR-03.01.12.a": "Establish usage restrictions, configuration requirements, and connection requirements for each type of allowable remote system access.",
			"SR-03.01.12.b": "Authorize each type of remote system access prior to establishing such connections.",
			"SR-03.01.12.c": "Route remote access to the system through authorized and managed access control points.",
			"SR-03.01.12.d": "Authorize the remote execution of privileged commands and remote access to security-relevant information.",
		},
	},
	"03.01.16": {
		"family": "03.01",
		"title": "Wireless Access",
		"statements": {
			"SR-03.01.16": "",
			"SR-03.01.16.a": "Establish usage restrictions, configuration requirements, and connection requirements for each type of wireless access to the system.",
			"SR-03.01.16.b": "Authorize each type of wireless access to the system prior to establishing such connections.",
			"SR-03.01.16.c": "Disable, when not intended for use, wireless networking capabilities prior to issuance and deployment.",
			"SR-03.01.16.d": "Protect wireless access to the system using authentication and encryption.",
		},
	},
	"03.01.18": {
		"family": "03.01",
		"title": "Access Control for Mobile Devices",
		"statements": {
			"SR-03.01.18": "",
			"SR-03.01.18.a": "Establish usage restrictions, configuration requirements, and connection requirements for mobile devices.",
			"SR-03.01.18.b": "Authorize the connection of mobile devices to the system.",
			"SR-03.01.18.c": "Implement full-device or container-based encryption to protect the confidentiality of CUI on mobile devices.",
		},
	},
	"03.01.20": {
		"family": "03.01",
		"title": "Use of External Systems",
		"statements": {
			"SR-03.01.20": "",
			"SR-03.01.20.a": "Prohibit the use of external systems unless the systems are specifically authorized.",
			"SR-03.01.20.b": "Establish the following security requirements to be satisfied on external systems prior to allowing use of or access to those systems by authorized individuals: [Assignment: organization-defined security requirements].",
			"SR-03.01.20.c": "Permit authorized individuals to use external systems to access the organizational system or to process, store, or transmit CUI only after:",
			"SR-03.01.20.c.01": "Verifying that the security requirements on the external systems as specified in the organization’s system security plans have been satisfied and",
			"SR-03.01.20.c.02": "Retaining approved system connection or processing agreements with the organizational entities hosting the external systems.",
			"SR-03.01.20.d": "Restrict the use of organization-controlled portable storage devices by authorized individuals on external systems.",
		},
	},
	"03.01.22": {
		"family": "03.01",
		"title": "Publicly Accessible Content",
		"statements": {
			"SR-03.01.22": "",
			"SR-03.01.22.a": "Train authorized individuals to ensure that publicly accessible information does not contain CUI.",
			"SR-03.01.22.b": "Review the content on publicly accessible systems for CUI and remove such information, if discovered.",
		},
	},
	"03.02.01": {
		"family": "03.02",
		"title": "Literacy Training and Awareness",
		"statements": {
			"SR-03.02.01": "",
			"SR-03.02.01.a": "Provide security literacy training to system users:",
			"SR-03.02.01.a.01": "As part of initial training for new users and [Assignment: organization-defined frequency] thereafter,",
			"SR-03.02.01.a.02": "When required by system changes or following [Assignment: organization-defined events], and",
			"SR-03.02.01.a.03": "On recognizing and reporting indicators of insider threat, social engineering, and social mining.",
			"SR-03.02.01.b": "Update security literacy training content [Assignment: organization-defined frequency] and following [Assignment: organization-defined events].",
		},
	},
	"03.02.02": {
		"family": "03.02",
		"title": "Role-Based Training",
		"statements": {
			"SR-03.02.02": "",
			"SR-03.02.02.a": "Provide role-based security training to organizational personnel:",
			"SR-03.02.02.a.01": "Before authorizing access to the system or CUI, before performing assigned duties, and [Assignment: organization-defined frequency] thereafter",
			"SR-03.02.02.a.02": "When required by system changes or following [Assignment: organization-defined events].",
			"SR-03.02.02.b": "Update role-based training content [Assignment: organization-defined frequency] and following [Assignment: organization-defined events].",
		},
	},
	"03.03.01": {
		"family": "03.03",
		"title": "Event Logging",
		"statements": {
			"SR-03.03.01": "",
			"SR-03.03.01.a": "Specify the following event types selected for logging within the system: [Assignment: organization-defined event types].",
			"SR-03.03.01.b": "Review and update the event types selected for logging [Assignment: organization-defined frequency].",
		},
	},
	"03.03.02": {
		"family": "03.03",
		"title": "Audit Record Content",
		"statements": {
			"SR-03.03.02": "",
			"SR-03.03.02.a": "Include the following content in audit records:",
			"SR-03.03.02.a.01": "What type of event occurred",
			"SR-03.03.02.a.02": "When the event occurred",
			"SR-03.03.02.a.03": "Where the event occurred",
			"SR-03.03.02.a.04": "Source of the event",
			"SR-03.03.02.a.05": "Outcome of the event",
			"SR-03.03.02.a.06": "Identity of the individuals, subjects, objects, or entities associated with the event",
			"SR-03.03.02.b": "Provide additional information for audit records as needed.",
		},
	},
	"03.03.03": {
		"family": "03.03",
		"title": "Audit Record Generation",
		"statements": {
			"SR-03.03.03": "",
			"SR-03.03.03.a": "Generate audit records for the selected event types and audit record content specified in 03.03.01 and 03.03.02.",
			"SR-03.03.03.b": "Retain audit records for a time period consistent with the records retention policy.",
		},
	},
	"03.03.04": {
		"family": "03.03",
		"title": "Response to Audit Logging Process Failures",
		"statements": {
			"SR-03.03.04": "",
			"SR-03.03.04.a": "Alert organizational personnel or roles within [Assignment: organization-defined time period] in the event of an audit logging process failure.",
			"SR-03.03.04.b": "Take the following additional actions: [Assignment: organization-defined additional actions].",
		},
	},
	"03.03.05": {
		"family": "03.03",
		"title": "Audit Record Review, Analysis, and Reporting",
		"statements": {
			"SR-03.03.05": "",
			"SR-03.03.05.a": "Review and analyze system audit records [Assignment: organization-defined frequency] for indications and the potential impact of inappropriate or unusual activity.",
			"SR-03.03.05.b": "Report findings to organizational personnel or roles.",
			"SR-03.03.05.c": "Analyze and correlate audit records across different repositories to gain organization-wide situational awareness.",
		},
	},
	"03.03.06": {
		"family": "03.03",
		"title": "Audit Record Reduction and Report Generation",
		"statements": {
			"SR-03.03.06": "",
			"SR-03.03.06.a": "Implement an audit record reduction and report generation capability that supports audit record review, analysis, reporting requirements, and after-the-fact investigations of incidents.",
			"SR-03.03.06.b": "Preserve the original content and time ordering of audit records.",
		},
	},
	"03.03.07": {
		"family": "03.03",
		"title": "Time Stamps",
		"statements": {
			"SR-03.03.07": "",
			"SR-03.03.07.a": "Use internal system clocks to generate time stamps for audit records.",
			"SR-03.03.07.b": "Record time stamps for audit records that meet [Assignment: organization-defined granularity of time measurement] and that use Coordinated Universal Time (UTC), have a fixed local time offset from UTC, or include the local time offset as part of the time stamp.",
		},
	},
	"03.03.08": {
		"family": "03.03",
		"title": "Protection of Audit Information",
		"statements": {
			"SR-03.03.08": "",
			"SR-03.03.08.a": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
			"SR-03.03.08.b": "Authorize access to management of audit logging functionality to only a subset of privileged users or roles.",
		},
	},
	"03.04.01": {
		"family": "03.04",
		"title": "Baseline Configuration",
		"statements": {
			"SR-03.04.01": "",
			"SR-03.04.01.a": "Develop and maintain under configuration control, a current baseline configuration of the system.",
			"SR-03.04.01.b": "Review and update the baseline configuration of the system [Assignment: organization-defined frequency] and when system components are installed or modified.",
		},
	},
	"03.04.02": {
		"family": "03.04",
		"title": "Configuration Settings",
		"statements": {
			"SR-03.04.02": "",
			"SR-03.04.02.a": "Establish, document, and implement the following configuration settings for the system that reflect the most restrictive mode consistent with operational requirements: [Assignment: organization-defined configuration settings].",
			"SR-03.04.02.b": "Identify, document, and approve any deviations from established configuration settings.",
		},
	},
	"03.04.03": {
		"family": "03.04",
		"title": "Configuration Change Control",
		"statements": {
			"SR-03.04.03": "",
			"SR-03.04.03.a": "Define the types of changes to the system that are configuration-controlled.",
			"SR-03.04.03.b": "Review proposed configuration-controlled changes to the system, and approve or disapprove such changes with explicit consideration for security impacts.",
			"SR-03.04.03.c": "Implement and document approved configuration-controlled changes to the system.",
			"SR-03.04.03.d": "Monitor and review activities associated with configuration-controlled changes to the system.",
		},
	},
	"03.04.04": {
		"family": "03.04",
		"title": "Impact Analyses",
		"statements": {
			"SR-03.04.04": "",
			"SR-03.04.04.a": "Analyze changes to the system to determine potential security impacts prior to change implementation.",
			"SR-03.04.04.b": "Verify that the security requirements for the system continue to be satisfied after the system changes have been implemented.",
		},
	},
	"03.04.05": {
		"family": "03.04",
		"title": "Access Restrictions for Change",
		"statements": {"SR-03.04.05": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system."},
	},
	"03.04.06": {
		"family": "03.04",
		"title": "Least Functionality",
		"statements": {
			"SR-03.04.06": "",
			"SR-03.04.06.a": "Configure the system to provide only mission-essential capabilities.",
			"SR-03.04.06.b": "Prohibit or restrict use of the following functions, ports, protocols, connections, and services: [Assignment: organization-defined functions, ports, protocols, connections, and services].",
			"SR-03.04.06.c": "Review the system [Assignment: organization-defined frequency] to identify unnecessary or nonsecure functions, ports, protocols, connections, and services.",
			"SR-03.04.06.d": "Disable or remove functions, ports, protocols, connections, and services that are unnecessary or nonsecure.",
		},
	},
	"03.04.08": {
		"family": "03.04",
		"title": "Authorized Software – Allow by Exception",
		"statements": {
			"SR-03.04.08": "",
			"SR-03.04.08.a": "Identify software programs authorized to execute on the system.",
			"SR-03.04.08.b": "Implement a deny-all, allow-by-exception policy for the execution of authorized software programs on the system.",
			"SR-03.04.08.c": "Review and update the list of authorized software programs [Assignment: organization-defined frequency].",
		},
	},
	"03.04.10": {
		"family": "03.04",
		"title": "System Component Inventory",
		"statements": {
			"SR-03.04.10": "",
			"SR-03.04.10.a": "Develop and document an inventory of system components.",
			"SR-03.04.10.b": "Review and update the system component inventory [Assignment: organization-defined frequency].",
			"SR-03.04.10.c": "Update the system component inventory as part of installations, removals, and system updates.",
		},
	},
	"03.04.11": {
		"family": "03.04",
		"title": "Information Location",
		"statements": {
			"SR-03.04.11": "",
			"SR-03.04.11.a": "Identify and document the location of CUI and the system components on which the information is processed and stored.",
			"SR-03.04.11.b": "Document changes to the system or system component location where CUI is processed and stored.",
		},
	},
	"03.04.12": {
		"family": "03.04",
		"title": "System and Component Configuration for High-Risk Areas",
		"statements": {
			"SR-03.04.12": "",
			"SR-03.04.12.a": "Issue systems or system components with the following configurations to individuals traveling to high-risk locations: [Assignment: organization-defined system configurations].",
			"SR-03.04.12.b": "Apply the following security requirements to the systems or components when the individuals return from travel: [Assignment: organization-defined security requirements].",
		},
	},
	"03.05.01": {
		"family": "03.05",
		"title": "User Identification and Authentication",
		"statements": {
			"SR-03.05.01": "",
			"SR-03.05.01.a": "Uniquely identify and authenticate system users, and associate that unique identification with processes acting on behalf of those users.",
			"SR-03.05.01.b": "Re-authenticate users when [Assignment: organization-defined circumstances or situations requiring re-authentication].",
		},
	},
	"03.05.02": {
		"family": "03.05",
		"title": "Device Identification and Authentication",
		"statements": {"SR-03.05.02": "Uniquely identify and authenticate [Assignment: organization-defined devices or types of devices] before establishing a system connection."},
	},
	"03.05.03": {
		"family": "03.05",
		"title": "Multi-Factor Authentication",
		"statements": {"SR-03.05.03": "Implement multi-factor authentication for access to privileged and non-privileged accounts."},
	},
	"03.05.04": {
		"family": "03.05",
		"title": "Replay-Resistant Authentication",
		"statements": {"SR-03.05.04": "Implement replay-resistant authentication mechanisms for access to privileged and non-privileged accounts."},
	},
	"03.05.05": {
		"family": "03.05",
		"title": "Identifier Management",
		"statements": {
			"SR-03.05.05": "",
			"SR-03.05.05.a": "Receive authorization from organizational personnel or roles to assign an individual, group, role, service, or device identifier.",
			"SR-03.05.05.b": "Select and assign an identifier that identifies an individual, group, role, service, or device.",
			"SR-03.05.05.c": "Prevent the reuse of identifiers for [Assignment: organization-defined time period].",
			"SR-03.05.05.d": "Manage individual identifiers by uniquely identifying each individual as [Assignment: organization-defined characteristic identifying individual status].",
		},
	},
	"03.05.07": {
		"family": "03.05",
		"title": "Password Management",
		"statements": {
			"SR-03.05.07": "",
			"SR-03.05.07.a": "Maintain a list of commonly-used, expected, or compromised passwords, and update the list [Assignment: organization-defined frequency] and when organizational passwords are suspected to have been compromised.",
			"SR-03.05.07.b": "Verify that passwords are not found on the list of commonly used, expected, or compromised passwords when users create or update passwords.",
			"SR-03.05.07.c": "Transmit passwords only over cryptographically protected channels.",
			"SR-03.05.07.d": "Store passwords in a cryptographically protected form.",
			"SR-03.05.07.e": "Select a new password upon first use after account recovery.",
			"SR-03.05.07.f": "Enforce the following composition and complexity rules for passwords: [Assignment: organization-defined composition and complexity rules].",
		},
	},
	"03.05.11": {
		"family": "03.05",
		"title": "Authentication Feedback",
		"statements": {"SR-03.05.11": "Obscure feedback of authentication information during the authentication process."},
	},
	"03.05.12": {
		"family": "03.05",
		"title": "Authenticator Management",
		"statements": {
			"SR-03.05.12": "",
			"SR-03.05.12.a": "Verify the identity of the individual, group, role, service, or device receiving the authenticator as part of the initial authenticator distribution.",
			"SR-03.05.12.b": "Establish initial authenticator content for any authenticators issued by the organization.",
			"SR-03.05.12.c": "Establish and implement administrative procedures for initial authenticator distribution; for lost, compromised, or damaged authenticators; and for revoking authenticators.",
			"SR-03.05.12.d": "Change default authenticators at first use.",
			"SR-03.05.12.e": "Change or refresh authenticators [Assignment: organization-defined frequency] or when the following events occur: [Assignment: organization-defined events].",
			"SR-03.05.12.f": "Protect authenticator content from unauthorized disclosure and modification.",
		},
	},
	"03.06.01": {
		"family": "03.06",
		"title": "Incident Handling",
		"statements": {"SR-03.06.01": "Implement an incident-handling capability that is consistent with the incident response plan and includes preparation, detection and analysis, containment, eradication, and recovery."},
	},
	"03.06.02": {
		"family": "03.06",
		"title": "Incident Monitoring, Reporting, and Response Assistance",
		"statements": {
			"SR-03.06.02": "",
			"SR-03.06.02.a": "Track and document system security incidents.",
			"SR-03.06.02.b": "Report suspected incidents to the organizational incident response capability within [Assignment: organization-defined time period].",
			"SR-03.06.02.c": "Report incident information to [Assignment: organization-defined authorities].",
			"SR-03.06.02.d": "Provide an incident response support resource that offers advice and assistance to system users on handling and reporting incidents.",
		},
	},
	"03.06.03": {
		"family": "03.06",
		"title": "Incident Response Testing",
		"statements": {"SR-03.06.03": "Test the effectiveness of the incident response capability [Assignment: organization-defined frequency]."},
	},
	"03.06.04": {
		"family": "03.06",
		"title": "Incident Response Training",
		"statements": {
			"SR-03.06.04": "",
			"SR-03.06.04.a": "Provide incident response training to system users consistent with assigned roles and responsibilities:",
			"SR-03.06.04.a.01": "Within [Assignment: organization-defined time period] of assuming an incident response role or responsibility or acquiring system access,",
			"SR-03.06.04.a.02": "When required by system changes, and",
			"SR-03.06.04.a.03": "[Assignment: organization-defined frequency] thereafter.",
			"SR-03.06.04.b": "Review and update incident response training content [Assignment: organization-defined frequency] and following [Assignment: organization-defined events].",
		},
	},
	"03.06.05": {
		"family": "03.06",
		"title": "Incident Response Plan",
		"statements": {
			"SR-03.06.05": "",
			"SR-03.06.05.a": "Develop an incident response plan that:",
			"SR-03.06.05.a.01": "Provides the organization with a roadmap for implementing its incident response capability,",
			"SR-03.06.05.a.02": "Describes the structure and organization of the incident response capability,",
			"SR-03.06.05.a.03": "Provides a high-level approach for how the incident response capability fits into the overall organization,",
			"SR-03.06.05.a.04": "Defines reportable incidents,",
			"SR-03.06.05.a.05": "Addresses the sharing of incident information, and",
			"SR-03.06.05.a.06": "Designates responsibilities to organizational entities, personnel, or roles.",
			"SR-03.06.05.b": "Distribute copies of the incident response plan to designated incident response personnel (identified by name and/or by role) and organizational elements.",
			"SR-03.06.05.c": "Update the incident response plan to address system and organizational changes or problems encountered during plan implementation, execution, or testing.",
			"SR-03.06.05.d": "Protect the incident response plan from unauthorized disclosure.",
		},
	},
	"03.07.04": {
		"family": "03.07",
		"title": "Maintenance Tools",
		"statements": {
			"SR-03.07.04": "",
			"SR-03.07.04.a": "Approve, control, and monitor the use of system maintenance tools.",
			"SR-03.07.04.b": "Check media with diagnostic and test programs for malicious code before it is used in the system.",
			"SR-03.07.04.c": "Prevent the removal of system maintenance equipment containing CUI by verifying that there is no CUI on the equipment, sanitizing or destroying the equipment, or retaining the equipment within the facility.",
		},
	},
	"03.07.05": {
		"family": "03.07",
		"title": "Nonlocal Maintenance",
		"statements": {
			"SR-03.07.05": "",
			"SR-03.07.05.a": "Approve and monitor nonlocal maintenance and diagnostic activities.",
			"SR-03.07.05.b": "Implement multi-factor authentication and replay resistance in the establishment of nonlocal maintenance and diagnostic sessions.",
			"SR-03.07.05.c": "Terminate session and network connections when nonlocal maintenance is completed.",
		},
	},
	"03.07.06": {
		"family": "03.07",
		"title": "Maintenance Personnel",
		"statements": {
			"SR-03.07.06": "",
			"SR-03.07.06.a": "Establish a process for maintenance personnel authorization.",
			"SR-03.07.06.b": "Maintain a list of authorized maintenance organizations or personnel.",
			"SR-03.07.06.c": "Verify that non-escorted personnel who perform maintenance on the system possess the required access authorizations.",
			"SR-03.07.06.d": "Designate organizational personnel with required access authorizations and technical competence to supervise the maintenance activities of personnel who do not possess the required access authorizations.",
		},
	},
	"03.08.01": {
		"family": "03.08",
		"title": "Media Storage",
		"statements": {"SR-03.08.01": "Physically control and securely store system media that contain CUI."},
	},
	"03.08.02": {
		"family": "03.08",
		"title": "Media Access",
		"statements": {"SR-03.08.02": "Restrict access to CUI on system media to authorized personnel or roles."},
	},
	"03.08.03": {
		"family": "03.08",
		"title": "Media Sanitization",
		"statements": {"SR-03.08.03": "Sanitize system media that contain CUI prior to disposal, release out of organizational control, or release for reuse."},
	},
	"03.08.04": {
		"family": "03.08",
		"title": "Media Marking",
		"statements": {"SR-03.08.04": "Mark system media that contain CUI to indicate distribution limitations, handling caveats, and applicable CUI markings."},
	},
	"03.08.05": {
		"family": "03.08",
		"title": "Media Transport",
		"statements": {
			"SR-03.08.05": "",
			"SR-03.08.05.a": "Protect and control system media that contain CUI during transport outside of controlled areas.",
			"SR-03.08.05.b": "Maintain accountability of system media that contain CUI during transport outside of controlled areas.",
			"SR-03.08.05.c": "Document activities associated with the transport of system media that contain CUI.",
		},
	},
	"03.08.07": {
		"family": "03.08",
		"title": "Media Use",
		"statements": {
			"SR-03.08.07": "",
			"SR-03.08.07.a": "Restrict or prohibit the use of [Assignment: organization-defined types of system media].",
			"SR-03.08.07.b": "Prohibit the use of removable system media without an identifiable owner.",
		},
	},
	"03.08.09": {
		"family": "03.08",
		"title": "System Backup – Cryptographic Protection",
		"statements": {
			"SR-03.08.09": "",
			"SR-03.08.09.a": "Protect the confidentiality of backup information.",
			"SR-03.08.09.b": "Implement cryptographic mechanisms to prevent the unauthorized disclosure of CUI at backup storage locations.",
		},
	},
	"03.09.01": {
		"family": "03.09",
		"title": "Personnel Screening",
		"statements": {
			"SR-03.09.01": "",
			"SR-03.09.01.a": "Screen individuals prior to authorizing access to the system.",
			"SR-03.09.01.b": "Rescreen individuals in accordance with [Assignment: organization-defined conditions requiring rescreening].",
		},
	},
	"03.09.02": {
		"family": "03.09",
		"title": "Personnel Termination and Transfer",
		"statements": {
			"SR-03.09.02": "",
			"SR-03.09.02.a": "When individual employment is terminated:",
			"SR-03.09.02.a.01": "Disable system access within [Assignment: organization-defined time period],",
			"SR-03.09.02.a.02": "Terminate or revoke authenticators and credentials associated with the individual, and",
			"SR-03.09.02.a.03": "Retrieve security-related system property.",
			"SR-03.09.02.b": "When individuals are reassigned or transferred to other positions in the organization:",
			"SR-03.09.02.b.01": "Review and confirm the ongoing operational need for current logical and physical access authorizations to the system and facility, and",
			"SR-03.09.02.b.02": "Modify access authorization to correspond with any changes in operational need.",
		},
	},
	"03.10.01": {
		"family": "03.10",
		"title": "Physical Access Authorizations",
		"statements": {
			"SR-03.10.01": "",
			"SR-03.10.01.a": "Develop, approve, and maintain a list of individuals with authorized access to the facility where the system resides.",
			"SR-03.10.01.b": "Issue authorization credentials for facility access.",
			"SR-03.10.01.c": "Review the facility access list [Assignment: organization-defined frequency].",
			"SR-03.10.01.d": "Remove individuals from the facility access list when access is no longer required.",
		},
	},
	"03.10.02": {
		"family": "03.10",
		"title": "Monitoring Physical Access",
		"statements": {
			"SR-03.10.02": "",
			"SR-03.10.02.a": "Monitor physical access to the facility where the system resides to detect and respond to physical security incidents.",
			"SR-03.10.02.b": "Review physical access logs [Assignment: organization-defined frequency] and upon occurrence of [Assignment: organization-defined events or potential indications of events].",
		},
	},
	"03.10.06": {
		"family": "03.10",
		"title": "Alternate Work Site",
		"statements": {
			"SR-03.10.06": "",
			"SR-03.10.06.a": "Determine alternate work sites allowed for use by employees.",
			"SR-03.10.06.b": "Employ the following security requirements at alternate work sites: [Assignment: organization-defined security requirements].",
		},
	},
	"03.10.07": {
		"family": "03.10",
		"title": "Physical Access Control",
		"statements": {
			"SR-03.10.07": "",
			"SR-03.10.07.a": "Enforce physical access authorizations at entry and exit points to the facility where the system resides by:",
			"SR-03.10.07.a.01": "Verifying individual physical access authorizations before granting access to the facility and",
			"SR-03.10.07.a.02": "Controlling ingress and egress with physical access control systems, devices, or guards.",
			"SR-03.10.07.b": "Maintain physical access audit logs for entry or exit points.",
			"SR-03.10.07.c": "Escort visitors, and control visitor activity.",
			"SR-03.10.07.d": "Secure keys, combinations, and other physical access devices.",
			"SR-03.10.07.e": "Control physical access to output devices to prevent unauthorized individuals from obtaining access to CUI.",
		},
	},
	"03.10.08": {
		"family": "03.10",
		"title": "Access Control for Transmission",
		"statements": {"SR-03.10.08": "Control physical access to system distribution and transmission lines within organizational facilities."},
	},
	"03.11.01": {
		"family": "03.11",
		"title": "Risk Assessment",
		"statements": {
			"SR-03.11.01": "",
			"SR-03.11.01.a": "Assess the risk (including supply chain risk) of unauthorized disclosure resulting from the processing, storage, or transmission of CUI.",
			"SR-03.11.01.b": "Update risk assessments [Assignment: organization-defined frequency].",
		},
	},
	"03.11.02": {
		"family": "03.11",
		"title": "Vulnerability Monitoring and Scanning",
		"statements": {
			"SR-03.11.02": "",
			"SR-03.11.02.a": "Monitor and scan the system for vulnerabilities [Assignment: organization-defined frequency] and when new vulnerabilities affecting the system are identified.",
			"SR-03.11.02.b": "Remediate system vulnerabilities within [Assignment: organization-defined response times].",
			"SR-03.11.02.c": "Update system vulnerabilities to be scanned [Assignment: organization-defined frequency] and when new vulnerabilities are identified and reported.",
		},
	},
	"03.11.04": {
		"family": "03.11",
		"title": "Risk Response",
		"statements": {"SR-03.11.04": "Respond to findings from security assessments, monitoring, and audits."},
	},
	"03.12.01": {
		"family": "03.12",
		"title": "Security Assessment",
		"statements": {"SR-03.12.01": "Assess the security requirements for the system and its environment of operation [Assignment: organization-defined frequency] to determine if the requirements have been satisfied."},
	},
	"03.12.02": {
		"family": "03.12",
		"title": "Plan of Action and Milestones",
		"statements": {
			"SR-03.12.02": "",
			"SR-03.12.02.a": "Develop a plan of action and milestones for the system:",
			"SR-03.12.02.a.01": "To document the planned remediation actions to correct weaknesses or deficiencies noted during security assessments and",
			"SR-03.12.02.a.02": "To reduce or eliminate known system vulnerabilities.",
			"SR-03.12.02.b": "Update the existing plan of action and milestones based on the findings from:",
			"SR-03.12.02.b.01": "Security assessments,",
			"SR-03.12.02.b.02": "Audits or reviews, and",
			"SR-03.12.02.b.03": "Continuous monitoring activities.",
		},
	},
	"03.12.03": {
		"family": "03.12",
		"title": "Continuous Monitoring",
		"statements": {"SR-03.12.03": "Develop and implement a system-level continuous monitoring strategy that includes ongoing monitoring and security assessments."},
	},
	"03.12.05": {
		"family": "03.12",
		"title": "Information Exchange",
		"statements": {
			"SR-03.12.05": "",
			"SR-03.12.05.a": "Approve and manage the exchange of CUI between the system and other systems using [Selection (one or more): interconnection security agreements; information exchange security agreements; memoranda of understanding or agreement; service-level agreements; user agreements; non-disclosure agreements; other types of agreements].",
			"SR-03.12.05.b": "Document interface characteristics, security requirements, and responsibilities for each system as part of the exchange agreements.",
			"SR-03.12.05.c": "Review and update the exchange agreements [Assignment: organization-defined frequency].",
		},
	},
	"03.13.01": {
		"family": "03.13",
		"title": "Boundary Protection",
		"statements": {
			"SR-03.13.01": "",
			"SR-03.13.01.a": "Monitor and control communications at external managed interfaces to the system and key internal managed interfaces within the system.",
			"SR-03.13.01.b": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
			"SR-03.13.01.c": "Connect to external systems only through managed interfaces that consist of boundary protection devices arranged in accordance with an organizational security architecture.",
		},
	},
	"03.13.04": {
		"family": "03.13",
		"title": "Information in Shared System Resources",
		"statements": {"SR-03.13.04": "Prevent unauthorized and unintended information transfer via shared system resources."},
	},
	"03.13.06": {
		"family": "03.13",
		"title": "Network Communications – Deny by Default – Allow by Exception",
		"statements": {"SR-03.13.06": "Deny network communications traffic by default, and allow network communications traffic by exception."},
	},
	"03.13.08": {
		"family": "03.13",
		"title": "Transmission and Storage Confidentiality",
		"statements": {"SR-03.13.08": "Implement cryptographic mechanisms to prevent the unauthorized disclosure of CUI during transmission and while in storage."},
	},
	"03.13.09": {
		"family": "03.13",
		"title": "Network Disconnect",
		"statements": {"SR-03.13.09": "Terminate the network connection associated with a communications session at the end of the session or after [Assignment: organization-defined time period] of inactivity."},
	},
	"03.13.10": {
		"family": "03.13",
		"title": "Cryptographic Key Establishment and Management",
		"statements": {"SR-03.13.10": "Establish and manage cryptographic keys in the system in accordance with the following key management requirements: [Assignment: organization-defined requirements for key generation, distribution, storage, access, and destruction]."},
	},
	"03.13.11": {
		"family": "03.13",
		"title": "Cryptographic Protection",
		"statements": {"SR-03.13.11": "Implement the following types of cryptography to protect the confidentiality of CUI: [Assignment: organization-defined types of cryptography]."},
	},
	"03.13.12": {
		"family": "03.13",
		"title": "Collaborative Computing Devices and Applications",
		"statements": {
			"SR-03.13.12": "",
			"SR-03.13.12.a": "Prohibit the remote activation of collaborative computing devices and applications with the following exceptions: [Assignment: organization-defined exceptions where remote activation is to be allowed].",
			"SR-03.13.12.b": "Provide an explicit indication of use to users physically present at the devices.",
		},
	},
	"03.13.13": {
		"family": "03.13",
		"title": "Mobile Code",
		"statements": {
			"SR-03.13.13": "",
			"SR-03.13.13.a": "Define acceptable mobile code and mobile code technologies.",
			"SR-03.13.13.b": "Authorize, monitor, and control the use of mobile code.",
		},
	},
	"03.13.15": {
		"family": "03.13",
		"title": "Session Authenticity",
		"statements": {"SR-03.13.15": "Protect the authenticity of communications sessions."},
	},
	"03.14.01": {
		"family": "03.14",
		"title": "Flaw Remediation",
		"statements": {
			"SR-03.14.01": "",
			"SR-03.14.01.a": "Identify, report, and correct system flaws.",
			"SR-03.14.01.b": "Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates.",
		},
	},
	"03.14.02": {
		"family": "03.14",
		"title": "Malicious Code Protection",
		"statements": {
			"SR-03.14.02": "",
			"SR-03.14.02.a": "Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.",
			"SR-03.14.02.b": "Update malicious code protection mechanisms as new releases are available in accordance with configuration management policies and procedures.",
			"SR-03.14.02.c": "Configure malicious code protection mechanisms to:",
			"SR-03.14.02.c.01": "Perform scans of the system [Assignment: organization-defined frequency] and real-time scans of files from external sources at endpoints or system entry and exit points as the files are downloaded, opened, or executed; and",
			"SR-03.14.02.c.02": "Block malicious code, quarantine malicious code, or take other mitigation actions in response to malicious code detection.",
		},
	},
	"03.14.03": {
		"family": "03.14",
		"title": "Security Alerts, Advisories, and Directives",
		"statements": {
			"SR-03.14.03": "",
			"SR-03.14.03.a": "Receive system security alerts, advisories, and directives from external organizations on an ongoing basis.",
			"SR-03.14.03.b": "Generate and disseminate internal system security alerts, advisories, and directives, as necessary.",
		},
	},
	"03.14.06": {
		"family": "03.14",
		"title": "System Monitoring",
		"statements": {
			"SR-03.14.06": "",
			"SR-03.14.06.a": "Monitor the system to detect:",
			"SR-03.14.06.a.01": "Attacks and indicators of potential attacks and",
			"SR-03.14.06.a.02": "Unauthorized connections.",
			"SR-03.14.06.b": "Identify unauthorized use of the system.",
			"SR-03.14.06.c": "Monitor inbound and outbound communications traffic to detect unusual or unauthorized activities or conditions.",
		},
	},
	"03.14.08": {
		"family": "03.14",
		"title": "Information Management and Retention",
		"statements": {"SR-03.14.08": "Manage and retain CUI within the system and CUI output from the system in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements."},
	},
	"03.15.01": {
		"family": "03.15",
		"title": "Policy and Procedures",
		"statements": {
			"SR-03.15.01": "",
			"SR-03.15.01.a": "Develop, document, and disseminate to organizational personnel or roles the policies and procedures needed to satisfy the security requirements for the protection of CUI.",
			"SR-03.15.01.b": "Review and update policies and procedures [Assignment: organization-defined frequency].",
		},
	},
	"03.15.02": {
		"family": "03.15",
		"title": "System Security Plan",
		"statements": {
			"SR-03.15.02": "",
			"SR-03.15.02.a": "Develop a system security plan that:",
			"SR-03.15.02.a.01": "Defines the constituent system components;",
			"SR-03.15.02.a.02": "Identifies the information types processed, stored, and transmitted by the system;",
			"SR-03.15.02.a.03": "Describes specific threats to the system that are of concern to the organization;",
			"SR-03.15.02.a.04": "Describes the operational environment for the system and any dependencies on or connections to other systems or system components;",
			"SR-03.15.02.a.05": "Provides an overview of the security requirements for the system;",
			"SR-03.15.02.a.06": "Describes the safeguards in place or planned for meeting the security requirements;",
			"SR-03.15.02.a.07": "Identifies individuals that fulfill system roles and responsibilities; and",
			"SR-03.15.02.a.08": "Includes other relevant information necessary for the protection of CUI.",
			"SR-03.15.02.b": "Review and update the system security plan [Assignment: organization-defined frequency].",
			"SR-03.15.02.c": "Protect the system security plan from unauthorized disclosure.",
		},
	},
	"03.15.03": {
		"family": "03.15",
		"title": "Rules of Behavior",
		"statements": {
			"SR-03.15.03": "",
			"SR-03.15.03.a": "Establish rules that describe the responsibilities and expected behavior for system usage and protecting CUI.",
			"SR-03.15.03.b": "Provide rules to individuals who require access to the system.",
			"SR-03.15.03.c": "Receive a documented acknowledgement from individuals indicating that they have read, understand, and agree to abide by the rules of behavior before authorizing access to CUI and the system.",
			"SR-03.15.03.d": "Review and update the rules of behavior [Assignment: organization-defined frequency].",
		},
	},
	"03.16.01": {
		"family": "03.16",
		"title": "Security Engineering Principles",
		"statements": {"SR-03.16.01": "Apply the following systems security engineering principles to the development or modification of the system and system components: [Assignment: organization-defined systems security engineering principles]."},
	},
	"03.16.02": {
		"family": "03.16",
		"title": "Unsupported System Components",
		"statements": {
			"SR-03.16.02": "",
			"SR-03.16.02.a": "Replace system components when support for the components is no longer available from the developer, vendor, or manufacturer.",
			"SR-03.16.02.b": "Provide options for risk mitigation or alternative sources for continued support for unsupported components that cannot be replaced.",
		},
	},
	"03.16.03": {
		"family": "03.16",
		"title": "External System Services",
		"statements": {
			"SR-03.16.03": "",
			"SR-03.16.03.a": "Require the providers of external system services used for the processing, storage, or transmission of CUI to comply with the following security requirements: [Assignment: organization-defined security requirements].",
			"SR-03.16.03.b": "Define and document user roles and responsibilities with regard to external system services, including shared responsibilities with external service providers.",
			"SR-03.16.03.c": "Implement processes, methods, and techniques to monitor security requirement compliance by external service providers on an ongoing basis.",
		},
	},
	"03.17.01": {
		"family": "03.17",
		"title": "Supply Chain Risk Management Plan",
		"statements": {
			"SR-03.17.01": "",
			"SR-03.17.01.a": "Develop a plan for managing supply chain risks associated with the research and development, design, manufacturing, acquisition, delivery, integration, operations, maintenance, and disposal of the system, system components, or system services.",
			"SR-03.17.01.b": "Review and update the supply chain risk management plan [Assignment: organization-defined frequency].",
			"SR-03.17.01.c": "Protect the supply chain risk management plan from unauthorized disclosure.",
		},
	},
	"03.17.02": {
		"family": "03.17",
		"title": "Acquisition Strategies, Tools, and Methods",
		"statements": {"SR-03.17.02": "Develop and implement acquisition strategies, contract tools, and procurement methods to identify, protect against, and mitigate supply chain risks."},
	},
	"03.17.03": {
		"family": "03.17",
		"title": "Supply Chain Requirements and Processes",
		"statements": {
			"SR-03.17.03": "",
			"SR-03.17.03.a": "Establish a process for identifying and addressing weaknesses or deficiencies in the supply chain elements and processes.",
			"SR-03.17.03.b": "Enforce the following security requirements to protect against supply chain risks to the system, system components, or system services and to limit the harm or consequences from supply chain-related events: [Assignment: organization-defined security requirements].",
		},
	},
}

withdrawn := {
	"03.01.13": {
		"reason": "Addressed by 03.13.08.",
		"incorporated_into": [],
		"addressed_by": ["03.13.08"],
	},
	"03.01.14": {
		"reason": "Incorporated into 03.01.12.",
		"incorporated_into": ["03.01.12"],
		"addressed_by": [],
	},
	"03.01.15": {
		"reason": "Incorporated into 03.01.12.",
		"incorporated_into": ["03.01.12"],
		"addressed_by": [],
	},
	"03.01.17": {
		"reason": "Incorporated into 03.01.16.",
		"incorporated_into": ["03.01.16"],
		"addressed_by": [],
	},
	"03.01.19": {
		"reason": "Incorporated into 03.01.18.",
		"incorporated_into": ["03.01.18"],
		"addressed_by": [],
	},
	"03.01.21": {
		"reason": "Incorporated into 03.01.20.",
		"incorporated_into": ["03.01.20"],
		"addressed_by": [],
	},
	"03.02.03": {
		"reason": "Incorporated into 03.02.01.",
		"incorporated_into": ["03.02.01"],
		"addressed_by": [],
	},
	"03.03.09": {
		"reason": "Incorporated into 03.03.08.",
		"incorporated_into": ["03.03.08"],
		"addressed_by": [],
	},
	"03.04.07": {
		"reason": "Incorporated into 03.04.06 and 03.04.08.",
		"incorporated_into": [
			"03.04.06",
			"03.04.08",
		],
		"addressed_by": [],
	},
	"03.04.09": {
		"reason": "Addressed by 03.01.05, 03.01.06, 03.01.07, 03.04.08, and 03.12.03.",
		"incorporated_into": [],
		"addressed_by": [
			"03.01.05",
			"03.01.06",
			"03.01.07",
			"03.04.08",
			"03.12.03",
		],
	},
	"03.05.06": {
		"reason": "Consistency with SP 800-53.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.05.08": {
		"reason": "Consistency with SP 800-53.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.05.09": {
		"reason": "Consistency with SP 800-53.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.05.10": {
		"reason": "Incorporated into 03.05.07.",
		"incorporated_into": ["03.05.07"],
		"addressed_by": [],
	},
	"03.07.01": {
		"reason": "Recategorized as NCO.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.07.02": {
		"reason": "Incorporated into 03.07.04 and 03.07.06.",
		"incorporated_into": [
			"03.07.04",
			"03.07.06",
		],
		"addressed_by": [],
	},
	"03.07.03": {
		"reason": "Incorporated into 03.08.03.",
		"incorporated_into": ["03.08.03"],
		"addressed_by": [],
	},
	"03.08.06": {
		"reason": "Incorporated into 03.13.08.",
		"incorporated_into": ["03.13.08"],
		"addressed_by": [],
	},
	"03.08.08": {
		"reason": "Incorporated into 03.08.07.",
		"incorporated_into": ["03.08.07"],
		"addressed_by": [],
	},
	"03.10.03": {
		"reason": "Incorporated into 03.10.07.",
		"incorporated_into": ["03.10.07"],
		"addressed_by": [],
	},
	"03.10.04": {
		"reason": "Incorporated into 03.10.07.",
		"incorporated_into": ["03.10.07"],
		"addressed_by": [],
	},
	"03.10.05": {
		"reason": "Incorporated into 03.10.07.",
		"incorporated_into": ["03.10.07"],
		"addressed_by": [],
	},
	"03.11.03": {
		"reason": "Incorporated into 03.11.02.",
		"incorporated_into": ["03.11.02"],
		"addressed_by": [],
	},
	"03.12.04": {
		"reason": "Incorporated into 03.15.02.",
		"incorporated_into": ["03.15.02"],
		"addressed_by": [],
	},
	"03.13.02": {
		"reason": "Recategorized as NCO.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.13.03": {
		"reason": "Addressed by 03.01.01, 03.01.02, 03.01.03, 03.01.04, 03.01.05, 03.01.06, and 03.01.07.",
		"incorporated_into": [],
		"addressed_by": [
			"03.01.01",
			"03.01.02",
			"03.01.03",
			"03.01.04",
			"03.01.05",
			"03.01.06",
			"03.01.07",
		],
	},
	"03.13.05": {
		"reason": "Incorporated into 03.13.01.",
		"incorporated_into": ["03.13.01"],
		"addressed_by": [],
	},
	"03.13.07": {
		"reason": "Addressed by 03.01.12, 03.04.02 and 03.04.06.",
		"incorporated_into": [],
		"addressed_by": [
			"03.01.12",
			"03.04.02",
			"03.04.06",
		],
	},
	"03.13.14": {
		"reason": "Technology-specific.",
		"incorporated_into": [],
		"addressed_by": [],
	},
	"03.13.16": {
		"reason": "Incorporated into 03.13.08.",
		"incorporated_into": ["03.13.08"],
		"addressed_by": [],
	},
	"03.14.04": {
		"reason": "Incorporated into 03.14.02.",
		"incorporated_into": ["03.14.02"],
		"addressed_by": [],
	},
	"03.14.05": {
		"reason": "Addressed by 03.14.02.",
		"incorporated_into": [],
		"addressed_by": ["03.14.02"],
	},
	"03.14.07": {
		"reason": "Incorporated into 03.14.06.",
		"incorporated_into": ["03.14.06"],
		"addressed_by": [],
	},
}

# Rev 3 requirement -> fact rules in data.nist.sp800_171.<pkg> (Rev 2 slot it came from)
fact_checks := {
	"03.01.01": [{
		"rev2": "3.1.1",
		"pkg": "access_control",
		"rule": "authorized_access_only",
	}],
	"03.01.02": [{
		"rev2": "3.1.2",
		"pkg": "access_control",
		"rule": "transaction_function_limits",
	}],
	"03.01.03": [{
		"rev2": "3.1.3",
		"pkg": "access_control",
		"rule": "cui_flow_control",
	}],
	"03.01.04": [{
		"rev2": "3.1.4",
		"pkg": "access_control",
		"rule": "duty_separation",
	}],
	"03.01.05": [{
		"rev2": "3.1.5",
		"pkg": "access_control",
		"rule": "least_privilege_implementation",
	}],
	"03.01.06": [{
		"rev2": "3.1.6",
		"pkg": "access_control",
		"rule": "non_privileged_access",
	}],
	"03.01.07": [{
		"rev2": "3.1.7",
		"pkg": "access_control",
		"rule": "privileged_function_prevention",
	}],
	"03.01.08": [{
		"rev2": "3.1.8",
		"pkg": "access_control",
		"rule": "logon_attempt_limits",
	}],
	"03.01.09": [{
		"rev2": "3.1.9",
		"pkg": "access_control",
		"rule": "privacy_security_notices",
	}],
	"03.01.10": [{
		"rev2": "3.1.10",
		"pkg": "access_control",
		"rule": "session_lock_implementation",
	}],
	"03.01.11": [{
		"rev2": "3.1.11",
		"pkg": "access_control",
		"rule": "session_termination",
	}],
	"03.01.12": [
		{
			"rev2": "3.1.12",
			"pkg": "access_control",
			"rule": "remote_access_monitoring",
		},
		{
			"rev2": "3.1.14",
			"pkg": "access_control",
			"rule": "managed_access_control_points",
		},
		{
			"rev2": "3.1.15",
			"pkg": "access_control",
			"rule": "authorized_remote_privileged_access",
		},
	],
	"03.01.16": [
		{
			"rev2": "3.1.16",
			"pkg": "access_control",
			"rule": "wireless_access_authorization",
		},
		{
			"rev2": "3.1.17",
			"pkg": "access_control",
			"rule": "wireless_protection",
		},
	],
	"03.01.18": [
		{
			"rev2": "3.1.18",
			"pkg": "access_control",
			"rule": "mobile_device_control",
		},
		{
			"rev2": "3.1.19",
			"pkg": "access_control",
			"rule": "mobile_device_encryption",
		},
	],
	"03.01.20": [
		{
			"rev2": "3.1.20",
			"pkg": "access_control",
			"rule": "external_system_control",
		},
		{
			"rev2": "3.1.21",
			"pkg": "access_control",
			"rule": "portable_storage_limits",
		},
	],
	"03.01.22": [{
		"rev2": "3.1.22",
		"pkg": "access_control",
		"rule": "public_system_cui_control",
	}],
	"03.02.01": [
		{
			"rev2": "3.2.1",
			"pkg": "awareness_training",
			"rule": "security_awareness_program",
		},
		{
			"rev2": "3.2.3",
			"pkg": "awareness_training",
			"rule": "threat_recognition_training",
		},
	],
	"03.02.02": [{
		"rev2": "3.2.2",
		"pkg": "awareness_training",
		"rule": "role_based_training",
	}],
	"03.03.01": [{
		"rev2": "3.3.1",
		"pkg": "audit_accountability",
		"rule": "audit_logs_created_retained",
	}],
	"03.03.02": [{
		"rev2": "3.3.2",
		"pkg": "audit_accountability",
		"rule": "user_accountability",
	}],
	"03.03.03": [{
		"rev2": "3.3.3",
		"pkg": "audit_accountability",
		"rule": "logged_events_reviewed",
	}],
	"03.03.04": [{
		"rev2": "3.3.4",
		"pkg": "audit_accountability",
		"rule": "audit_failure_alerting",
	}],
	"03.03.05": [{
		"rev2": "3.3.5",
		"pkg": "audit_accountability",
		"rule": "audit_correlation",
	}],
	"03.03.06": [{
		"rev2": "3.3.6",
		"pkg": "audit_accountability",
		"rule": "audit_reduction_reporting",
	}],
	"03.03.07": [{
		"rev2": "3.3.7",
		"pkg": "audit_accountability",
		"rule": "time_synchronization",
	}],
	"03.03.08": [
		{
			"rev2": "3.3.8",
			"pkg": "audit_accountability",
			"rule": "audit_protection",
		},
		{
			"rev2": "3.3.9",
			"pkg": "audit_accountability",
			"rule": "audit_management_limited",
		},
	],
	"03.04.01": [{
		"rev2": "3.4.1",
		"pkg": "configuration_management",
		"rule": "baseline_configurations",
	}],
	"03.04.02": [{
		"rev2": "3.4.2",
		"pkg": "configuration_management",
		"rule": "security_configuration_settings",
	}],
	"03.04.03": [{
		"rev2": "3.4.3",
		"pkg": "configuration_management",
		"rule": "change_control",
	}],
	"03.04.04": [{
		"rev2": "3.4.4",
		"pkg": "configuration_management",
		"rule": "security_impact_analysis",
	}],
	"03.04.05": [{
		"rev2": "3.4.5",
		"pkg": "configuration_management",
		"rule": "change_access_restrictions",
	}],
	"03.04.06": [
		{
			"rev2": "3.4.6",
			"pkg": "configuration_management",
			"rule": "least_functionality",
		},
		{
			"rev2": "3.4.7",
			"pkg": "configuration_management",
			"rule": "nonessential_services_restricted",
		},
	],
	"03.04.08": [
		{
			"rev2": "3.4.7",
			"pkg": "configuration_management",
			"rule": "nonessential_services_restricted",
		},
		{
			"rev2": "3.4.8",
			"pkg": "configuration_management",
			"rule": "deny_by_exception_policy",
		},
	],
	"03.05.01": [{
		"rev2": "3.5.1",
		"pkg": "identification_authentication",
		"rule": "system_identification",
	}],
	"03.05.02": [{
		"rev2": "3.5.2",
		"pkg": "identification_authentication",
		"rule": "identity_authentication",
	}],
	"03.05.03": [{
		"rev2": "3.5.3",
		"pkg": "identification_authentication",
		"rule": "multifactor_authentication",
	}],
	"03.05.04": [{
		"rev2": "3.5.4",
		"pkg": "identification_authentication",
		"rule": "replay_resistant_authentication",
	}],
	"03.05.05": [{
		"rev2": "3.5.5",
		"pkg": "identification_authentication",
		"rule": "identifier_management",
	}],
	"03.05.07": [
		{
			"rev2": "3.5.7",
			"pkg": "identification_authentication",
			"rule": "password_complexity",
		},
		{
			"rev2": "3.5.10",
			"pkg": "identification_authentication",
			"rule": "password_cryptographic_protection",
		},
	],
	"03.05.11": [{
		"rev2": "3.5.11",
		"pkg": "identification_authentication",
		"rule": "authentication_feedback_obscured",
	}],
	"03.06.01": [{
		"rev2": "3.6.1",
		"pkg": "incident_response",
		"rule": "incident_handling_capability",
	}],
	"03.06.02": [{
		"rev2": "3.6.2",
		"pkg": "incident_response",
		"rule": "incident_tracking_reporting",
	}],
	"03.06.03": [{
		"rev2": "3.6.3",
		"pkg": "incident_response",
		"rule": "incident_response_testing",
	}],
	"03.07.04": [
		{
			"rev2": "3.7.2",
			"pkg": "maintenance",
			"rule": "maintenance_controls",
		},
		{
			"rev2": "3.7.4",
			"pkg": "maintenance",
			"rule": "diagnostic_media_checked",
		},
	],
	"03.07.05": [{
		"rev2": "3.7.5",
		"pkg": "maintenance",
		"rule": "remote_maintenance_mfa",
	}],
	"03.07.06": [
		{
			"rev2": "3.7.2",
			"pkg": "maintenance",
			"rule": "maintenance_controls",
		},
		{
			"rev2": "3.7.6",
			"pkg": "maintenance",
			"rule": "maintenance_supervision",
		},
	],
	"03.08.01": [{
		"rev2": "3.8.1",
		"pkg": "media_protection",
		"rule": "media_physical_protection",
	}],
	"03.08.02": [{
		"rev2": "3.8.2",
		"pkg": "media_protection",
		"rule": "media_access_limited",
	}],
	"03.08.03": [
		{
			"rev2": "3.7.3",
			"pkg": "maintenance",
			"rule": "equipment_sanitization",
		},
		{
			"rev2": "3.8.3",
			"pkg": "media_protection",
			"rule": "media_sanitization_disposal",
		},
	],
	"03.08.04": [{
		"rev2": "3.8.4",
		"pkg": "media_protection",
		"rule": "media_marking",
	}],
	"03.08.05": [{
		"rev2": "3.8.5",
		"pkg": "media_protection",
		"rule": "media_transport_control",
	}],
	"03.08.07": [
		{
			"rev2": "3.8.7",
			"pkg": "media_protection",
			"rule": "removable_media_controlled",
		},
		{
			"rev2": "3.8.8",
			"pkg": "media_protection",
			"rule": "portable_storage_owner_required",
		},
	],
	"03.08.09": [{
		"rev2": "3.8.9",
		"pkg": "media_protection",
		"rule": "backup_cui_protected",
	}],
	"03.09.01": [{
		"rev2": "3.9.1",
		"pkg": "personnel_security",
		"rule": "personnel_screening",
	}],
	"03.09.02": [{
		"rev2": "3.9.2",
		"pkg": "personnel_security",
		"rule": "personnel_actions_protection",
	}],
	"03.10.01": [{
		"rev2": "3.10.1",
		"pkg": "physical_protection",
		"rule": "physical_access_limited",
	}],
	"03.10.02": [{
		"rev2": "3.10.2",
		"pkg": "physical_protection",
		"rule": "facility_monitoring",
	}],
	"03.10.06": [{
		"rev2": "3.10.6",
		"pkg": "physical_protection",
		"rule": "alternate_work_site_safeguards",
	}],
	"03.10.07": [
		{
			"rev2": "3.10.3",
			"pkg": "physical_protection",
			"rule": "visitor_escort",
		},
		{
			"rev2": "3.10.4",
			"pkg": "physical_protection",
			"rule": "physical_access_logs",
		},
		{
			"rev2": "3.10.5",
			"pkg": "physical_protection",
			"rule": "physical_access_devices_managed",
		},
	],
	"03.11.01": [{
		"rev2": "3.11.1",
		"pkg": "risk_assessment",
		"rule": "risk_assessment_performed",
	}],
	"03.11.02": [
		{
			"rev2": "3.11.2",
			"pkg": "risk_assessment",
			"rule": "vulnerability_scanning",
		},
		{
			"rev2": "3.11.3",
			"pkg": "risk_assessment",
			"rule": "vulnerability_remediation",
		},
	],
	"03.12.01": [{
		"rev2": "3.12.1",
		"pkg": "security_assessment",
		"rule": "security_controls_assessed",
	}],
	"03.12.02": [{
		"rev2": "3.12.2",
		"pkg": "security_assessment",
		"rule": "plans_of_action",
	}],
	"03.12.03": [{
		"rev2": "3.12.3",
		"pkg": "security_assessment",
		"rule": "continuous_monitoring",
	}],
	"03.13.01": [
		{
			"rev2": "3.13.1",
			"pkg": "system_communications",
			"rule": "boundary_protection",
		},
		{
			"rev2": "3.13.5",
			"pkg": "system_communications",
			"rule": "dmz_implementation",
		},
	],
	"03.13.04": [{
		"rev2": "3.13.4",
		"pkg": "system_communications",
		"rule": "shared_resource_control",
	}],
	"03.13.06": [{
		"rev2": "3.13.6",
		"pkg": "system_communications",
		"rule": "deny_all_permit_exception",
	}],
	"03.13.08": [
		{
			"rev2": "3.8.6",
			"pkg": "media_protection",
			"rule": "media_transport_encryption",
		},
		{
			"rev2": "3.13.8",
			"pkg": "system_communications",
			"rule": "transmission_encryption",
		},
		{
			"rev2": "3.13.16",
			"pkg": "system_communications",
			"rule": "cui_at_rest_protection",
		},
	],
	"03.13.09": [{
		"rev2": "3.13.9",
		"pkg": "system_communications",
		"rule": "session_termination_inactivity",
	}],
	"03.13.10": [{
		"rev2": "3.13.10",
		"pkg": "system_communications",
		"rule": "cryptographic_key_management",
	}],
	"03.13.11": [{
		"rev2": "3.13.11",
		"pkg": "system_communications",
		"rule": "fips_validated_cryptography",
	}],
	"03.13.12": [{
		"rev2": "3.13.12",
		"pkg": "system_communications",
		"rule": "collaborative_device_control",
	}],
	"03.13.13": [{
		"rev2": "3.13.13",
		"pkg": "system_communications",
		"rule": "mobile_code_control",
	}],
	"03.13.15": [{
		"rev2": "3.13.15",
		"pkg": "system_communications",
		"rule": "session_authenticity",
	}],
	"03.14.01": [{
		"rev2": "3.14.1",
		"pkg": "system_information",
		"rule": "flaw_remediation",
	}],
	"03.14.02": [
		{
			"rev2": "3.14.2",
			"pkg": "system_information",
			"rule": "malicious_code_protection",
		},
		{
			"rev2": "3.14.4",
			"pkg": "system_information",
			"rule": "malicious_code_updated",
		},
	],
	"03.14.03": [{
		"rev2": "3.14.3",
		"pkg": "system_information",
		"rule": "security_alerts_monitored",
	}],
	"03.14.06": [
		{
			"rev2": "3.14.6",
			"pkg": "system_information",
			"rule": "attack_detection_monitoring",
		},
		{
			"rev2": "3.14.7",
			"pkg": "system_information",
			"rule": "unauthorized_use_detection",
		},
	],
	"03.15.02": [{
		"rev2": "3.12.4",
		"pkg": "security_assessment",
		"rule": "system_security_plan",
	}],
}

retired_rev2_checks := {
	"3.1.13": {
		"rule": "remote_access_encryption",
		"withdraw_reason": "Addressed by 03.13.08.",
	},
	"3.4.9": {
		"rule": "user_installed_software_controlled",
		"withdraw_reason": "Addressed by 03.01.05, 03.01.06, 03.01.07, 03.04.08, and 03.12.03.",
	},
	"3.5.6": {
		"rule": "identifier_inactivity_disable",
		"withdraw_reason": "Consistency with SP 800-53.",
	},
	"3.5.8": {
		"rule": "password_reuse_prohibited",
		"withdraw_reason": "Consistency with SP 800-53.",
	},
	"3.5.9": {
		"rule": "temporary_password_control",
		"withdraw_reason": "Consistency with SP 800-53.",
	},
	"3.7.1": {
		"rule": "maintenance_performed",
		"withdraw_reason": "Recategorized as NCO.",
	},
	"3.13.2": {
		"rule": "security_engineering_principles",
		"withdraw_reason": "Recategorized as NCO.",
	},
	"3.13.3": {
		"rule": "functionality_separation",
		"withdraw_reason": "Addressed by 03.01.01, 03.01.02, 03.01.03, 03.01.04, 03.01.05, 03.01.06, and 03.01.07.",
	},
	"3.13.7": {
		"rule": "split_tunneling_prevention",
		"withdraw_reason": "Addressed by 03.01.12, 03.04.02 and 03.04.06.",
	},
	"3.13.14": {
		"rule": "voip_control",
		"withdraw_reason": "Technology-specific.",
	},
	"3.14.5": {
		"rule": "system_scanning",
		"withdraw_reason": "Addressed by 03.14.02.",
	},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_sp_800_171", {})

_attestations := a if {
	a := _in.requirements
	is_object(a)
}

_supplied if _attestations

_attested(id) if _attestations[id] == true

_fact_ok(c) if data.nist.sp800_171[c.pkg][c.rule] == true

_failed_facts[id] := [c.rev2 | some c in checks; not _fact_ok(c)] if {
	some id, checks in fact_checks
}

_fact_evaluated(id) if fact_checks[id]

_satisfied(id) if {
	requirements[id]
	_fact_evaluated(id)
	count(_failed_facts[id]) == 0
}

_satisfied(id) if {
	requirements[id]
	not _fact_evaluated(id)
	_attested(id)
}

violations contains "NIST SP 800-171 Rev 3: FAIL-CLOSED - attestations 'input.nist_sp_800_171.requirements' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, r in requirements
	not _fact_evaluated(id)
	not _attested(id)
	msg := sprintf("NIST SP 800-171 %v %v (%v): not attested — input.nist_sp_800_171.requirements[\"%v\"] must be true", [id, r.title, families[r.family], id])
}

violations contains msg if {
	some id, failed in _failed_facts
	some rev2 in failed
	c := [x | some x in fact_checks[id]; x.rev2 == rev2][0]
	msg := sprintf("NIST SP 800-171 %v %v: fact check failed — Rev 2 %v %v (data.nist.sp800_171.%v)", [id, requirements[id].title, rev2, c.rule, c.pkg])
}

violations contains msg if {
	some id, _ in _attestations
	w := withdrawn[id]
	msg := sprintf("NIST SP 800-171 Input Contract: %v is withdrawn in Rev 3 (%v) — attest the requirement that replaces it, not the withdrawn id", [id, w.reason])
}

violations contains msg if {
	some id, _ in _attestations
	not requirements[id]
	not withdrawn[id]
	msg := sprintf("NIST SP 800-171 Input Contract: attestation for unknown requirement id %v — ids are CPRT Rev 3 element identifiers such as 03.01.01", [id])
}

requirement_status[id] := s if {
	some id, r in requirements
	s := {
		"family": r.family,
		"title": r.title,
		"statements": count(r.statements),
		"basis": _basis(id),
		"attested": _attested_bool(id),
		"fact_checks_failed": object.get(_failed_facts, id, []),
		"satisfied": _satisfied_bool(id),
	}
}

_basis(id) := "facts" if _fact_evaluated(id)

else := "attestation"

_attested_bool(id) if _attested(id)

else := false

_satisfied_bool(id) if _satisfied(id)

else := false

family_reports[f] := r if {
	some f, name in families
	ids := {id | some id, q in requirements; q.family == f}
	ok := {id | some id in ids; _satisfied(id)}
	r := {
		"name": name,
		"requirements": count(ids),
		"satisfied": count(ok),
		"withdrawn": count({id | some id, _ in withdrawn; startswith(id, concat("", [f, "."]))}),
		"gaps": sort([id | some id in ids; not id in ok]),
	}
}

_n_satisfied := count({id | some id, _ in requirements; _satisfied(id)})

compliance_report := {
	"framework": "NIST SP 800-171 Rev 3",
	"standard": "NIST SP 800-171 Rev 3 — Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations",
	"source": source,
	"compliant": compliant,
	"overall_compliant": compliant,
	"total_controls": count(requirements),
	"standard_total": 97, # SP 800-171 Rev 3: 130 requirement ids in the text, 33 withdrawn, 97 active (CPRT export)
	"requirements_total": count(requirements),
	"requirements_satisfied": _n_satisfied,
	"requirements_fact_evaluated": count(fact_checks),
	"requirements_attested": count(requirements) - count(fact_checks),
	"statements_total": sum([count(r.statements) | some r in requirements]),
	"withdrawn_total": count(withdrawn),
	"families_total": count(families),
	"families_passing": count([f | some f, r in family_reports; count(r.gaps) == 0]),
	"families": family_reports,
	"requirements": requirement_status,
	"withdrawn": withdrawn,
	"retired_rev2_checks": retired_rev2_checks,
	"violation_count": count(violations),
	"violations": violations,
}
