# NIST SP 800-171A (June 2018) — Assessing Security Requirements for Controlled Unclassified Information:
# the assessment procedures for the 110 SP 800-171 requirements (Rev 1 / Rev 2 ids). One attested row per determination statement.
#
# Source of truth: the NIST PDF (NIST's CPRT has no separate SP 800-171A Rev 2-era export),
#   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171A.pdf
#   sha256 21bf3acc43f4284f723639b82eb71e3ce597fa3610f7e9dcf5e8484e22bc0f71, retrieved 2026-10-13.
#   Document date: June 2018 (93-page PDF; its cover sheet records withdrawal on May 14, 2024, superseded by
#   SP 800-171A Rev 3, which is frameworks/federal/nist/sp_800_171a/). DFARS 252.204-7012 / CMMC 2.0 Level 2
#   assessments of the Rev 2 requirements (frameworks/federal/nist/sp_800_171_r2/) still use these objectives.
# Revision: the PDF was written against SP 800-171 Revision 1 (December 2016; its Appendix A reference 6). Rev 2
# keeps the same 110 requirement ids, which is why this module rolls up to the Rev 2 module. The 110 requirement
# statements printed here were diffed against the Rev 2 module's CPRT text (case and whitespace normalised):
# 108 identical; 2 differ in punctuation only and are kept as the PDF prints them — 3.3.2 (Rev 2 adds a comma
# before "so they") and 3.5.4 ("non-privileged" here, "nonprivileged" in Rev 2).
# NIST text is public domain. Every id and every text string below is copied verbatim from Chapter Three
# ("The Procedures") of that PDF by a generator; nothing is paraphrased. Family titles are upper-case because
# the PDF prints them so.
#
# Extraction: pdftotext -layout and pdftotext -raw were both parsed and compared. Requirement statements agree
# in both (110 of 110) and objective texts agree for 316 of 320. The 4 that differ (3.1.12[a], 3.1.12[b],
# 3.1.13[a], 3.1.13[b]) are layout-mode artefacts of vertically centred labels; they were re-read page by page
# (printed page 14, PDF page 25) and are taken from the raw stream, which matches the printed page. Examine/Interview/Test
# lists are taken from layout mode, which prints the spacing the page shows: in 96 lists (requirements 3.4.1–
# 3.9.2) the raw stream drops the space after "SELECT FROM:" (and, in 3.7.2 Test, one after a ";"), and in
# 3.14.7 Test it runs into the next page's furniture; all other lists agree character for character. Page
# furniture (running header, "CHAPTER THREE … PAGE n", the doi.org availability line) is removed before lines
# are joined; the one
# line-final hyphen in Chapter Three is the compound "security-relevant" (3.1.15) and is kept.
#
# Id scheme (exactly as the PDF labels them):
#   objective    3.1.1[a], 3.1.1[b], … — 297 labelled determination statements in 87 requirements
#                3.4.4, 3.9.1, … — the 23 requirements whose objective is one unlabelled sentence
#                ("Determine if <statement>") are keyed by the bare requirement id, not an invented [a]:
#                3.4.4, 3.5.4, 3.5.9, 3.5.11, 3.6.3, 3.7.1, 3.7.3, 3.7.4,
#                3.7.6, 3.8.2, 3.8.6, 3.8.7, 3.8.8, 3.8.9, 3.9.1, 3.10.4,
#                3.12.3, 3.13.4, 3.13.7, 3.13.11, 3.13.15, 3.13.16, 3.14.4 (labelled: false)
#   requirement  3.1.1 … 3.14.7, the same 110 ids as frameworks/federal/nist/sp_800_171_r2/
#   methods      Examine / Interview / Test object lists per requirement: report data, not controls
# Count: the PDF does not state a total number of determination statements anywhere (searched the whole
# text). Measured: 320 = 297 labelled + 23 unlabelled, which matches the figure commonly cited for
# SP 800-171A. Every requirement has one objective block and exactly one
# Examine, one Interview and one Test list. Bracket letters run [a]… contiguously in every requirement.
# Could not read: none.
#
# Families (requirements, objectives):
#   3.1   ACCESS CONTROL                              22 requirements,  70 objectives
#   3.2   AWARENESS AND TRAINING                       3 requirements,   9 objectives
#   3.3   AUDIT AND ACCOUNTABILITY                     9 requirements,  29 objectives
#   3.4   CONFIGURATION MANAGEMENT                     9 requirements,  44 objectives
#   3.5   IDENTIFICATION AND AUTHENTICATION           11 requirements,  25 objectives
#   3.6   INCIDENT RESPONSE                            3 requirements,  14 objectives
#   3.7   MAINTENANCE                                  6 requirements,  10 objectives
#   3.8   MEDIA PROTECTION                             9 requirements,  15 objectives
#   3.9   PERSONNEL SECURITY                           2 requirements,   4 objectives
#   3.10  PHYSICAL PROTECTION                          6 requirements,  16 objectives
#   3.11  RISK ASSESSMENT                              3 requirements,   9 objectives
#   3.12  SECURITY ASSESSMENT                          4 requirements,  14 objectives
#   3.13  SYSTEM AND COMMUNICATIONS PROTECTION        16 requirements,  41 objectives
#   3.14  SYSTEM AND INFORMATION INTEGRITY             7 requirements,  20 objectives
#   total                                            110 requirements, 320 objectives
#
# Input: input.nist_sp_800_171a_r2.determinations["3.1.1[a]"] == true means the assessor determined that
# statement satisfied. Fail-closed: a missing or non-object determinations container is a FAIL-CLOSED
# violation; a missing, false or non-true value is a violation; an unknown id is a violation. A requirement
# is satisfied only when every one of its objectives is true (every requirement has at least one).
#
# Query: POST /v1/data/nist/sp800_171a_r2/main/compliance_report

# METADATA
# title: "NIST SP 800-171A (June 2018) — 320 assessment objectives for the 110 SP 800-171 Rev 2 requirements, attested"
# custom:
#   class: compliance
#   framework: nist_sp_800_171a_r2
#   source: nist
#   domains: [us-federal, cui, assessment]
#   coverage:
#     checks: 324
#     cited: 323
#     expected: 320
#     found: 323
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171a_r2.main

import rego.v1

source := {
	"publication": "NIST SP 800-171A, Assessing Security Requirements for Controlled Unclassified Information (assessment procedures for SP 800-171 Rev 2)",
	"document_date": "June 2018",
	"withdrawn": "May 14, 2024 (superseded by NIST SP 800-171A Rev 3)",
	"url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171A.pdf",
	"sha256": "21bf3acc43f4284f723639b82eb71e3ce597fa3610f7e9dcf5e8484e22bc0f71",
	"retrieved": "2026-10-13",
}

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

requirements := {
	"3.1.1": {
		"family": "3.1",
		"text": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing account management; system security plan; system design documentation; system configuration settings and associated documentation; list of active system accounts and the name of the individual associated with each account; notifications or records of recently transferred, separated, or terminated employees; list of conditions for group and role membership; list of recently disabled system accounts along with the name of the individual associated with each account; access authorization records; account management compliance reviews; system monitoring records; system audit logs and records; list of devices and systems authorized to connect to organizational systems; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with account management responsibilities; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for managing system accounts; mechanisms for implementing account management]."],
		},
	},
	"3.1.2": {
		"family": "3.1",
		"text": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing access enforcement; system security plan; system design documentation; list of approved authorizations including remote access authorizations; system audit logs and records; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with access enforcement responsibilities; system or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing access control policy]."],
		},
	},
	"3.1.3": {
		"family": "3.1",
		"text": "Control the flow of CUI in accordance with approved authorizations.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system security plan; system design documentation; system configuration settings and associated documentation; list of information flow authorizations; system baseline configuration; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing information flow enforcement policy]."],
		},
	},
	"3.1.4": {
		"family": "3.1",
		"text": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing divisions of responsibility and separation of duties; system security plan; system configuration settings and associated documentation; list of divisions of responsibility and separation of duties; system access authorizations; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for defining divisions of responsibility and separation of duties; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms implementing separation of duties policy]."],
		},
	},
	"3.1.5": {
		"family": "3.1",
		"text": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing account management; system security plan; system design documentation; system configuration settings and associated documentation; list of active system accounts and the name of the individual associated with each account; list of conditions for group and role membership; notifications or records of recently transferred, separated, or terminated employees; list of recently disabled system accounts along with the name of the individual associated with each account; access authorization records; account management compliance reviews; system monitoring/audit records; procedures addressing least privilege; list of security functions (deployed in hardware, software, and firmware) and security-relevant information for which access is to be explicitly authorized; list of system-generated privileged accounts; list of system administration personnel; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with account management responsibilities; system or network administrators; personnel with information security responsibilities; personnel with responsibilities for defining least privileges necessary to accomplish specified tasks]."],
			"test": ["[SELECT FROM: Organizational processes for managing system accounts; mechanisms for implementing account management; mechanisms implementing least privilege functions; mechanisms prohibiting privileged access to the system]."],
		},
	},
	"3.1.6": {
		"family": "3.1",
		"text": "Use non-privileged accounts or roles when accessing nonsecurity functions.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing least privilege; system security plan; list of system-generated security functions assigned to system accounts or roles; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for defining least privileges necessary to accomplish specified organizational tasks; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms implementing least privilege functions]."],
		},
	},
	"3.1.7": {
		"family": "3.1",
		"text": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing least privilege; system security plan; system design documentation; list of privileged functions and associated user account assignments; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for defining least privileges necessary to accomplish specified tasks; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing least privilege functions for non-privileged users; mechanisms auditing the execution of privileged functions]."],
		},
	},
	"3.1.8": {
		"family": "3.1",
		"text": "Limit unsuccessful logon attempts.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing unsuccessful logon attempts; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with information security responsibilities; system developers; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms implementing access control policy for unsuccessful logon attempts]."],
		},
	},
	"3.1.9": {
		"family": "3.1",
		"text": "Provide privacy and security notices consistent with applicable CUI rules.",
		"methods": {
			"examine": ["[SELECT FROM: Privacy and security policies, procedures addressing system use notification; documented approval of system use notification messages or banners; system audit logs and records; system design documentation; user acknowledgements of notification message or banner; system security plan; system use notification messages; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel with responsibility for providing legal advice; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing system use notification]."],
		},
	},
	"3.1.10": {
		"family": "3.1",
		"text": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing session lock; procedures addressing identification and authentication; system design documentation; system configuration settings and associated documentation; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing access control policy for session lock]."],
		},
	},
	"3.1.11": {
		"family": "3.1",
		"text": "Terminate (automatically) a user session after a defined condition.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing session termination; system design documentation; system security plan; system configuration settings and associated documentation; list of conditions or trigger events requiring session disconnect; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing user session termination]."],
		},
	},
	"3.1.12": {
		"family": "3.1",
		"text": "Monitor and control remote access sessions.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing remote access implementation and usage (including restrictions); configuration management plan; system security plan; system design documentation; system configuration settings and associated documentation; remote access authorizations; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for managing remote access connections; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Remote access management capability for the system]."],
		},
	},
	"3.1.13": {
		"family": "3.1",
		"text": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing remote access to the system; system security plan; system design documentation; system configuration settings and associated documentation; cryptographic mechanisms and associated configuration documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Cryptographic mechanisms protecting remote access sessions]."],
		},
	},
	"3.1.14": {
		"family": "3.1",
		"text": "Route remote access via managed access control points.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing remote access to the system; system security plan; system design documentation; list of all managed network access control points; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms routing all remote accesses through managed network access control points]."],
		},
	},
	"3.1.15": {
		"family": "3.1",
		"text": "Authorize remote execution of privileged commands and remote access to security-relevant information.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing remote access to the system; system configuration settings and associated documentation; system security plan; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing remote access management]."],
		},
	},
	"3.1.16": {
		"family": "3.1",
		"text": "Authorize wireless access prior to allowing such connections.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; configuration management plan; procedures addressing wireless access implementation and usage (including restrictions); system security plan; system design documentation; system configuration settings and associated documentation; wireless access authorizations; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for managing wireless access connections; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Wireless access management capability for the system]."],
		},
	},
	"3.1.17": {
		"family": "3.1",
		"text": "Protect wireless access using authentication and encryption.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; system design documentation; procedures addressing wireless implementation and usage (including restrictions); system security plan; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing wireless access protections to the system]."],
		},
	},
	"3.1.18": {
		"family": "3.1",
		"text": "Control connection of mobile devices.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; authorizations for mobile device connections to organizational systems; procedures addressing access control for mobile device usage (including restrictions); system design documentation; configuration management plan; system security plan; system audit logs and records; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel using mobile devices to access organizational systems; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Access control capability authorizing mobile device connections to organizational systems]."],
		},
	},
	"3.1.19": {
		"family": "3.1",
		"text": "Encrypt CUI on mobile devices and mobile computing platforms.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing access control for mobile devices; system design documentation; system configuration settings and associated documentation; encryption mechanisms and associated configuration documentation; system security plan; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with access control responsibilities for mobile devices; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Encryption mechanisms protecting confidentiality of information on mobile devices]."],
		},
	},
	"3.1.20": {
		"family": "3.1",
		"text": "Verify and control/limit connections to and use of external systems.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing the use of external systems; terms and conditions for external systems; system security plan; list of applications accessible from external systems; system configuration settings and associated documentation; system connection or processing agreements; account management documents; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for defining terms and conditions for use of external systems to access organizational systems; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing terms and conditions on use of external systems]."],
		},
	},
	"3.1.21": {
		"family": "3.1",
		"text": "Limit use of portable storage devices on external systems.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing the use of external systems; system security plan; system configuration settings and associated documentation; system connection or processing agreements; account management documents; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for restricting or prohibiting use of organization-controlled storage devices on external systems; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing restrictions on use of portable storage devices]."],
		},
	},
	"3.1.22": {
		"family": "3.1",
		"text": "Control CUI posted or processed on publicly accessible systems.",
		"methods": {
			"examine": ["[SELECT FROM: Access control policy; procedures addressing publicly accessible content; system security plan; list of users authorized to post publicly accessible content on organizational systems; training materials and/or records; records of publicly accessible information reviews; records of response to nonpublic information on public websites; system audit logs and records; security awareness training records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for managing publicly accessible information posted on organizational systems; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing management of publicly accessible content]."],
		},
	},
	"3.2.1": {
		"family": "3.2",
		"text": "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
		"methods": {
			"examine": ["[SELECT FROM: Security awareness and training policy; procedures addressing security awareness training implementation; relevant codes of federal regulations; security awareness training curriculum; security awareness training materials; system security plan; training records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for security awareness training; personnel with information security responsibilities; personnel composing the general system user community; personnel with responsibilities for role-based awareness training]."],
			"test": ["[SELECT FROM: Mechanisms managing security awareness training; mechanisms managing role-based security training]."],
		},
	},
	"3.2.2": {
		"family": "3.2",
		"text": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
		"methods": {
			"examine": ["[SELECT FROM: Security awareness and training policy; procedures addressing security training implementation; codes of federal regulations; security training curriculum; security training materials; system security plan; training records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for role-based security training; personnel with assigned system security roles and responsibilities; personnel with responsibilities for security awareness training; personnel with information security responsibilities; personnel representing the general system user community]."],
			"test": ["[SELECT FROM: Mechanisms managing role-based security training; mechanisms managing security awareness training]."],
		},
	},
	"3.2.3": {
		"family": "3.2",
		"text": "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
		"methods": {
			"examine": ["[SELECT FROM: Security awareness and training policy; procedures addressing security awareness training implementation; security awareness training curriculum; security awareness training materials; insider threat policy and procedures; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel that participate in security awareness training; personnel with responsibilities for basic security awareness training; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms managing insider threat training]."],
		},
	},
	"3.3.1": {
		"family": "3.3",
		"text": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing auditable events; system security plan; system design documentation; system configuration settings and associated documentation; procedures addressing control of audit records; procedures addressing audit record generation; system audit logs and records; system auditable events; system incident reports; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; personnel with audit review, analysis and reporting responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms implementing system audit logging]."],
		},
	},
	"3.3.2": {
		"family": "3.3",
		"text": "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing audit records and event types; system security plan; system design documentation; system configuration settings and associated documentation; procedures addressing audit record generation; procedures addressing audit review, analysis, and reporting; reports of audit findings; system audit logs and records; system events; system incident reports; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms implementing system audit logging]."],
		},
	},
	"3.3.3": {
		"family": "3.3",
		"text": "Review and update logged events.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing audit records and event types; system security plan; list of organization-defined event types to be logged; reviewed and updated records of logged event types; system audit logs and records; system incident reports; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms supporting review and update of logged event types]."],
		},
	},
	"3.3.4": {
		"family": "3.3",
		"text": "Alert in the event of an audit logging process failure.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing response to audit logging processing failures; system design documentation; system security plan; system configuration settings and associated documentation; list of personnel to be notified in case of an audit logging processing failure; system incident reports; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing system response to audit logging processing failures]."],
		},
	},
	"3.3.5": {
		"family": "3.3",
		"text": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing audit record review, analysis, and reporting; system security plan; system design documentation; system configuration settings and associated documentation; procedures addressing investigation of and response to suspicious activities; system audit logs and records across different repositories; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit record review, analysis, and reporting responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms supporting analysis and correlation of audit records; mechanisms integrating audit review, analysis and reporting]."],
		},
	},
	"3.3.6": {
		"family": "3.3",
		"text": "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing audit record reduction and report generation; system design documentation; system security plan; system configuration settings and associated documentation; audit record reduction, review, analysis, and reporting tools; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit record reduction and report generation responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Audit record reduction and report generation capability]."],
		},
	},
	"3.3.7": {
		"family": "3.3",
		"text": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; procedures addressing time stamp generation; system design documentation; system security plan; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing time stamp generation; mechanisms implementing internal information system clock synchronization]."],
		},
	},
	"3.3.8": {
		"family": "3.3",
		"text": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; access control policy and procedures; procedures addressing protection of audit information; system security plan; system design documentation; system configuration settings and associated documentation, system audit logs and records; audit logging tools; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms implementing audit information protection]."],
		},
	},
	"3.3.9": {
		"family": "3.3",
		"text": "Limit management of audit logging functionality to a subset of privileged users.",
		"methods": {
			"examine": ["[SELECT FROM: Audit and accountability policy; access control policy and procedures; procedures addressing protection of audit information; system security plan; system design documentation; system configuration settings and associated documentation; access authorizations; system-generated list of privileged users with access to management of audit logging functionality; access control list; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms managing access to audit logging functionality]."],
		},
	},
	"3.4.1": {
		"family": "3.4",
		"text": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing the baseline configuration of the system; procedures addressing system inventory; system security plan; configuration management plan; system inventory records; inventory review and update records; enterprise architecture documentation; system design documentation; system architecture and configuration documentation; system configuration settings and associated documentation; change control records; system component installation records; system component removal records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with configuration management responsibilities; personnel with responsibilities for establishing the system inventory; personnel with responsibilities for updating the system inventory; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for managing baseline configurations; mechanisms supporting configuration control of the baseline configuration; organizational processes for developing and documenting an inventory of system components; organizational processes for updating inventory of system components; mechanisms supporting or implementing the system inventory; mechanisms implementing updating of the system inventory]."],
		},
	},
	"3.4.2": {
		"family": "3.4",
		"text": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; baseline configuration; procedures addressing configuration settings for the system; configuration management plan; system security plan; system design documentation; system configuration settings and associated documentation; security configuration checklists; evidence supporting approved deviations from established configuration settings; change control records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security configuration management responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for managing configuration settings; mechanisms that implement, monitor, and/or control system configuration settings; mechanisms that identify and/or document deviations from established configuration settings; processes for managing baseline configurations; mechanisms supporting configuration control of baseline configurations]."],
		},
	},
	"3.4.3": {
		"family": "3.4",
		"text": "Track, review, approve or disapprove, and log changes to organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing system configuration change control; configuration management plan; system architecture and configuration documentation; system security plan; change control records; system audit logs and records; change control audit and review reports; agenda/minutes from configuration change control oversight meetings; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with configuration change control responsibilities; personnel with information security responsibilities; system or network administrators; members of change control board or similar]."],
			"test": ["[SELECT FROM: Organizational processes for configuration change control; mechanisms that implement configuration change control]."],
		},
	},
	"3.4.4": {
		"family": "3.4",
		"text": "Analyze the security impact of changes prior to implementation.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing security impact analysis for system changes; configuration management plan; security impact analysis documentation; system security plan; analysis tools and associated outputs; change control records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibility for conducting security impact analysis; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for security impact analysis]."],
		},
	},
	"3.4.5": {
		"family": "3.4",
		"text": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing access restrictions for changes to the system; system security plan; configuration management plan; system design documentation; system architecture and configuration documentation; system configuration settings and associated documentation; logical access approvals; physical access approvals; access credentials; change control records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with logical access control responsibilities; personnel with physical access control responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for managing access restrictions associated with changes to the system; mechanisms supporting, implementing, and enforcing access restrictions associated with changes to the system]."],
		},
	},
	"3.4.6": {
		"family": "3.4",
		"text": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; configuration management plan; procedures addressing least functionality in the system; system security plan; system design documentation; system configuration settings and associated documentation; security configuration checklists; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security configuration management responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes prohibiting or restricting functions, ports, protocols, or services; mechanisms implementing restrictions or prohibition of functions, ports, protocols, or services]."],
		},
	},
	"3.4.7": {
		"family": "3.4",
		"text": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing least functionality in the system; configuration management plan; system security plan; system design documentation; security configuration checklists; system configuration settings and associated documentation; specifications for preventing software program execution; documented reviews of programs, functions, ports, protocols, and/or services; change control records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for reviewing programs, functions, ports, protocols, and services on the system; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Organizational processes for reviewing and disabling nonessential programs, functions, ports, protocols, or services; mechanisms implementing review and handling of nonessential programs, functions, ports, protocols, or services; organizational processes preventing program execution on the system; organizational processes for software program usage and restrictions; mechanisms supporting or implementing software program usage and restrictions; mechanisms preventing program execution on the system]."],
		},
	},
	"3.4.8": {
		"family": "3.4",
		"text": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing least functionality in the system; system security plan; configuration management plan; system design documentation; system configuration settings and associated documentation; list of software programs not authorized to execute on the system; list of software programs authorized to execute on the system; security configuration checklists; review and update records associated with list of authorized or unauthorized software programs; change control records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for identifying software authorized or not authorized to execute on the system; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational process for identifying, reviewing, and updating programs authorized or not authorized to execute on the system; process for implementing blacklisting or whitelisting; mechanisms supporting or implementing blacklisting or whitelisting]."],
		},
	},
	"3.4.9": {
		"family": "3.4",
		"text": "Control and monitor user-installed software.",
		"methods": {
			"examine": ["[SELECT FROM: Configuration management policy; procedures addressing user installed software; configuration management plan; system security plan; system design documentation; system configuration settings and associated documentation; list of rules governing user-installed software; system monitoring records; system audit logs and records; continuous monitoring strategy; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibilities for governing user-installed software; personnel operating, using, or maintaining the system; personnel monitoring compliance with user-installed software policy; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes governing user-installed software on the system; mechanisms enforcing rules or methods for governing the installation of software by users; mechanisms monitoring policy compliance]."],
		},
	},
	"3.5.1": {
		"family": "3.5",
		"text": "Identify system users, processes acting on behalf of users, and devices.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing user identification and authentication; system security plan, system design documentation; system configuration settings and associated documentation; system audit logs and records; list of system accounts; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system operations responsibilities; personnel with information security responsibilities; system or network administrators; personnel with account management responsibilities; system developers]."],
			"test": ["[SELECT FROM: Organizational processes for uniquely identifying and authenticating users; mechanisms supporting or implementing identification and authentication capability]."],
		},
	},
	"3.5.2": {
		"family": "3.5",
		"text": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; system security plan; procedures addressing authenticator management; procedures addressing user identification and authentication; system design documentation; list of system authenticator types; system configuration settings and associated documentation; change control records associated with managing system authenticators; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing authenticator management capability]."],
		},
	},
	"3.5.3": {
		"family": "3.5",
		"text": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing user identification and authentication; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; list of system accounts; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system operations responsibilities; personnel with account management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing multifactor authentication capability]."],
		},
	},
	"3.5.4": {
		"family": "3.5",
		"text": "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing user identification and authentication; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; list of privileged system accounts; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system operations responsibilities; personnel with account management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing identification and authentication capability or replay resistant authentication mechanisms]."],
		},
	},
	"3.5.5": {
		"family": "3.5",
		"text": "Prevent reuse of identifiers for a defined period.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing identifier management; procedures addressing account management; system security plan; system design documentation; system configuration settings and associated documentation; list of system accounts; list of identifiers generated from physical access control devices; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with identifier management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing identifier management]."],
		},
	},
	"3.5.6": {
		"family": "3.5",
		"text": "Disable identifiers after a defined period of inactivity.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing identifier management; procedures addressing account management; system security plan; system design documentation; system configuration settings and associated documentation; list of system accounts; list of identifiers generated from physical access control devices; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with identifier management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing identifier management]."],
		},
	},
	"3.5.7": {
		"family": "3.5",
		"text": "Enforce a minimum password complexity and change of characters when new passwords are created.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; password policy; procedures addressing authenticator management; system security plan; system configuration settings and associated documentation; system design documentation; password configurations and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing password-based authenticator management capability]."],
		},
	},
	"3.5.8": {
		"family": "3.5",
		"text": "Prohibit password reuse for a specified number of generations.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; password policy; procedures addressing authenticator management; system security plan; system design documentation; system configuration settings and associated documentation; password configurations and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing password-based authenticator management capability]."],
		},
	},
	"3.5.9": {
		"family": "3.5",
		"text": "Allow temporary password use for system logons with an immediate change to a permanent password.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; password policy; procedures addressing authenticator management; system security plan; system configuration settings and associated documentation; system design documentation; password configurations and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing password-based authenticator management capability]."],
		},
	},
	"3.5.10": {
		"family": "3.5",
		"text": "Store and transmit only cryptographically-protected passwords.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; password policy; procedures addressing authenticator management; system security plan; system configuration settings and associated documentation; system design documentation; password configurations and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing password-based authenticator management capability]."],
		},
	},
	"3.5.11": {
		"family": "3.5",
		"text": "Obscure feedback of authentication information.",
		"methods": {
			"examine": ["[SELECT FROM: Identification and authentication policy; procedures addressing authenticator feedback; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with information security responsibilities; system or network administrators; system developers]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing the obscuring of feedback of authentication information during authentication]."],
		},
	},
	"3.6.1": {
		"family": "3.6",
		"text": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
		"methods": {
			"examine": ["[SELECT FROM: Incident response policy; contingency planning policy; procedures addressing incident handling; procedures addressing incident response assistance; incident response plan; contingency plan; system security plan; procedures addressing incident response training; incident response training curriculum; incident response training materials; incident response training records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with incident handling responsibilities; personnel with contingency planning responsibilities; personnel with incident response training and operational responsibilities; personnel with incident response assistance and support responsibilities; personnel with access to incident response support and assistance capability; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Incident-handling capability for the organization; organizational processes for incident response assistance; mechanisms supporting or implementing incident response assistance]."],
		},
	},
	"3.6.2": {
		"family": "3.6",
		"text": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
		"methods": {
			"examine": ["[SELECT FROM: Incident response policy; procedures addressing incident monitoring; incident response records and documentation; procedures addressing incident reporting; incident reporting records and documentation; incident response plan; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with incident monitoring responsibilities; personnel with incident reporting responsibilities; personnel who have or should have reported incidents; personnel (authorities) to whom incident information is to be reported; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Incident monitoring capability for the organization; mechanisms supporting or implementing tracking and documenting of system security incidents; organizational processes for incident reporting; mechanisms supporting or implementing incident reporting]."],
		},
	},
	"3.6.3": {
		"family": "3.6",
		"text": "Test the organizational incident response capability.",
		"methods": {
			"examine": ["[SELECT FROM: Incident response policy; contingency planning policy; procedures addressing incident response testing; procedures addressing contingency plan testing; incident response testing material; incident response test results; incident response test plan; incident response plan; contingency plan; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with incident response testing responsibilities; personnel with information security responsibilities; personnel with responsibilities for testing plans related to incident response]."],
			"test": ["[SELECT FROM: Mechanisms and processes for incident response]."],
		},
	},
	"3.7.1": {
		"family": "3.7",
		"text": "Perform maintenance on organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing controlled system maintenance; maintenance records; manufacturer or vendor maintenance specifications; equipment sanitization records; media sanitization records; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities; personnel responsible for media sanitization; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for scheduling, performing, documenting, reviewing, approving, and monitoring maintenance and repairs for systems; organizational processes for sanitizing system components; mechanisms supporting or implementing controlled maintenance; mechanisms implementing sanitization of system components]."],
		},
	},
	"3.7.2": {
		"family": "3.7",
		"text": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing system maintenance tools and media; maintenance records; system maintenance tools and associated documentation; maintenance tool inspection records; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for approving, controlling, and monitoring maintenance tools; mechanisms supporting or implementing approval, control, and monitoring of maintenance tools; organizational processes for inspecting maintenance tools; mechanisms supporting or implementing inspection of maintenance tools; organizational process for inspecting media for malicious code; mechanisms supporting or implementing inspection of media used for maintenance]."],
		},
	},
	"3.7.3": {
		"family": "3.7",
		"text": "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing controlled system maintenance; maintenance records; manufacturer or vendor maintenance specifications; equipment sanitization records; media sanitization records; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities; personnel responsible for media sanitization; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for scheduling, performing, documenting, reviewing, approving, and monitoring maintenance and repairs for systems; organizational processes for sanitizing system components; mechanisms supporting or implementing controlled maintenance; mechanisms implementing sanitization of system components]."],
		},
	},
	"3.7.4": {
		"family": "3.7",
		"text": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing system maintenance tools; system maintenance tools and associated documentation; maintenance records; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational process for inspecting media for malicious code; mechanisms supporting or implementing inspection of media used for maintenance]."],
		},
	},
	"3.7.5": {
		"family": "3.7",
		"text": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing nonlocal system maintenance; system security plan; system design documentation; system configuration settings and associated documentation; maintenance records; diagnostic records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for managing nonlocal maintenance; mechanisms implementing, supporting, and managing nonlocal maintenance; mechanisms for strong authentication of nonlocal maintenance diagnostic sessions; mechanisms for terminating nonlocal maintenance sessions and network connections]."],
		},
	},
	"3.7.6": {
		"family": "3.7",
		"text": "Supervise the maintenance activities of maintenance personnel without required access authorization.",
		"methods": {
			"examine": ["[SELECT FROM: System maintenance policy; procedures addressing maintenance personnel; service provider contracts; service-level agreements; list of authorized personnel; maintenance records; access control records; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for authorizing and managing maintenance personnel; mechanisms supporting or implementing authorization of maintenance personnel]."],
		},
	},
	"3.8.1": {
		"family": "3.8",
		"text": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media storage; procedures addressing media access restrictions; access control policy and procedures; physical and environmental protection policy and procedures; system security plan; media storage facilities; access control records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media protection responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for restricting information media; mechanisms supporting or implementing media access restrictions]."],
		},
	},
	"3.8.2": {
		"family": "3.8",
		"text": "Limit access to CUI on system media to authorized users.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media storage; physical and environmental protection policy and procedures; access control policy and procedures; system security plan; system media; designated controlled areas; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media protection and storage responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for storing media; mechanisms supporting or implementing secure media storage and media protection]."],
		},
	},
	"3.8.3": {
		"family": "3.8",
		"text": "Sanitize or destroy system media containing CUI before disposal or release for reuse.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media sanitization and disposal; applicable standards and policies addressing media sanitization; system security plan; media sanitization records; system audit logs and records; system design documentation; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with media sanitization responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for media sanitization; mechanisms supporting or implementing media sanitization]."],
		},
	},
	"3.8.4": {
		"family": "3.8",
		"text": "Mark media with necessary CUI markings and distribution limitations.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media marking; physical and environmental protection policy and procedures; system security plan; list of system media marking security attributes; designated controlled areas; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media protection and marking responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for marking information media; mechanisms supporting or implementing media marking]."],
		},
	},
	"3.8.5": {
		"family": "3.8",
		"text": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media storage; physical and environmental protection policy and procedures; access control policy and procedures; system security plan; system media; designated controlled areas; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media protection and storage responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for storing media; mechanisms supporting or implementing media storage and media protection]."],
		},
	},
	"3.8.6": {
		"family": "3.8",
		"text": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; procedures addressing media transport; system design documentation; system security plan; system configuration settings and associated documentation; system media transport records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media transport responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Cryptographic mechanisms protecting information on digital media during transportation outside controlled areas]."],
		},
	},
	"3.8.7": {
		"family": "3.8",
		"text": "Control the use of removable media on system components.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; system use policy; procedures addressing media usage restrictions; system security plan; rules of behavior; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media use responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for media use; mechanisms restricting or prohibiting use of system media on systems or system components]."],
		},
	},
	"3.8.8": {
		"family": "3.8",
		"text": "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
		"methods": {
			"examine": ["[SELECT FROM: System media protection policy; system use policy; procedures addressing media usage restrictions; system security plan; rules of behavior; system configuration settings and associated documentation; system design documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system media use responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for media use; mechanisms prohibiting use of media on systems or system components]."],
		},
	},
	"3.8.9": {
		"family": "3.8",
		"text": "Protect the confidentiality of backup CUI at storage locations.",
		"methods": {
			"examine": ["[SELECT FROM: Procedures addressing system backup; system configuration settings and associated documentation; security plan; backup storage locations; system backup logs or records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with system backup responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for conducting system backups; mechanisms supporting or implementing system backups]."],
		},
	},
	"3.9.1": {
		"family": "3.9",
		"text": "Screen individuals prior to authorizing access to organizational systems containing CUI.",
		"methods": {
			"examine": ["[SELECT FROM: Personnel security policy; procedures addressing personnel screening; records of screened personnel; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with personnel security responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for personnel screening]."],
		},
	},
	"3.9.2": {
		"family": "3.9",
		"text": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
		"methods": {
			"examine": ["[SELECT FROM: Personnel security policy; procedures addressing personnel transfer and termination; records of personnel transfer and termination actions; list of system accounts; records of terminated or revoked authenticators and credentials; records of exit interviews; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with personnel security responsibilities; personnel with account management responsibilities; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for personnel transfer and termination; mechanisms supporting or implementing personnel transfer and termination notifications; mechanisms for disabling system access and revoking authenticators]."],
		},
	},
	"3.10.1": {
		"family": "3.10",
		"text": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access authorizations; system security plan; authorized personnel access list; authorization credentials; physical access list reviews; physical access termination records and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with physical access authorization responsibilities; personnel with physical access to system facility; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for physical access authorizations; mechanisms supporting or implementing physical access authorizations]."],
		},
	},
	"3.10.2": {
		"family": "3.10",
		"text": "Protect and monitor the physical facility and support infrastructure for organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access monitoring; system security plan; physical access logs or records; physical access monitoring records; physical access log reviews; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with physical access monitoring responsibilities; personnel with incident response responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for monitoring physical access; mechanisms supporting or implementing physical access monitoring; mechanisms supporting or implementing the review of physical access logs]."],
		},
	},
	"3.10.3": {
		"family": "3.10",
		"text": "Escort visitors and monitor visitor activity.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access control; system security plan; physical access control logs or records; inventory records of physical access control devices; system entry and exit points; records of key and lock combination changes; storage locations for physical access control devices; physical access control devices; list of security safeguards controlling access to designated publicly accessible areas within facility; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with physical access control responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for physical access control; mechanisms supporting or implementing physical access control; physical access control devices]."],
		},
	},
	"3.10.4": {
		"family": "3.10",
		"text": "Maintain audit logs of physical access.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access control; system security plan; physical access control logs or records; inventory records of physical access control devices; system entry and exit points; records of key and lock combination changes; storage locations for physical access control devices; physical access control devices; list of security safeguards controlling access to designated publicly accessible areas within facility; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with physical access control responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for physical access control; mechanisms supporting or implementing physical access control; physical access control devices]."],
		},
	},
	"3.10.5": {
		"family": "3.10",
		"text": "Control and manage physical access devices.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access control; system security plan; physical access control logs or records; inventory records of physical access control devices; system entry and exit points; records of key and lock combination changes; storage locations for physical access control devices; physical access control devices; list of security safeguards controlling access to designated publicly accessible areas within facility; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with physical access control responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for physical access control; mechanisms supporting or implementing physical access control; physical access control devices]."],
		},
	},
	"3.10.6": {
		"family": "3.10",
		"text": "Enforce safeguarding measures for CUI at alternate work sites.",
		"methods": {
			"examine": ["[SELECT FROM: Physical and environmental protection policy; procedures addressing alternate work sites for personnel; system security plan; list of safeguards required for alternate work sites; assessments of safeguards at alternate work sites; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel approving use of alternate work sites; personnel using alternate work sites; personnel assessing controls at alternate work sites; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for security at alternate work sites; mechanisms supporting alternate work sites; safeguards employed at alternate work sites; means of communications between personnel at alternate work sites and security personnel]."],
		},
	},
	"3.11.1": {
		"family": "3.11",
		"text": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
		"methods": {
			"examine": ["[SELECT FROM: Risk assessment policy; security planning policy and procedures; procedures addressing organizational risk assessments; system security plan; risk assessment; risk assessment results; risk assessment reviews; risk assessment updates; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with risk assessment responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for risk assessment; mechanisms supporting or for conducting, documenting, reviewing, disseminating, and updating the risk assessment]."],
		},
	},
	"3.11.2": {
		"family": "3.11",
		"text": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
		"methods": {
			"examine": ["[SELECT FROM: Risk assessment policy; procedures addressing vulnerability scanning; risk assessment; system security plan; security assessment report; vulnerability scanning tools and associated configuration documentation; vulnerability scanning results; patch and vulnerability management records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with risk assessment, security assessment and vulnerability scanning responsibilities; personnel with vulnerability scan analysis and remediation responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for vulnerability scanning, analysis, remediation, and information sharing; mechanisms supporting or implementing vulnerability scanning, analysis, remediation, and information sharing]."],
		},
	},
	"3.11.3": {
		"family": "3.11",
		"text": "Remediate vulnerabilities in accordance with risk assessments.",
		"methods": {
			"examine": ["[SELECT FROM: Risk assessment policy; procedures addressing vulnerability scanning; risk assessment; system security plan; security assessment report; vulnerability scanning tools and associated configuration documentation; vulnerability scanning results; patch and vulnerability management records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with risk assessment, security assessment and vulnerability scanning responsibilities; personnel with vulnerability scan analysis responsibilities; personnel with vulnerability remediation responsibilities; personnel with information security responsibilities; system or network administrators]."],
			"test": ["[SELECT FROM: Organizational processes for vulnerability scanning, analysis, remediation, and information sharing; mechanisms supporting or implementing vulnerability scanning, analysis, remediation, and information sharing]."],
		},
	},
	"3.12.1": {
		"family": "3.12",
		"text": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
		"methods": {
			"examine": ["[SELECT FROM: Security assessment and authorization policy; procedures addressing security assessment planning; procedures addressing security assessments; security assessment plan; system security plan; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security assessment responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms supporting security assessment, security assessment plan development, and security assessment reporting]."],
		},
	},
	"3.12.2": {
		"family": "3.12",
		"text": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Security assessment and authorization policy; procedures addressing plan of action; system security plan; security assessment plan; security assessment report; security assessment evidence; plan of action; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with plan of action development and implementation responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms for developing, implementing, and maintaining plan of action]."],
		},
	},
	"3.12.3": {
		"family": "3.12",
		"text": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
		"methods": {
			"examine": ["[SELECT FROM: Security planning policy; organizational procedures addressing system security plan development and implementation; procedures addressing system security plan reviews and updates; enterprise architecture documentation; system security plan; records of system security plan reviews and updates; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security planning and system security plan implementation responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for system security plan development, review, update, and approval; mechanisms supporting the system security plan]."],
		},
	},
	"3.12.4": {
		"family": "3.12",
		"text": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
		"methods": {
			"examine": ["[SELECT FROM: Security planning policy; procedures addressing system security plan development and implementation; procedures addressing system security plan reviews and updates; enterprise architecture documentation; system security plan; records of system security plan reviews and updates; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security planning and system security plan implementation responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for system security plan development, review, update, and approval; mechanisms supporting the system security plan]."],
		},
	},
	"3.13.1": {
		"family": "3.13",
		"text": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system security plan; list of key internal boundaries of the system; system design documentation; boundary protection hardware and software; enterprise security architecture documentation; system audit logs and records; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with boundary protection responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing boundary protection capability]."],
		},
	},
	"3.13.2": {
		"family": "3.13",
		"text": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Security planning policy; procedures addressing system security plan development and implementation; procedures addressing system security plan reviews and updates; enterprise architecture documentation; system security plan; records of system security plan reviews and updates; system and communications protection policy; procedures addressing security engineering principles used in the specification, design, development, implementation, and modification of the system; security architecture documentation; security requirements and specifications for the system; system design documentation; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with responsibility for determining information system security requirements; personnel with information system design, development, implementation, and modification responsibilities; personnel with security planning and system security plan implementation responsibilities; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for system security plan development, review, update, and approval; mechanisms supporting the system security plan; processes for applying security engineering principles in system specification, design, development, implementation, and modification; automated mechanisms supporting the application of security engineering principles in information system specification, design, development, implementation, and modification]."],
		},
	},
	"3.13.3": {
		"family": "3.13",
		"text": "Separate user functionality from system management functionality.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing application partitioning; system design documentation; system configuration settings and associated documentation; system security plan; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer]."],
			"test": ["[SELECT FROM: Separation of user functionality from system management functionality]."],
		},
	},
	"3.13.4": {
		"family": "3.13",
		"text": "Prevent unauthorized and unintended information transfer via shared system resources.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing application partitioning; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer]."],
			"test": ["[SELECT FROM: Separation of user functionality from system management functionality]."],
		},
	},
	"3.13.5": {
		"family": "3.13",
		"text": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system security plan; list of key internal boundaries of the system; system design documentation; boundary protection hardware and software; system configuration settings and associated documentation; enterprise security architecture documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with boundary protection responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing boundary protection capability]."],
		},
	},
	"3.13.6": {
		"family": "3.13",
		"text": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with boundary protection responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing traffic management at managed interfaces]."],
		},
	},
	"3.13.7": {
		"family": "3.13",
		"text": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system security plan; system design documentation; system hardware and software; system architecture; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with boundary protection responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms implementing boundary protection capability; mechanisms supporting or restricting non-remote connections]."],
		},
	},
	"3.13.8": {
		"family": "3.13",
		"text": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing transmission confidentiality and integrity; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer]."],
			"test": ["[SELECT FROM: Cryptographic mechanisms or mechanisms supporting or implementing transmission confidentiality; organizational processes for defining and implementing alternative physical safeguards]."],
		},
	},
	"3.13.9": {
		"family": "3.13",
		"text": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing network disconnect; system design documentation; system security plan; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing network disconnect capability]."],
		},
	},
	"3.13.10": {
		"family": "3.13",
		"text": "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing cryptographic key establishment and management; system security plan; system design documentation; cryptographic mechanisms; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel with responsibilities for cryptographic key establishment and management]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing cryptographic key establishment and management]."],
		},
	},
	"3.13.11": {
		"family": "3.13",
		"text": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing cryptographic protection; system security plan; system design documentation; system configuration settings and associated documentation; cryptographic module validation certificates; list of FIPS-validated cryptographic modules; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with responsibilities for cryptographic protection]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing cryptographic protection]."],
		},
	},
	"3.13.12": {
		"family": "3.13",
		"text": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing collaborative computing; access control policy and procedures; system security plan; system design documentation; system audit logs and records; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer; personnel with responsibilities for managing collaborative computing devices]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing management of remote activation of collaborative computing devices; mechanisms providing an indication of use of collaborative computing devices]."],
		},
	},
	"3.13.13": {
		"family": "3.13",
		"text": "Control and monitor the use of mobile code.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing mobile code; mobile code usage restrictions, mobile code implementation policy and procedures; system audit logs and records; system security plan; list of acceptable mobile code and mobile code technologies; list of unacceptable mobile code and mobile technologies; authorization records; system monitoring records; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel with responsibilities for managing mobile code]."],
			"test": ["[SELECT FROM: Organizational process for controlling, authorizing, monitoring, and restricting mobile code; mechanisms supporting or implementing the management of mobile code; mechanisms supporting or implementing the monitoring of mobile code]."],
		},
	},
	"3.13.14": {
		"family": "3.13",
		"text": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing VoIP; VoIP usage restrictions; VoIP implementation guidance; system security plan; system design documentation; system audit logs and records; system configuration settings and associated documentation; system monitoring records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel with responsibilities for managing VoIP]."],
			"test": ["[SELECT FROM: Organizational process for authorizing, monitoring, and controlling VoIP; mechanisms supporting or implementing authorizing, monitoring, and controlling VoIP]."],
		},
	},
	"3.13.15": {
		"family": "3.13",
		"text": "Protect the authenticity of communications sessions.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing session authenticity; system security plan; system design documentation; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing session authenticity]."],
		},
	},
	"3.13.16": {
		"family": "3.13",
		"text": "Protect the confidentiality of CUI at rest.",
		"methods": {
			"examine": ["[SELECT FROM: System and communications protection policy; procedures addressing protection of information at rest; system security plan; system design documentation; list of information at rest requiring confidentiality protections; system configuration settings and associated documentation; cryptographic mechanisms and associated configuration documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; system developer]."],
			"test": ["[SELECT FROM: Mechanisms supporting or implementing confidentiality protections for information at rest]."],
		},
	},
	"3.14.1": {
		"family": "3.14",
		"text": "Identify, report, and correct system flaws in a timely manner.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; procedures addressing flaw remediation; procedures addressing configuration management; system security plan; list of flaws and vulnerabilities potentially affecting the system; list of recent security flaw remediation actions performed on the system (e.g., list of installed patches, service packs, hot fixes, and other software updates to correct system flaws); test results from the installation of software and firmware updates to correct system flaws; installation/change control records for security-relevant software and firmware updates; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility for flaw remediation; personnel with configuration management responsibility]."],
			"test": ["[SELECT FROM: Organizational processes for identifying, reporting, and correcting system flaws; organizational process for installing software and firmware updates; mechanisms supporting or implementing reporting, and correcting system flaws; mechanisms supporting or implementing testing software and firmware updates]."],
		},
	},
	"3.14.2": {
		"family": "3.14",
		"text": "Provide protection from malicious code at designated locations within organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; configuration management policy and procedures; procedures addressing malicious code protection; records of malicious code protection updates; malicious code protection mechanisms; system security plan; system configuration settings and associated documentation; record of actions initiated by malicious code protection mechanisms in response to malicious code detection; scan results from malicious code protection mechanisms; system design documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility for malicious code protection; personnel with configuration management responsibility]."],
			"test": ["[SELECT FROM: Organizational processes for employing, updating, and configuring malicious code protection mechanisms; organizational process for addressing false positives and resulting potential impact; mechanisms supporting or implementing employing, updating, and configuring malicious code protection mechanisms; mechanisms supporting or implementing malicious code scanning and subsequent actions]."],
		},
	},
	"3.14.3": {
		"family": "3.14",
		"text": "Monitor system security alerts and advisories and take action in response.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; procedures addressing security alerts, advisories, and directives; system security plan; records of security alerts and advisories; other relevant documents or records]."],
			"interview": ["[SELECT FROM: Personnel with security alert and advisory responsibilities; personnel implementing, operating, maintaining, and using the system; personnel, organizational elements, and external organizations to whom alerts, advisories, and directives are to be disseminated; system or network administrators; personnel with information security responsibilities]."],
			"test": ["[SELECT FROM: Organizational processes for defining, receiving, generating, disseminating, and complying with security alerts, advisories, and directives; mechanisms supporting or implementing definition, receipt, generation, and dissemination of security alerts, advisories, and directives; mechanisms supporting or implementing security directives]."],
		},
	},
	"3.14.4": {
		"family": "3.14",
		"text": "Update malicious code protection mechanisms when new releases are available.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; configuration management policy and procedures; procedures addressing malicious code protection; malicious code protection mechanisms; records of malicious code protection updates; system security plan; system design documentation; system configuration settings and associated documentation; scan results from malicious code protection mechanisms; record of actions initiated by malicious code protection mechanisms in response to malicious code detection; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility for malicious code protection; personnel with configuration management responsibility]."],
			"test": ["[SELECT FROM: Organizational processes for employing, updating, and configuring malicious code protection mechanisms; organizational process for addressing false positives and resulting potential impact; mechanisms supporting or implementing malicious code protection mechanisms (including updates and configurations); mechanisms supporting or implementing malicious code scanning and subsequent actions]."],
		},
	},
	"3.14.5": {
		"family": "3.14",
		"text": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; configuration management policy and procedures; procedures addressing malicious code protection; malicious code protection mechanisms; records of malicious code protection updates; system security plan; system design documentation; system configuration settings and associated documentation; scan results from malicious code protection mechanisms; record of actions initiated by malicious code protection mechanisms in response to malicious code detection; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility for malicious code protection; personnel with configuration management responsibility]."],
			"test": ["[SELECT FROM: Organizational processes for employing, updating, and configuring malicious code protection mechanisms; organizational process for addressing false positives and resulting potential impact; mechanisms supporting or implementing malicious code protection mechanisms (including updates and configurations); mechanisms supporting or implementing malicious code scanning and subsequent actions]."],
		},
	},
	"3.14.6": {
		"family": "3.14",
		"text": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
		"methods": {
			"examine": ["[SELECT FROM: System and information integrity policy; procedures addressing system monitoring tools and techniques; continuous monitoring strategy; system and information integrity policy; procedures addressing system monitoring tools and techniques; facility diagram or layout; system security plan; system monitoring tools and techniques documentation; system design documentation; locations within system where monitoring devices are deployed; system protocols; system configuration settings and associated documentation; system audit logs and records; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility monitoring the system; personnel with responsibility for the intrusion detection system]."],
			"test": ["[SELECT FROM: Organizational processes for system monitoring; mechanisms supporting or implementing intrusion detection capability and system monitoring; mechanisms supporting or implementing system monitoring capability; organizational processes for intrusion detection and system monitoring; mechanisms supporting or implementing the monitoring of inbound and outbound communications traffic]."],
		},
	},
	"3.14.7": {
		"family": "3.14",
		"text": "Identify unauthorized use of organizational systems.",
		"methods": {
			"examine": ["[SELECT FROM: Continuous monitoring strategy; system and information integrity policy; procedures addressing system monitoring tools and techniques; facility diagram/layout; system security plan; system design documentation; system monitoring tools and techniques documentation; locations within system where monitoring devices are deployed; system configuration settings and associated documentation; other relevant documents or records]."],
			"interview": ["[SELECT FROM: System or network administrators; personnel with information security responsibilities; personnel installing, configuring, and maintaining the system; personnel with responsibility for monitoring the system]."],
			"test": ["[SELECT FROM: Organizational processes for system monitoring; mechanisms supporting or implementing system monitoring capability]."],
		},
	},
}

# document order; the determinations lookup below is keyed by id
objectives := [
	{"id": "3.1.1[a]", "requirement": "3.1.1", "labelled": true, "text": "authorized users are identified."},
	{"id": "3.1.1[b]", "requirement": "3.1.1", "labelled": true, "text": "processes acting on behalf of authorized users are identified."},
	{"id": "3.1.1[c]", "requirement": "3.1.1", "labelled": true, "text": "devices (and other systems) authorized to connect to the system are identified."},
	{"id": "3.1.1[d]", "requirement": "3.1.1", "labelled": true, "text": "system access is limited to authorized users."},
	{"id": "3.1.1[e]", "requirement": "3.1.1", "labelled": true, "text": "system access is limited to processes acting on behalf of authorized users."},
	{"id": "3.1.1[f]", "requirement": "3.1.1", "labelled": true, "text": "system access is limited to authorized devices (including other systems)."},
	{"id": "3.1.2[a]", "requirement": "3.1.2", "labelled": true, "text": "the types of transactions and functions that authorized users are permitted to execute are defined."},
	{"id": "3.1.2[b]", "requirement": "3.1.2", "labelled": true, "text": "system access is limited to the defined types of transactions and functions for authorized users."},
	{"id": "3.1.3[a]", "requirement": "3.1.3", "labelled": true, "text": "information flow control policies are defined."},
	{"id": "3.1.3[b]", "requirement": "3.1.3", "labelled": true, "text": "methods and enforcement mechanisms for controlling the flow of CUI are defined."},
	{"id": "3.1.3[c]", "requirement": "3.1.3", "labelled": true, "text": "designated sources and destinations (e.g., networks, individuals, and devices) for CUI within the system and between interconnected systems are identified."},
	{"id": "3.1.3[d]", "requirement": "3.1.3", "labelled": true, "text": "authorizations for controlling the flow of CUI are defined."},
	{"id": "3.1.3[e]", "requirement": "3.1.3", "labelled": true, "text": "approved authorizations for controlling the flow of CUI are enforced."},
	{"id": "3.1.4[a]", "requirement": "3.1.4", "labelled": true, "text": "the duties of individuals requiring separation are defined."},
	{"id": "3.1.4[b]", "requirement": "3.1.4", "labelled": true, "text": "responsibilities for duties that require separation are assigned to separate individuals."},
	{"id": "3.1.4[c]", "requirement": "3.1.4", "labelled": true, "text": "access privileges that enable individuals to exercise the duties that require separation are granted to separate individuals."},
	{"id": "3.1.5[a]", "requirement": "3.1.5", "labelled": true, "text": "privileged accounts are identified."},
	{"id": "3.1.5[b]", "requirement": "3.1.5", "labelled": true, "text": "access to privileged accounts is authorized in accordance with the principle of least privilege."},
	{"id": "3.1.5[c]", "requirement": "3.1.5", "labelled": true, "text": "security functions are identified."},
	{"id": "3.1.5[d]", "requirement": "3.1.5", "labelled": true, "text": "access to security functions is authorized in accordance with the principle of least privilege."},
	{"id": "3.1.6[a]", "requirement": "3.1.6", "labelled": true, "text": "nonsecurity functions are identified."},
	{"id": "3.1.6[b]", "requirement": "3.1.6", "labelled": true, "text": "users are required to use non-privileged accounts or roles when accessing nonsecurity functions."},
	{"id": "3.1.7[a]", "requirement": "3.1.7", "labelled": true, "text": "privileged functions are defined."},
	{"id": "3.1.7[b]", "requirement": "3.1.7", "labelled": true, "text": "non-privileged users are defined."},
	{"id": "3.1.7[c]", "requirement": "3.1.7", "labelled": true, "text": "non-privileged users are prevented from executing privileged functions."},
	{"id": "3.1.7[d]", "requirement": "3.1.7", "labelled": true, "text": "the execution of privileged functions is captured in audit logs."},
	{"id": "3.1.8[a]", "requirement": "3.1.8", "labelled": true, "text": "the means of limiting unsuccessful logon attempts is defined."},
	{"id": "3.1.8[b]", "requirement": "3.1.8", "labelled": true, "text": "the defined means of limiting unsuccessful logon attempts is implemented."},
	{"id": "3.1.9[a]", "requirement": "3.1.9", "labelled": true, "text": "privacy and security notices required by CUI-specified rules are identified, consistent, and associated with the specific CUI category."},
	{"id": "3.1.9[b]", "requirement": "3.1.9", "labelled": true, "text": "privacy and security notices are displayed."},
	{"id": "3.1.10[a]", "requirement": "3.1.10", "labelled": true, "text": "the period of inactivity after which the system initiates a session lock is defined."},
	{"id": "3.1.10[b]", "requirement": "3.1.10", "labelled": true, "text": "access to the system and viewing of data is prevented by initiating a session lock after the defined period of inactivity."},
	{"id": "3.1.10[c]", "requirement": "3.1.10", "labelled": true, "text": "previously visible information is concealed via a pattern-hiding display after the defined period of inactivity."},
	{"id": "3.1.11[a]", "requirement": "3.1.11", "labelled": true, "text": "conditions requiring a user session to terminate are defined."},
	{"id": "3.1.11[b]", "requirement": "3.1.11", "labelled": true, "text": "a user session is automatically terminated after any of the defined conditions occur."},
	{"id": "3.1.12[a]", "requirement": "3.1.12", "labelled": true, "text": "remote access sessions are permitted."},
	{"id": "3.1.12[b]", "requirement": "3.1.12", "labelled": true, "text": "the types of permitted remote access are identified."},
	{"id": "3.1.12[c]", "requirement": "3.1.12", "labelled": true, "text": "remote access sessions are controlled."},
	{"id": "3.1.12[d]", "requirement": "3.1.12", "labelled": true, "text": "remote access sessions are monitored."},
	{"id": "3.1.13[a]", "requirement": "3.1.13", "labelled": true, "text": "cryptographic mechanisms to protect the confidentiality of remote access sessions are identified."},
	{"id": "3.1.13[b]", "requirement": "3.1.13", "labelled": true, "text": "cryptographic mechanisms to protect the confidentiality of remote access sessions are implemented."},
	{"id": "3.1.14[a]", "requirement": "3.1.14", "labelled": true, "text": "managed access control points are identified and implemented."},
	{"id": "3.1.14[b]", "requirement": "3.1.14", "labelled": true, "text": "remote access is routed through managed network access control points."},
	{"id": "3.1.15[a]", "requirement": "3.1.15", "labelled": true, "text": "privileged commands authorized for remote execution are identified."},
	{"id": "3.1.15[b]", "requirement": "3.1.15", "labelled": true, "text": "security-relevant information authorized to be accessed remotely is identified."},
	{"id": "3.1.15[c]", "requirement": "3.1.15", "labelled": true, "text": "the execution of the identified privileged commands via remote access is authorized."},
	{"id": "3.1.15[d]", "requirement": "3.1.15", "labelled": true, "text": "access to the identified security-relevant information via remote access is authorized."},
	{"id": "3.1.16[a]", "requirement": "3.1.16", "labelled": true, "text": "wireless access points are identified."},
	{"id": "3.1.16[b]", "requirement": "3.1.16", "labelled": true, "text": "wireless access is authorized prior to allowing such connections."},
	{"id": "3.1.17[a]", "requirement": "3.1.17", "labelled": true, "text": "wireless access to the system is protected using authentication."},
	{"id": "3.1.17[b]", "requirement": "3.1.17", "labelled": true, "text": "wireless access to the system is protected using encryption."},
	{"id": "3.1.18[a]", "requirement": "3.1.18", "labelled": true, "text": "mobile devices that process, store, or transmit CUI are identified."},
	{"id": "3.1.18[b]", "requirement": "3.1.18", "labelled": true, "text": "mobile device connections are authorized."},
	{"id": "3.1.18[c]", "requirement": "3.1.18", "labelled": true, "text": "mobile device connections are monitored and logged."},
	{"id": "3.1.19[a]", "requirement": "3.1.19", "labelled": true, "text": "mobile devices and mobile computing platforms that process, store, or transmit CUI are identified."},
	{"id": "3.1.19[b]", "requirement": "3.1.19", "labelled": true, "text": "encryption is employed to protect CUI on identified mobile devices and mobile computing platforms."},
	{"id": "3.1.20[a]", "requirement": "3.1.20", "labelled": true, "text": "connections to external systems are identified."},
	{"id": "3.1.20[b]", "requirement": "3.1.20", "labelled": true, "text": "the use of external systems is identified."},
	{"id": "3.1.20[c]", "requirement": "3.1.20", "labelled": true, "text": "connections to external systems are verified."},
	{"id": "3.1.20[d]", "requirement": "3.1.20", "labelled": true, "text": "the use of external systems is verified."},
	{"id": "3.1.20[e]", "requirement": "3.1.20", "labelled": true, "text": "connections to external systems are controlled/limited."},
	{"id": "3.1.20[f]", "requirement": "3.1.20", "labelled": true, "text": "the use of external systems is controlled/limited."},
	{"id": "3.1.21[a]", "requirement": "3.1.21", "labelled": true, "text": "the use of portable storage devices containing CUI on external systems is identified and documented."},
	{"id": "3.1.21[b]", "requirement": "3.1.21", "labelled": true, "text": "limits on the use of portable storage devices containing CUI on external systems are defined."},
	{"id": "3.1.21[c]", "requirement": "3.1.21", "labelled": true, "text": "the use of portable storage devices containing CUI on external systems is limited as defined."},
	{"id": "3.1.22[a]", "requirement": "3.1.22", "labelled": true, "text": "individuals authorized to post or process information on publicly accessible systems are identified."},
	{"id": "3.1.22[b]", "requirement": "3.1.22", "labelled": true, "text": "procedures to ensure CUI is not posted or processed on publicly accessible systems are identified."},
	{"id": "3.1.22[c]", "requirement": "3.1.22", "labelled": true, "text": "a review process is in place prior to posting of any content to publicly accessible systems."},
	{"id": "3.1.22[d]", "requirement": "3.1.22", "labelled": true, "text": "content on publicly accessible systems is reviewed to ensure that it does not include CUI."},
	{"id": "3.1.22[e]", "requirement": "3.1.22", "labelled": true, "text": "mechanisms are in place to remove and address improper posting of CUI."},
	{"id": "3.2.1[a]", "requirement": "3.2.1", "labelled": true, "text": "security risks associated with organizational activities involving CUI are identified."},
	{"id": "3.2.1[b]", "requirement": "3.2.1", "labelled": true, "text": "policies, standards, and procedures related to the security of the system are identified."},
	{"id": "3.2.1[c]", "requirement": "3.2.1", "labelled": true, "text": "managers, systems administrators, and users of the system are made aware of the security risks associated with their activities."},
	{"id": "3.2.1[d]", "requirement": "3.2.1", "labelled": true, "text": "managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system."},
	{"id": "3.2.2[a]", "requirement": "3.2.2", "labelled": true, "text": "information security-related duties, roles, and responsibilities are defined."},
	{"id": "3.2.2[b]", "requirement": "3.2.2", "labelled": true, "text": "information security-related duties, roles, and responsibilities are assigned to designated personnel."},
	{"id": "3.2.2[c]", "requirement": "3.2.2", "labelled": true, "text": "personnel are adequately trained to carry out their assigned information security-related duties, roles, and responsibilities."},
	{"id": "3.2.3[a]", "requirement": "3.2.3", "labelled": true, "text": "potential indicators associated with insider threats are identified."},
	{"id": "3.2.3[b]", "requirement": "3.2.3", "labelled": true, "text": "security awareness training on recognizing and reporting potential indicators of insider threat is provided to managers and employees."},
	{"id": "3.3.1[a]", "requirement": "3.3.1", "labelled": true, "text": "audit logs needed (i.e., event types to be logged) to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity are specified."},
	{"id": "3.3.1[b]", "requirement": "3.3.1", "labelled": true, "text": "the content of audit records needed to support monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity is defined."},
	{"id": "3.3.1[c]", "requirement": "3.3.1", "labelled": true, "text": "audit records are created (generated)."},
	{"id": "3.3.1[d]", "requirement": "3.3.1", "labelled": true, "text": "audit records, once created, contain the defined content."},
	{"id": "3.3.1[e]", "requirement": "3.3.1", "labelled": true, "text": "retention requirements for audit records are defined."},
	{"id": "3.3.1[f]", "requirement": "3.3.1", "labelled": true, "text": "audit records are retained as defined."},
	{"id": "3.3.2[a]", "requirement": "3.3.2", "labelled": true, "text": "the content of the audit records needed to support the ability to uniquely trace users to their actions is defined."},
	{"id": "3.3.2[b]", "requirement": "3.3.2", "labelled": true, "text": "audit records, once created, contain the defined content."},
	{"id": "3.3.3[a]", "requirement": "3.3.3", "labelled": true, "text": "a process for determining when to review logged events is defined."},
	{"id": "3.3.3[b]", "requirement": "3.3.3", "labelled": true, "text": "event types being logged are reviewed in accordance with the defined review process."},
	{"id": "3.3.3[c]", "requirement": "3.3.3", "labelled": true, "text": "event types being logged are updated based on the review."},
	{"id": "3.3.4[a]", "requirement": "3.3.4", "labelled": true, "text": "personnel or roles to be alerted in the event of an audit logging process failure are identified."},
	{"id": "3.3.4[b]", "requirement": "3.3.4", "labelled": true, "text": "types of audit logging process failures for which alert will be generated are defined."},
	{"id": "3.3.4[c]", "requirement": "3.3.4", "labelled": true, "text": "identified personnel or roles are alerted in the event of an audit logging process failure."},
	{"id": "3.3.5[a]", "requirement": "3.3.5", "labelled": true, "text": "audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity are defined."},
	{"id": "3.3.5[b]", "requirement": "3.3.5", "labelled": true, "text": "defined audit record review, analysis, and reporting processes are correlated."},
	{"id": "3.3.6[a]", "requirement": "3.3.6", "labelled": true, "text": "an audit record reduction capability that supports on-demand analysis is provided."},
	{"id": "3.3.6[b]", "requirement": "3.3.6", "labelled": true, "text": "a report generation capability that supports on-demand reporting is provided."},
	{"id": "3.3.7[a]", "requirement": "3.3.7", "labelled": true, "text": "internal system clocks are used to generate time stamps for audit records."},
	{"id": "3.3.7[b]", "requirement": "3.3.7", "labelled": true, "text": "an authoritative source with which to compare and synchronize internal system clocks is specified."},
	{"id": "3.3.7[c]", "requirement": "3.3.7", "labelled": true, "text": "internal system clocks used to generate time stamps for audit records are compared to and synchronized with the specified authoritative time source."},
	{"id": "3.3.8[a]", "requirement": "3.3.8", "labelled": true, "text": "audit information is protected from unauthorized access."},
	{"id": "3.3.8[b]", "requirement": "3.3.8", "labelled": true, "text": "audit information is protected from unauthorized modification."},
	{"id": "3.3.8[c]", "requirement": "3.3.8", "labelled": true, "text": "audit information is protected from unauthorized deletion."},
	{"id": "3.3.8[d]", "requirement": "3.3.8", "labelled": true, "text": "audit logging tools are protected from unauthorized access."},
	{"id": "3.3.8[e]", "requirement": "3.3.8", "labelled": true, "text": "audit logging tools are protected from unauthorized modification."},
	{"id": "3.3.8[f]", "requirement": "3.3.8", "labelled": true, "text": "audit logging tools are protected from unauthorized deletion."},
	{"id": "3.3.9[a]", "requirement": "3.3.9", "labelled": true, "text": "a subset of privileged users granted access to manage audit logging functionality is defined."},
	{"id": "3.3.9[b]", "requirement": "3.3.9", "labelled": true, "text": "management of audit logging functionality is limited to the defined subset of privileged users."},
	{"id": "3.4.1[a]", "requirement": "3.4.1", "labelled": true, "text": "a baseline configuration is established."},
	{"id": "3.4.1[b]", "requirement": "3.4.1", "labelled": true, "text": "the baseline configuration includes hardware, software, firmware, and documentation."},
	{"id": "3.4.1[c]", "requirement": "3.4.1", "labelled": true, "text": "the baseline configuration is maintained (reviewed and updated) throughout the system development life cycle."},
	{"id": "3.4.1[d]", "requirement": "3.4.1", "labelled": true, "text": "a system inventory is established."},
	{"id": "3.4.1[e]", "requirement": "3.4.1", "labelled": true, "text": "the system inventory includes hardware, software, firmware, and documentation."},
	{"id": "3.4.1[f]", "requirement": "3.4.1", "labelled": true, "text": "the inventory is maintained (reviewed and updated) throughout the system development life cycle."},
	{"id": "3.4.2[a]", "requirement": "3.4.2", "labelled": true, "text": "security configuration settings for information technology products employed in the system are established and included in the baseline configuration."},
	{"id": "3.4.2[b]", "requirement": "3.4.2", "labelled": true, "text": "security configuration settings for information technology products employed in the system are enforced."},
	{"id": "3.4.3[a]", "requirement": "3.4.3", "labelled": true, "text": "changes to the system are tracked."},
	{"id": "3.4.3[b]", "requirement": "3.4.3", "labelled": true, "text": "changes to the system are reviewed."},
	{"id": "3.4.3[c]", "requirement": "3.4.3", "labelled": true, "text": "changes to the system are approved or disapproved."},
	{"id": "3.4.3[d]", "requirement": "3.4.3", "labelled": true, "text": "changes to the system are logged."},
	{"id": "3.4.4", "requirement": "3.4.4", "labelled": false, "text": "the security impact of changes to the system is analyzed prior to implementation."},
	{"id": "3.4.5[a]", "requirement": "3.4.5", "labelled": true, "text": "physical access restrictions associated with changes to the system are defined."},
	{"id": "3.4.5[b]", "requirement": "3.4.5", "labelled": true, "text": "physical access restrictions associated with changes to the system are documented."},
	{"id": "3.4.5[c]", "requirement": "3.4.5", "labelled": true, "text": "physical access restrictions associated with changes to the system are approved."},
	{"id": "3.4.5[d]", "requirement": "3.4.5", "labelled": true, "text": "physical access restrictions associated with changes to the system are enforced."},
	{"id": "3.4.5[e]", "requirement": "3.4.5", "labelled": true, "text": "logical access restrictions associated with changes to the system are defined."},
	{"id": "3.4.5[f]", "requirement": "3.4.5", "labelled": true, "text": "logical access restrictions associated with changes to the system are documented."},
	{"id": "3.4.5[g]", "requirement": "3.4.5", "labelled": true, "text": "logical access restrictions associated with changes to the system are approved."},
	{"id": "3.4.5[h]", "requirement": "3.4.5", "labelled": true, "text": "logical access restrictions associated with changes to the system are enforced."},
	{"id": "3.4.6[a]", "requirement": "3.4.6", "labelled": true, "text": "essential system capabilities are defined based on the principle of least functionality."},
	{"id": "3.4.6[b]", "requirement": "3.4.6", "labelled": true, "text": "the system is configured to provide only the defined essential capabilities."},
	{"id": "3.4.7[a]", "requirement": "3.4.7", "labelled": true, "text": "essential programs are defined."},
	{"id": "3.4.7[b]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential programs is defined."},
	{"id": "3.4.7[c]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential programs is restricted, disabled, or prevented as defined."},
	{"id": "3.4.7[d]", "requirement": "3.4.7", "labelled": true, "text": "essential functions are defined."},
	{"id": "3.4.7[e]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential functions is defined."},
	{"id": "3.4.7[f]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential functions is restricted, disabled, or prevented as defined."},
	{"id": "3.4.7[g]", "requirement": "3.4.7", "labelled": true, "text": "essential ports are defined."},
	{"id": "3.4.7[h]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential ports is defined."},
	{"id": "3.4.7[i]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential ports is restricted, disabled, or prevented as defined."},
	{"id": "3.4.7[j]", "requirement": "3.4.7", "labelled": true, "text": "essential protocols are defined."},
	{"id": "3.4.7[k]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential protocols is defined."},
	{"id": "3.4.7[l]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential protocols is restricted, disabled, or prevented as defined."},
	{"id": "3.4.7[m]", "requirement": "3.4.7", "labelled": true, "text": "essential services are defined."},
	{"id": "3.4.7[n]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential services is defined."},
	{"id": "3.4.7[o]", "requirement": "3.4.7", "labelled": true, "text": "the use of nonessential services is restricted, disabled, or prevented as defined."},
	{"id": "3.4.8[a]", "requirement": "3.4.8", "labelled": true, "text": "a policy specifying whether whitelisting or blacklisting is to be implemented is specified."},
	{"id": "3.4.8[b]", "requirement": "3.4.8", "labelled": true, "text": "the software allowed to execute under whitelisting or denied use under blacklisting is specified."},
	{"id": "3.4.8[c]", "requirement": "3.4.8", "labelled": true, "text": "whitelisting to allow the execution of authorized software or blacklisting to prevent the use of unauthorized software is implemented as specified."},
	{"id": "3.4.9[a]", "requirement": "3.4.9", "labelled": true, "text": "a policy for controlling the installation of software by users is established."},
	{"id": "3.4.9[b]", "requirement": "3.4.9", "labelled": true, "text": "installation of software by users is controlled based on the established policy."},
	{"id": "3.4.9[c]", "requirement": "3.4.9", "labelled": true, "text": "installation of software by users is monitored."},
	{"id": "3.5.1[a]", "requirement": "3.5.1", "labelled": true, "text": "system users are identified."},
	{"id": "3.5.1[b]", "requirement": "3.5.1", "labelled": true, "text": "processes acting on behalf of users are identified."},
	{"id": "3.5.1[c]", "requirement": "3.5.1", "labelled": true, "text": "devices accessing the system are identified."},
	{"id": "3.5.2[a]", "requirement": "3.5.2", "labelled": true, "text": "the identity of each user is authenticated or verified as a prerequisite to system access."},
	{"id": "3.5.2[b]", "requirement": "3.5.2", "labelled": true, "text": "the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access."},
	{"id": "3.5.2[c]", "requirement": "3.5.2", "labelled": true, "text": "the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access."},
	{"id": "3.5.3[a]", "requirement": "3.5.3", "labelled": true, "text": "privileged accounts are identified."},
	{"id": "3.5.3[b]", "requirement": "3.5.3", "labelled": true, "text": "multifactor authentication is implemented for local access to privileged accounts."},
	{"id": "3.5.3[c]", "requirement": "3.5.3", "labelled": true, "text": "multifactor authentication is implemented for network access to privileged accounts."},
	{"id": "3.5.3[d]", "requirement": "3.5.3", "labelled": true, "text": "multifactor authentication is implemented for network access to non-privileged accounts."},
	{"id": "3.5.4", "requirement": "3.5.4", "labelled": false, "text": "replay-resistant authentication mechanisms are implemented for network account access to privileged and non-privileged accounts."},
	{"id": "3.5.5[a]", "requirement": "3.5.5", "labelled": true, "text": "a period within which identifiers cannot be reused is defined."},
	{"id": "3.5.5[b]", "requirement": "3.5.5", "labelled": true, "text": "reuse of identifiers is prevented within the defined period."},
	{"id": "3.5.6[a]", "requirement": "3.5.6", "labelled": true, "text": "a period of inactivity after which an identifier is disabled is defined."},
	{"id": "3.5.6[b]", "requirement": "3.5.6", "labelled": true, "text": "identifiers are disabled after the defined period of inactivity."},
	{"id": "3.5.7[a]", "requirement": "3.5.7", "labelled": true, "text": "password complexity requirements are defined."},
	{"id": "3.5.7[b]", "requirement": "3.5.7", "labelled": true, "text": "password change of character requirements are defined."},
	{"id": "3.5.7[c]", "requirement": "3.5.7", "labelled": true, "text": "minimum password complexity requirements as defined are enforced when new passwords are created."},
	{"id": "3.5.7[d]", "requirement": "3.5.7", "labelled": true, "text": "minimum password change of character requirements as defined are enforced when new passwords are created."},
	{"id": "3.5.8[a]", "requirement": "3.5.8", "labelled": true, "text": "the number of generations during which a password cannot be reused is specified."},
	{"id": "3.5.8[b]", "requirement": "3.5.8", "labelled": true, "text": "reuse of passwords is prohibited during the specified number of generations."},
	{"id": "3.5.9", "requirement": "3.5.9", "labelled": false, "text": "an immediate change to a permanent password is required when a temporary password is used for system logon."},
	{"id": "3.5.10[a]", "requirement": "3.5.10", "labelled": true, "text": "passwords are cryptographically protected in storage."},
	{"id": "3.5.10[b]", "requirement": "3.5.10", "labelled": true, "text": "passwords are cryptographically protected in transit."},
	{"id": "3.5.11", "requirement": "3.5.11", "labelled": false, "text": "authentication information is obscured during the authentication process."},
	{"id": "3.6.1[a]", "requirement": "3.6.1", "labelled": true, "text": "an operational incident-handling capability is established."},
	{"id": "3.6.1[b]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes preparation."},
	{"id": "3.6.1[c]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes detection."},
	{"id": "3.6.1[d]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes analysis."},
	{"id": "3.6.1[e]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes containment."},
	{"id": "3.6.1[f]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes recovery."},
	{"id": "3.6.1[g]", "requirement": "3.6.1", "labelled": true, "text": "the operational incident-handling capability includes user response activities."},
	{"id": "3.6.2[a]", "requirement": "3.6.2", "labelled": true, "text": "incidents are tracked."},
	{"id": "3.6.2[b]", "requirement": "3.6.2", "labelled": true, "text": "incidents are documented."},
	{"id": "3.6.2[c]", "requirement": "3.6.2", "labelled": true, "text": "authorities to whom incidents are to be reported are identified."},
	{"id": "3.6.2[d]", "requirement": "3.6.2", "labelled": true, "text": "organizational officials to whom incidents are to be reported are identified."},
	{"id": "3.6.2[e]", "requirement": "3.6.2", "labelled": true, "text": "identified authorities are notified of incidents."},
	{"id": "3.6.2[f]", "requirement": "3.6.2", "labelled": true, "text": "identified organizational officials are notified of incidents."},
	{"id": "3.6.3", "requirement": "3.6.3", "labelled": false, "text": "the incident response capability is tested."},
	{"id": "3.7.1", "requirement": "3.7.1", "labelled": false, "text": "system maintenance is performed."},
	{"id": "3.7.2[a]", "requirement": "3.7.2", "labelled": true, "text": "tools used to conduct system maintenance are controlled."},
	{"id": "3.7.2[b]", "requirement": "3.7.2", "labelled": true, "text": "techniques used to conduct system maintenance are controlled."},
	{"id": "3.7.2[c]", "requirement": "3.7.2", "labelled": true, "text": "mechanisms used to conduct system maintenance are controlled."},
	{"id": "3.7.2[d]", "requirement": "3.7.2", "labelled": true, "text": "personnel used to conduct system maintenance are controlled."},
	{"id": "3.7.3", "requirement": "3.7.3", "labelled": false, "text": "equipment to be removed from organizational spaces for off-site maintenance is sanitized of any CUI."},
	{"id": "3.7.4", "requirement": "3.7.4", "labelled": false, "text": "media containing diagnostic and test programs are checked for malicious code before being used in organizational systems that process, store, or transmit CUI."},
	{"id": "3.7.5[a]", "requirement": "3.7.5", "labelled": true, "text": "multifactor authentication is used to establish nonlocal maintenance sessions via external network connections."},
	{"id": "3.7.5[b]", "requirement": "3.7.5", "labelled": true, "text": "nonlocal maintenance sessions established via external network connections are terminated when nonlocal maintenance is complete."},
	{"id": "3.7.6", "requirement": "3.7.6", "labelled": false, "text": "maintenance personnel without required access authorization are supervised during maintenance activities."},
	{"id": "3.8.1[a]", "requirement": "3.8.1", "labelled": true, "text": "paper media containing CUI is physically controlled."},
	{"id": "3.8.1[b]", "requirement": "3.8.1", "labelled": true, "text": "digital media containing CUI is physically controlled."},
	{"id": "3.8.1[c]", "requirement": "3.8.1", "labelled": true, "text": "paper media containing CUI is securely stored."},
	{"id": "3.8.1[d]", "requirement": "3.8.1", "labelled": true, "text": "digital media containing CUI is securely stored."},
	{"id": "3.8.2", "requirement": "3.8.2", "labelled": false, "text": "access to CUI on system media is limited to authorized users."},
	{"id": "3.8.3[a]", "requirement": "3.8.3", "labelled": true, "text": "system media containing CUI is sanitized or destroyed before disposal."},
	{"id": "3.8.3[b]", "requirement": "3.8.3", "labelled": true, "text": "system media containing CUI is sanitized before it is released for reuse."},
	{"id": "3.8.4[a]", "requirement": "3.8.4", "labelled": true, "text": "media containing CUI is marked with applicable CUI markings."},
	{"id": "3.8.4[b]", "requirement": "3.8.4", "labelled": true, "text": "media containing CUI is marked with distribution limitations."},
	{"id": "3.8.5[a]", "requirement": "3.8.5", "labelled": true, "text": "access to media containing CUI is controlled."},
	{"id": "3.8.5[b]", "requirement": "3.8.5", "labelled": true, "text": "accountability for media containing CUI is maintained during transport outside of controlled areas."},
	{"id": "3.8.6", "requirement": "3.8.6", "labelled": false, "text": "the confidentiality of CUI stored on digital media is protected during transport using cryptographic mechanisms or alternative physical safeguards."},
	{"id": "3.8.7", "requirement": "3.8.7", "labelled": false, "text": "the use of removable media on system components is controlled."},
	{"id": "3.8.8", "requirement": "3.8.8", "labelled": false, "text": "the use of portable storage devices is prohibited when such devices have no identifiable owner."},
	{"id": "3.8.9", "requirement": "3.8.9", "labelled": false, "text": "the confidentiality of backup CUI is protected at storage locations."},
	{"id": "3.9.1", "requirement": "3.9.1", "labelled": false, "text": "individuals are screened prior to authorizing access to organizational systems containing CUI."},
	{"id": "3.9.2[a]", "requirement": "3.9.2", "labelled": true, "text": "a policy and/or process for terminating system access and any credentials coincident with personnel actions is established."},
	{"id": "3.9.2[b]", "requirement": "3.9.2", "labelled": true, "text": "system access and credentials are terminated consistent with personnel actions such as termination or transfer."},
	{"id": "3.9.2[c]", "requirement": "3.9.2", "labelled": true, "text": "the system is protected during and after personnel transfer actions."},
	{"id": "3.10.1[a]", "requirement": "3.10.1", "labelled": true, "text": "authorized individuals allowed physical access are identified."},
	{"id": "3.10.1[b]", "requirement": "3.10.1", "labelled": true, "text": "physical access to organizational systems is limited to authorized individuals."},
	{"id": "3.10.1[c]", "requirement": "3.10.1", "labelled": true, "text": "physical access to equipment is limited to authorized individuals."},
	{"id": "3.10.1[d]", "requirement": "3.10.1", "labelled": true, "text": "physical access to operating environments is limited to authorized individuals."},
	{"id": "3.10.2[a]", "requirement": "3.10.2", "labelled": true, "text": "the physical facility where organizational systems reside is protected."},
	{"id": "3.10.2[b]", "requirement": "3.10.2", "labelled": true, "text": "the support infrastructure for organizational systems is protected."},
	{"id": "3.10.2[c]", "requirement": "3.10.2", "labelled": true, "text": "the physical facility where organizational systems reside is monitored."},
	{"id": "3.10.2[d]", "requirement": "3.10.2", "labelled": true, "text": "the support infrastructure for organizational systems is monitored."},
	{"id": "3.10.3[a]", "requirement": "3.10.3", "labelled": true, "text": "visitors are escorted."},
	{"id": "3.10.3[b]", "requirement": "3.10.3", "labelled": true, "text": "visitor activity is monitored."},
	{"id": "3.10.4", "requirement": "3.10.4", "labelled": false, "text": "audit logs of physical access are maintained."},
	{"id": "3.10.5[a]", "requirement": "3.10.5", "labelled": true, "text": "physical access devices are identified."},
	{"id": "3.10.5[b]", "requirement": "3.10.5", "labelled": true, "text": "physical access devices are controlled."},
	{"id": "3.10.5[c]", "requirement": "3.10.5", "labelled": true, "text": "physical access devices are managed."},
	{"id": "3.10.6[a]", "requirement": "3.10.6", "labelled": true, "text": "safeguarding measures for CUI are defined for alternate work sites."},
	{"id": "3.10.6[b]", "requirement": "3.10.6", "labelled": true, "text": "safeguarding measures for CUI are enforced for alternate work sites."},
	{"id": "3.11.1[a]", "requirement": "3.11.1", "labelled": true, "text": "the frequency to assess risk to organizational operations, organizational assets, and individuals is defined."},
	{"id": "3.11.1[b]", "requirement": "3.11.1", "labelled": true, "text": "risk to organizational operations, organizational assets, and individuals resulting from the operation of an organizational system that processes, stores, or transmits CUI is assessed with the defined frequency."},
	{"id": "3.11.2[a]", "requirement": "3.11.2", "labelled": true, "text": "the frequency to scan for vulnerabilities in organizational systems and applications is defined."},
	{"id": "3.11.2[b]", "requirement": "3.11.2", "labelled": true, "text": "vulnerability scans are performed on organizational systems with the defined frequency."},
	{"id": "3.11.2[c]", "requirement": "3.11.2", "labelled": true, "text": "vulnerability scans are performed on applications with the defined frequency."},
	{"id": "3.11.2[d]", "requirement": "3.11.2", "labelled": true, "text": "vulnerability scans are performed on organizational systems when new vulnerabilities are identified."},
	{"id": "3.11.2[e]", "requirement": "3.11.2", "labelled": true, "text": "vulnerability scans are performed on applications when new vulnerabilities are identified."},
	{"id": "3.11.3[a]", "requirement": "3.11.3", "labelled": true, "text": "vulnerabilities are identified."},
	{"id": "3.11.3[b]", "requirement": "3.11.3", "labelled": true, "text": "vulnerabilities are remediated in accordance with risk assessments."},
	{"id": "3.12.1[a]", "requirement": "3.12.1", "labelled": true, "text": "the frequency of security control assessments is defined."},
	{"id": "3.12.1[b]", "requirement": "3.12.1", "labelled": true, "text": "security controls are assessed with the defined frequency to determine if the controls are effective in their application."},
	{"id": "3.12.2[a]", "requirement": "3.12.2", "labelled": true, "text": "deficiencies and vulnerabilities to be addressed by the plan of action are identified."},
	{"id": "3.12.2[b]", "requirement": "3.12.2", "labelled": true, "text": "a plan of action is developed to correct identified deficiencies and reduce or eliminate identified vulnerabilities."},
	{"id": "3.12.2[c]", "requirement": "3.12.2", "labelled": true, "text": "the plan of action is implemented to correct identified deficiencies and reduce or eliminate identified vulnerabilities."},
	{"id": "3.12.3", "requirement": "3.12.3", "labelled": false, "text": "security controls are monitored on an ongoing basis to ensure the continued effectiveness of those controls."},
	{"id": "3.12.4[a]", "requirement": "3.12.4", "labelled": true, "text": "a system security plan is developed."},
	{"id": "3.12.4[b]", "requirement": "3.12.4", "labelled": true, "text": "the system boundary is described and documented in the system security plan."},
	{"id": "3.12.4[c]", "requirement": "3.12.4", "labelled": true, "text": "the system environment of operation is described and documented in the system security plan."},
	{"id": "3.12.4[d]", "requirement": "3.12.4", "labelled": true, "text": "the security requirements identified and approved by the designated authority as non-applicable are identified."},
	{"id": "3.12.4[e]", "requirement": "3.12.4", "labelled": true, "text": "the method of security requirement implementation is described and documented in the system security plan."},
	{"id": "3.12.4[f]", "requirement": "3.12.4", "labelled": true, "text": "the relationship with or connection to other systems is described and documented in the system security plan."},
	{"id": "3.12.4[g]", "requirement": "3.12.4", "labelled": true, "text": "the frequency to update the system security plan is defined."},
	{"id": "3.12.4[h]", "requirement": "3.12.4", "labelled": true, "text": "system security plan is updated with the defined frequency."},
	{"id": "3.13.1[a]", "requirement": "3.13.1", "labelled": true, "text": "the external system boundary is defined."},
	{"id": "3.13.1[b]", "requirement": "3.13.1", "labelled": true, "text": "key internal system boundaries are defined."},
	{"id": "3.13.1[c]", "requirement": "3.13.1", "labelled": true, "text": "communications are monitored at the external system boundary."},
	{"id": "3.13.1[d]", "requirement": "3.13.1", "labelled": true, "text": "communications are monitored at key internal boundaries."},
	{"id": "3.13.1[e]", "requirement": "3.13.1", "labelled": true, "text": "communications are controlled at the external system boundary."},
	{"id": "3.13.1[f]", "requirement": "3.13.1", "labelled": true, "text": "communications are controlled at key internal boundaries."},
	{"id": "3.13.1[g]", "requirement": "3.13.1", "labelled": true, "text": "communications are protected at the external system boundary."},
	{"id": "3.13.1[h]", "requirement": "3.13.1", "labelled": true, "text": "communications are protected at key internal boundaries."},
	{"id": "3.13.2[a]", "requirement": "3.13.2", "labelled": true, "text": "architectural designs that promote effective information security are identified."},
	{"id": "3.13.2[b]", "requirement": "3.13.2", "labelled": true, "text": "software development techniques that promote effective information security are identified."},
	{"id": "3.13.2[c]", "requirement": "3.13.2", "labelled": true, "text": "systems engineering principles that promote effective information security are identified."},
	{"id": "3.13.2[d]", "requirement": "3.13.2", "labelled": true, "text": "identified architectural designs that promote effective information security are employed."},
	{"id": "3.13.2[e]", "requirement": "3.13.2", "labelled": true, "text": "identified software development techniques that promote effective information security are employed."},
	{"id": "3.13.2[f]", "requirement": "3.13.2", "labelled": true, "text": "identified systems engineering principles that promote effective information security are employed."},
	{"id": "3.13.3[a]", "requirement": "3.13.3", "labelled": true, "text": "user functionality is identified."},
	{"id": "3.13.3[b]", "requirement": "3.13.3", "labelled": true, "text": "system management functionality is identified."},
	{"id": "3.13.3[c]", "requirement": "3.13.3", "labelled": true, "text": "user functionality is separated from system management functionality."},
	{"id": "3.13.4", "requirement": "3.13.4", "labelled": false, "text": "unauthorized and unintended information transfer via shared system resources is prevented."},
	{"id": "3.13.5[a]", "requirement": "3.13.5", "labelled": true, "text": "publicly accessible system components are identified."},
	{"id": "3.13.5[b]", "requirement": "3.13.5", "labelled": true, "text": "subnetworks for publicly accessible system components are physically or logically separated from internal networks."},
	{"id": "3.13.6[a]", "requirement": "3.13.6", "labelled": true, "text": "network communications traffic is denied by default."},
	{"id": "3.13.6[b]", "requirement": "3.13.6", "labelled": true, "text": "network communications traffic is allowed by exception."},
	{"id": "3.13.7", "requirement": "3.13.7", "labelled": false, "text": "remote devices are prevented from simultaneously establishing non-remote connections with the system and communicating via some other connection to resources in external networks (i.e., split tunneling)."},
	{"id": "3.13.8[a]", "requirement": "3.13.8", "labelled": true, "text": "cryptographic mechanisms intended to prevent unauthorized disclosure of CUI are identified."},
	{"id": "3.13.8[b]", "requirement": "3.13.8", "labelled": true, "text": "alternative physical safeguards intended to prevent unauthorized disclosure of CUI are identified."},
	{"id": "3.13.8[c]", "requirement": "3.13.8", "labelled": true, "text": "either cryptographic mechanisms or alternative physical safeguards are implemented to prevent unauthorized disclosure of CUI during transmission."},
	{"id": "3.13.9[a]", "requirement": "3.13.9", "labelled": true, "text": "a period of inactivity to terminate network connections associated with communications sessions is defined."},
	{"id": "3.13.9[b]", "requirement": "3.13.9", "labelled": true, "text": "network connections associated with communications sessions are terminated at the end of the sessions."},
	{"id": "3.13.9[c]", "requirement": "3.13.9", "labelled": true, "text": "network connections associated with communications sessions are terminated after the defined period of inactivity."},
	{"id": "3.13.10[a]", "requirement": "3.13.10", "labelled": true, "text": "cryptographic keys are established whenever cryptography is employed."},
	{"id": "3.13.10[b]", "requirement": "3.13.10", "labelled": true, "text": "cryptographic keys are managed whenever cryptography is employed."},
	{"id": "3.13.11", "requirement": "3.13.11", "labelled": false, "text": "FIPS-validated cryptography is employed to protect the confidentiality of CUI."},
	{"id": "3.13.12[a]", "requirement": "3.13.12", "labelled": true, "text": "collaborative computing devices are identified."},
	{"id": "3.13.12[b]", "requirement": "3.13.12", "labelled": true, "text": "collaborative computing devices provide indication to users of devices in use."},
	{"id": "3.13.12[c]", "requirement": "3.13.12", "labelled": true, "text": "remote activation of collaborative computing devices is prohibited."},
	{"id": "3.13.13[a]", "requirement": "3.13.13", "labelled": true, "text": "use of mobile code is controlled."},
	{"id": "3.13.13[b]", "requirement": "3.13.13", "labelled": true, "text": "use of mobile code is monitored."},
	{"id": "3.13.14[a]", "requirement": "3.13.14", "labelled": true, "text": "use of Voice over Internet Protocol (VoIP) technologies is controlled."},
	{"id": "3.13.14[b]", "requirement": "3.13.14", "labelled": true, "text": "use of Voice over Internet Protocol (VoIP) technologies is monitored."},
	{"id": "3.13.15", "requirement": "3.13.15", "labelled": false, "text": "the authenticity of communications sessions is protected."},
	{"id": "3.13.16", "requirement": "3.13.16", "labelled": false, "text": "the confidentiality of CUI at rest is protected."},
	{"id": "3.14.1[a]", "requirement": "3.14.1", "labelled": true, "text": "the time within which to identify system flaws is specified."},
	{"id": "3.14.1[b]", "requirement": "3.14.1", "labelled": true, "text": "system flaws are identified within the specified time frame."},
	{"id": "3.14.1[c]", "requirement": "3.14.1", "labelled": true, "text": "the time within which to report system flaws is specified."},
	{"id": "3.14.1[d]", "requirement": "3.14.1", "labelled": true, "text": "system flaws are reported within the specified time frame."},
	{"id": "3.14.1[e]", "requirement": "3.14.1", "labelled": true, "text": "the time within which to correct system flaws is specified."},
	{"id": "3.14.1[f]", "requirement": "3.14.1", "labelled": true, "text": "system flaws are corrected within the specified time frame."},
	{"id": "3.14.2[a]", "requirement": "3.14.2", "labelled": true, "text": "designated locations for malicious code protection are identified."},
	{"id": "3.14.2[b]", "requirement": "3.14.2", "labelled": true, "text": "protection from malicious code at designated locations is provided."},
	{"id": "3.14.3[a]", "requirement": "3.14.3", "labelled": true, "text": "response actions to system security alerts and advisories are identified."},
	{"id": "3.14.3[b]", "requirement": "3.14.3", "labelled": true, "text": "system security alerts and advisories are monitored."},
	{"id": "3.14.3[c]", "requirement": "3.14.3", "labelled": true, "text": "actions in response to system security alerts and advisories are taken."},
	{"id": "3.14.4", "requirement": "3.14.4", "labelled": false, "text": "malicious code protection mechanisms are updated when new releases are available."},
	{"id": "3.14.5[a]", "requirement": "3.14.5", "labelled": true, "text": "the frequency for malicious code scans is defined."},
	{"id": "3.14.5[b]", "requirement": "3.14.5", "labelled": true, "text": "malicious code scans are performed with the defined frequency."},
	{"id": "3.14.5[c]", "requirement": "3.14.5", "labelled": true, "text": "real-time malicious code scans of files from external sources as files are downloaded, opened, or executed are performed."},
	{"id": "3.14.6[a]", "requirement": "3.14.6", "labelled": true, "text": "the system is monitored to detect attacks and indicators of potential attacks."},
	{"id": "3.14.6[b]", "requirement": "3.14.6", "labelled": true, "text": "inbound communications traffic is monitored to detect attacks and indicators of potential attacks."},
	{"id": "3.14.6[c]", "requirement": "3.14.6", "labelled": true, "text": "outbound communications traffic is monitored to detect attacks and indicators of potential attacks."},
	{"id": "3.14.7[a]", "requirement": "3.14.7", "labelled": true, "text": "authorized use of the system is defined."},
	{"id": "3.14.7[b]", "requirement": "3.14.7", "labelled": true, "text": "unauthorized use of the system is identified."},
]

determinations := {o.id: {"requirement": o.requirement, "labelled": o.labelled, "text": o.text} | some o in objectives}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_sp_800_171a_r2", {})

_given := d if {
	d := _in.determinations
	is_object(d)
}

_supplied if _given

_true(id) if _given[id] == true

_by_requirement[r] := ids if {
	some r, _ in requirements
	ids := {id | some id, d in determinations; d.requirement == r}
}

violations contains "NIST SP 800-171A: FAIL-CLOSED - determinations 'input.nist_sp_800_171a_r2.determinations' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, d in determinations
	not _true(id)
	msg := sprintf("NIST SP 800-171A %v (requirement %v): not determined satisfied — %v", [id, d.requirement, d.text])
}

violations contains msg if {
	some id, _ in _given
	not determinations[id]
	msg := sprintf("NIST SP 800-171A Input Contract: unknown determination id %v — ids are the SP 800-171A objective labels such as 3.1.1[a], or the bare requirement id such as 3.4.4 for a requirement with one unlabelled objective", [id])
}

# a requirement with no objectives can never be satisfied (no vacuous pass)
_req_satisfied(r) if {
	ids := _by_requirement[r]
	count(ids) > 0
	every id in ids { _true(id) }
}

_req_satisfied_bool(r) if _req_satisfied(r)

else := false

requirement_rollup[r] := s if {
	some r, q in requirements
	ids := _by_requirement[r]
	unsat := sort([id | some id in ids; not _true(id)])
	s := {
		"family": q.family,
		"text": q.text,
		"determinations_total": count(ids),
		"determinations_satisfied": count(ids) - count(unsat),
		"satisfied": _req_satisfied_bool(r),
		"not_satisfied": unsat,
		"methods": q.methods,
	}
}

family_reports[f] := s if {
	some f, name in families
	reqs := {r | some r, q in requirements; q.family == f}
	ids := {id | some r in reqs; some id in _by_requirement[r]}
	s := {
		"name": name,
		"determinations_total": count(ids),
		"determinations_satisfied": count({id | some id in ids; _true(id)}),
		"requirements_total": count(reqs),
		"requirements_satisfied": count({r | some r in reqs; _req_satisfied(r)}),
		"requirements_not_satisfied": sort([r | some r in reqs; not _req_satisfied(r)]),
	}
}

compliance_report := {
	"framework": "NIST SP 800-171A (Rev 2 assessment procedures)",
	"standard": "NIST SP 800-171A (June 2018) — Assessing Security Requirements for Controlled Unclassified Information",
	"source": source,
	"compliant": compliant,
	"total_controls": count(determinations),
	"standard_total": 320, # measured in the PDF (297 labelled + 23 unlabelled); the PDF itself states no total
	"determinations_total": count(determinations),
	"determinations_satisfied": count({id | some id, _ in determinations; _true(id)}),
	"requirements_total": count(requirements),
	"requirements_satisfied": count({r | some r, _ in requirements; _req_satisfied(r)}),
	"families_total": count(families),
	"families": family_reports,
	"requirements": requirement_rollup,
	"violation_count": count(violations),
	"violations": violations,
}
