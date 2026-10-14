# NIST SP 800-171A Rev 3 — Assessing Security Requirements for Controlled Unclassified Information
# the assessment procedures for SP 800-171 Rev 3. One attested row per determination statement.
#
# Source of truth: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export of
# SP 800-171 Rev 3 (doc_identifier SP_800_171_3_0_0, version 3.0.0),
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all
#   sha256 19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa, retrieved 2026-10-13.
# NIST text is public domain. Every id and every text string below is copied verbatim from that export by
# a generator; nothing is paraphrased. Parentage (family -> requirement -> statement -> determination)
# is taken from the export's `projection` relationships and was checked against the id spelling: zero
# disagreements.
# The SP 800-171A determinations and examine/interview/test methods are carried inside the SP 800-171
# Rev 3 CPRT export (element types `determination`, `examine`, `interview`, `test`); CPRT's separate
# SP_800_171A_3_0_0 export returned an empty response, so this module is built from the same file, hash
# and URL as frameworks/federal/nist/sp_800_171/.
#
# Id scheme (exactly the CPRT element_identifier values, prefixes kept):
#   determination  DS-A.03.01.01.a[01], DS-A.03.01.01.c.01, DS-A.03.05.03, …    (422)
#   statement      SR-03.01.01.a — the security requirement statement a determination belongs to
#   requirement    03.01.01 (97 active; withdrawn requirements have no determinations)
#   methods        E-03.01.01 (examine), I-03.01.01 (interview), T-03.01.01 (test): report data, not controls
# Export irregularities, kept verbatim: 2 determination ids use a one-digit bracket
# (DS-A.03.01.12.d[1], DS-A.03.01.12.d[2]); requirements without an examine/interview method:
# 03.01.22, 03.14.03; without a test method: 03.01.22, 03.06.03, 03.06.04, 03.12.05, 03.14.03, 03.15.01 — their method lists are empty.
# Not included: the 88 organization-defined-parameter objectives (`odp`, A.03.xx.yy.ODP[nn]); this
# module covers the 422 `determination` elements only, so the rollup does not include ODP definition.
#
# Families:
#   03.01 Access Control                                16 requirements,  74 determinations
#   03.02 Awareness and Training                         2 requirements,  17 determinations
#   03.03 Audit and Accountability                       8 requirements,  30 determinations
#   03.04 Configuration Management                      10 requirements,  49 determinations
#   03.05 Identification and Authentication              8 requirements,  36 determinations
#   03.06 Incident Response                              5 requirements,  29 determinations
#   03.07 Maintenance                                    3 requirements,  16 determinations
#   03.08 Media Protection                               7 requirements,  15 determinations
#   03.09 Personnel Security                             2 requirements,   9 determinations
#   03.10 Physical Protection                            5 requirements,  20 determinations
#   03.11 Risk Assessment                                3 requirements,  12 determinations
#   03.12 Security Assessment and Monitoring             4 requirements,  17 determinations
#   03.13 System and Communications Protection          10 requirements,  24 determinations
#   03.14 System and Information Integrity               5 requirements,  24 determinations
#   03.15 Planning                                       3 requirements,  22 determinations
#   03.16 System and Services Acquisition                3 requirements,   6 determinations
#   03.17 Supply Chain Risk Management                   3 requirements,  22 determinations
#
# Input: input.nist_sp_800_171a.determinations["DS-A.03.01.01.a[01]"] == true means the assessor determined
# that statement satisfied. Fail-closed: a missing or non-object determinations container is a FAIL-CLOSED
# violation; a missing, false or non-true value is a violation; an unknown id is a violation. A requirement
# is satisfied only when every one of its determinations is true (every requirement has at least one).
#
# Query: POST /v1/data/nist/sp800_171a/main/compliance_report

# METADATA
# title: "NIST SP 800-171A Rev 3 — 422 assessment determination statements (CPRT ids), attested"
# custom:
#   class: compliance
#   framework: nist_sp_800_171a
#   source: nist
#   domains: [us-federal, cui, assessment]
#   coverage:
#     checks: 456
#     cited: 455
#     expected: 422
#     found: 455
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171a.main

import rego.v1

source := {
	"publication": "NIST SP 800-171A Rev 3 (assessment procedures for SP 800-171 Rev 3)",
	"carried_in": "SP_800_171_3_0_0",
	"version": "3.0.0",
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
		"methods": {
			"examine": [{
				"id": "E-03.01.01",
				"text": "[SELECT FROM: access control policy and procedures; personnel termination or transfer policies and procedures; procedures for account management; list of active system accounts and the name of the individual associated with each account; system design documentation; list of conditions for group and role membership; system configuration settings; notifications of recent transfers, separations, or terminations of employees; list of recently disabled system accounts and the name of the individual associated with each account; list of user activities that pose significant organizational risks; access authorization records; account management compliance reviews; system monitoring and audit records; system security plan; system-generated list of accounts removed; system-generated list of emergency accounts disabled; system-generated list of disabled accounts; other relevant documents and records]",
			}],
			"interview": [{
				"id": "I-03.01.01",
				"text": "[SELECT FROM: personnel with account management responsibilities; system administrators; personnel with information security responsibilities; system developers]",
			}],
			"test": [{
				"id": "T-03.01.01",
				"text": "[SELECT FROM: processes for account management on the system; mechanisms for implementing account management]",
			}],
		},
	},
	"03.01.02": {
		"family": "03.01",
		"title": "Access Enforcement",
		"methods": {
			"examine": [{
				"id": "E-03.01.02",
				"text": "[SELECT FROM: access control policy and procedures; procedures for access enforcement; system design documentation; system configuration settings; list of approved authorizations (i.e., user privileges); system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.02",
				"text": "[SELECT FROM: personnel with access enforcement responsibilities; system administrators; personnel with information security responsibilities; system developers]",
			}],
			"test": [{
				"id": "T-03.01.02",
				"text": "[SELECT FROM: mechanisms for implementing the access control policy]",
			}],
		},
	},
	"03.01.03": {
		"family": "03.01",
		"title": "Information Flow Enforcement",
		"methods": {
			"examine": [{
				"id": "E-03.01.03",
				"text": "[SELECT FROM: access control policy and procedures; information flow control policies; procedures for information flow enforcement; security architecture and design documentation; system configuration settings; system baseline configuration; system audit records; list of information flow authorizations; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.03",
				"text": "[SELECT FROM: system administrators; personnel with security architecture responsibilities; personnel with information security responsibilities; system developers]",
			}],
			"test": [{
				"id": "T-03.01.03",
				"text": "[SELECT FROM: mechanisms for implementing the information flow enforcement policy]",
			}],
		},
	},
	"03.01.04": {
		"family": "03.01",
		"title": "Separation of Duties",
		"methods": {
			"examine": [{
				"id": "E-03.01.04",
				"text": "[SELECT FROM: access control policy and procedures; procedures for the separation of duties and the division of responsibilities; system configuration settings; system audit records; system access authorizations; list of divisions of responsibility and separation of duties; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.04",
				"text": "[SELECT FROM: personnel with responsibilities for defining the separation of duties and the division of responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.04",
				"text": "[SELECT FROM: mechanisms for implementing the separation of duties policy]",
			}],
		},
	},
	"03.01.05": {
		"family": "03.01",
		"title": "Least Privilege",
		"methods": {
			"examine": [{
				"id": "E-03.01.05",
				"text": "[SELECT FROM: access control policy and procedures; procedures for least privilege; list of assigned access authorizations (i.e., privileges); system configuration settings; system audit records; list of security functions (implemented in hardware, software, and firmware); security-relevant information for which access must be explicitly authorized; list of system-generated roles or classes of users and assigned privileges; validation reviews of privileges assigned to roles or classes of users; records of privilege removals or reassignments for roles or classes of users; system security plan; system design documentation; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.05",
				"text": "[SELECT FROM: personnel with responsibilities for defining least privileges; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.05",
				"text": "[SELECT FROM: mechanisms for implementing least privilege functions; mechanisms for implementing reviews of user privileges]",
			}],
		},
	},
	"03.01.06": {
		"family": "03.01",
		"title": "Least Privilege – Privileged Accounts",
		"methods": {
			"examine": [{
				"id": "E-03.01.06",
				"text": "[SELECT FROM: access control policy and procedures; procedures for least privilege; list of system-generated privileged accounts; list of system administration personnel; system audit records; system configuration settings; system security plan; list of system-generated security functions or security-relevant information assigned to system accounts or roles; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.06",
				"text": "[SELECT FROM: personnel with responsibilities for defining least privileges; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.06",
				"text": "[SELECT FROM: mechanisms for implementing least privilege functions]",
			}],
		},
	},
	"03.01.07": {
		"family": "03.01",
		"title": "Least Privilege – Privileged Functions",
		"methods": {
			"examine": [{
				"id": "E-03.01.07",
				"text": "[SELECT FROM: access control policy and procedures; procedures for least privilege; system design documentation; system configuration settings; system audit records; list of audited events; list of privileged functions to be audited and associated user account assignments; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.07",
				"text": "[SELECT FROM: personnel with responsibilities for reviewing least privileges; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.07",
				"text": "[SELECT FROM: mechanisms for auditing the execution of least privilege functions; mechanisms for implementing least privilege functions for non-privileged users]",
			}],
		},
	},
	"03.01.08": {
		"family": "03.01",
		"title": "Unsuccessful Logon Attempts",
		"methods": {
			"examine": [{
				"id": "E-03.01.08",
				"text": "[SELECT FROM: access control policy and procedures; procedures for unsuccessful logon attempts; system design documentation; system audit records; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.08",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.08",
				"text": "[SELECT FROM: mechanisms for implementing the access control policy for unsuccessful logon attempts]",
			}],
		},
	},
	"03.01.09": {
		"family": "03.01",
		"title": "System Use Notification",
		"methods": {
			"examine": [{
				"id": "E-03.01.09",
				"text": "[SELECT FROM: access control policy and procedures; privacy and security policies, procedures for system use notification; documented approval of system use notification messages; system audit records; user acknowledgements of system use notification messages; system design documentation; system configuration settings; system use notification messages; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.09",
				"text": "[SELECT FROM: personnel with information security responsibilities; legal counsel; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.09",
				"text": "[SELECT FROM: mechanisms for implementing system use notifications]",
			}],
		},
	},
	"03.01.10": {
		"family": "03.01",
		"title": "Device Lock",
		"methods": {
			"examine": [{
				"id": "E-03.01.10",
				"text": "[SELECT FROM: access control policy and procedures; procedures for session lock and identification and authentication; system design documentation; system configuration settings; display screen with session lock activated; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.10",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.10",
				"text": "[SELECT FROM: mechanisms for implementing the access control policy for session lock; session lock mechanisms]",
			}],
		},
	},
	"03.01.11": {
		"family": "03.01",
		"title": "Session Termination",
		"methods": {
			"examine": [{
				"id": "E-03.01.11",
				"text": "[SELECT FROM: access control policy and procedures; procedures for session termination; system design documentation; system configuration settings; list of conditions or trigger events requiring session disconnect; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.11",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.11",
				"text": "[SELECT FROM: automated mechanisms for implementing user session termination]",
			}],
		},
	},
	"03.01.12": {
		"family": "03.01",
		"title": "Remote Access",
		"methods": {
			"examine": [{
				"id": "E-03.01.12",
				"text": "[SELECT FROM: access control policy and procedures; procedures for remote system access; remote system access configuration and connection requirements; configuration management plan; system configuration settings; remote access authorizations; system audit records; system design documentation; procedures for remote access to the system; system monitoring records; list of managed network access control points; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.12",
				"text": "[SELECT FROM: personnel with responsibilities for managing remote access connections; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.12",
				"text": "[SELECT FROM: mechanisms for monitoring and controlling remote access methods; mechanisms for routing remote accesses through managed access control points; remote access management capability for the system]",
			}],
		},
	},
	"03.01.16": {
		"family": "03.01",
		"title": "Wireless Access",
		"methods": {
			"examine": [{
				"id": "E-03.01.16",
				"text": "[SELECT FROM: access control policy and procedures; procedures for wireless system access; wireless system access configuration and connection requirements; configuration management plan; system configuration settings; wireless access authorizations; system audit records; system design documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.16",
				"text": "[SELECT FROM: personnel with responsibilities for managing wireless access connections; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.16",
				"text": "[SELECT FROM: wireless access management capability for the system; mechanisms for implementing wireless access protections to the system; mechanisms for managing the disabling of wireless networking capabilities]",
			}],
		},
	},
	"03.01.18": {
		"family": "03.01",
		"title": "Access Control for Mobile Devices",
		"methods": {
			"examine": [{
				"id": "E-03.01.18",
				"text": "[SELECT FROM: access control policy and procedures; procedures for mobile device access control; system design documentation; configuration management plan; system configuration settings; authorizations for mobile device connections to organizational systems; system audit records; encryption mechanisms and associated configuration documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.18",
				"text": "[SELECT FROM: personnel with access control responsibilities for mobile devices; personnel using mobile devices to access organizational systems; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.18",
				"text": "[SELECT FROM: access control capability for mobile device connections to organizational systems; encryption mechanisms for protecting the confidentiality of CUI on mobile devices; configurations of mobile devices]",
			}],
		},
	},
	"03.01.20": {
		"family": "03.01",
		"title": "Use of External Systems",
		"methods": {
			"examine": [{
				"id": "E-03.01.20",
				"text": "[SELECT FROM: access control policy and procedures; procedures for the use of external systems; terms and conditions for the use of external systems; external systems security requirements; list of types of applications accessible from external systems; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.01.20",
				"text": "[SELECT FROM: personnel with responsibilities for defining terms, conditions, and security requirements for the use of external systems; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.01.20",
				"text": "[SELECT FROM: mechanisms for implementing or enforcing terms, conditions, and security requirements for the use of external systems]",
			}],
		},
	},
	"03.01.22": {
		"family": "03.01",
		"title": "Publicly Accessible Content",
		"methods": {
			"examine": [],
			"interview": [],
			"test": [],
		},
	},
	"03.02.01": {
		"family": "03.02",
		"title": "Literacy Training and Awareness",
		"methods": {
			"examine": [{
				"id": "E-03.02.01",
				"text": "[SELECT FROM: security literacy training and awareness policy and procedures; procedures for security literacy training and awareness implementation; codes of federal regulations; security literacy and awareness training curriculum; security literacy and awareness training materials; training records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.02.01",
				"text": "[SELECT FROM: personnel with responsibilities for security literacy training and awareness; personnel comprising the general system user community; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.02.01",
				"text": "[SELECT FROM: mechanisms for managing information security literacy training and awareness]",
			}],
		},
	},
	"03.02.02": {
		"family": "03.02",
		"title": "Role-Based Training",
		"methods": {
			"examine": [{
				"id": "E-03.02.02",
				"text": "[SELECT FROM: security awareness and training policy and procedures; procedures for security training implementation; codes of federal regulations; security training curriculum; security training materials; training records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.02.02",
				"text": "[SELECT FROM: personnel with responsibilities for role-based security training; personnel with assigned system security roles and responsibilities]",
			}],
			"test": [{
				"id": "T-03.02.02",
				"text": "[SELECT FROM: mechanisms for managing role-based security training and awareness]",
			}],
		},
	},
	"03.03.01": {
		"family": "03.03",
		"title": "Event Logging",
		"methods": {
			"examine": [{
				"id": "E-03.03.01",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for auditable events; system design documentation; system configuration settings; system audit records; system auditable events; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.01",
				"text": "[SELECT FROM: personnel with audit and accountability responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.01",
				"text": "[SELECT FROM: mechanisms for implementing system auditing]",
			}],
		},
	},
	"03.03.02": {
		"family": "03.03",
		"title": "Audit Record Content",
		"methods": {
			"examine": [{
				"id": "E-03.03.02",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for the content of audit records; list of organization-defined auditable events; system design documentation; system configuration settings; system audit records; system incident reports; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.02",
				"text": "[SELECT FROM: personnel with audit and accountability responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.02",
				"text": "[SELECT FROM: mechanisms for implementing system auditing of auditable events; system audit capability]",
			}],
		},
	},
	"03.03.03": {
		"family": "03.03",
		"title": "Audit Record Generation",
		"methods": {
			"examine": [{
				"id": "E-03.03.03",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for audit record generation; system design documentation; list of auditable events; system audit records; audit record retention policy and procedures; organization-defined retention period for audit records; audit record archives; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.03",
				"text": "[SELECT FROM: personnel with audit record generation responsibilities; personnel with audit record retention responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.03",
				"text": "[SELECT FROM: mechanisms for implementing the audit record generation capability]",
			}],
		},
	},
	"03.03.04": {
		"family": "03.03",
		"title": "Response to Audit Logging Process Failures",
		"methods": {
			"examine": [{
				"id": "E-03.03.04",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for responding to audit processing failures; system design documentation; system configuration settings; list of personnel to be notified in case of an audit processing failure; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.04",
				"text": "[SELECT FROM: personnel with audit and accountability responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.04",
				"text": "[SELECT FROM: mechanisms for implementing system response to audit processing failures]",
			}],
		},
	},
	"03.03.05": {
		"family": "03.03",
		"title": "Audit Record Review, Analysis, and Reporting",
		"methods": {
			"examine": [{
				"id": "E-03.03.05",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for audit record review, analysis, and reporting; reports of audit record findings; records of actions taken in response to reviews and analyses of audit records; system design documentation; system audit records across different repositories; system security plan; system configuration settings; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.05",
				"text": "[SELECT FROM: personnel with audit record review, analysis, and reporting responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.03.05",
				"text": "[SELECT FROM: mechanisms for supporting the analysis and correlation of audit records]",
			}],
		},
	},
	"03.03.06": {
		"family": "03.03",
		"title": "Audit Record Reduction and Report Generation",
		"methods": {
			"examine": [{
				"id": "E-03.03.06",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for audit record reduction and report generation; audit record reduction, review, analysis, and reporting tools; system audit records; system design documentation; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.06",
				"text": "[SELECT FROM: personnel with audit record reduction and report generation responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.03.06",
				"text": "[SELECT FROM: mechanisms for supporting audit record reduction and report generation capability]",
			}],
		},
	},
	"03.03.07": {
		"family": "03.03",
		"title": "Time Stamps",
		"methods": {
			"examine": [{
				"id": "E-03.03.07",
				"text": "[SELECT FROM: audit and accountability policy and procedures; procedures for timestamp generation; system design documentation; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.07",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.07",
				"text": "[SELECT FROM: mechanisms for implementing timestamp generation]",
			}],
		},
	},
	"03.03.08": {
		"family": "03.03",
		"title": "Protection of Audit Information",
		"methods": {
			"examine": [{
				"id": "E-03.03.08",
				"text": "[SELECT FROM: audit and accountability policy and procedures; access control policy and procedures; procedures for the protection of audit information; system configuration settings; system audit records; audit tools; system-generated list of privileged users with access to the management of audit functionality; access authorizations; access control list; system design documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.03.08",
				"text": "[SELECT FROM: personnel with audit and accountability responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.03.08",
				"text": "[SELECT FROM: mechanisms for implementing audit information protection; mechanisms for managing access to audit functionality]",
			}],
		},
	},
	"03.04.01": {
		"family": "03.04",
		"title": "Baseline Configuration",
		"methods": {
			"examine": [{
				"id": "E-03.04.01",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for the baseline system configuration; configuration management plan; enterprise architecture; system design documentation; system architecture; system configuration settings; system component inventory; change control records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.01",
				"text": "[SELECT FROM: personnel with configuration management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.01",
				"text": "[SELECT FROM: processes for managing baseline configurations; mechanisms for supporting configuration control of the baseline configuration]",
			}],
		},
	},
	"03.04.02": {
		"family": "03.04",
		"title": "Configuration Settings",
		"methods": {
			"examine": [{
				"id": "E-03.04.02",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for system configuration settings; configuration management plan; system design documentation; system configuration settings; common secure configuration checklists; system component inventory; evidence supporting approved deviations from established configuration settings; change control records; system data processing and retention permissions; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.02",
				"text": "[SELECT FROM: personnel with security configuration management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.02",
				"text": "[SELECT FROM: processes for managing configuration settings; mechanisms that implement, monitor, or control system configuration settings; mechanisms that identify or document deviations from established configuration settings]",
			}],
		},
	},
	"03.04.03": {
		"family": "03.04",
		"title": "Configuration Change Control",
		"methods": {
			"examine": [{
				"id": "E-03.04.03",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for system configuration change control; configuration management plan; system architecture; configuration settings; change control records; system audit records; change control audit and review reports; agenda, minutes, and documentation from configuration change control oversight meetings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.03",
				"text": "[SELECT FROM: personnel with configuration change control responsibilities; personnel with information security responsibilities; members of change control board or similar; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.03",
				"text": "[SELECT FROM: processes for configuration change control; mechanisms that implement configuration change control]",
			}],
		},
	},
	"03.04.04": {
		"family": "03.04",
		"title": "Impact Analyses",
		"methods": {
			"examine": [{
				"id": "E-03.04.04",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for security impact analyses for system changes; configuration management plan; security impact analysis documentation; system design documentation; analysis tools and outputs; change control records; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.04",
				"text": "[SELECT FROM: personnel with security impact analysis responsibilities; personnel with information security responsibilities; members of change control board; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.04",
				"text": "[SELECT FROM: processes for security impact analyses]",
			}],
		},
	},
	"03.04.05": {
		"family": "03.04",
		"title": "Access Restrictions for Change",
		"methods": {
			"examine": [{
				"id": "E-03.04.05",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for access restrictions for system changes; configuration management plan; system design documentation; system architecture; system configuration settings; logical access approvals; physical access approvals; access credentials; change control records; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.05",
				"text": "[SELECT FROM: personnel with logical access control responsibilities; personnel with physical access control responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.05",
				"text": "[SELECT FROM: processes for managing access restrictions for system changes; mechanisms for supporting, implementing, or enforcing access restrictions associated with system changes]",
			}],
		},
	},
	"03.04.06": {
		"family": "03.04",
		"title": "Least Functionality",
		"methods": {
			"examine": [{
				"id": "E-03.04.06",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for least functionality in the system; configuration management plan; system design documentation; system configuration settings; system component inventory; common secure configuration checklists; documented reviews of functions, ports, protocols, and services; change control records; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.06",
				"text": "[SELECT FROM: personnel with configuration management responsibilities; personnel with responsibilities for reviewing functions, ports, protocols, and services; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.06",
				"text": "[SELECT FROM: processes for prohibiting or restricting functions, ports, protocols, and services; processes for reviewing or disabling functions, ports, protocols, and services; mechanisms for implementing the review and disabling of functions, ports, protocols, and services; mechanisms for implementing restrictions on or the prohibition of functions, ports, protocols, and services]",
			}],
		},
	},
	"03.04.08": {
		"family": "03.04",
		"title": "Authorized Software – Allow by Exception",
		"methods": {
			"examine": [{
				"id": "E-03.04.08",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for least functionality in the system; configuration management plan; system design documentation; system configuration settings; list of software programs authorized to execute on the system; system component inventory; records associated with the review and update of the list of authorized software programs; common secure configuration checklists; change control records; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.08",
				"text": "[SELECT FROM: personnel with responsibilities for identifying software authorized to execute on the system; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.08",
				"text": "[SELECT FROM: processes for identifying, reviewing, and updating programs authorized to execute on the system; processes for implementing authorized software policy; mechanisms for supporting or implementing authorized software policy]",
			}],
		},
	},
	"03.04.10": {
		"family": "03.04",
		"title": "System Component Inventory",
		"methods": {
			"examine": [{
				"id": "E-03.04.10",
				"text": "[SELECT FROM: configuration management policy and procedures; procedures for system component inventory; configuration management plan; system design documentation; system component inventory; inventory reviews and update records; component installation records; change control records; component removal records; system change records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.10",
				"text": "[SELECT FROM: personnel with component inventory management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.10",
				"text": "[SELECT FROM: processes for managing the system component inventory; mechanisms for supporting or implementing the system component inventory; processes for updating the system component inventory; mechanisms for supporting or implementing the system component inventory updates]",
			}],
		},
	},
	"03.04.11": {
		"family": "03.04",
		"title": "Information Location",
		"methods": {
			"examine": [{
				"id": "E-03.04.11",
				"text": "[SELECT FROM: configuration management policy and procedures; configuration management plan; procedures for identification and documentation of information location; system audit records; architecture documentation; system design documentation; list of users with system and system component access; change control records; system component inventory; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.11",
				"text": "[SELECT FROM: personnel with responsibilities for managing information location and user access; personnel with responsibilities for operating, using, or maintaining the system; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.11",
				"text": "[SELECT FROM: processes governing information location; mechanisms for enforcing policies and methods for governing information location]",
			}],
		},
	},
	"03.04.12": {
		"family": "03.04",
		"title": "System and Component Configuration for High-Risk Areas",
		"methods": {
			"examine": [{
				"id": "E-03.04.12",
				"text": "[SELECT FROM: configuration management policy and procedures; configuration management plan; procedures for the baseline configuration of the system; procedures for system component installations and upgrades; system component inventory; system component installations or upgrades and associated records; records of system baseline configuration reviews and updates; system configuration settings; system architecture; change control records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.04.12",
				"text": "[SELECT FROM: personnel with configuration management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.04.12",
				"text": "[SELECT FROM: processes for managing baseline configurations]",
			}],
		},
	},
	"03.05.01": {
		"family": "03.05",
		"title": "User Identification and Authentication",
		"methods": {
			"examine": [{
				"id": "E-03.05.01",
				"text": "[SELECT FROM: identification and authentication policy and procedures; list of circumstances or situations requiring re-authentication; system design documentation; system configuration settings; system audit records; list of system accounts; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.01",
				"text": "[SELECT FROM: personnel with identification and authentication responsibilities; personnel with system operations responsibilities; personnel with account management responsibilities; system developers; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.01",
				"text": "[SELECT FROM: processes for uniquely identifying and authenticating users; mechanisms for supporting or implementing identification and authentication capabilities]",
			}],
		},
	},
	"03.05.02": {
		"family": "03.05",
		"title": "Device Identification and Authentication",
		"methods": {
			"examine": [{
				"id": "E-03.05.02",
				"text": "[SELECT FROM: identification and authentication policy and procedures; procedures for device identification and authentication; system design documentation; list of devices requiring unique identification and authentication; device connection reports; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.02",
				"text": "[SELECT FROM: personnel with responsibilities for device identification and authentication; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.02",
				"text": "[SELECT FROM: mechanisms for supporting or implementing device identification and authentication capabilities]",
			}],
		},
	},
	"03.05.03": {
		"family": "03.05",
		"title": "Multi-Factor Authentication",
		"methods": {
			"examine": [{
				"id": "E-03.05.03",
				"text": "[SELECT FROM: identification and authentication policy and procedures; system design documentation; list of system accounts; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.03",
				"text": "[SELECT FROM: personnel with system operations responsibilities; personnel with account management responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.03",
				"text": "[SELECT FROM: mechanisms for supporting or implementing a multi-factor authentication capability]",
			}],
		},
	},
	"03.05.04": {
		"family": "03.05",
		"title": "Replay-Resistant Authentication",
		"methods": {
			"examine": [{
				"id": "E-03.05.04",
				"text": "[SELECT FROM: identification and authentication policy and procedures; system design documentation; system audit records; system configuration settings; list of privileged system accounts; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.04",
				"text": "[SELECT FROM: personnel with system operations responsibilities; personnel with account management responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.04",
				"text": "[SELECT FROM: mechanisms for supporting or implementing identification and authentication capabilities; mechanisms for supporting or implementing replay-resistance]",
			}],
		},
	},
	"03.05.05": {
		"family": "03.05",
		"title": "Identifier Management",
		"methods": {
			"examine": [{
				"id": "E-03.05.05",
				"text": "[SELECT FROM: identification and authentication policy and procedures; procedures for identifier management; procedures for account management; system design documentation; list of system accounts; list of characteristics identifying individual status; system configuration settings; list of identifiers generated from physical access control devices; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.05",
				"text": "[SELECT FROM: personnel with identifier management responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.05",
				"text": "[SELECT FROM: mechanisms for supporting or implementing identifier management]",
			}],
		},
	},
	"03.05.07": {
		"family": "03.05",
		"title": "Password Management",
		"methods": {
			"examine": [{
				"id": "E-03.05.07",
				"text": "[SELECT FROM: identification and authentication policy and procedures; password policy; procedures for authenticator management; system design documentation; system configuration settings; password configurations; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.07",
				"text": "[SELECT FROM: personnel with authenticator management responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.07",
				"text": "[SELECT FROM: mechanisms for supporting or implementing a password-based authenticator management capability]",
			}],
		},
	},
	"03.05.11": {
		"family": "03.05",
		"title": "Authentication Feedback",
		"methods": {
			"examine": [{
				"id": "E-03.05.11",
				"text": "[SELECT FROM: identification and authentication policy and procedures; procedures for authenticator feedback; system design documentation; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.11",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.11",
				"text": "[SELECT FROM: mechanisms for supporting or implementing the obscuring of feedback of authentication information during authentication]",
			}],
		},
	},
	"03.05.12": {
		"family": "03.05",
		"title": "Authenticator Management",
		"methods": {
			"examine": [{
				"id": "E-03.05.12",
				"text": "[SELECT FROM: identification and authentication policy and procedures; procedures for authenticator management; system configuration settings; list of system authenticator types; system design documentation; system audit records; change control records associated with managing system authenticators; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.05.12",
				"text": "[SELECT FROM: personnel with authenticator management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.05.12",
				"text": "[SELECT FROM: mechanisms for supporting or implementing the authenticator management capability]",
			}],
		},
	},
	"03.06.01": {
		"family": "03.06",
		"title": "Incident Handling",
		"methods": {
			"examine": [{
				"id": "E-03.06.01",
				"text": "[SELECT FROM: incident response policy and procedures; contingency planning policy and procedures; procedures for incident handling; procedures for incident response planning; incident response plan; contingency plan; records of incident response plan reviews and approvals; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.06.01",
				"text": "[SELECT FROM: personnel with incident handling responsibilities; personnel with incident response planning responsibilities; personnel with contingency planning responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.06.01",
				"text": "[SELECT FROM: incident handling capability for the organization; incident response plan]",
			}],
		},
	},
	"03.06.02": {
		"family": "03.06",
		"title": "Incident Monitoring, Reporting, and Response Assistance",
		"methods": {
			"examine": [{
				"id": "E-03.06.02",
				"text": "[SELECT FROM: incident response policy and procedures; procedures for incident monitoring; procedures for incident response assistance; incident response records and documentation; incident response plan; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.06.02",
				"text": "[SELECT FROM: personnel with incident monitoring responsibilities; personnel with incident response assistance and support responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.06.02",
				"text": "[SELECT FROM: processes for incident reporting; incident monitoring capability; mechanisms for supporting or implementing the tracking and documenting of system security incidents; mechanisms for supporting or implementing incident reporting; mechanisms for supporting or implementing incident response assistance; processes for incident response assistance]",
			}],
		},
	},
	"03.06.03": {
		"family": "03.06",
		"title": "Incident Response Testing",
		"methods": {
			"examine": [{
				"id": "E-03.06.03",
				"text": "[SELECT FROM: incident response policy and procedures; contingency planning policy and procedures; procedures for incident response testing; procedures for contingency plan testing; incident response testing material; incident response test results; incident response test plan; incident response plan; contingency plan; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.06.03",
				"text": "[SELECT FROM: personnel with incident response testing responsibilities; personnel with information security responsibilities]",
			}],
			"test": [],
		},
	},
	"03.06.04": {
		"family": "03.06",
		"title": "Incident Response Training",
		"methods": {
			"examine": [{
				"id": "E-03.06.04",
				"text": "[SELECT FROM: incident response policy and procedures; procedures for incident response training; incident response training curriculum; incident response training materials; incident response plan; incident response training records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.06.04",
				"text": "[SELECT FROM: personnel with incident response training and operational responsibilities; personnel with information security responsibilities]",
			}],
			"test": [],
		},
	},
	"03.06.05": {
		"family": "03.06",
		"title": "Incident Response Plan",
		"methods": {
			"examine": [{
				"id": "E-03.06.05",
				"text": "[SELECT FROM: incident response policy; procedures addressing incident response planning; incident response plan; system security plan; records of incident response plan reviews and approvals; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.06.05",
				"text": "[SELECT FROM: personnel with incident response planning responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.06.05",
				"text": "[SELECT FROM: incident response plan and related processes]",
			}],
		},
	},
	"03.07.04": {
		"family": "03.07",
		"title": "Maintenance Tools",
		"methods": {
			"examine": [{
				"id": "E-03.07.04",
				"text": "[SELECT FROM: maintenance policy and procedures; procedures for system maintenance tools; system maintenance tools; maintenance tool inspection records; equipment sanitization records; media sanitization records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.07.04",
				"text": "[SELECT FROM: personnel with system maintenance responsibilities; personnel responsible for media sanitization; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.07.04",
				"text": "[SELECT FROM: processes for approving, controlling, and monitoring maintenance tools; mechanisms for supporting or implementing the approval, control, or monitoring of maintenance tools; processes for preventing the unauthorized removal of information; processes for inspecting media for malicious code; mechanisms for supporting media sanitization or the destruction of equipment; mechanisms for supporting the verification of media sanitization; processes for inspecting maintenance tools; mechanisms for supporting or implementing the inspection of maintenance tools; mechanisms for supporting or implementing the inspection of media used for maintenance]",
			}],
		},
	},
	"03.07.05": {
		"family": "03.07",
		"title": "Nonlocal Maintenance",
		"methods": {
			"examine": [{
				"id": "E-03.07.05",
				"text": "[SELECT FROM: maintenance policy and procedures; remote access policy and procedures; procedures for nonlocal system maintenance; records of remote access; maintenance records; diagnostic records; system design documentation; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.07.05",
				"text": "[SELECT FROM: personnel with system maintenance responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.07.05",
				"text": "[SELECT FROM: processes for managing nonlocal maintenance; mechanisms for implementing, supporting, or managing nonlocal maintenance; mechanisms for implementing multi-factor authentication and replay resistance; mechanisms for terminating nonlocal maintenance sessions and network connections]",
			}],
		},
	},
	"03.07.06": {
		"family": "03.07",
		"title": "Maintenance Personnel",
		"methods": {
			"examine": [{
				"id": "E-03.07.06",
				"text": "[SELECT FROM: maintenance policy and procedures; service provider contracts; service-level agreements; list of authorized personnel; maintenance records; access control records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.07.06",
				"text": "[SELECT FROM: personnel with system maintenance responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.07.06",
				"text": "[SELECT FROM: processes for authorizing and managing maintenance personnel; mechanisms for supporting or implementing the authorization of maintenance personnel]",
			}],
		},
	},
	"03.08.01": {
		"family": "03.08",
		"title": "Media Storage",
		"methods": {
			"examine": [{
				"id": "E-03.08.01",
				"text": "[SELECT FROM: physical protection policy and procedures; media protection policy and procedures; procedures for media storage; access control policy and procedures; system media; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.01",
				"text": "[SELECT FROM: personnel with system media protection and storage responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.08.01",
				"text": "[SELECT FROM: processes for storing information media; mechanisms for supporting or implementing secure media storage/media protection]",
			}],
		},
	},
	"03.08.02": {
		"family": "03.08",
		"title": "Media Access",
		"methods": {
			"examine": [{
				"id": "E-03.08.02",
				"text": "[SELECT FROM: physical protection policy and procedures; media protection policy and procedures; procedures for media access restrictions; access control policy and procedures; media storage facilities; access control records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.02",
				"text": "[SELECT FROM: personnel with system media protection responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.08.02",
				"text": "[SELECT FROM: processes for restricting information on media; mechanisms for supporting or implementing media access restrictions]",
			}],
		},
	},
	"03.08.03": {
		"family": "03.08",
		"title": "Media Sanitization",
		"methods": {
			"examine": [{
				"id": "E-03.08.03",
				"text": "[SELECT FROM: media protection policy and procedures; procedures for media sanitization and disposal; applicable standards and policies that address media sanitization policy; system audit records; media sanitization records; system design documentation; system configuration settings; records retention and disposition policy; records retention and disposition procedures; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.03",
				"text": "[SELECT FROM: personnel with media sanitization responsibilities; personnel with records retention and disposition responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.08.03",
				"text": "[SELECT FROM: processes for media sanitization; mechanisms for supporting or implementing media sanitization]",
			}],
		},
	},
	"03.08.04": {
		"family": "03.08",
		"title": "Media Marking",
		"methods": {
			"examine": [{
				"id": "E-03.08.04",
				"text": "[SELECT FROM: physical protection policy and procedures; media protection policy and procedures; procedures for media marking; list of system media marking security attributes; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.04",
				"text": "[SELECT FROM: personnel with system media protection and marking responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.08.04",
				"text": "[SELECT FROM: processes for marking information media; mechanisms for supporting or implementing media marking]",
			}],
		},
	},
	"03.08.05": {
		"family": "03.08",
		"title": "Media Transport",
		"methods": {
			"examine": [{
				"id": "E-03.08.05",
				"text": "[SELECT FROM: physical protection policy and procedures; media protection policy and procedures; procedures for media storage; access control policy and procedures; authorized personnel list; system media; designated controlled areas; system and communications protection policy and procedures; cryptographic mechanisms and configuration documentation; procedures for the protection of information at rest; system design documentation; system configuration settings; list of information at rest requiring confidentiality protections; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.05",
				"text": "[SELECT FROM: personnel with system media protection and storage responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.08.05",
				"text": "[SELECT FROM: processes for storing information media; mechanisms for supporting or implementing media storage/media protection; mechanisms for supporting or implementing confidentiality protections for information at rest]",
			}],
		},
	},
	"03.08.07": {
		"family": "03.08",
		"title": "Media Use",
		"methods": {
			"examine": [{
				"id": "E-03.08.07",
				"text": "[SELECT FROM: system media protection policy and procedures; system use policy; procedures for media usage restrictions; rules of behavior; system audit records; system design documentation; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.07",
				"text": "[SELECT FROM: personnel with system media use responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.08.07",
				"text": "[SELECT FROM: processes for media use; mechanisms for restricting or prohibiting the use of system media on systems or system components]",
			}],
		},
	},
	"03.08.09": {
		"family": "03.08",
		"title": "System Backup – Cryptographic Protection",
		"methods": {
			"examine": [{
				"id": "E-03.08.09",
				"text": "[SELECT FROM: contingency planning policy and procedures; procedures for system backup; contingency plan; system design documentation; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.08.09",
				"text": "[SELECT FROM: personnel with system backup responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.08.09",
				"text": "[SELECT FROM: mechanisms for supporting or implementing the cryptographic protection of backup information]",
			}],
		},
	},
	"03.09.01": {
		"family": "03.09",
		"title": "Personnel Screening",
		"methods": {
			"examine": [{
				"id": "E-03.09.01",
				"text": "[SELECT FROM: personnel security policy and procedures; procedures for personnel screening and rescreening; records of screened personnel; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.09.01",
				"text": "[SELECT FROM: personnel with personnel security responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.09.01",
				"text": "[SELECT FROM: processes for personnel screening and rescreening]",
			}],
		},
	},
	"03.09.02": {
		"family": "03.09",
		"title": "Personnel Termination and Transfer",
		"methods": {
			"examine": [{
				"id": "E-03.09.02",
				"text": "[SELECT FROM: personnel security policy and procedures; procedures for personnel termination; records of personnel transfer actions; procedures for personnel transfer; list of system and facility access authorizations; records of personnel termination actions; records of terminated or revoked authenticators or credentials; list of system accounts; records of exit interviews; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.09.02",
				"text": "[SELECT FROM: personnel with personnel security responsibilities; personnel with account management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.09.02",
				"text": "[SELECT FROM: processes for personnel termination; processes for personnel transfer; mechanisms for supporting or implementing personnel transfer notifications; mechanisms for supporting or implementing personnel termination notifications; mechanisms for disabling system access and revoking authenticators]",
			}],
		},
	},
	"03.10.01": {
		"family": "03.10",
		"title": "Physical Access Authorizations",
		"methods": {
			"examine": [{
				"id": "E-03.10.01",
				"text": "[SELECT FROM: physical protection policy and procedures; procedures for physical access authorizations; authorized personnel access list; physical access list reviews; physical access termination records; authorization credentials; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.10.01",
				"text": "[SELECT FROM: personnel with physical access authorization responsibilities; personnel with physical access to the facility where the system resides; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.10.01",
				"text": "[SELECT FROM: processes for physical access authorizations; mechanisms for supporting or implementing physical access authorizations]",
			}],
		},
	},
	"03.10.02": {
		"family": "03.10",
		"title": "Monitoring Physical Access",
		"methods": {
			"examine": [{
				"id": "E-03.10.02",
				"text": "[SELECT FROM: physical protection policy and procedures; procedures for physical access monitoring; physical access logs or records; physical access monitoring records; physical access log reviews; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.10.02",
				"text": "[SELECT FROM: personnel with physical access monitoring responsibilities; personnel with incident response responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.10.02",
				"text": "[SELECT FROM: processes for monitoring physical access; mechanisms for supporting or implementing physical access monitoring; mechanisms for supporting or implementing the review of physical access logs]",
			}],
		},
	},
	"03.10.06": {
		"family": "03.10",
		"title": "Alternate Work Site",
		"methods": {
			"examine": [{
				"id": "E-03.10.06",
				"text": "[SELECT FROM: physical protection policy and procedures; procedures for alternate work sites for personnel; list of security requirements for alternate work sites; assessments of security requirements at alternate work sites; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.10.06",
				"text": "[SELECT FROM: personnel approving the use of alternate work sites; personnel using alternate work sites; personnel assessing security requirements at alternate work sites; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.10.06",
				"text": "[SELECT FROM: processes for security at alternate work sites; mechanisms for supporting alternate work sites; security requirements employed at alternate work sites; means of communication between personnel at alternate work sites and security personnel]",
			}],
		},
	},
	"03.10.07": {
		"family": "03.10",
		"title": "Physical Access Control",
		"methods": {
			"examine": [{
				"id": "E-03.10.07",
				"text": "[SELECT FROM: physical protection policy and procedures; procedures for physical access control; physical access control logs or records; inventory records of physical access control devices; system entry and exit points; records of key and lock combination changes; storage locations for physical access control devices; physical access control devices; list of security safeguards controlling access to designated publicly accessible areas within facility; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.10.07",
				"text": "[SELECT FROM: personnel with physical access control responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.10.07",
				"text": "[SELECT FROM: processes for physical access control; mechanisms for supporting or implementing physical access control; physical access control devices]",
			}],
		},
	},
	"03.10.08": {
		"family": "03.10",
		"title": "Access Control for Transmission",
		"methods": {
			"examine": [{
				"id": "E-03.10.08",
				"text": "[SELECT FROM: physical protection policy and procedures; procedures for access control for transmission mediums; system design documentation; facility communications and wiring diagrams; list of physical security safeguards applied to system distribution and transmission lines; procedures for access control for display medium; facility layout of system components; list of output devices and associated outputs that require physical access controls; actual displays from system components; physical access control logs or records for areas containing output devices and related outputs; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.10.08",
				"text": "[SELECT FROM: personnel with physical access control responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.10.08",
				"text": "[SELECT FROM: processes for access control for distribution and transmission lines; mechanisms for supporting or implementing access control for distribution and transmission lines; processes for access control to output devices; mechanisms for supporting or implementing access control for output devices]",
			}],
		},
	},
	"03.11.01": {
		"family": "03.11",
		"title": "Risk Assessment",
		"methods": {
			"examine": [{
				"id": "E-03.11.01",
				"text": "[SELECT FROM: risk assessment policy and procedures; security planning policy and procedures; procedures for organizational assessments of risk; risk assessment; risk assessment results; risk assessment reviews; risk assessment updates; SCRM policy and procedures; inventory of critical systems, system components, and system services; procedures for organizational assessments of supply chain risk; acquisition policy; SCRM plan; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.11.01",
				"text": "[SELECT FROM: personnel with risk assessment responsibilities; personnel with SCRM responsibilities; personnel with security responsibilities]",
			}],
			"test": [{
				"id": "T-03.11.01",
				"text": "[SELECT FROM: processes for organizational risk assessments; mechanisms for supporting or conducting, documenting, reviewing, disseminating, and updating risk assessments; mechanisms for supporting or conducting, documenting, reviewing, disseminating, and updating supply chain risk assessments]",
			}],
		},
	},
	"03.11.02": {
		"family": "03.11",
		"title": "Vulnerability Monitoring and Scanning",
		"methods": {
			"examine": [{
				"id": "E-03.11.02",
				"text": "[SELECT FROM: risk assessment policy and procedures; procedures for vulnerability scanning; patch and vulnerability management records; vulnerability scanning tools and configuration documentation; vulnerability scanning results; risk assessment; risk assessment report; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.11.02",
				"text": "[SELECT FROM: personnel with risk assessment and vulnerability scanning responsibilities; personnel with vulnerability scan analysis responsibilities; personnel with vulnerability remediation responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.11.02",
				"text": "[SELECT FROM: processes for vulnerability monitoring, scanning, analysis, and remediation; mechanisms for supporting or implementing vulnerability monitoring, scanning, analysis, and remediation]",
			}],
		},
	},
	"03.11.04": {
		"family": "03.11",
		"title": "Risk Response",
		"methods": {
			"examine": [{
				"id": "E-03.11.04",
				"text": "[SELECT FROM: risk assessment policy; assessment reports; system audit records; event logs; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.11.04",
				"text": "[SELECT FROM: personnel with assessment and auditing responsibilities; system administrators; personnel with security responsibilities]",
			}],
			"test": [{
				"id": "T-03.11.04",
				"text": "[SELECT FROM: processes for assessments and audits; mechanisms and tools supporting or implementing assessments and auditing]",
			}],
		},
	},
	"03.12.01": {
		"family": "03.12",
		"title": "Security Assessment",
		"methods": {
			"examine": [{
				"id": "E-03.12.01",
				"text": "[SELECT FROM: security assessment and monitoring policy and procedures; procedures for security assessment planning; security assessment plan; security assessment report; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.12.01",
				"text": "[SELECT FROM: personnel with security assessment responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.12.01",
				"text": "[SELECT FROM: mechanisms for supporting security assessments, processes for security assessment plan development, or security assessment reporting]",
			}],
		},
	},
	"03.12.02": {
		"family": "03.12",
		"title": "Plan of Action and Milestones",
		"methods": {
			"examine": [{
				"id": "E-03.12.02",
				"text": "[SELECT FROM: security assessment and monitoring policy and procedures; procedures for plans of action and milestones; security assessment plan; security assessment report; security assessment evidence; plan of action and milestones; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.12.02",
				"text": "[SELECT FROM: personnel with plans of action and milestones development and implementation responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.12.02",
				"text": "[SELECT FROM: mechanisms for developing, implementing, and maintaining plans of action and milestones]",
			}],
		},
	},
	"03.12.03": {
		"family": "03.12",
		"title": "Continuous Monitoring",
		"methods": {
			"examine": [{
				"id": "E-03.12.03",
				"text": "[SELECT FROM: security assessment and monitoring policy and procedures; organizational continuous monitoring strategy; system-level continuous monitoring strategy; procedures for continuous monitoring of the system; procedures for configuration management; security assessment report; plan of action and milestones; system monitoring records; configuration management records; impact analyses; status reports; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.12.03",
				"text": "[SELECT FROM: personnel with continuous monitoring responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.12.03",
				"text": "[SELECT FROM: mechanisms for implementing continuous monitoring; mechanisms for supporting response actions for assessment and monitoring results; mechanisms for supporting security status reporting]",
			}],
		},
	},
	"03.12.05": {
		"family": "03.12",
		"title": "Information Exchange",
		"methods": {
			"examine": [{
				"id": "E-03.12.05",
				"text": "[SELECT FROM: access control policy and procedures; procedures for system connections; system and communications protection policy and procedures; system interconnection security agreements; information exchange security agreements; service-level agreements; memoranda of understanding or agreements; non-disclosure agreements; system design documentation; enterprise architecture; security architecture; system configuration settings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.12.05",
				"text": "[SELECT FROM: personnel with development, implementation, and approval responsibilities for system interconnection agreements; personnel who manage systems to which the exchange agreements apply; personnel with information security responsibilities]",
			}],
			"test": [],
		},
	},
	"03.13.01": {
		"family": "03.13",
		"title": "Boundary Protection",
		"methods": {
			"examine": [{
				"id": "E-03.13.01",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for boundary protection; list of key internal boundaries within the system; boundary protection hardware and software; system configuration settings; security architecture; system audit records; system design documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.01",
				"text": "[SELECT FROM: personnel with boundary protection responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.01",
				"text": "[SELECT FROM: mechanisms for implementing boundary protection capabilities]",
			}],
		},
	},
	"03.13.04": {
		"family": "03.13",
		"title": "Information in Shared System Resources",
		"methods": {
			"examine": [{
				"id": "E-03.13.04",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for information protection in shared system resources; system configuration settings; system audit records; system design documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.04",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.04",
				"text": "[SELECT FROM: mechanisms for preventing the unauthorized and unintended transfer of information via shared system resources]",
			}],
		},
	},
	"03.13.06": {
		"family": "03.13",
		"title": "Network Communications – Deny by Default – Allow by Exception",
		"methods": {
			"examine": [{
				"id": "E-03.13.06",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for boundary protection; system design documentation; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.06",
				"text": "[SELECT FROM: personnel with boundary protection responsibilities; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.06",
				"text": "[SELECT FROM: mechanisms for implementing traffic management at managed interfaces]",
			}],
		},
	},
	"03.13.08": {
		"family": "03.13",
		"title": "Transmission and Storage Confidentiality",
		"methods": {
			"examine": [{
				"id": "E-03.13.08",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for transmission confidentiality; procedures for the protection of information at rest; system design documentation; system configuration settings; cryptographic mechanisms and associated configuration documentation; information in storage requiring confidentiality protection; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.08",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.08",
				"text": "[SELECT FROM: mechanisms for supporting or implementing transmission confidentiality; cryptographic mechanisms for supporting or implementing transmission confidentiality; mechanisms for supporting or implementing confidentiality protection for information in storage; cryptographic mechanisms for implementing confidentiality protections for information in storage]",
			}],
		},
	},
	"03.13.09": {
		"family": "03.13",
		"title": "Network Disconnect",
		"methods": {
			"examine": [{
				"id": "E-03.13.09",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for network disconnect; system design documentation; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.09",
				"text": "[SELECT FROM: personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.09",
				"text": "[SELECT FROM: mechanisms for supporting or implementing a network disconnect capability]",
			}],
		},
	},
	"03.13.10": {
		"family": "03.13",
		"title": "Cryptographic Key Establishment and Management",
		"methods": {
			"examine": [{
				"id": "E-03.13.10",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for cryptographic key establishment and management; system design documentation; system configuration settings; cryptographic mechanisms; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.10",
				"text": "[SELECT FROM: personnel with responsibilities for cryptographic key establishment or management; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.10",
				"text": "[SELECT FROM: mechanisms for supporting or implementing cryptographic key establishment and management]",
			}],
		},
	},
	"03.13.11": {
		"family": "03.13",
		"title": "Cryptographic Protection",
		"methods": {
			"examine": [{
				"id": "E-03.13.11",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for cryptographic protection; system design documentation; system configuration settings; cryptographic module validation certificates; list of FIPS-validated cryptographic modules; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.11",
				"text": "[SELECT FROM: personnel with responsibilities for cryptographic protection; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.11",
				"text": "[SELECT FROM: mechanisms for supporting or implementing cryptographic protection]",
			}],
		},
	},
	"03.13.12": {
		"family": "03.13",
		"title": "Collaborative Computing Devices and Applications",
		"methods": {
			"examine": [{
				"id": "E-03.13.12",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for collaborative computing; access control policy and procedures; system configuration settings; system design documentation; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.12",
				"text": "[SELECT FROM: personnel with responsibilities for managing collaborative computing devices; personnel with information security responsibilities; system developers; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.12",
				"text": "[SELECT FROM: mechanisms for supporting or implementing the management of remote activation of collaborative computing devices; mechanisms for providing an indication of use of collaborative computing devices]",
			}],
		},
	},
	"03.13.13": {
		"family": "03.13",
		"title": "Mobile Code",
		"methods": {
			"examine": [{
				"id": "E-03.13.13",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for mobile code; mobile code implementation policy and procedures; list of acceptable mobile code and mobile code technologies; authorization records; system monitoring records; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.13",
				"text": "[SELECT FROM: personnel with responsibilities for managing mobile code; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.13",
				"text": "[SELECT FROM: processes for authorizing, monitoring, and controlling mobile code; mechanisms for supporting or implementing the management of mobile code; mechanisms for supporting or implementing mobile code monitoring]",
			}],
		},
	},
	"03.13.15": {
		"family": "03.13",
		"title": "Session Authenticity",
		"methods": {
			"examine": [{
				"id": "E-03.13.15",
				"text": "[SELECT FROM: system and communications protection policy and procedures; procedures for session authenticity; system design documentation; system configuration settings; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.13.15",
				"text": "[SELECT FROM: personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.13.15",
				"text": "[SELECT FROM: mechanisms for supporting or implementing session authenticity]",
			}],
		},
	},
	"03.14.01": {
		"family": "03.14",
		"title": "Flaw Remediation",
		"methods": {
			"examine": [{
				"id": "E-03.14.01",
				"text": "[SELECT FROM: system and information integrity policy and procedures; procedures for flaw remediation; procedures for configuration management; list of recent security flaw remediation actions performed on the system; list of flaws and vulnerabilities that may potentially affect the system; test results from the installation of software and firmware updates to correct system flaws; installation and change control records for security-relevant software and firmware updates; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.14.01",
				"text": "[SELECT FROM: personnel responsible for installing, configuring, or maintaining the system; personnel responsible for flaw remediation; personnel with configuration management responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.14.01",
				"text": "[SELECT FROM: processes for identifying, reporting, and correcting system flaws; processes for installing software and firmware updates; mechanisms for supporting or implementing the reporting and correction of system flaws; mechanisms for supporting or implementing the testing software and firmware updates]",
			}],
		},
	},
	"03.14.02": {
		"family": "03.14",
		"title": "Malicious Code Protection",
		"methods": {
			"examine": [{
				"id": "E-03.14.02",
				"text": "[SELECT FROM: system and information integrity policy and procedures; configuration management policy and procedures; procedures for malicious code protection; records of malicious code protection updates; system design documentation; system configuration settings; scan results from malicious code protection mechanisms; record of actions initiated by malicious code protection mechanisms in response to malicious code detection; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.14.02",
				"text": "[SELECT FROM: personnel responsible for malicious code protection; personnel with system installation, configuration, or maintenance responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.14.02",
				"text": "[SELECT FROM: processes for employing, updating, and configuring malicious code protection mechanisms; processes for addressing the detection of false positives and resulting potential impacts; mechanisms for supporting or implementing, employing, updating, and configuring malicious code protection mechanisms; mechanisms for supporting or implementing malicious code scanning and the execution of subsequent actions]",
			}],
		},
	},
	"03.14.03": {
		"family": "03.14",
		"title": "Security Alerts, Advisories, and Directives",
		"methods": {
			"examine": [],
			"interview": [],
			"test": [],
		},
	},
	"03.14.06": {
		"family": "03.14",
		"title": "System Monitoring",
		"methods": {
			"examine": [{
				"id": "E-03.14.06",
				"text": "[SELECT FROM: system and information integrity policy and procedures; procedures for system monitoring tools and techniques; continuous monitoring strategy; facility diagram or layout; system design documentation; locations within the system where monitoring devices are deployed; system configuration settings; system protocols; system audit records; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.14.06",
				"text": "[SELECT FROM: personnel with responsibilities for installing, configuring, or maintaining the system; personnel with system monitoring responsibilities; personnel with intrusion detection responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.14.06",
				"text": "[SELECT FROM: processes for intrusion detection and system monitoring; mechanisms for supporting or implementing system monitoring capabilities; mechanisms for supporting or implementing intrusion detection and system monitoring capabilities; mechanisms for supporting or implementing the monitoring of inbound and outbound communications traffic]",
			}],
		},
	},
	"03.14.08": {
		"family": "03.14",
		"title": "Information Management and Retention",
		"methods": {
			"examine": [{
				"id": "E-03.14.08",
				"text": "[SELECT FROM: system and information integrity policy and procedures; laws, Executive Orders, directives, policies, regulations, standards, and operational requirements applicable to information management and retention; records retention and disposition policy; records retention and disposition procedures; media protection policy; media protection procedures; audit findings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.14.08",
				"text": "[SELECT FROM: personnel with information and records management, retention, and disposition responsibilities; personnel with information security responsibilities; system administrators]",
			}],
			"test": [{
				"id": "T-03.14.08",
				"text": "[SELECT FROM: processes for information management, retention, and disposition; mechanisms for supporting or implementing information management, retention, and disposition]",
			}],
		},
	},
	"03.15.01": {
		"family": "03.15",
		"title": "Policy and Procedures",
		"methods": {
			"examine": [{
				"id": "E-03.15.01",
				"text": "[SELECT FROM: security policies and procedures associated with the protection of CUI; audit findings; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.15.01",
				"text": "[SELECT FROM: personnel with information security responsibilities]",
			}],
			"test": [],
		},
	},
	"03.15.02": {
		"family": "03.15",
		"title": "System Security Plan",
		"methods": {
			"examine": [{
				"id": "E-03.15.02",
				"text": "[SELECT FROM: security planning policy and procedures; procedures for system security plan development and implementation; procedures for system security plan reviews and updates; enterprise architecture; system security plan; records of system security plan reviews and updates; risk assessments; risk assessment results; security architecture and design documentation; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.15.02",
				"text": "[SELECT FROM: personnel with system security planning and plan implementation responsibilities; system developers; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.15.02",
				"text": "[SELECT FROM: processes for system security plan development, review, update, and approval]",
			}],
		},
	},
	"03.15.03": {
		"family": "03.15",
		"title": "Rules of Behavior",
		"methods": {
			"examine": [{
				"id": "E-03.15.03",
				"text": "[SELECT FROM: security planning policy and procedures; rules of behavior for system users; signed acknowledgements of rules of behavior; records for rules of behavior reviews and updates; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.15.03",
				"text": "[SELECT FROM: personnel with rules of behavior establishment, review, and update responsibilities; personnel with literacy training and awareness responsibilities; personnel with role-based training responsibilities; authorized users of the system who have signed rules of behavior; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.15.03",
				"text": "[SELECT FROM: processes for establishing, reviewing, disseminating, and updating rules of behavior; mechanisms for supporting or implementing the establishment, dissemination, review, and update of rules of behavior]",
			}],
		},
	},
	"03.16.01": {
		"family": "03.16",
		"title": "Security Engineering Principles",
		"methods": {
			"examine": [{
				"id": "E-03.16.01",
				"text": "[SELECT FROM: system and services acquisition policy; system and services  acquisition procedures; procedures addressing security engineering principles used in the development and modification of the system; system design documentation; security requirements and specifications for the system; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.16.01",
				"text": "[SELECT FROM: personnel with acquisition/contracting responsibilities; personnel with information security responsibilities; personnel with system development and modification responsibilities; system developers]",
			}],
			"test": [{
				"id": "T-03.16.01",
				"text": "[SELECT FROM: processes for applying security engineering principles in system development and modification; mechanisms supporting the application of security engineering principles in system development and modification]",
			}],
		},
	},
	"03.16.02": {
		"family": "03.16",
		"title": "Unsupported System Components",
		"methods": {
			"examine": [{
				"id": "E-03.16.02",
				"text": "[SELECT FROM: system and services acquisition policy and procedures; procedures for the replacement or continued use of unsupported system components; documented evidence of replacing unsupported system components; documented approvals (including justification) for the continued use of unsupported system components; SCRM plan; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.16.02",
				"text": "[SELECT FROM: personnel with system and service acquisition responsibilities; personnel responsible for component replacement; personnel with system development life cycle responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.16.02",
				"text": "[SELECT FROM: processes for replacing unsupported system components; mechanisms for supporting or implementing the replacement of unsupported system components]",
			}],
		},
	},
	"03.16.03": {
		"family": "03.16",
		"title": "External System Services",
		"methods": {
			"examine": [{
				"id": "E-03.16.03",
				"text": "[SELECT FROM: system and services acquisition policy and procedures; procedures for monitoring security requirement compliance by external service providers; acquisition documentation; contracts; service-level agreements; interagency agreements; licensing agreements; list of security requirements for external provider services; assessment results or reports from external service providers; SCRM plan; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.16.03",
				"text": "[SELECT FROM: personnel with acquisition responsibilities; external providers of system services; personnel with SCRM responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.16.03",
				"text": "[SELECT FROM: organizational processes for monitoring security and privacy control compliance by external service providers on an ongoing basis; mechanisms for monitoring security and privacy control compliance by external service providers on an ongoing basis]",
			}],
		},
	},
	"03.17.01": {
		"family": "03.17",
		"title": "Supply Chain Risk Management Plan",
		"methods": {
			"examine": [{
				"id": "E-03.17.01",
				"text": "[SELECT FROM: SCRM policy and procedures; SCRM plan; system and services acquisition policy and procedures; system and services acquisition procedures; procedures for supply chain protection; procedures for protecting the SCRM plan from unauthorized disclosure; system development life cycle procedures; procedures for the integration of information security requirements into the acquisition process; acquisition documentation; service-level agreements; acquisition contracts for the system, system components, or system services; list of supply chain threats; list of safeguards for supply chain threats; system life cycle documentation, including research and development, design, manufacturing, acquisition, delivery, integration, operations, maintenance, and disposal; inter-organizational agreements and procedures; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.17.01",
				"text": "[SELECT FROM: personnel with acquisition responsibilities; personnel with SCRM responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.17.01",
				"text": "[SELECT FROM: organizational processes for defining and documenting the system development life cycle (SDLC); organizational processes for identifying SDLC roles and responsibilities; organizational processes for integrating SCRM into the SDLC; mechanisms for supporting or implementing the SDLC]",
			}],
		},
	},
	"03.17.02": {
		"family": "03.17",
		"title": "Acquisition Strategies, Tools, and Methods",
		"methods": {
			"examine": [{
				"id": "E-03.17.02",
				"text": "[SELECT FROM: SCRM policy and procedures; SCRM plan; system and services acquisition policy and procedures; procedures for supply chain protection; procedures for the integration of information security requirements into the acquisition process; solicitation documentation; acquisition documentation (including purchase orders); service-level agreements; acquisition contracts for the system, system components, or services; documentation of identified supply chain risks; mitigation plans for supply chain risks; documentation of training, education, and awareness programs for personnel regarding supply chain risk; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.17.02",
				"text": "[SELECT FROM: personnel with acquisition responsibilities; personnel with SCRM responsibilities; personnel with information security responsibilities]",
			}],
			"test": [{
				"id": "T-03.17.02",
				"text": "[SELECT FROM: processes for defining and employing tailored acquisition strategies, contract tools, and procurement methods; mechanisms for implementing tailored acquisition strategies, contract tools, and procurement methods]",
			}],
		},
	},
	"03.17.03": {
		"family": "03.17",
		"title": "Supply Chain Requirements and Processes",
		"methods": {
			"examine": [{
				"id": "E-03.17.03",
				"text": "[SELECT FROM: SCRM policy and procedures; SCRM strategy; SCRM plan; systems and critical system components inventory documentation; system and services acquisition policy and procedures; procedures for the integration of security requirements into the acquisition process; solicitation documentation; acquisition documentation (including purchase orders); shipping and handling procedures; configuration management documentation and records; acquisition contracts for systems or services; service-level agreements; risk register documentation; system security plan; other relevant documents or records]",
			}],
			"interview": [{
				"id": "I-03.17.03",
				"text": "[SELECT FROM: personnel with acquisition responsibilities; personnel with information security responsibilities; personnel with SCRM responsibilities]",
			}],
			"test": [{
				"id": "T-03.17.03",
				"text": "[SELECT FROM: processes for identifying and addressing supply chain element and process deficiencies]",
			}],
		},
	},
}

determinations := {
	"DS-A.03.01.01.a[01]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.a",
		"text": "system account types allowed are defined.",
	},
	"DS-A.03.01.01.a[02]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.a",
		"text": "system account types prohibited are defined.",
	},
	"DS-A.03.01.01.b[01]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.b",
		"text": "system accounts are created in accordance with organizational policy, procedures, prerequisites, and criteria.",
	},
	"DS-A.03.01.01.b[02]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.b",
		"text": "system accounts are enabled in accordance with organizational policy, procedures, prerequisites, and criteria.",
	},
	"DS-A.03.01.01.b[03]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.b",
		"text": "system accounts are modified in accordance with organizational policy, procedures, prerequisites, and criteria.",
	},
	"DS-A.03.01.01.b[04]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.b",
		"text": "system accounts are disabled in accordance with organizational policy, procedures, prerequisites, and criteria.",
	},
	"DS-A.03.01.01.b[05]": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.b",
		"text": "system accounts are removed in accordance with organizational policy, procedures, prerequisites, and criteria.",
	},
	"DS-A.03.01.01.c.01": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.c.01",
		"text": "authorized users of the system are specified.",
	},
	"DS-A.03.01.01.c.02": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.c.02",
		"text": "group and role memberships are specified.",
	},
	"DS-A.03.01.01.c.03": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.c.03",
		"text": "access authorizations (i.e., privileges) for each account are specified.",
	},
	"DS-A.03.01.01.d.01": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.d.01",
		"text": "access to the system is authorized based on a valid access authorization.",
	},
	"DS-A.03.01.01.d.02": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.d.02",
		"text": "access to the system is authorized based on intended system usage.",
	},
	"DS-A.03.01.01.e": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.e",
		"text": "the use of system accounts is monitored.",
	},
	"DS-A.03.01.01.f.01": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.f.01",
		"text": "system accounts are disabled when the accounts have expired.",
	},
	"DS-A.03.01.01.f.02": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.f.02",
		"text": "system accounts are disabled when the accounts have been inactive for <A.03.01.01.ODP[01]: time period>.",
	},
	"DS-A.03.01.01.f.03": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.f.03",
		"text": "system accounts are disabled when the accounts are no longer associated with a user or individual.",
	},
	"DS-A.03.01.01.f.04": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.f.04",
		"text": "system accounts are disabled when the accounts violate organizational policy.",
	},
	"DS-A.03.01.01.f.05": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.f.05",
		"text": "system accounts are disabled when significant risks associated with individuals are discovered.",
	},
	"DS-A.03.01.01.g.01": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.g.01",
		"text": "account managers and designated personnel or roles are notified within <A.03.01.01.ODP[02]: time period> when accounts are no longer required.",
	},
	"DS-A.03.01.01.g.02": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.g.02",
		"text": "account managers and designated personnel or roles are notified within <A.03.01.01.ODP[03]: time period> when users are terminated or transferred.",
	},
	"DS-A.03.01.01.g.03": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.g.03",
		"text": "account managers and designated personnel or roles are notified within <A.03.01.01.ODP[04]: time period> when system usage or the need-to-know changes for an individual.",
	},
	"DS-A.03.01.01.h": {
		"requirement": "03.01.01",
		"statement": "SR-03.01.01.h",
		"text": "users are required to log out of the system after <A.03.01.01.ODP[05]: time period> of expected inactivity or when the following circumstances occur: <A.03.01.01.ODP[06]: circumstances>.",
	},
	"DS-A.03.01.02[01]": {
		"requirement": "03.01.02",
		"statement": "SR-03.01.02",
		"text": "approved authorizations for logical access to CUI are enforced in accordance with applicable access control policies.",
	},
	"DS-A.03.01.02[02]": {
		"requirement": "03.01.02",
		"statement": "SR-03.01.02",
		"text": "approved authorizations for logical access to system resources are enforced in accordance with applicable access control policies.",
	},
	"DS-A.03.01.03[01]": {
		"requirement": "03.01.03",
		"statement": "SR-03.01.03",
		"text": "approved authorizations are enforced for controlling the flow of CUI within the system.",
	},
	"DS-A.03.01.03[02]": {
		"requirement": "03.01.03",
		"statement": "SR-03.01.03",
		"text": "approved authorizations are enforced for controlling the flow of CUI between connected systems.",
	},
	"DS-A.03.01.04.a": {
		"requirement": "03.01.04",
		"statement": "SR-03.01.04.a",
		"text": "duties of individuals requiring separation are identified.",
	},
	"DS-A.03.01.04.b": {
		"requirement": "03.01.04",
		"statement": "SR-03.01.04.b",
		"text": "system access authorizations to support separation of duties are defined.",
	},
	"DS-A.03.01.05.a": {
		"requirement": "03.01.05",
		"statement": "SR-03.01.05.a",
		"text": "system access for users (or processes acting on behalf of users) is authorized only when necessary to accomplish assigned organizational tasks.",
	},
	"DS-A.03.01.05.b[01]": {
		"requirement": "03.01.05",
		"statement": "SR-03.01.05.b",
		"text": "access to <A.03.01.05.ODP[01]: security functions> is authorized.",
	},
	"DS-A.03.01.05.b[02]": {
		"requirement": "03.01.05",
		"statement": "SR-03.01.05.b",
		"text": "access to <A.03.01.05.ODP[02]: security-relevant information> is authorized.",
	},
	"DS-A.03.01.05.c": {
		"requirement": "03.01.05",
		"statement": "SR-03.01.05.c",
		"text": "the privileges assigned to roles or classes of users are reviewed <A.03.01.05.ODP[03]: frequency> to validate the need for such privileges.",
	},
	"DS-A.03.01.05.d": {
		"requirement": "03.01.05",
		"statement": "SR-03.01.05.d",
		"text": "privileges are reassigned or removed, as necessary.",
	},
	"DS-A.03.01.06.a": {
		"requirement": "03.01.06",
		"statement": "SR-03.01.06.a",
		"text": "privileged accounts on the system are restricted to <A.03.01.06.ODP[01]: personnel or roles>.",
	},
	"DS-A.03.01.06.b": {
		"requirement": "03.01.06",
		"statement": "SR-03.01.06.b",
		"text": "users (or roles) with privileged accounts are required to use non-privileged accounts when accessing non-security functions or non-security information.",
	},
	"DS-A.03.01.07.a": {
		"requirement": "03.01.07",
		"statement": "SR-03.01.07.a",
		"text": "non-privileged users are prevented from executing privileged functions.",
	},
	"DS-A.03.01.07.b": {
		"requirement": "03.01.07",
		"statement": "SR-03.01.07.b",
		"text": "the execution of privileged functions is logged.",
	},
	"DS-A.03.01.08.a": {
		"requirement": "03.01.08",
		"statement": "SR-03.01.08.a",
		"text": "a limit of <A.03.01.08.ODP[01]: number> consecutive invalid logon attempts by a user during <A.03.01.08.ODP[02]: time period> is enforced.",
	},
	"DS-A.03.01.08.b": {
		"requirement": "03.01.08",
		"statement": "SR-03.01.08.b",
		"text": "<A.03.01.08.ODP[03]: SELECTED PARAMETER VALUES> when the maximum number of unsuccessful attempts is exceeded.",
	},
	"DS-A.03.01.09": {
		"requirement": "03.01.09",
		"statement": "SR-03.01.09",
		"text": "a system use notification message with privacy and security notices consistent with applicable CUI rules is displayed before granting access to the system.",
	},
	"DS-A.03.01.10.a": {
		"requirement": "03.01.10",
		"statement": "SR-03.01.10.a",
		"text": "access to the system is prevented by <A.03.01.10.ODP[01]: SELECTED PARAMETER VALUES>.",
	},
	"DS-A.03.01.10.b": {
		"requirement": "03.01.10",
		"statement": "SR-03.01.10.b",
		"text": "the device lock is retained until the user reestablishes access using established identification and authentication procedures.",
	},
	"DS-A.03.01.10.c": {
		"requirement": "03.01.10",
		"statement": "SR-03.01.10.c",
		"text": "information previously visible on the display is concealed via device lock with a publicly viewable image.",
	},
	"DS-A.03.01.11": {
		"requirement": "03.01.11",
		"statement": "SR-03.01.11",
		"text": "a user session is terminated automatically after <A.03.01.11.ODP[01]: conditions or trigger events>.",
	},
	"DS-A.03.01.12.a[01]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.a",
		"text": "types of allowable remote system access are defined.",
	},
	"DS-A.03.01.12.a[02]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.a",
		"text": "usage restrictions are established for each type of allowable remote system access.",
	},
	"DS-A.03.01.12.a[03]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.a",
		"text": "configuration requirements are established for each type of allowable remote system access.",
	},
	"DS-A.03.01.12.a[04]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.a",
		"text": "connection requirements are established for each type of allowable remote system access.",
	},
	"DS-A.03.01.12.b": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.b",
		"text": "each type of remote system access is authorized prior to establishing such connections.",
	},
	"DS-A.03.01.12.c[01]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.c",
		"text": "remote access to the system is routed through authorized access control points.",
	},
	"DS-A.03.01.12.c[02]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.c",
		"text": "remote access to the system is routed through managed access control points.",
	},
	"DS-A.03.01.12.d[1]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.d",
		"text": "remote execution of privileged commands is authorized.",
	},
	"DS-A.03.01.12.d[2]": {
		"requirement": "03.01.12",
		"statement": "SR-03.01.12.d",
		"text": "remote access to security-relevant information is authorized.",
	},
	"DS-A.03.01.16.a[01]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.a",
		"text": "each type of wireless access to the system is defined.",
	},
	"DS-A.03.01.16.a[02]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.a",
		"text": "usage restrictions are established for each type of wireless access to the system.",
	},
	"DS-A.03.01.16.a[03]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.a",
		"text": "configuration requirements are established for each type of wireless access to the system.",
	},
	"DS-A.03.01.16.a[04]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.a",
		"text": "connection requirements are established for each type of wireless access to the system.",
	},
	"DS-A.03.01.16.b": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.b",
		"text": "each type of wireless access to the system is authorized prior to establishing such connections.",
	},
	"DS-A.03.01.16.c": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.c",
		"text": "wireless networking capabilities not intended for use are disabled prior to issuance and deployment.",
	},
	"DS-A.03.01.16.d[01]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.d",
		"text": "wireless access to the system is protected using authentication.",
	},
	"DS-A.03.01.16.d[02]": {
		"requirement": "03.01.16",
		"statement": "SR-03.01.16.d",
		"text": "wireless access to the system is protected using encryption.",
	},
	"DS-A.03.01.18.a[01]": {
		"requirement": "03.01.18",
		"statement": "SR-03.01.18.a",
		"text": "usage restrictions are established for mobile devices.",
	},
	"DS-A.03.01.18.a[02]": {
		"requirement": "03.01.18",
		"statement": "SR-03.01.18.a",
		"text": "configuration requirements are established for mobile devices.",
	},
	"DS-A.03.01.18.a[03]": {
		"requirement": "03.01.18",
		"statement": "SR-03.01.18.a",
		"text": "connection requirements are established for mobile devices.",
	},
	"DS-A.03.01.18.b": {
		"requirement": "03.01.18",
		"statement": "SR-03.01.18.b",
		"text": "the connection of mobile devices to the system is authorized.",
	},
	"DS-A.03.01.18.c": {
		"requirement": "03.01.18",
		"statement": "SR-03.01.18.c",
		"text": "full-device or container-based encryption is implemented to protect the confidentiality of CUI on mobile devices.",
	},
	"DS-A.03.01.20.a": {
		"requirement": "03.01.20",
		"statement": "SR-03.01.20.a",
		"text": "the use of external systems is prohibited unless the systems are specifically authorized.",
	},
	"DS-A.03.01.20.b": {
		"requirement": "03.01.20",
		"statement": "SR-03.01.20.b",
		"text": "the following security requirements to be satisfied on external systems prior to allowing the use of or access to those systems by authorized individuals are established: <A.03.01.20.ODP[01]: security requirements>.",
	},
	"DS-A.03.01.20.c.01": {
		"requirement": "03.01.20",
		"statement": "SR-03.01.20.c.01",
		"text": "authorized individuals are permitted to use external systems to access the organizational system or to process, store, or transmit CUI only after verifying that the security requirements on the external systems as specified in the organization’s system security plans have been satisfied.",
	},
	"DS-A.03.01.20.c.02": {
		"requirement": "03.01.20",
		"statement": "SR-03.01.20.c.02",
		"text": "authorized individuals are permitted to use external systems to access the organizational system or to process, store, or transmit CUI only after retaining approved system connection or processing agreements with the organizational entity hosting the external systems.",
	},
	"DS-A.03.01.20.d": {
		"requirement": "03.01.20",
		"statement": "SR-03.01.20.d",
		"text": "the use of organization-controlled portable storage devices by authorized individuals on external systems is restricted.",
	},
	"DS-A.03.01.22.a": {
		"requirement": "03.01.22",
		"statement": "SR-03.01.22.a",
		"text": "authorized individuals are trained to ensure that publicly accessible information does not contain CUI.",
	},
	"DS-A.03.01.22.b[01]": {
		"requirement": "03.01.22",
		"statement": "SR-03.01.22.b",
		"text": "the content on publicly accessible systems is reviewed for CUI.",
	},
	"DS-A.03.01.22.b[02]": {
		"requirement": "03.01.22",
		"statement": "SR-03.01.22.b",
		"text": "CUI is removed from publicly accessible systems, if discovered.",
	},
	"DS-A.03.02.01.a.01[01]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.01",
		"text": "security literacy training is provided to system users as part of initial training for new users.",
	},
	"DS-A.03.02.01.a.01[02]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.01",
		"text": "security literacy training is provided to system users <A.03.02.01.ODP[01]: frequency> after initial training.",
	},
	"DS-A.03.02.01.a.02": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.02",
		"text": "security literacy training is provided to system users when required by system changes or following <A.03.02.01.ODP[02]: events>.",
	},
	"DS-A.03.02.01.a.03[01]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on recognizing indicators of insider threat.",
	},
	"DS-A.03.02.01.a.03[02]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on reporting indicators of insider threat.",
	},
	"DS-A.03.02.01.a.03[03]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on recognizing indicators of social engineering.",
	},
	"DS-A.03.02.01.a.03[04]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on reporting indicators of social engineering.",
	},
	"DS-A.03.02.01.a.03[05]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on recognizing indicators of social mining.",
	},
	"DS-A.03.02.01.a.03[06]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.a.03",
		"text": "security literacy training is provided to system users on reporting indicators of social mining.",
	},
	"DS-A.03.02.01.b[01]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.b",
		"text": "security literacy training content is updated <A.03.02.01.ODP[03]: frequency>.",
	},
	"DS-A.03.02.01.b[02]": {
		"requirement": "03.02.01",
		"statement": "SR-03.02.01.b",
		"text": "security literacy training content is updated following <A.03.02.01.ODP[04]: events>.",
	},
	"DS-A.03.02.02.a.01[01]": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.a.01",
		"text": "role-based security training is provided to organizational personnel before authorizing access to the system or CUI.",
	},
	"DS-A.03.02.02.a.01[02]": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.a.01",
		"text": "role-based security training is provided to organizational personnel before performing assigned duties.",
	},
	"DS-A.03.02.02.a.01[03]": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.a.01",
		"text": "role-based security training is provided to organizational personnel <A.03.02.02.ODP[01]: frequency> after initial training.",
	},
	"DS-A.03.02.02.a.02": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.a.02",
		"text": "role-based security training is provided to organizational personnel when required by system changes or following <A.03.02.02.ODP[02]: events>.",
	},
	"DS-A.03.02.02.b[01]": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.b",
		"text": "role-based security training content is updated <A.03.02.02.ODP[03]: frequency>.",
	},
	"DS-A.03.02.02.b[02]": {
		"requirement": "03.02.02",
		"statement": "SR-03.02.02.b",
		"text": "role-based security training content is updated following <A.03.02.02.ODP[04]: events>.",
	},
	"DS-A.03.03.01.a": {
		"requirement": "03.03.01",
		"statement": "SR-03.03.01.a",
		"text": "the following event types are specified for logging within the system: <A.03.03.01.ODP[01]: event types>.",
	},
	"DS-A.03.03.01.b[01]": {
		"requirement": "03.03.01",
		"statement": "SR-03.03.01.b",
		"text": "the event types selected for logging are reviewed <A.03.03.01.ODP[02]: frequency>.",
	},
	"DS-A.03.03.01.b[02]": {
		"requirement": "03.03.01",
		"statement": "SR-03.03.01.b",
		"text": "the event types selected for logging are updated <A.03.03.01.ODP[02]: frequency>.",
	},
	"DS-A.03.03.02.a.01": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.01",
		"text": "audit records contain information that establishes what type of event occurred.",
	},
	"DS-A.03.03.02.a.02": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.02",
		"text": "audit records contain information that establishes when the event occurred.",
	},
	"DS-A.03.03.02.a.03": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.03",
		"text": "audit records contain information that establishes where the event occurred.",
	},
	"DS-A.03.03.02.a.04": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.04",
		"text": "audit records contain information that establishes the source of the event.",
	},
	"DS-A.03.03.02.a.05": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.05",
		"text": "audit records contain information that establishes the outcome of the event.",
	},
	"DS-A.03.03.02.a.06": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.a.06",
		"text": "audit records contain information that establishes the identity of the individuals, subjects, objects, or entities associated with the event.",
	},
	"DS-A.03.03.02.b": {
		"requirement": "03.03.02",
		"statement": "SR-03.03.02.b",
		"text": "additional information for audit records is provided, as needed.",
	},
	"DS-A.03.03.03.a": {
		"requirement": "03.03.03",
		"statement": "SR-03.03.03.a",
		"text": "audit records for the selected event types and audit record content specified in 03.03.01 and 03.03.02 are generated.",
	},
	"DS-A.03.03.03.b": {
		"requirement": "03.03.03",
		"statement": "SR-03.03.03.b",
		"text": "audit records are retained for a time period consistent with the records retention policy.",
	},
	"DS-A.03.03.04.a": {
		"requirement": "03.03.04",
		"statement": "SR-03.03.04.a",
		"text": "organizational personnel or roles are alerted in the event of an audit logging process failure within <A.03.03.04.ODP[01]: time period>.",
	},
	"DS-A.03.03.04.b": {
		"requirement": "03.03.04",
		"statement": "SR-03.03.04.b",
		"text": "the following additional actions are taken: <A.03.03.04.ODP[02]: additional actions>.",
	},
	"DS-A.03.03.05.a": {
		"requirement": "03.03.05",
		"statement": "SR-03.03.05.a",
		"text": "system audit records are reviewed and analyzed <A.03.03.05.ODP[01]: frequency> for indications and the potential impact of inappropriate or unusual activity.",
	},
	"DS-A.03.03.05.b": {
		"requirement": "03.03.05",
		"statement": "SR-03.03.05.b",
		"text": "findings are reported to organizational personnel or roles.",
	},
	"DS-A.03.03.05.c[01]": {
		"requirement": "03.03.05",
		"statement": "SR-03.03.05.c",
		"text": "audit records across different repositories are analyzed to gain organization-wide situational awareness.",
	},
	"DS-A.03.03.05.c[02]": {
		"requirement": "03.03.05",
		"statement": "SR-03.03.05.c",
		"text": "audit records across different repositories are correlated to gain organization-wide situational awareness.",
	},
	"DS-A.03.03.06.a[01]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.a",
		"text": "an audit record reduction and report generation capability that supports audit record review is implemented.",
	},
	"DS-A.03.03.06.a[02]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.a",
		"text": "an audit record reduction and report generation capability that supports audit record analysis is implemented.",
	},
	"DS-A.03.03.06.a[03]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.a",
		"text": "an audit record reduction and report generation capability that supports audit record reporting requirements is implemented.",
	},
	"DS-A.03.03.06.a[04]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.a",
		"text": "an audit record reduction and report generation capability that supports after-the-fact investigations of incidents is implemented.",
	},
	"DS-A.03.03.06.b[01]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.b",
		"text": "the original content of audit records is preserved.",
	},
	"DS-A.03.03.06.b[02]": {
		"requirement": "03.03.06",
		"statement": "SR-03.03.06.b",
		"text": "the original time ordering of audit records is preserved.",
	},
	"DS-A.03.03.07.a": {
		"requirement": "03.03.07",
		"statement": "SR-03.03.07.a",
		"text": "internal system clocks are used to generate time stamps for audit records.",
	},
	"DS-A.03.03.07.b[01]": {
		"requirement": "03.03.07",
		"statement": "SR-03.03.07.b",
		"text": "time stamps are recorded for audit records that meet <A.03.03.07.ODP[01]: granularity of time measurement>.",
	},
	"DS-A.03.03.07.b[02]": {
		"requirement": "03.03.07",
		"statement": "SR-03.03.07.b",
		"text": "time stamps are recorded for audit records that use Coordinated Universal Time (UTC), have a fixed local time offset from UTC, or include the local time offset as part of the time stamp.",
	},
	"DS-A.03.03.08.a[01]": {
		"requirement": "03.03.08",
		"statement": "SR-03.03.08.a",
		"text": "audit information is protected from unauthorized access, modification, and deletion.",
	},
	"DS-A.03.03.08.a[02]": {
		"requirement": "03.03.08",
		"statement": "SR-03.03.08.a",
		"text": "audit logging tools are protected from unauthorized access, modification, and deletion.",
	},
	"DS-A.03.03.08.b": {
		"requirement": "03.03.08",
		"statement": "SR-03.03.08.b",
		"text": "access to management of audit logging functionality is authorized to only a subset of privileged users or roles.",
	},
	"DS-A.03.04.01.a[01]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.a",
		"text": "a current baseline configuration of the system is developed.",
	},
	"DS-A.03.04.01.a[02]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.a",
		"text": "a current baseline configuration of the system is maintained under configuration control.",
	},
	"DS-A.03.04.01.b[01]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.b",
		"text": "the baseline configuration of the system is reviewed <A.03.04.01.ODP[01]: frequency>.",
	},
	"DS-A.03.04.01.b[02]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.b",
		"text": "the baseline configuration of the system is updated <A.03.04.01.ODP[01]: frequency>.",
	},
	"DS-A.03.04.01.b[03]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.b",
		"text": "the baseline configuration of the system is reviewed when system components are installed or modified.",
	},
	"DS-A.03.04.01.b[04]": {
		"requirement": "03.04.01",
		"statement": "SR-03.04.01.b",
		"text": "the baseline configuration of the system is updated when system components are installed or modified.",
	},
	"DS-A.03.04.02.a[01]": {
		"requirement": "03.04.02",
		"statement": "SR-03.04.02.a",
		"text": "the following configuration settings for the system that reflect the most restrictive mode consistent with operational requirements are established and documented: <A.03.04.02.ODP[01]: configuration settings>.",
	},
	"DS-A.03.04.02.a[02]": {
		"requirement": "03.04.02",
		"statement": "SR-03.04.02.a",
		"text": "the following configuration settings for the system are implemented: <A.03.04.02.ODP[01]: configuration settings>.",
	},
	"DS-A.03.04.02.b[01]": {
		"requirement": "03.04.02",
		"statement": "SR-03.04.02.b",
		"text": "any deviations from established configuration settings are identified and documented.",
	},
	"DS-A.03.04.02.b[02]": {
		"requirement": "03.04.02",
		"statement": "SR-03.04.02.b",
		"text": "any deviations from established configuration settings are approved.",
	},
	"DS-A.03.04.03.a": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.a",
		"text": "the types of changes to the system that are configuration-controlled are defined.",
	},
	"DS-A.03.04.03.b[01]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.b",
		"text": "proposed configuration-controlled changes to the system are reviewed with explicit consideration for security impacts.",
	},
	"DS-A.03.04.03.b[02]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.b",
		"text": "proposed configuration-controlled changes to the system are approved or disapproved with explicit consideration for security impacts.",
	},
	"DS-A.03.04.03.c[01]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.c",
		"text": "approved configuration-controlled changes to the system are implemented.",
	},
	"DS-A.03.04.03.c[02]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.c",
		"text": "approved configuration-controlled changes to the system are documented.",
	},
	"DS-A.03.04.03.d[01]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.d",
		"text": "activities associated with configuration-controlled changes to the system are monitored.",
	},
	"DS-A.03.04.03.d[02]": {
		"requirement": "03.04.03",
		"statement": "SR-03.04.03.d",
		"text": "activities associated with configuration-controlled changes to the system are reviewed.",
	},
	"DS-A.03.04.04.a": {
		"requirement": "03.04.04",
		"statement": "SR-03.04.04.a",
		"text": "changes to the system are analyzed to determine potential security impacts prior to change implementation.",
	},
	"DS-A.03.04.04.b": {
		"requirement": "03.04.04",
		"statement": "SR-03.04.04.b",
		"text": "the security requirements for the system continue to be satisfied after the system changes have been implemented.",
	},
	"DS-A.03.04.05[01]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "physical access restrictions associated with changes to the system are defined and documented.",
	},
	"DS-A.03.04.05[02]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "physical access restrictions associated with changes to the system are approved.",
	},
	"DS-A.03.04.05[03]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "physical access restrictions associated with changes to the system are enforced.",
	},
	"DS-A.03.04.05[04]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "logical access restrictions associated with changes to the system are defined and documented.",
	},
	"DS-A.03.04.05[05]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "logical access restrictions associated with changes to the system are approved.",
	},
	"DS-A.03.04.05[06]": {
		"requirement": "03.04.05",
		"statement": "SR-03.04.05",
		"text": "logical access restrictions associated with changes to the system are enforced.",
	},
	"DS-A.03.04.06.a": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.a",
		"text": "the system is configured to provide only mission-essential capabilities.",
	},
	"DS-A.03.04.06.b[01]": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.b",
		"text": "the use of the following functions is prohibited or restricted: <A.03.04.06.ODP[01]: functions>.",
	},
	"DS-A.03.04.06.b[02]": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.b",
		"text": "the use of the following ports is prohibited or restricted: <A.03.04.06.ODP[02]: ports>.",
	},
	"DS-A.03.04.06.b[03]": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.b",
		"text": "the use of the following protocols is prohibited or restricted: <A.03.04.06.ODP[03]: protocols>.",
	},
	"DS-A.03.04.06.b[04]": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.b",
		"text": "the use of the following connections is prohibited or restricted: <A.03.04.06.ODP[04]: connections>.",
	},
	"DS-A.03.04.06.b[05]": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.b",
		"text": "the use of the following services is prohibited or restricted: <A.03.04.06.ODP[05]: services>.",
	},
	"DS-A.03.04.06.c": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.c",
		"text": "the system is reviewed <A.03.04.06.ODP[06]: frequency> to identify unnecessary or nonsecure functions, ports, protocols, connections, and services.",
	},
	"DS-A.03.04.06.d": {
		"requirement": "03.04.06",
		"statement": "SR-03.04.06.d",
		"text": "unnecessary or nonsecure functions, ports, protocols, connections, and services are disabled or removed.",
	},
	"DS-A.03.04.08.a": {
		"requirement": "03.04.08",
		"statement": "SR-03.04.08.a",
		"text": "software programs authorized to execute on the system are identified.",
	},
	"DS-A.03.04.08.b": {
		"requirement": "03.04.08",
		"statement": "SR-03.04.08.b",
		"text": "a deny-all, allow-by-exception policy for the execution of authorized software programs on the system is implemented.",
	},
	"DS-A.03.04.08.c": {
		"requirement": "03.04.08",
		"statement": "SR-03.04.08.c",
		"text": "the list of authorized software programs is reviewed and updated <A.03.04.08.ODP[01]: frequency>.",
	},
	"DS-A.03.04.10.a": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.a",
		"text": "an inventory of system components is developed and documented.",
	},
	"DS-A.03.04.10.b[01]": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.b",
		"text": "the system component inventory is reviewed <A.03.04.10.ODP[01]: frequency>.",
	},
	"DS-A.03.04.10.b[02]": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.b",
		"text": "the system component inventory is updated <A.03.04.10.ODP[01]: frequency>.",
	},
	"DS-A.03.04.10.c[01]": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.c",
		"text": "the system component inventory is updated as part of component installations.",
	},
	"DS-A.03.04.10.c[02]": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.c",
		"text": "the system component inventory is updated as part of component removals.",
	},
	"DS-A.03.04.10.c[03]": {
		"requirement": "03.04.10",
		"statement": "SR-03.04.10.c",
		"text": "the system component inventory is updated as part of system updates.",
	},
	"DS-A.03.04.11.a[01]": {
		"requirement": "03.04.11",
		"statement": "SR-03.04.11.a",
		"text": "the location of CUI is identified and documented.",
	},
	"DS-A.03.04.11.a[02]": {
		"requirement": "03.04.11",
		"statement": "SR-03.04.11.a",
		"text": "the system components on which CUI is processed are identified and documented.",
	},
	"DS-A.03.04.11.a[03]": {
		"requirement": "03.04.11",
		"statement": "SR-03.04.11.a",
		"text": "the system components on which CUI is stored are identified and documented.",
	},
	"DS-A.03.04.11.b[01]": {
		"requirement": "03.04.11",
		"statement": "SR-03.04.11.b",
		"text": "changes to the system or system component location where CUI is processed are documented.",
	},
	"DS-A.03.04.11.b[02]": {
		"requirement": "03.04.11",
		"statement": "SR-03.04.11.b",
		"text": "changes to the system or system component location where CUI is stored are documented.",
	},
	"DS-A.03.04.12.a": {
		"requirement": "03.04.12",
		"statement": "SR-03.04.12.a",
		"text": "systems or system components with the following configurations are issued to individuals traveling to high-risk locations: <A.03.04.12.ODP[01]: configurations>.",
	},
	"DS-A.03.04.12.b": {
		"requirement": "03.04.12",
		"statement": "SR-03.04.12.b",
		"text": "the following security requirements are applied to the system or system components when the individuals return from travel: <A.03.04.12.ODP[02]: security requirements>.",
	},
	"DS-A.03.05.01.a[01]": {
		"requirement": "03.05.01",
		"statement": "SR-03.05.01.a",
		"text": "system users are uniquely identified.",
	},
	"DS-A.03.05.01.a[02]": {
		"requirement": "03.05.01",
		"statement": "SR-03.05.01.a",
		"text": "system users are authenticated.",
	},
	"DS-A.03.05.01.a[03]": {
		"requirement": "03.05.01",
		"statement": "SR-03.05.01.a",
		"text": "processes acting on behalf of users are associated with uniquely identified and authenticated system users.",
	},
	"DS-A.03.05.01.b": {
		"requirement": "03.05.01",
		"statement": "SR-03.05.01.b",
		"text": "users are reauthenticated when <A.03.05.01.ODP[01]: circumstances or situations>.",
	},
	"DS-A.03.05.02[01]": {
		"requirement": "03.05.02",
		"statement": "SR-03.05.02",
		"text": "<A.03.05.02.ODP[01]: devices or types of devices> are uniquely identified before establishing a system connection.",
	},
	"DS-A.03.05.02[02]": {
		"requirement": "03.05.02",
		"statement": "SR-03.05.02",
		"text": "<A.03.05.02.ODP[01]: devices or types of devices> are authenticated before establishing a system connection.",
	},
	"DS-A.03.05.03[01]": {
		"requirement": "03.05.03",
		"statement": "SR-03.05.03",
		"text": "multi-factor authentication for access to privileged accounts is implemented.",
	},
	"DS-A.03.05.03[02]": {
		"requirement": "03.05.03",
		"statement": "SR-03.05.03",
		"text": "multi-factor authentication for access to non-privileged accounts is implemented.",
	},
	"DS-A.03.05.04[01]": {
		"requirement": "03.05.04",
		"statement": "SR-03.05.04",
		"text": "replay-resistant authentication mechanisms for access to privileged accounts are implemented.",
	},
	"DS-A.03.05.04[02]": {
		"requirement": "03.05.04",
		"statement": "SR-03.05.04",
		"text": "replay-resistant authentication mechanisms for access to non-privileged accounts are implemented.",
	},
	"DS-A.03.05.05.a": {
		"requirement": "03.05.05",
		"statement": "SR-03.05.05.a",
		"text": "authorization is received from organizational personnel or roles to assign an individual, group, role, service, or device identifier.",
	},
	"DS-A.03.05.05.b[01]": {
		"requirement": "03.05.05",
		"statement": "SR-03.05.05.b",
		"text": "an identifier that identifies an individual, group, role, service, or device is selected.",
	},
	"DS-A.03.05.05.b[02]": {
		"requirement": "03.05.05",
		"statement": "SR-03.05.05.b",
		"text": "an identifier that identifies an individual, group, role, service, or device is assigned.",
	},
	"DS-A.03.05.05.c": {
		"requirement": "03.05.05",
		"statement": "SR-03.05.05.c",
		"text": "the reuse of identifiers for <A.03.05.05.ODP[01]: time period> is prevented.",
	},
	"DS-A.03.05.05.d": {
		"requirement": "03.05.05",
		"statement": "SR-03.05.05.d",
		"text": "individual identifiers are managed by uniquely identifying each individual as <A.03.05.05.ODP[02]: characteristic>.",
	},
	"DS-A.03.05.07.a[01]": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.a",
		"text": "a list of commonly used, expected, or compromised passwords is maintained.",
	},
	"DS-A.03.05.07.a[02]": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.a",
		"text": "a list of commonly used, expected, or compromised passwords is updated <A.03.05.07.ODP[01]: frequency>.",
	},
	"DS-A.03.05.07.a[03]": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.a",
		"text": "a list of commonly used, expected, or compromised passwords is updated when organizational passwords are suspected to have been compromised.",
	},
	"DS-A.03.05.07.b": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.b",
		"text": "passwords are verified not to be found on the list of commonly used, expected, or compromised passwords when they are created or updated by users.",
	},
	"DS-A.03.05.07.c": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.c",
		"text": "passwords are only transmitted over cryptographically protected channels.",
	},
	"DS-A.03.05.07.d": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.d",
		"text": "passwords are stored in a cryptographically protected form.",
	},
	"DS-A.03.05.07.e": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.e",
		"text": "a new password is selected upon first use after account recovery.",
	},
	"DS-A.03.05.07.f": {
		"requirement": "03.05.07",
		"statement": "SR-03.05.07.f",
		"text": "the following composition and complexity rules for passwords are enforced: <A.03.05.07.ODP[02]: rules>.",
	},
	"DS-A.03.05.11": {
		"requirement": "03.05.11",
		"statement": "SR-03.05.11",
		"text": "feedback of authentication information during the authentication process is obscured.",
	},
	"DS-A.03.05.12.a": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.a",
		"text": "the identity of the individual, group, role, service, or device receiving the authenticator as part of the initial authenticator distribution is verified.",
	},
	"DS-A.03.05.12.b": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.b",
		"text": "initial authenticator content for any authenticators issued by the organization is established.",
	},
	"DS-A.03.05.12.c[01]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for initial authenticator distribution are established.",
	},
	"DS-A.03.05.12.c[02]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for lost, compromised, or damaged authenticators are established.",
	},
	"DS-A.03.05.12.c[03]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for revoking authenticators are established.",
	},
	"DS-A.03.05.12.c[04]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for initial authenticator distribution are implemented.",
	},
	"DS-A.03.05.12.c[05]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for lost, compromised, or damaged authenticators are implemented.",
	},
	"DS-A.03.05.12.c[06]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.c",
		"text": "administrative procedures for revoking authenticators are implemented.",
	},
	"DS-A.03.05.12.d": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.d",
		"text": "default authenticators are changed at first use.",
	},
	"DS-A.03.05.12.e": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.e",
		"text": "authenticators are changed or refreshed <A.03.05.12.ODP[01]: frequency> or when the following events occur: <A.03.05.12.ODP[02]: events>.",
	},
	"DS-A.03.05.12.f[01]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.f",
		"text": "authenticator content is protected from unauthorized disclosure.",
	},
	"DS-A.03.05.12.f[02]": {
		"requirement": "03.05.12",
		"statement": "SR-03.05.12.f",
		"text": "authenticator content is protected from unauthorized modification.",
	},
	"DS-A.03.06.01[01]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "an incident-handling capability that is consistent with the incident response plan is implemented.",
	},
	"DS-A.03.06.01[02]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "the incident handling capability includes preparation.",
	},
	"DS-A.03.06.01[03]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "the incident handling capability includes detection and analysis.",
	},
	"DS-A.03.06.01[04]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "the incident handling capability includes containment.",
	},
	"DS-A.03.06.01[05]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "the incident handling capability includes eradication.",
	},
	"DS-A.03.06.01[06]": {
		"requirement": "03.06.01",
		"statement": "SR-03.06.01",
		"text": "the incident handling capability includes recovery.",
	},
	"DS-A.03.06.02.a[01]": {
		"requirement": "03.06.02",
		"statement": "SR-03.06.02.a",
		"text": "system security incidents are tracked.",
	},
	"DS-A.03.06.02.a[02]": {
		"requirement": "03.06.02",
		"statement": "SR-03.06.02.a",
		"text": "system security incidents are documented.",
	},
	"DS-A.03.06.02.b": {
		"requirement": "03.06.02",
		"statement": "SR-03.06.02.b",
		"text": "suspected incidents are reported to the organizational incident response capability within <A.03.06.02.ODP[01]: time period>.",
	},
	"DS-A.03.06.02.c": {
		"requirement": "03.06.02",
		"statement": "SR-03.06.02.c",
		"text": "incident information is reported to <A.03.06.02.ODP[02]: authorities>.",
	},
	"DS-A.03.06.02.d": {
		"requirement": "03.06.02",
		"statement": "SR-03.06.02.d",
		"text": "an incident response support resource that offers advice and assistance to system users on handling and reporting incidents is provided.",
	},
	"DS-A.03.06.03": {
		"requirement": "03.06.03",
		"statement": "SR-03.06.03",
		"text": "the effectiveness of the incident response capability is tested <A.03.06.03.ODP[01]: frequency>.",
	},
	"DS-A.03.06.04.a.01": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.a.01",
		"text": "incident response training for system users consistent with assigned roles and responsibilities is provided within <A.03.06.04.ODP[01]: time period> of assuming an incident response role or responsibility or acquiring system access.",
	},
	"DS-A.03.06.04.a.02": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.a.02",
		"text": "incident response training for system users consistent with assigned roles and responsibilities is provided when required by system changes.",
	},
	"DS-A.03.06.04.a.03": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.a.03",
		"text": "incident response training for system users consistent with assigned roles and responsibilities is provided <A.03.06.04.ODP[02]: frequency> thereafter.",
	},
	"DS-A.03.06.04.b[01]": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.b",
		"text": "incident response training content is reviewed <A.03.06.04.ODP[03]: frequency>.",
	},
	"DS-A.03.06.04.b[02]": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.b",
		"text": "incident response training content is updated <A.03.06.04.ODP[03]: frequency>.",
	},
	"DS-A.03.06.04.b[03]": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.b",
		"text": "incident response training content is reviewed following <A.03.06.04.ODP[04]: events>.",
	},
	"DS-A.03.06.04.b[04]": {
		"requirement": "03.06.04",
		"statement": "SR-03.06.04.b",
		"text": "incident response training content is updated following <A.03.06.04.ODP[04]: events>.",
	},
	"DS-A.03.06.05.a.01": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.01",
		"text": "an incident response plan is developed that provides the organization with a roadmap for implementing its incident response capability.",
	},
	"DS-A.03.06.05.a.02": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.02",
		"text": "an incident response plan is developed that describes the structure and organization of the incident response capability.",
	},
	"DS-A.03.06.05.a.03": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.03",
		"text": "an incident response plan is developed that provides a high-level approach for how the incident response capability fits into the overall organization.",
	},
	"DS-A.03.06.05.a.04": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.04",
		"text": "an incident response plan is developed that defines reportable incidents.",
	},
	"DS-A.03.06.05.a.05": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.05",
		"text": "an incident response plan is developed that addresses the sharing of incident information.",
	},
	"DS-A.03.06.05.a.06": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.a.06",
		"text": "an incident response plan is developed that designates responsibilities to organizational entities, personnel, or roles.",
	},
	"DS-A.03.06.05.b[01]": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.b",
		"text": "copies of the incident response plan are distributed to designated incident response personnel (identified by name or by role).",
	},
	"DS-A.03.06.05.b[02]": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.b",
		"text": "copies of the incident response plan are distributed to organizational elements.",
	},
	"DS-A.03.06.05.c": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.c",
		"text": "the incident response plan is updated to address system and organizational changes or problems encountered during plan implementation, execution, or testing.",
	},
	"DS-A.03.06.05.d": {
		"requirement": "03.06.05",
		"statement": "SR-03.06.05.d",
		"text": "the incident response plan is protected from unauthorized disclosure.",
	},
	"DS-A.03.07.04.a[01]": {
		"requirement": "03.07.04",
		"statement": "SR-03.07.04.a",
		"text": "the use of system maintenance tools is approved.",
	},
	"DS-A.03.07.04.a[02]": {
		"requirement": "03.07.04",
		"statement": "SR-03.07.04.a",
		"text": "the use of system maintenance tools is controlled.",
	},
	"DS-A.03.07.04.a[03]": {
		"requirement": "03.07.04",
		"statement": "SR-03.07.04.a",
		"text": "the use of system maintenance tools is monitored.",
	},
	"DS-A.03.07.04.b": {
		"requirement": "03.07.04",
		"statement": "SR-03.07.04.b",
		"text": "media with diagnostic and test programs are checked for malicious code before the media are used in the system.",
	},
	"DS-A.03.07.04.c": {
		"requirement": "03.07.04",
		"statement": "SR-03.07.04.c",
		"text": "the removal of system maintenance equipment containing CUI is prevented by verifying that there is no CUI on the equipment, sanitizing or destroying the equipment, or retaining the equipment within the facility.",
	},
	"DS-A.03.07.05.a[01]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.a",
		"text": "nonlocal maintenance and diagnostic activities are approved.",
	},
	"DS-A.03.07.05.a[02]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.a",
		"text": "nonlocal maintenance and diagnostic activities are monitored.",
	},
	"DS-A.03.07.05.b[01]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.b",
		"text": "multi-factor authentication is implemented in the establishment of nonlocal maintenance and diagnostic sessions.",
	},
	"DS-A.03.07.05.b[02]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.b",
		"text": "replay resistance is implemented in the establishment of nonlocal maintenance and diagnostic sessions.",
	},
	"DS-A.03.07.05.c[01]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.c",
		"text": "session connections are terminated when nonlocal maintenance is completed.",
	},
	"DS-A.03.07.05.c[02]": {
		"requirement": "03.07.05",
		"statement": "SR-03.07.05.c",
		"text": "network connections are terminated when nonlocal maintenance is completed.",
	},
	"DS-A.03.07.06.a": {
		"requirement": "03.07.06",
		"statement": "SR-03.07.06.a",
		"text": "a process for maintenance personnel authorization is established.",
	},
	"DS-A.03.07.06.b": {
		"requirement": "03.07.06",
		"statement": "SR-03.07.06.b",
		"text": "a list of authorized maintenance organizations or personnel is maintained.",
	},
	"DS-A.03.07.06.c": {
		"requirement": "03.07.06",
		"statement": "SR-03.07.06.c",
		"text": "non-escorted personnel who perform maintenance on the system possess the required access authorizations.",
	},
	"DS-A.03.07.06.d[01]": {
		"requirement": "03.07.06",
		"statement": "SR-03.07.06.d",
		"text": "organizational personnel with required access authorizations are designated to supervise the maintenance activities of personnel who do not possess the required access authorizations.",
	},
	"DS-A.03.07.06.d[02]": {
		"requirement": "03.07.06",
		"statement": "SR-03.07.06.d",
		"text": "organizational personnel with required technical competence are designated to supervise the maintenance activities of personnel who do not possess the required access authorizations.",
	},
	"DS-A.03.08.01[01]": {
		"requirement": "03.08.01",
		"statement": "SR-03.08.01",
		"text": "system media that contain CUI are physically controlled.",
	},
	"DS-A.03.08.01[02]": {
		"requirement": "03.08.01",
		"statement": "SR-03.08.01",
		"text": "system media that contain CUI are securely stored.",
	},
	"DS-A.03.08.02": {
		"requirement": "03.08.02",
		"statement": "SR-03.08.02",
		"text": "access to CUI on system media is restricted to authorized personnel or roles.",
	},
	"DS-A.03.08.03": {
		"requirement": "03.08.03",
		"statement": "SR-03.08.03",
		"text": "system media that contain CUI are sanitized prior to disposal, release out of organizational control, or release for reuse.",
	},
	"DS-A.03.08.04[01]": {
		"requirement": "03.08.04",
		"statement": "SR-03.08.04",
		"text": "system media that contain CUI are marked to indicate distribution limitations.",
	},
	"DS-A.03.08.04[02]": {
		"requirement": "03.08.04",
		"statement": "SR-03.08.04",
		"text": "system media that contain CUI are marked to indicate handling caveats.",
	},
	"DS-A.03.08.04[03]": {
		"requirement": "03.08.04",
		"statement": "SR-03.08.04",
		"text": "system media that contain CUI are marked to indicate applicable CUI markings.",
	},
	"DS-A.03.08.05.a[01]": {
		"requirement": "03.08.05",
		"statement": "SR-03.08.05.a",
		"text": "system media that contain CUI are protected during transport outside of controlled areas.",
	},
	"DS-A.03.08.05.a[02]": {
		"requirement": "03.08.05",
		"statement": "SR-03.08.05.a",
		"text": "system media that contain CUI are controlled during transport outside of controlled areas.",
	},
	"DS-A.03.08.05.b": {
		"requirement": "03.08.05",
		"statement": "SR-03.08.05.b",
		"text": "accountability for system media that contain CUI is maintained during transport outside of controlled areas.",
	},
	"DS-A.03.08.05.c": {
		"requirement": "03.08.05",
		"statement": "SR-03.08.05.c",
		"text": "activities associated with the transport of system media that contain CUI are documented.",
	},
	"DS-A.03.08.07.a": {
		"requirement": "03.08.07",
		"statement": "SR-03.08.07.a",
		"text": "the use of the following types of system media is restricted or prohibited: <A.03.08.07.ODP[01]: types of system media>.",
	},
	"DS-A.03.08.07.b": {
		"requirement": "03.08.07",
		"statement": "SR-03.08.07.b",
		"text": "the use of removable system media without an identifiable owner is prohibited.",
	},
	"DS-A.03.08.09.a": {
		"requirement": "03.08.09",
		"statement": "SR-03.08.09.a",
		"text": "the confidentiality of backup information is protected.",
	},
	"DS-A.03.08.09.b": {
		"requirement": "03.08.09",
		"statement": "SR-03.08.09.b",
		"text": "cryptographic mechanisms are implemented to prevent the unauthorized disclosure of CUI at backup storage locations.",
	},
	"DS-A.03.09.01.a": {
		"requirement": "03.09.01",
		"statement": "SR-03.09.01.a",
		"text": "individuals are screened prior to authorizing access to the system.",
	},
	"DS-A.03.09.01.b": {
		"requirement": "03.09.01",
		"statement": "SR-03.09.01.b",
		"text": "individuals are rescreened in accordance with the following conditions: <A.03.09.01.ODP[01]: conditions>.",
	},
	"DS-A.03.09.02.a.01": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.a.01",
		"text": "upon termination of individual employment, system access is disabled within <A.03.09.02.ODP[01]: time period>.",
	},
	"DS-A.03.09.02.a.02[01]": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.a.02",
		"text": "upon termination of individual employment, authenticators associated with the individual are terminated or revoked.",
	},
	"DS-A.03.09.02.a.02[02]": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.a.02",
		"text": "upon termination of individual employment, credentials associated with the individual are terminated or revoked.",
	},
	"DS-A.03.09.02.a.03": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.a.03",
		"text": "upon termination of individual employment, security-related system property is retrieved.",
	},
	"DS-A.03.09.02.b.01[01]": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.b.01",
		"text": "upon individual reassignment or transfer to other positions in the organization, the ongoing operational need for current logical and physical access authorizations to the system and facility is reviewed.",
	},
	"DS-A.03.09.02.b.01[02]": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.b.01",
		"text": "upon individual reassignment or transfer to other positions in the organization, the ongoing operational need for current logical and physical access authorizations to the system and facility is confirmed.",
	},
	"DS-A.03.09.02.b.02": {
		"requirement": "03.09.02",
		"statement": "SR-03.09.02.b.02",
		"text": "upon individual reassignment or transfer to other positions in the organization, access authorization is modified to correspond with any changes in operational need.",
	},
	"DS-A.03.10.01.a[01]": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.a",
		"text": "a list of individuals with authorized access to the facility where the system resides is developed.",
	},
	"DS-A.03.10.01.a[02]": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.a",
		"text": "a list of individuals with authorized access to the facility where the system resides is approved.",
	},
	"DS-A.03.10.01.a[03]": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.a",
		"text": "a list of individuals with authorized access to the facility where the system resides is maintained.",
	},
	"DS-A.03.10.01.b": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.b",
		"text": "authorization credentials for facility access are issued.",
	},
	"DS-A.03.10.01.c": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.c",
		"text": "the facility access list is reviewed <A.03.10.01.ODP[01]: frequency>.",
	},
	"DS-A.03.10.01.d": {
		"requirement": "03.10.01",
		"statement": "SR-03.10.01.d",
		"text": "individuals from the facility access list are removed when access is no longer required.",
	},
	"DS-A.03.10.02.a[01]": {
		"requirement": "03.10.02",
		"statement": "SR-03.10.02.a",
		"text": "physical access to the facility where the system resides is monitored to detect physical security incidents.",
	},
	"DS-A.03.10.02.a[02]": {
		"requirement": "03.10.02",
		"statement": "SR-03.10.02.a",
		"text": "physical security incidents are responded to.",
	},
	"DS-A.03.10.02.b[01]": {
		"requirement": "03.10.02",
		"statement": "SR-03.10.02.b",
		"text": "physical access logs are reviewed <A.03.10.02.ODP[01]: frequency>.",
	},
	"DS-A.03.10.02.b[02]": {
		"requirement": "03.10.02",
		"statement": "SR-03.10.02.b",
		"text": "physical access logs are reviewed upon occurrence of <A.03.10.02.ODP[02]: events or potential indicators of events>.",
	},
	"DS-A.03.10.06.a": {
		"requirement": "03.10.06",
		"statement": "SR-03.10.06.a",
		"text": "alternate work sites allowed for use by employees are determined.",
	},
	"DS-A.03.10.06.b": {
		"requirement": "03.10.06",
		"statement": "SR-03.10.06.b",
		"text": "the following security requirements are employed at alternate work sites: <A.03.10.06.ODP[01]: security requirements>.",
	},
	"DS-A.03.10.07.a.01": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.a.01",
		"text": "physical access authorizations are enforced at entry and exit points to the facility where the system resides by verifying individual physical access authorizations before granting access.",
	},
	"DS-A.03.10.07.a.02": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.a.02",
		"text": "physical access authorizations are enforced at entry and exit points to the facility where the system resides by controlling ingress and egress with physical access control systems, devices, or guards.",
	},
	"DS-A.03.10.07.b": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.b",
		"text": "physical access audit logs for entry or exit points are maintained.",
	},
	"DS-A.03.10.07.c[01]": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.c",
		"text": "visitors are escorted.",
	},
	"DS-A.03.10.07.c[02]": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.c",
		"text": "visitor activity is controlled.",
	},
	"DS-A.03.10.07.d": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.d",
		"text": "keys, combinations, and other physical access devices are secured.",
	},
	"DS-A.03.10.07.e": {
		"requirement": "03.10.07",
		"statement": "SR-03.10.07.e",
		"text": "physical access to output devices is controlled to prevent unauthorized individuals from obtaining access to CUI.",
	},
	"DS-A.03.10.08": {
		"requirement": "03.10.08",
		"statement": "SR-03.10.08",
		"text": "physical access to system distribution and transmission lines within organizational facilities is controlled.",
	},
	"DS-A.03.11.01.a": {
		"requirement": "03.11.01",
		"statement": "SR-03.11.01.a",
		"text": "the risk (including supply chain risk) of unauthorized disclosure resulting from the processing, storage, or transmission of CUI is assessed.",
	},
	"DS-A.03.11.01.b": {
		"requirement": "03.11.01",
		"statement": "SR-03.11.01.b",
		"text": "risk assessments are updated <A.03.11.01.ODP[01]: frequency>.",
	},
	"DS-A.03.11.02.a[01]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.a",
		"text": "the system is monitored for vulnerabilities <A.03.11.02.ODP[01]: frequency>.",
	},
	"DS-A.03.11.02.a[02]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.a",
		"text": "the system is scanned for vulnerabilities <A.03.11.02.ODP[02]: frequency>.",
	},
	"DS-A.03.11.02.a[03]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.a",
		"text": "the system is monitored for vulnerabilities when new vulnerabilities that affect the system are identified.",
	},
	"DS-A.03.11.02.a[04]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.a",
		"text": "the system is scanned for vulnerabilities when new vulnerabilities that affect the system are identified.",
	},
	"DS-A.03.11.02.b": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.b",
		"text": "system vulnerabilities are remediated within <A.03.11.02.ODP[03]: response times>.",
	},
	"DS-A.03.11.02.c[01]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.c",
		"text": "system vulnerabilities to be scanned are updated <A.03.11.02.ODP[04]: frequency>.",
	},
	"DS-A.03.11.02.c[02]": {
		"requirement": "03.11.02",
		"statement": "SR-03.11.02.c",
		"text": "system vulnerabilities to be scanned are updated when new vulnerabilities are identified and reported.",
	},
	"DS-A.03.11.04[01]": {
		"requirement": "03.11.04",
		"statement": "SR-03.11.04",
		"text": "findings from security assessments are responded to.",
	},
	"DS-A.03.11.04[02]": {
		"requirement": "03.11.04",
		"statement": "SR-03.11.04",
		"text": "findings from security monitoring are responded to.",
	},
	"DS-A.03.11.04[03]": {
		"requirement": "03.11.04",
		"statement": "SR-03.11.04",
		"text": "findings from security audits are responded to.",
	},
	"DS-A.03.12.01": {
		"requirement": "03.12.01",
		"statement": "SR-03.12.01",
		"text": "the security requirements for the system and its environment of operation are assessed <A.03.12.01.ODP[01]: frequency> to determine if the requirements have been satisfied.",
	},
	"DS-A.03.12.02.a.01": {
		"requirement": "03.12.02",
		"statement": "SR-03.12.02.a.01",
		"text": "a plan of action and milestones for the system is developed to document the planned remediation actions for correcting weaknesses or deficiencies noted during security assessments.",
	},
	"DS-A.03.12.02.a.02": {
		"requirement": "03.12.02",
		"statement": "SR-03.12.02.a.02",
		"text": "a plan of action and milestones for the system is developed to reduce or eliminate known system vulnerabilities.",
	},
	"DS-A.03.12.02.b.01": {
		"requirement": "03.12.02",
		"statement": "SR-03.12.02.b.01",
		"text": "the existing plan of action and milestones is updated based on the findings from security assessments.",
	},
	"DS-A.03.12.02.b.02": {
		"requirement": "03.12.02",
		"statement": "SR-03.12.02.b.02",
		"text": "the existing plan of action and milestones is updated based on the findings from audits or reviews.",
	},
	"DS-A.03.12.02.b.03": {
		"requirement": "03.12.02",
		"statement": "SR-03.12.02.b.03",
		"text": "the existing plan of action and milestones is updated based on the findings from continuous monitoring activities.",
	},
	"DS-A.03.12.03[01]": {
		"requirement": "03.12.03",
		"statement": "SR-03.12.03",
		"text": "a system-level continuous monitoring strategy is developed.",
	},
	"DS-A.03.12.03[02]": {
		"requirement": "03.12.03",
		"statement": "SR-03.12.03",
		"text": "a system-level continuous monitoring strategy is implemented.",
	},
	"DS-A.03.12.03[03]": {
		"requirement": "03.12.03",
		"statement": "SR-03.12.03",
		"text": "ongoing monitoring is included in the continuous monitoring strategy.",
	},
	"DS-A.03.12.03[04]": {
		"requirement": "03.12.03",
		"statement": "SR-03.12.03",
		"text": "security assessments are included in the continuous monitoring strategy.",
	},
	"DS-A.03.12.05.a[01]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.a",
		"text": "the exchange of CUI between the system and other systems is approved using <A.03.12.05.ODP[01]: SELECTED PARAMETER VALUES>.",
	},
	"DS-A.03.12.05.a[02]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.a",
		"text": "the exchange of CUI between the system and other systems is managed using <A.03.12.05.ODP[01]: SELECTED PARAMETER VALUES>.",
	},
	"DS-A.03.12.05.b[01]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.b",
		"text": "interface characteristics for each system are documented as part of the exchange agreements.",
	},
	"DS-A.03.12.05.b[02]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.b",
		"text": "security requirements for each system are documented as part of the exchange agreements.",
	},
	"DS-A.03.12.05.b[03]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.b",
		"text": "responsibilities for each system are documented as part of the exchange agreements.",
	},
	"DS-A.03.12.05.c[01]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.c",
		"text": "exchange agreements are reviewed <A.03.12.05.ODP[02]: frequency>.",
	},
	"DS-A.03.12.05.c[02]": {
		"requirement": "03.12.05",
		"statement": "SR-03.12.05.c",
		"text": "exchange agreements are updated <A.03.12.05.ODP[02]: frequency>.",
	},
	"DS-A.03.13.01.a[01]": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.a",
		"text": "communications at external managed interfaces to the system are monitored.",
	},
	"DS-A.03.13.01.a[02]": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.a",
		"text": "communications at external managed interfaces to the system are controlled.",
	},
	"DS-A.03.13.01.a[03]": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.a",
		"text": "communications at key internal managed interfaces within the system are monitored.",
	},
	"DS-A.03.13.01.a[04]": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.a",
		"text": "communications at key internal managed interfaces within the system are controlled.",
	},
	"DS-A.03.13.01.b": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.b",
		"text": "subnetworks are implemented for publicly accessible system components that are physically or logically separated from internal networks.",
	},
	"DS-A.03.13.01.c": {
		"requirement": "03.13.01",
		"statement": "SR-03.13.01.c",
		"text": "external system connections are only made through managed interfaces that consist of boundary protection devices arranged in accordance with an organizational security architecture.",
	},
	"DS-A.03.13.04[01]": {
		"requirement": "03.13.04",
		"statement": "SR-03.13.04",
		"text": "unauthorized information transfer via shared system resources is prevented.",
	},
	"DS-A.03.13.04[02]": {
		"requirement": "03.13.04",
		"statement": "SR-03.13.04",
		"text": "unintended information transfer via shared system resources is prevented.",
	},
	"DS-A.03.13.06[01]": {
		"requirement": "03.13.06",
		"statement": "SR-03.13.06",
		"text": "network communications traffic is denied by default.",
	},
	"DS-A.03.13.06[02]": {
		"requirement": "03.13.06",
		"statement": "SR-03.13.06",
		"text": "network communications traffic is allowed by exception.",
	},
	"DS-A.03.13.08[01]": {
		"requirement": "03.13.08",
		"statement": "SR-03.13.08",
		"text": "cryptographic mechanisms are implemented to prevent the unauthorized disclosure of CUI during transmission.",
	},
	"DS-A.03.13.08[02]": {
		"requirement": "03.13.08",
		"statement": "SR-03.13.08",
		"text": "cryptographic mechanisms are implemented to prevent the unauthorized disclosure of CUI while in storage.",
	},
	"DS-A.03.13.09": {
		"requirement": "03.13.09",
		"statement": "SR-03.13.09",
		"text": "the network connection associated with a communications session is terminated at the end of the session or after <A.03.13.09.ODP[01]: time period> of inactivity.",
	},
	"DS-A.03.13.10[01]": {
		"requirement": "03.13.10",
		"statement": "SR-03.13.10",
		"text": "cryptographic keys are established in the system in accordance with the following key management requirements: <A.03.13.10.ODP[01]: requirements>.",
	},
	"DS-A.03.13.10[02]": {
		"requirement": "03.13.10",
		"statement": "SR-03.13.10",
		"text": "cryptographic keys are managed in the system in accordance with the following key management requirements: <A.03.13.10.ODP[01]: requirements>.",
	},
	"DS-A.03.13.11": {
		"requirement": "03.13.11",
		"statement": "SR-03.13.11",
		"text": "the following types of cryptography are implemented to protect the confidentiality of CUI: <A.03.13.11.ODP[01]: types of cryptography>.",
	},
	"DS-A.03.13.12.a": {
		"requirement": "03.13.12",
		"statement": "SR-03.13.12.a",
		"text": "the remote activation of collaborative computing devices and applications is prohibited with the following exceptions: <A.03.13.12.ODP[01]: exceptions>.",
	},
	"DS-A.03.13.12.b": {
		"requirement": "03.13.12",
		"statement": "SR-03.13.12.b",
		"text": "an explicit indication of use is provided to users who are physically present at the devices.",
	},
	"DS-A.03.13.13.a[01]": {
		"requirement": "03.13.13",
		"statement": "SR-03.13.13.a",
		"text": "acceptable mobile code is defined.",
	},
	"DS-A.03.13.13.a[02]": {
		"requirement": "03.13.13",
		"statement": "SR-03.13.13.a",
		"text": "acceptable mobile code technologies are defined.",
	},
	"DS-A.03.13.13.b[01]": {
		"requirement": "03.13.13",
		"statement": "SR-03.13.13.b",
		"text": "the use of mobile code is authorized.",
	},
	"DS-A.03.13.13.b[02]": {
		"requirement": "03.13.13",
		"statement": "SR-03.13.13.b",
		"text": "the use of mobile code is monitored.",
	},
	"DS-A.03.13.13.b[03]": {
		"requirement": "03.13.13",
		"statement": "SR-03.13.13.b",
		"text": "the use of mobile code is controlled.",
	},
	"DS-A.03.13.15": {
		"requirement": "03.13.15",
		"statement": "SR-03.13.15",
		"text": "the authenticity of communications sessions is protected.",
	},
	"DS-A.03.14.01.a[01]": {
		"requirement": "03.14.01",
		"statement": "SR-03.14.01.a",
		"text": "system flaws are identified.",
	},
	"DS-A.03.14.01.a[02]": {
		"requirement": "03.14.01",
		"statement": "SR-03.14.01.a",
		"text": "system flaws are reported.",
	},
	"DS-A.03.14.01.a[03]": {
		"requirement": "03.14.01",
		"statement": "SR-03.14.01.a",
		"text": "system flaws are corrected.",
	},
	"DS-A.03.14.01.b[01]": {
		"requirement": "03.14.01",
		"statement": "SR-03.14.01.b",
		"text": "security-relevant software updates are installed within <A.03.14.01.ODP[01]: time period> of the release of the updates.",
	},
	"DS-A.03.14.01.b[02]": {
		"requirement": "03.14.01",
		"statement": "SR-03.14.01.b",
		"text": "security-relevant firmware updates are installed within <A.03.14.01.ODP[02]: time period> of the release of the updates.",
	},
	"DS-A.03.14.02.a[01]": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.a",
		"text": "malicious code protection mechanisms are implemented at system entry and exit points to detect malicious code.",
	},
	"DS-A.03.14.02.a[02]": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.a",
		"text": "malicious code protection mechanisms are implemented at system entry and exit points to eradicate malicious code.",
	},
	"DS-A.03.14.02.b": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.b",
		"text": "malicious code protection mechanisms are updated as new releases are available in accordance with configuration management policy and procedures.",
	},
	"DS-A.03.14.02.c.01[01]": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.c.01",
		"text": "malicious code protection mechanisms are configured to perform scans of the system <A.03.14.02.ODP[01]: frequency>.",
	},
	"DS-A.03.14.02.c.01[02]": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.c.01",
		"text": "malicious code protection mechanisms are configured to perform real-time scans of files from external sources at endpoints or system entry and exit points as the files are downloaded, opened, or executed.",
	},
	"DS-A.03.14.02.c.02": {
		"requirement": "03.14.02",
		"statement": "SR-03.14.02.c.02",
		"text": "malicious code protection mechanisms are configured to block malicious code, quarantine malicious code, or take other actions in response to malicious code detection.",
	},
	"DS-A.03.14.03.a": {
		"requirement": "03.14.03",
		"statement": "SR-03.14.03.a",
		"text": "system security alerts, advisories, and directives from external organizations are received on an ongoing basis.",
	},
	"DS-A.03.14.03.b[01]": {
		"requirement": "03.14.03",
		"statement": "SR-03.14.03.b",
		"text": "internal security alerts, advisories, and directives are generated, as necessary.",
	},
	"DS-A.03.14.03.b[02]": {
		"requirement": "03.14.03",
		"statement": "SR-03.14.03.b",
		"text": "internal security alerts, advisories, and directives are disseminated, as necessary.",
	},
	"DS-A.03.14.06.a.01[01]": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.a.01",
		"text": "the system is monitored to detect attacks.",
	},
	"DS-A.03.14.06.a.01[02]": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.a.01",
		"text": "the system is monitored to detect indicators of potential attacks.",
	},
	"DS-A.03.14.06.a.02": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.a.02",
		"text": "the system is monitored to detect unauthorized connections.",
	},
	"DS-A.03.14.06.b": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.b",
		"text": "unauthorized use of the system is identified.",
	},
	"DS-A.03.14.06.c[01]": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.c",
		"text": "inbound communications traffic is monitored to detect unusual or unauthorized activities or conditions.",
	},
	"DS-A.03.14.06.c[02]": {
		"requirement": "03.14.06",
		"statement": "SR-03.14.06.c",
		"text": "outbound communications traffic is monitored to detect unusual or unauthorized activities or conditions.",
	},
	"DS-A.03.14.08[01]": {
		"requirement": "03.14.08",
		"statement": "SR-03.14.08",
		"text": "CUI within the system is managed in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements.",
	},
	"DS-A.03.14.08[02]": {
		"requirement": "03.14.08",
		"statement": "SR-03.14.08",
		"text": "CUI within the system is retained in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements.",
	},
	"DS-A.03.14.08[03]": {
		"requirement": "03.14.08",
		"statement": "SR-03.14.08",
		"text": "CUI output from the system is managed in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements.",
	},
	"DS-A.03.14.08[04]": {
		"requirement": "03.14.08",
		"statement": "SR-03.14.08",
		"text": "CUI output from the system is retained in accordance with applicable laws, Executive Orders, directives, regulations, policies, standards, guidelines, and operational requirements.",
	},
	"DS-A.03.15.01.a[01]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.a",
		"text": "policies needed to satisfy the security requirements for the protection of CUI are developed and documented.",
	},
	"DS-A.03.15.01.a[02]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.a",
		"text": "policies needed to satisfy the security requirements for the protection of CUI are disseminated to organizational personnel or roles.",
	},
	"DS-A.03.15.01.a[03]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.a",
		"text": "procedures needed to satisfy the security requirements for the protection of CUI are developed and documented.",
	},
	"DS-A.03.15.01.a[04]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.a",
		"text": "procedures needed to satisfy the security requirements for the protection of CUI are disseminated to organizational personnel or roles.",
	},
	"DS-A.03.15.01.b[01]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.b",
		"text": "policies and procedures are reviewed <A.03.15.01.ODP[01]: frequency>.",
	},
	"DS-A.03.15.01.b[02]": {
		"requirement": "03.15.01",
		"statement": "SR-03.15.01.b",
		"text": "policies and procedures are updated <A.03.15.01.ODP[01]: frequency>.",
	},
	"DS-A.03.15.02.a.01": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.01",
		"text": "a system security plan that defines the constituent system components is developed.",
	},
	"DS-A.03.15.02.a.02": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.02",
		"text": "a system security plan that identifies the information types processed, stored, and transmitted by the system is developed.",
	},
	"DS-A.03.15.02.a.03": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.03",
		"text": "a system security plan that describes specific threats to the system that are of concern to the organization is developed.",
	},
	"DS-A.03.15.02.a.04": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.04",
		"text": "a system security plan that describes the operational environment for the system and any dependencies on or connections to other systems or system components is developed.",
	},
	"DS-A.03.15.02.a.05": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.05",
		"text": "a system security plan that provides an overview of the security requirements for the system is developed.",
	},
	"DS-A.03.15.02.a.06": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.06",
		"text": "a system security plan that describes the safeguards in place or planned for meeting the security requirements is developed.",
	},
	"DS-A.03.15.02.a.07": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.07",
		"text": "a system security plan that identifies individuals that fulfill system roles and responsibilities is developed.",
	},
	"DS-A.03.15.02.a.08": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.a.08",
		"text": "a system security plan that includes other relevant information necessary for the protection of CUI is developed.",
	},
	"DS-A.03.15.02.b[01]": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.b",
		"text": "the system security plan is reviewed <A.03.15.02.ODP[01]: frequency>.",
	},
	"DS-A.03.15.02.b[02]": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.b",
		"text": "the system security plan is updated <A.03.15.02.ODP[01]: frequency>.",
	},
	"DS-A.03.15.02.c": {
		"requirement": "03.15.02",
		"statement": "SR-03.15.02.c",
		"text": "the system security plan is protected from unauthorized disclosure.",
	},
	"DS-A.03.15.03.a": {
		"requirement": "03.15.03",
		"statement": "SR-03.15.03.a",
		"text": "rules that describe responsibilities and expected behavior for system usage and protecting CUI are established.",
	},
	"DS-A.03.15.03.b": {
		"requirement": "03.15.03",
		"statement": "SR-03.15.03.b",
		"text": "rules are provided to individuals who require access to the system.",
	},
	"DS-A.03.15.03.c": {
		"requirement": "03.15.03",
		"statement": "SR-03.15.03.c",
		"text": "a documented acknowledgement from individuals indicating that they have read, understand, and agree to abide by the rules of behavior is received before authorizing access to CUI and the system.",
	},
	"DS-A.03.15.03.d[01]": {
		"requirement": "03.15.03",
		"statement": "SR-03.15.03.d",
		"text": "the rules of behavior are reviewed <A.03.15.03.ODP[01]: frequency>.",
	},
	"DS-A.03.15.03.d[02]": {
		"requirement": "03.15.03",
		"statement": "SR-03.15.03.d",
		"text": "the rules of behavior are updated <A.03.15.03.ODP[01]: frequency>.",
	},
	"DS-A.03.16.01": {
		"requirement": "03.16.01",
		"statement": "SR-03.16.01",
		"text": "<A.03.16.01.ODP[01]: systems security engineering principles> are applied to the development or modification of the system and system components.",
	},
	"DS-A.03.16.02.a": {
		"requirement": "03.16.02",
		"statement": "SR-03.16.02.a",
		"text": "system components are replaced when support for the components is no longer available from the developer, vendor, or manufacturer.",
	},
	"DS-A.03.16.02.b": {
		"requirement": "03.16.02",
		"statement": "SR-03.16.02.b",
		"text": "options for risk mitigation or alternative sources for continued support for unsupported components that cannot be replaced are provided.",
	},
	"DS-A.03.16.03.a": {
		"requirement": "03.16.03",
		"statement": "SR-03.16.03.a",
		"text": "the providers of external system services used for the processing, storage, or transmission of CUI comply with the following security requirements: <A.03.16.03.ODP[01]: security requirements>.",
	},
	"DS-A.03.16.03.b": {
		"requirement": "03.16.03",
		"statement": "SR-03.16.03.b",
		"text": "user roles and responsibilities with regard to external system services, including shared responsibilities with external service providers, are defined and documented.",
	},
	"DS-A.03.16.03.c": {
		"requirement": "03.16.03",
		"statement": "SR-03.16.03.c",
		"text": "processes, methods, and techniques to monitor security requirement compliance by external service providers on an ongoing basis are implemented.",
	},
	"DS-A.03.17.01.a[01]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "a plan for managing supply chain risks is developed.",
	},
	"DS-A.03.17.01.a[02]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the research and development of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[03]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the design of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[04]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the manufacturing of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[05]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the acquisition of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[06]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the delivery of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[07]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the integration of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[08]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the operation of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[09]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the maintenance of the system, system components, or system services.",
	},
	"DS-A.03.17.01.a[10]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.a",
		"text": "the SCRM plan addresses risks associated with the disposal of the system, system components, or system services.",
	},
	"DS-A.03.17.01.b[01]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.b",
		"text": "the SCRM plan is reviewed <A.03.17.01.ODP[01]: frequency>.",
	},
	"DS-A.03.17.01.b[02]": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.b",
		"text": "the SCRM plan is updated <A.03.17.01.ODP[01]: frequency>.",
	},
	"DS-A.03.17.01.c": {
		"requirement": "03.17.01",
		"statement": "SR-03.17.01.c",
		"text": "the SCRM plan is protected from unauthorized disclosure.",
	},
	"DS-A.03.17.02[01]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are developed to identify supply chain risks.",
	},
	"DS-A.03.17.02[02]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are developed to protect against supply chain risks.",
	},
	"DS-A.03.17.02[03]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are developed to mitigate supply chain risks.",
	},
	"DS-A.03.17.02[04]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are implemented to identify supply chain risks.",
	},
	"DS-A.03.17.02[05]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are implemented to protect against supply chain risks.",
	},
	"DS-A.03.17.02[06]": {
		"requirement": "03.17.02",
		"statement": "SR-03.17.02",
		"text": "acquisition strategies, contract tools, and procurement methods are implemented to mitigate supply chain risks.",
	},
	"DS-A.03.17.03.a[01]": {
		"requirement": "03.17.03",
		"statement": "SR-03.17.03.a",
		"text": "a process for identifying weaknesses or deficiencies in the supply chain elements and processes is established.",
	},
	"DS-A.03.17.03.a[02]": {
		"requirement": "03.17.03",
		"statement": "SR-03.17.03.a",
		"text": "a process for addressing weaknesses or deficiencies in the supply chain elements and processes is established.",
	},
	"DS-A.03.17.03.b": {
		"requirement": "03.17.03",
		"statement": "SR-03.17.03.b",
		"text": "the following security requirements are enforced to protect against supply chain risks to the system, system components, or system services and to limit the harm or consequences of supply chain-related events: <A.03.17.03.ODP[01]: security requirements>.",
	},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_sp_800_171a", {})

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

violations contains "NIST SP 800-171A Rev 3: FAIL-CLOSED - determinations 'input.nist_sp_800_171a.determinations' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, d in determinations
	not _true(id)
	r := requirements[d.requirement]
	msg := sprintf("NIST SP 800-171A %v (%v %v): not determined satisfied — %v", [id, d.requirement, r.title, d.text])
}

violations contains msg if {
	some id, _ in _given
	not determinations[id]
	msg := sprintf("NIST SP 800-171A Input Contract: unknown determination id %v — ids are CPRT element identifiers such as DS-A.03.01.01.a[01]", [id])
}

# a requirement with no determinations can never be satisfied (no vacuous pass)
_req_satisfied(r) if {
	ids := _by_requirement[r]
	count(ids) > 0
	every id in ids { _true(id) }
}

requirement_rollup[r] := s if {
	some r, q in requirements
	ids := _by_requirement[r]
	unsat := sort([id | some id in ids; not _true(id)])
	s := {
		"family": q.family,
		"title": q.title,
		"determinations_total": count(ids),
		"determinations_satisfied": count(ids) - count(unsat),
		"satisfied": _req_satisfied_bool(r),
		"not_satisfied": unsat,
		"methods": q.methods,
	}
}

_req_satisfied_bool(r) if _req_satisfied(r)

else := false

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
	"framework": "NIST SP 800-171A Rev 3",
	"standard": "NIST SP 800-171A Rev 3 — Assessing Security Requirements for Controlled Unclassified Information",
	"source": source,
	"compliant": compliant,
	"total_controls": count(determinations),
	"standard_total": 422, # determination statements in the CPRT SP 800-171 Rev 3 export
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
