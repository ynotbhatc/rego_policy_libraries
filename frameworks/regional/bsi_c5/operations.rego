# METADATA
# title: "BSI C5:2026 — Operations (OPS), 35 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 36
#     cited: 35
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.operations

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.6 Operations (OPS), p. 92.
# 35 criteria, ids exactly as printed in the catalogue; 89 basic, 9 additional (sharpening) and 28
# additional (complementing) subcriteria; 18 of the 35 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["OPS-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "OPS", "section": "5.6", "name": "Operations", "page": 92}

criteria := {
	"OPS-01": {
		"title": "Capacity Management - Planning",
		"summary": "Plan capacity and resources through an established procedure with forecasting so that agreed service levels are maintained",
		"page": 92,
		"basic": ["OPS-01.01B", "OPS-01.02B", "OPS-01.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-02": {
		"title": "Capacity Management - Monitoring",
		"summary": "Monitor provisioning and capacity against contractual agreements and report capacity restrictions that breach obligations to customers",
		"page": 93,
		"basic": ["OPS-02.01B", "OPS-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-02.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-03": {
		"title": "Capacity Management - Controlling of Resources",
		"summary": "Let customers control and monitor the allocation of their assigned resources, and inform them of significant security changes",
		"page": 94,
		"basic": ["OPS-03.01B", "OPS-03.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-04": {
		"title": "Protection Against Malware - Policies and Procedures",
		"summary": "Document policies and procedures for protection against malware on provider systems and personnel endpoints",
		"page": 95,
		"basic": ["OPS-04.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-05": {
		"title": "Protection Against Malware - Implementation",
		"summary": "Configure malware protection on production system components per policy and keep detection definitions up to date",
		"page": 96,
		"basic": ["OPS-05.01B", "OPS-05.02B", "OPS-05.03B"],
		"additional_sharpening": ["OPS-05.02AS"],
		"additional_complementing": ["OPS-05.01AC", "OPS-05.02AC", "OPS-05.03AC"],
		"sharpens": [["OPS-05.02AS", "OPS-05.02B"]],
		"has_additional": true,
	},
	"OPS-06": {
		"title": "Data Backup and Recovery - Policies and Procedures",
		"summary": "Document policies for backup or replication and restore of data according to its sensitivity and the contractual agreements",
		"page": 97,
		"basic": ["OPS-06.01B"],
		"additional_sharpening": ["OPS-06.01AS"],
		"additional_complementing": [],
		"sharpens": [["OPS-06.01AS", "OPS-06.01B"]],
		"has_additional": true,
	},
	"OPS-07": {
		"title": "Data Backup and Recovery - Monitoring",
		"summary": "Monitor backup execution and have qualified personnel investigate and rectify backup incidents in time",
		"page": 99,
		"basic": ["OPS-07.01B", "OPS-07.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-07.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-08": {
		"title": "Data Backup and Recovery - Regular Testing",
		"summary": "Test restore procedures at least annually against the agreed RTO and RPO and document the results",
		"page": 99,
		"basic": ["OPS-08.01B", "OPS-08.02B", "OPS-08.03B", "OPS-08.04B", "OPS-08.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-08.01AC", "OPS-08.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-09": {
		"title": "Data Backup and Recovery - Storage",
		"summary": "Transfer backups to a remote location and apply the original data's protection needs (e.g. encryption, access control) to them",
		"page": 101,
		"basic": ["OPS-09.01B", "OPS-09.02B", "OPS-09.03B", "OPS-09.04B", "OPS-09.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-10": {
		"title": "Logging and Monitoring - Policies and Procedures",
		"summary": "Document policies for logging and monitoring security-relevant events on system components in the provider's responsibility",
		"page": 102,
		"basic": ["OPS-10.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-11": {
		"title": "Logging and Monitoring - Policies and Procedures for Handling Cloud Service Derived Data and Account Data",
		"summary": "Document policies restricting collection and use of cloud service derived data and account data to administering and operating the service",
		"page": 102,
		"basic": ["OPS-11.01B", "OPS-11.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-11.01AC", "OPS-11.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-12": {
		"title": "Logging and Monitoring - Access, Retention and Deletion",
		"summary": "Enforce technically the access restriction, retention period and deletion of logging and monitoring data",
		"page": 104,
		"basic": ["OPS-12.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-13": {
		"title": "Logging and Monitoring - Security Information and Event Management",
		"summary": "Integrate relevant log data into a SIEM with normalisation, automated correlation and alerting linked to incident management",
		"page": 104,
		"basic": ["OPS-13.01B", "OPS-13.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-13.01AC", "OPS-13.02AC", "OPS-13.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-14": {
		"title": "Logging and Monitoring - Retention of the Logging Data",
		"summary": "Retain log data centrally in unchangeable, aggregated form, delete it when no longer needed, and authenticate log transfers",
		"page": 105,
		"basic": ["OPS-14.01B", "OPS-14.02B", "OPS-14.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-15": {
		"title": "Logging and Monitoring - Accountability",
		"summary": "Generate log data that attributes user access unambiguously at tenant level with timestamps, supporting forensic analysis",
		"page": 106,
		"basic": ["OPS-15.01B", "OPS-15.02B", "OPS-15.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-15.01AC", "OPS-15.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-16": {
		"title": "Logging and Monitoring - Configuration",
		"summary": "Restrict access to logging and monitoring components to authorised users authenticating with two or more factors, and control configuration changes",
		"page": 107,
		"basic": ["OPS-16.01B", "OPS-16.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-17": {
		"title": "Logging and Monitoring - Availability of the Monitoring Software",
		"summary": "Monitor the availability of logging and monitoring components and report failures automatically to responsible staff",
		"page": 107,
		"basic": ["OPS-17.01B", "OPS-17.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-17.01AC", "OPS-17.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-18": {
		"title": "Managing Vulnerabilities - Policies and Procedures",
		"summary": "Document policies for timely identification, assessment and remediation of vulnerabilities in the service's system components",
		"page": 108,
		"basic": ["OPS-18.01B", "OPS-18.02B", "OPS-18.03B", "OPS-18.04B", "OPS-18.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-19": {
		"title": "Managing Incidents and Crashes - Policies and Procedures",
		"summary": "Document policies for classifying, prioritising and managing incidents and crashes of the service or its components",
		"page": 110,
		"basic": ["OPS-19.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-20": {
		"title": "Managing Incidents - Implementation",
		"summary": "Identify, record, classify, prioritise and address incidents according to the incident and crash management policy",
		"page": 111,
		"basic": ["OPS-20.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-21": {
		"title": "Managing Crashes - Implementation",
		"summary": "Identify, record and address crashes of system components or the service according to the incident and crash management policy",
		"page": 112,
		"basic": ["OPS-21.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-22": {
		"title": "Managing Vulnerabilities, Incidents and Crashes - Penetration Tests",
		"summary": "Have qualified testers perform penetration tests at least annually and on significant change, following a documented framework, and remediate findings",
		"page": 112,
		"basic": ["OPS-22.01B", "OPS-22.02B", "OPS-22.03B", "OPS-22.04B", "OPS-22.05B", "OPS-22.06B", "OPS-22.07B", "OPS-22.08B"],
		"additional_sharpening": ["OPS-22.01AS", "OPS-22.02AS", "OPS-22.03AS"],
		"additional_complementing": ["OPS-22.01AC", "OPS-22.02AC", "OPS-22.03AC", "OPS-22.04AC", "OPS-22.05AC"],
		"sharpens": [["OPS-22.01AS", "OPS-22.01B"], ["OPS-22.02AS", "OPS-22.02B"], ["OPS-22.03AS", "OPS-22.03B"]],
		"has_additional": true,
	},
	"OPS-23": {
		"title": "Managing Vulnerabilities, Incidents and Crashes - Measurements, Analyses and Assessments of Procedures",
		"summary": "Measure, analyse and assess vulnerability and incident handling procedures regularly, evaluating the results at least quarterly",
		"page": 115,
		"basic": ["OPS-23.01B", "OPS-23.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-24": {
		"title": "Involvement of Cloud Service Customers in the Event of Incidents",
		"summary": "Keep affected customers informed on the status of incidents, involve them where appropriate, and report actions taken on resolution",
		"page": 116,
		"basic": ["OPS-24.01B", "OPS-24.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-24.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-25": {
		"title": "Managing Vulnerabilities, Incidents and Crashes - Vulnerability Scans",
		"summary": "Run vulnerability scans of system components at least monthly against current vulnerability databases and handle the findings",
		"page": 117,
		"basic": ["OPS-25.01B", "OPS-25.02B", "OPS-25.03B", "OPS-25.04B"],
		"additional_sharpening": ["OPS-25.01AS", "OPS-25.02AS"],
		"additional_complementing": ["OPS-25.01AC"],
		"sharpens": [["OPS-25.01AS", "OPS-25.01B"], ["OPS-25.02AS", "OPS-25.02B"]],
		"has_additional": true,
	},
	"OPS-26": {
		"title": "Managing Vulnerabilities, Incidents and Crashes - System Hardening",
		"summary": "Harden production system components to accepted industry standards with documented requirements, including checks of immutable images",
		"page": 118,
		"basic": ["OPS-26.01B", "OPS-26.02B", "OPS-26.03B", "OPS-26.04B", "OPS-26.05B", "OPS-26.06B"],
		"additional_sharpening": ["OPS-26.05AS"],
		"additional_complementing": [],
		"sharpens": [["OPS-26.05AS", "OPS-26.05B"]],
		"has_additional": true,
	},
	"OPS-27": {
		"title": "Managing Vulnerabilities - Patch Management Policies and Procedures",
		"summary": "Document patch management policies ensuring components are patched in a suitable time frame given vulnerabilities and exploits",
		"page": 119,
		"basic": ["OPS-27.01B", "OPS-27.02B", "OPS-27.03B", "OPS-27.04B"],
		"additional_sharpening": ["OPS-27.03AS"],
		"additional_complementing": [],
		"sharpens": [["OPS-27.03AS", "OPS-27.03B"]],
		"has_additional": true,
	},
	"OPS-28": {
		"title": "Managing Vulnerabilities - Patch Management Implementation",
		"summary": "Implement and maintain the measures to deploy patches according to the patch management policy",
		"page": 120,
		"basic": ["OPS-28.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-29": {
		"title": "Managing Vulnerabilities, Incidents and Crashes - Externally Sourced Components",
		"summary": "Manage updates and known vulnerabilities of third-party and open-source libraries used in the service's components",
		"page": 121,
		"basic": ["OPS-29.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-30": {
		"title": "Separation of Datasets - Policies and Procedures",
		"summary": "Document risk-based policies ensuring separation of customer data between customers and from the provider",
		"page": 122,
		"basic": ["OPS-30.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-31": {
		"title": "Separation of Datasets - Implementation",
		"summary": "Implement measures to prevent, detect and react to breaches of data-set separation on shared virtual and physical resources",
		"page": 123,
		"basic": ["OPS-31.01B", "OPS-31.02B", "OPS-31.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OPS-32": {
		"title": "Confidential Computing - Policies and Procedures",
		"summary": "Where confidential computing is offered, document its purpose, scope and technical safeguards",
		"page": 124,
		"basic": ["OPS-32.01B", "OPS-32.02B", "OPS-32.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-32.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-33": {
		"title": "Confidential Computing - Remote Attestation",
		"summary": "Where confidential computing is offered, provide remote attestation rooted in trusted hardware/software with a customer verification interface",
		"page": 125,
		"basic": ["OPS-33.01B", "OPS-33.02B", "OPS-33.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-33.01AC", "OPS-33.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-34": {
		"title": "Container Management - Policies and Procedures",
		"summary": "Document policies for container management across the life cycle, from image creation through deployment and runtime",
		"page": 126,
		"basic": ["OPS-34.01B", "OPS-34.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["OPS-34.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OPS-35": {
		"title": "Container Management - Implementation",
		"summary": "Implement and maintain the measures for managing containers along their life cycle according to the container policy",
		"page": 128,
		"basic": ["OPS-35.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
}

_container := c if {
	c := input.bsi_c5.criteria
	is_object(c)
}

_attested(id) if _container[id] == true

default compliant := false

compliant if count(violations) == 0

# Fail closed: an unattested criterion (absent, false, or any non-true value) is a gap.
violations contains msg if {
	some id, c in criteria
	not _attested(id)
	msg := sprintf("BSI C5:2026 %v %v (%v): not attested — input.bsi_c5.criteria[\"%v\"] must be true", [id, c.title, area.name, id])
}

criteria_status[id] := s if {
	some id, c in criteria
	s := {
		"area": area.code,
		"title": c.title,
		"basis": "attestation",
		"has_additional": c.has_additional,
		"satisfied": _satisfied_bool(id),
	}
}

_satisfied_bool(id) if _attested(id)

else := false

compliance_report := {
	"area": area.code,
	"area_name": area.name,
	"section": area.section,
	"criteria_total": count(criteria),
	"criteria_satisfied": count([id | some id; _ = criteria[id]; _attested(id)]),
	"criteria_fact_evaluated": 0,
	"criteria_attested_basis": count(criteria),
	"criteria_with_additional": count([id | some id; c := criteria[id]; c.has_additional]),
	"gaps": sort([id | some id; _ = criteria[id]; not _attested(id)]),
	"criteria": criteria_status,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
