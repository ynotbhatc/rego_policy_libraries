# METADATA
# title: "BSI C5:2026 — Product Safety and Security (PSS), 12 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 13
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.product_security

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.17 Product Safety and Security (PSS), p. 209.
# 12 criteria, ids exactly as printed in the catalogue; 39 basic, 2 additional (sharpening) and 11
# additional (complementing) subcriteria; 8 of the 12 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["PSS-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "PSS", "section": "5.17", "name": "Product Safety and Security", "page": 209}

criteria := {
	"PSS-01": {
		"title": "Guidelines and Recommendations for Cloud Service Customers",
		"summary": "Publish guidelines and recommendations for the secure configuration and use of the service by customers",
		"page": 209,
		"basic": ["PSS-01.01B", "PSS-01.02B", "PSS-01.03B", "PSS-01.04B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-02": {
		"title": "Identification of Vulnerabilities of the Cloud Service",
		"summary": "Check the service for vulnerabilities introduced during software development as part of the development process",
		"page": 210,
		"basic": ["PSS-02.01B", "PSS-02.02B", "PSS-02.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-02.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-03": {
		"title": "Informing Customers about Known Vulnerabilities",
		"summary": "Give customers regularly updated information on known vulnerabilities of the service through a coordinated process",
		"page": 211,
		"basic": ["PSS-03.01B", "PSS-03.02B", "PSS-03.03B", "PSS-03.04B", "PSS-03.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-03.01AC", "PSS-03.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-04": {
		"title": "Error handling and Logging Mechanisms",
		"summary": "Equip the service with error handling and logging mechanisms that give customers security-relevant information",
		"page": 213,
		"basic": ["PSS-04.01B", "PSS-04.02B", "PSS-04.03B", "PSS-04.04B", "PSS-04.05B", "PSS-04.06B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-04.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-05": {
		"title": "Authentication Mechanisms",
		"summary": "Provide authentication mechanisms that can enforce multi-factor authentication at all customer access points",
		"page": 215,
		"basic": ["PSS-05.01B", "PSS-05.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-05.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-06": {
		"title": "Session Management",
		"summary": "Use session management protected against known attacks and invalidate sessions detected as inactive",
		"page": 216,
		"basic": ["PSS-06.01B", "PSS-06.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PSS-07": {
		"title": "Confidentiality of Authentication Information",
		"summary": "Where passwords are used, provide customers procedures protecting their confidentiality, such as user-set passwords and secure storage",
		"page": 216,
		"basic": ["PSS-07.01B", "PSS-07.02B", "PSS-07.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PSS-08": {
		"title": "Roles and Rights Framework",
		"summary": "Provide customers a roles and rights framework to manage access rights to the service's functions",
		"page": 217,
		"basic": ["PSS-08.01B", "PSS-08.02B", "PSS-08.03B", "PSS-08.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PSS-09": {
		"title": "Authorisation Mechanisms",
		"summary": "Restrict access to service functions by authorisation mechanisms, validated before release",
		"page": 218,
		"basic": ["PSS-09.01B", "PSS-09.02B", "PSS-09.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-09.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-10": {
		"title": "Software Defined Networking",
		"summary": "Where software-defined networking is offered, ensure customer data confidentiality through suitable SDN procedures, validated before release",
		"page": 219,
		"basic": ["PSS-10.01B", "PSS-10.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PSS-11": {
		"title": "Images for Virtual Machines and Containers",
		"summary": "Where customers run VMs or containers, let them restrict which images can be launched; provider images carry change information, origin labels and hardening",
		"page": 220,
		"basic": ["PSS-11.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["PSS-11.01AC", "PSS-11.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PSS-12": {
		"title": "Region of Data Processing and Storage",
		"summary": "Process and store customer data and its backups only in the contractually specified region",
		"page": 221,
		"basic": ["PSS-12.01B", "PSS-12.02B", "PSS-12.03B", "PSS-12.04B"],
		"additional_sharpening": ["PSS-12.01AS", "PSS-12.02AS"],
		"additional_complementing": ["PSS-12.01AC", "PSS-12.02AC"],
		"sharpens": [["PSS-12.01AS", "PSS-12.01B"], ["PSS-12.02AS", "PSS-12.02B"]],
		"has_additional": true,
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
	"criteria_satisfied": count([id | some id, _ in criteria; _attested(id)]),
	"criteria_fact_evaluated": 0,
	"criteria_attested_basis": count(criteria),
	"criteria_with_additional": count([id | some id, c in criteria; c.has_additional]),
	"gaps": sort([id | some id, _ in criteria; not _attested(id)]),
	"criteria": criteria_status,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
