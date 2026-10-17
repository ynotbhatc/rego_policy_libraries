# METADATA
# title: "BSI C5:2026 — Organisation of Information Security (OIS), 10 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 11
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.organisation_information_security

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.1 Organisation of Information Security (OIS), p. 44.
# 10 criteria, ids exactly as printed in the catalogue; 34 basic, 2 additional (sharpening) and 5
# additional (complementing) subcriteria; 3 of the 10 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["OIS-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "OIS", "section": "5.1", "name": "Organisation of Information Security", "page": 44}

criteria := {
	"OIS-01": {
		"title": "Information Security Management System (ISMS)",
		"summary": "Operate an ISO/IEC 27001-compliant ISMS whose documented scope covers the units, locations, zones, regions and procedures of the cloud service",
		"page": 44,
		"basic": ["OIS-01.01B", "OIS-01.02B", "OIS-01.03B"],
		"additional_sharpening": ["OIS-01.01AS"],
		"additional_complementing": ["OIS-01.01AC"],
		"sharpens": [["OIS-01.01AS", "OIS-01.01B"]],
		"has_additional": true,
	},
	"OIS-02": {
		"title": "Information Security Policy",
		"summary": "Top management adopts an information security policy covering objectives, commitment and organisation, and communicates it to personnel and customers",
		"page": 45,
		"basic": ["OIS-02.01B", "OIS-02.02B", "OIS-02.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-03": {
		"title": "Interfaces and Dependencies",
		"summary": "Establish, document, communicate and regularly review a Shared Security Responsibility Model defining provider/customer interfaces and dependencies",
		"page": 46,
		"basic": ["OIS-03.01B", "OIS-03.02B", "OIS-03.03B", "OIS-03.04B", "OIS-03.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-04": {
		"title": "Segregation of Duties",
		"summary": "Segregate conflicting tasks and responsibilities based on a risk assessment, with mitigating measures in the risk treatment plan",
		"page": 47,
		"basic": ["OIS-04.01B", "OIS-04.02B", "OIS-04.03B", "OIS-04.04B"],
		"additional_sharpening": [],
		"additional_complementing": ["OIS-04.01AC", "OIS-04.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"OIS-05": {
		"title": "Threat Intelligence",
		"summary": "Collect and analyse threat intelligence from internal and external sources and feed it into risk management",
		"page": 48,
		"basic": ["OIS-05.01B", "OIS-05.02B", "OIS-05.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-06": {
		"title": "Contact with Relevant Government Agencies and Interest Groups",
		"summary": "Where public-sector customers in Germany use the service, maintain contact with the BSI National IT Situation Centre and CERT Association",
		"page": 50,
		"basic": ["OIS-06.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-07": {
		"title": "Risk Management Policy",
		"summary": "Document a risk management policy with a reproducible methodology for identifying, analysing, evaluating and treating risks",
		"page": 50,
		"basic": ["OIS-07.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-08": {
		"title": "Application of the Risk Management Policy - Risk Assessment",
		"summary": "Perform the risk assessment at least annually and as needed, covering cloud-specific risk factors such as multi-tenancy and exposed interfaces",
		"page": 51,
		"basic": ["OIS-08.01B", "OIS-08.02B", "OIS-08.03B", "OIS-08.04B", "OIS-08.05B", "OIS-08.06B"],
		"additional_sharpening": ["OIS-08.01AS"],
		"additional_complementing": ["OIS-08.01AC", "OIS-08.02AC"],
		"sharpens": [["OIS-08.01AS", "OIS-08.01B"]],
		"has_additional": true,
	},
	"OIS-09": {
		"title": "Application of the Risk Management Policy - Risk Treatment",
		"summary": "Prioritise risk treatment, document and implement a treatment plan reducing risk to an acceptable residual level, and share it with relevant parties",
		"page": 54,
		"basic": ["OIS-09.01B", "OIS-09.02B", "OIS-09.03B", "OIS-09.04B", "OIS-09.05B", "OIS-09.06B", "OIS-09.07B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"OIS-10": {
		"title": "Information Security in Project Management",
		"summary": "Integrate information security and risk assessment into projects that may affect the provision, operation or security of the service",
		"page": 55,
		"basic": ["OIS-10.01B"],
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
