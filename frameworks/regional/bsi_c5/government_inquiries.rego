# METADATA
# title: "BSI C5:2026 — Dealing with Investigation Requests from Government Agencies (INQ), 4 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 5
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.government_inquiries

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.16 Dealing with Investigation Requests from Government Agencies (INQ), p. 205.
# 4 criteria, ids exactly as printed in the catalogue; 8 basic, 0 additional (sharpening) and 2
# additional (complementing) subcriteria; 1 of the 4 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["INQ-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "INQ", "section": "5.16", "name": "Dealing with Investigation Requests from Government Agencies", "page": 205}

criteria := {
	"INQ-01": {
		"title": "Legal Assessment of Investigation Requests",
		"summary": "Subject government investigation requests for data to a documented legal assessment of their validity",
		"page": 205,
		"basic": ["INQ-01.01B", "INQ-01.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"INQ-02": {
		"title": "Informing Cloud Service Customers about Investigation Requests",
		"summary": "Inform affected customers of government investigation requests without undue delay unless legally prohibited",
		"page": 206,
		"basic": ["INQ-02.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"INQ-03": {
		"title": "Limiting Access to or Disclosure of Data in Investigation Requests",
		"summary": "Limit access or disclosure in investigation requests to the data that is the subject of the request",
		"page": 207,
		"basic": ["INQ-03.01B", "INQ-03.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["INQ-03.01AC", "INQ-03.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"INQ-04": {
		"title": "Communication of Technical Procedures for Data Disclosure in Investigation Requests",
		"summary": "Document and provide customers the technical procedures for providing or disclosing customer data on valid investigation requests",
		"page": 207,
		"basic": ["INQ-04.01B", "INQ-04.02B", "INQ-04.03B"],
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
