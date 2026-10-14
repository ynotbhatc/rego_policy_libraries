# METADATA
# title: "BSI C5:2026 — Business Continuity Management (BCM), 4 criteria"
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
package bsi_c5.business_continuity

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.14 Business Continuity Management (BCM), p. 196.
# 4 criteria, ids exactly as printed in the catalogue; 10 basic, 0 additional (sharpening) and 4
# additional (complementing) subcriteria; 1 of the 4 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["BCM-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "BCM", "section": "5.14", "name": "Business Continuity Management", "page": 196}

criteria := {
	"BCM-01": {
		"title": "Business Continuity and Emergency Management System",
		"summary": "Operate a business continuity and emergency management system according to ISO 22301 and/or BSI 200-4 with documented policies",
		"page": 196,
		"basic": ["BCM-01.01B", "BCM-01.02B", "BCM-01.03B", "BCM-01.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"BCM-02": {
		"title": "Business Impact Analysis",
		"summary": "Perform a business impact analysis of disruptions to the development and operation of the service",
		"page": 197,
		"basic": ["BCM-02.01B", "BCM-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"BCM-03": {
		"title": "Business Continuity Plans",
		"summary": "Document business continuity plans consistently based on the business impact analysis",
		"page": 198,
		"basic": ["BCM-03.01B", "BCM-03.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"BCM-04": {
		"title": "Testing Business Continuity",
		"summary": "Test business continuity plans at least annually or on significant change, involving affected customers and third parties",
		"page": 199,
		"basic": ["BCM-04.01B", "BCM-04.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["BCM-04.01AC", "BCM-04.02AC", "BCM-04.03AC", "BCM-04.04AC"],
		"sharpens": [],
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
