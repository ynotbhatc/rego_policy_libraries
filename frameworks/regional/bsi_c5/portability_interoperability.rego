# METADATA
# title: "BSI C5:2026 — Portability and Interoperability (PI), 3 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 4
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.portability_interoperability

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.10 Portability and Interoperability (PI), p. 163.
# 3 criteria, ids exactly as printed in the catalogue; 6 basic, 0 additional (sharpening) and 5
# additional (complementing) subcriteria; 2 of the 3 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["PI-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "PI", "section": "5.10", "name": "Portability and Interoperability", "page": 163}

criteria := {
	"PI-01": {
		"title": "Safety of Input and Output Interfaces",
		"summary": "Secure inbound and outbound interfaces used by other cloud services or customer systems with standardised protocols and controls",
		"page": 164,
		"basic": ["PI-01.01B", "PI-01.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["PI-01.01AC", "PI-01.02AC", "PI-01.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PI-02": {
		"title": "Contractual Agreements for the Provision of Data",
		"summary": "Define contractually how customer data is provided to the customer after termination, including type, format, timing and support",
		"page": 165,
		"basic": ["PI-02.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["PI-02.01AC", "PI-02.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PI-03": {
		"title": "Secure Deletion of Data",
		"summary": "Delete customer, derived and account data on contract termination per the agreements, resistant to forensic recovery and documented as proof for the customer",
		"page": 167,
		"basic": ["PI-03.01B", "PI-03.02B", "PI-03.03B"],
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
