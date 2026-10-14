# METADATA
# title: "BSI C5:2026 — Security Policies and Procedures (SP), 3 criteria"
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
package bsi_c5.security_policies

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.2 Security Policies and Procedures (SP), p. 56.
# 3 criteria, ids exactly as printed in the catalogue; 11 basic, 0 additional (sharpening) and 3
# additional (complementing) subcriteria; 1 of the 3 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["SP-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "SP", "section": "5.2", "name": "Security Policies and Procedures", "page": 56}

criteria := {
	"SP-01": {
		"title": "Documentation, Communication and Provision of Policies and Procedures",
		"summary": "Derive policies and procedures from the security policy in a uniform structure, communicate them, keep them under version control and have them approved by top management",
		"page": 56,
		"basic": ["SP-01.01B", "SP-01.02B", "SP-01.03B", "SP-01.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SP-02": {
		"title": "Review and Approval of Policies and Procedures",
		"summary": "Review security policies and procedures at least annually and on significant change, with management approval of revisions",
		"page": 58,
		"basic": ["SP-02.01B", "SP-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SP-03": {
		"title": "Exceptions from Existing Policies and Procedures",
		"summary": "Keep a list of exceptions to security policies, put them through risk management and approval, and review them within a defined validity",
		"page": 59,
		"basic": ["SP-03.01B", "SP-03.02B", "SP-03.03B", "SP-03.04B", "SP-03.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["SP-03.01AC", "SP-03.02AC", "SP-03.03AC"],
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
