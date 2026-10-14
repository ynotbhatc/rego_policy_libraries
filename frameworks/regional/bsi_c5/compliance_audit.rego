# METADATA
# title: "BSI C5:2026 — Compliance (COM), 4 criteria"
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
package bsi_c5.compliance_audit

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.15 Compliance (COM), p. 201.
# 4 criteria, ids exactly as printed in the catalogue; 7 basic, 1 additional (sharpening) and 7
# additional (complementing) subcriteria; 4 of the 4 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["COM-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "COM", "section": "5.15", "name": "Compliance", "page": 201}

criteria := {
	"COM-01": {
		"title": "Identification of Applicable Legal, Regulatory, Self-imposed or Contractual Requirements",
		"summary": "Define and document the legal, regulatory, self-imposed and contractual requirements relevant to the service and how they are met",
		"page": 201,
		"basic": ["COM-01.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["COM-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"COM-02": {
		"title": "Policy for Planning and Conducting Audits",
		"summary": "Document and implement a multi-year, risk-based audit programme defining audit scope and frequency",
		"page": 202,
		"basic": ["COM-02.01B", "COM-02.02B"],
		"additional_sharpening": ["COM-02.01AS"],
		"additional_complementing": ["COM-02.01AC"],
		"sharpens": [["COM-02.01AS", "COM-02.01B"]],
		"has_additional": true,
	},
	"COM-03": {
		"title": "Internal Audits of the Information Security Management System",
		"summary": "Check ISMS compliance with applicable requirements through internal audits by subject matter experts at least annually",
		"page": 203,
		"basic": ["COM-03.01B", "COM-03.02B", "COM-03.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["COM-03.01AC", "COM-03.02AC", "COM-03.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"COM-04": {
		"title": "Information on Information Security Performance and Management Assessment of the ISMS",
		"summary": "Report information security performance regularly to top management and include it in the ISMS management review",
		"page": 204,
		"basic": ["COM-04.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["COM-04.01AC", "COM-04.02AC"],
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
