# METADATA
# title: "BSI C5:2026 — Personnel (HR), 8 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 9
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.personnel

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.3 Personnel (HR), p. 60.
# 8 criteria, ids exactly as printed in the catalogue; 28 basic, 1 additional (sharpening) and 6
# additional (complementing) subcriteria; 2 of the 8 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["HR-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "HR", "section": "5.3", "name": "Personnel", "page": 60}

criteria := {
	"HR-01": {
		"title": "Verification of Qualification and Trustworthiness",
		"summary": "Identify roles with access to sensitive data or components and verify competency and integrity of the personnel before employment",
		"page": 61,
		"basic": ["HR-01.01B", "HR-01.02B", "HR-01.03B", "HR-01.04B", "HR-01.05B", "HR-01.06B"],
		"additional_sharpening": [],
		"additional_complementing": ["HR-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"HR-02": {
		"title": "Employment Terms and Conditions",
		"summary": "Employment terms bind internal and external personnel to the security policy, the code of ethics and a non-disclosure provision",
		"page": 63,
		"basic": ["HR-02.01B", "HR-02.02B", "HR-02.03B", "HR-02.04B", "HR-02.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"HR-03": {
		"title": "Security Training and Awareness Programme",
		"summary": "Run a target-group-oriented, role-based security awareness and training programme that is regularly updated and completed by all personnel",
		"page": 64,
		"basic": ["HR-03.01B", "HR-03.02B", "HR-03.03B", "HR-03.04B"],
		"additional_sharpening": ["HR-03.02AS"],
		"additional_complementing": ["HR-03.01AC", "HR-03.02AC", "HR-03.03AC", "HR-03.04AC", "HR-03.05AC"],
		"sharpens": [["HR-03.02AS", "HR-03.02B"]],
		"has_additional": true,
	},
	"HR-04": {
		"title": "Disciplinary Measures",
		"summary": "Apply a defined, proportionate disciplinary process for violations of policies or legal requirements, and inform personnel about it",
		"page": 65,
		"basic": ["HR-04.01B", "HR-04.02B", "HR-04.03B", "HR-04.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"HR-05": {
		"title": "Responsibilities in the Event of Termination or Change of Employment",
		"summary": "Inform personnel which security responsibilities remain in force, and for how long, after termination or change of employment",
		"page": 66,
		"basic": ["HR-05.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"HR-06": {
		"title": "Non-disclosure Agreements",
		"summary": "Base non-disclosure agreements on identified protection requirements and have personnel and service organisations accept them before access",
		"page": 67,
		"basic": ["HR-06.01B", "HR-06.02B", "HR-06.03B", "HR-06.04B", "HR-06.05B", "HR-06.06B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"HR-07": {
		"title": "Remote Working - Policy",
		"summary": "Document and communicate policies protecting information when personnel work remotely, including remote access and approved equipment",
		"page": 68,
		"basic": ["HR-07.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"HR-08": {
		"title": "Remote Working - Implementation",
		"summary": "Implement and maintain the technical and organisational measures that let personnel comply with the remote-working policy",
		"page": 69,
		"basic": ["HR-08.01B"],
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
