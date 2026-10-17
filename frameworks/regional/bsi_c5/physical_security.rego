# METADATA
# title: "BSI C5:2026 — Physical Security (PS), 8 criteria"
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
package bsi_c5.physical_security

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.5 Physical Security (PS), p. 81.
# 8 criteria, ids exactly as printed in the catalogue; 28 basic, 2 additional (sharpening) and 10
# additional (complementing) subcriteria; 4 of the 8 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["PS-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "PS", "section": "5.5", "name": "Physical Security", "page": 81}

criteria := {
	"PS-01": {
		"title": "Physical Security and Environmental Control Requirements",
		"summary": "Define security areas and derive physical and environmental security requirements for premises from the security policy and a risk assessment",
		"page": 81,
		"basic": ["PS-01.01B", "PS-01.02B", "PS-01.03B", "PS-01.04B", "PS-01.05B", "PS-01.06B"],
		"additional_sharpening": [],
		"additional_complementing": ["PS-01.01AC", "PS-01.02AC", "PS-01.03AC", "PS-01.04AC", "PS-01.05AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PS-02": {
		"title": "Redundancy Model",
		"summary": "Provide the service from at least two adequately distant locations with redundancy meeting the SLA, tested at least annually",
		"page": 84,
		"basic": ["PS-02.01B", "PS-02.02B", "PS-02.03B"],
		"additional_sharpening": ["PS-02.01AS", "PS-02.02AS"],
		"additional_complementing": [],
		"sharpens": [["PS-02.01AS", "PS-02.01B"], ["PS-02.02AS", "PS-02.02B"]],
		"has_additional": true,
	},
	"PS-03": {
		"title": "Perimeter Protection",
		"summary": "Protect the structural shell and perimeter of premises with measures that detect and resist unauthorised entry for a defined time",
		"page": 85,
		"basic": ["PS-03.01B", "PS-03.02B", "PS-03.03B", "PS-03.04B", "PS-03.05B", "PS-03.06B"],
		"additional_sharpening": [],
		"additional_complementing": ["PS-03.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PS-04": {
		"title": "Physical Site Access Control",
		"summary": "Implement preventive and detective physical access controls based on least privilege and need-to-know, with revocation of unused access",
		"page": 86,
		"basic": ["PS-04.01B", "PS-04.02B", "PS-04.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PS-05": {
		"title": "Protection against Threats from Outside and from the Environment",
		"summary": "Protect premises against fire, smoke, lightning and water through structural, technical and organisational measures",
		"page": 88,
		"basic": ["PS-05.01B", "PS-05.02B", "PS-05.03B", "PS-05.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PS-06": {
		"title": "Protection against Interruptions caused by Power Failures and similar Risks to Supply Facilities",
		"summary": "Protect technical supply facilities with redundant power and cooling, UPS/emergency power and regular maintenance and testing",
		"page": 89,
		"basic": ["PS-06.01B", "PS-06.02B", "PS-06.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["PS-06.01AC", "PS-06.02AC", "PS-06.03AC", "PS-06.04AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"PS-07": {
		"title": "Surveillance of Operational and Environmental Parameters",
		"summary": "Monitor operational and environmental parameters of utilities and premises and alert responsible staff automatically when limits are exceeded",
		"page": 91,
		"basic": ["PS-07.01B", "PS-07.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"PS-08": {
		"title": "Workplace Security Requirements",
		"summary": "Document and communicate risk-based security requirements for office environments, including rented offices",
		"page": 91,
		"basic": ["PS-08.01B"],
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
