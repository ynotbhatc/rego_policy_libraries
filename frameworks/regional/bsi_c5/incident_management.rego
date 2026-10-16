# METADATA
# title: "BSI C5:2026 — Security Incident Management (SIM), 6 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 7
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.incident_management

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.13 Security Incident Management (SIM), p. 191.
# 6 criteria, ids exactly as printed in the catalogue; 22 basic, 0 additional (sharpening) and 5
# additional (complementing) subcriteria; 2 of the 6 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["SIM-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "SIM", "section": "5.13", "name": "Security Incident Management", "page": 191}

criteria := {
	"SIM-01": {
		"title": "Policy for Security Incident Management",
		"summary": "Document policies and safeguards for fast and effective response to security incidents, including classification and escalation",
		"page": 191,
		"basic": ["SIM-01.01B", "SIM-01.02B", "SIM-01.03B", "SIM-01.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SIM-02": {
		"title": "Security Incident Response Plans",
		"summary": "Document, approve and communicate security incident response plans covering all stages of incident response",
		"page": 192,
		"basic": ["SIM-02.01B", "SIM-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SIM-03": {
		"title": "Processing of Security Incidents",
		"summary": "Classify, prioritise and root-cause-analyse potential security incidents using an incident catalogue, with qualified external support where needed",
		"page": 192,
		"basic": ["SIM-03.01B", "SIM-03.02B", "SIM-03.03B", "SIM-03.04B", "SIM-03.05B", "SIM-03.06B", "SIM-03.07B"],
		"additional_sharpening": [],
		"additional_complementing": ["SIM-03.01AC", "SIM-03.02AC", "SIM-03.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"SIM-04": {
		"title": "Documentation and Reporting of Security Incidents",
		"summary": "Document resolved security incidents per contract, inform affected customers, and make security breach information available",
		"page": 193,
		"basic": ["SIM-04.01B", "SIM-04.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["SIM-04.01AC", "SIM-04.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"SIM-05": {
		"title": "Duty of the Personnel to Report Security Incidents to a Central Body",
		"summary": "Oblige personnel and business partners to report security events promptly to a designated central body",
		"page": 194,
		"basic": ["SIM-05.01B", "SIM-05.02B", "SIM-05.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SIM-06": {
		"title": "Evaluation and Learning Process",
		"summary": "Measure and monitor security incidents and keep a knowledge repository of incidents and remedies for learning",
		"page": 195,
		"basic": ["SIM-06.01B", "SIM-06.02B", "SIM-06.03B", "SIM-06.04B"],
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
