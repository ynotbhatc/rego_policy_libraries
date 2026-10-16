# METADATA
# title: "BSI C5:2026 — Communication Security (COS), 8 criteria"
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
package bsi_c5.communication_security

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.9 Communication Security (COS), p. 156.
# 8 criteria, ids exactly as printed in the catalogue; 20 basic, 1 additional (sharpening) and 3
# additional (complementing) subcriteria; 4 of the 8 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["COS-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "COS", "section": "5.9", "name": "Communication Security", "page": 156}

criteria := {
	"COS-01": {
		"title": "Technical Safeguards",
		"summary": "Implement risk-based technical safeguards to detect and respond to network attacks on the service's system components",
		"page": 157,
		"basic": ["COS-01.01B", "COS-01.02B", "COS-01.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["COS-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"COS-02": {
		"title": "Security Requirements for Connections in the Cloud Service Provider’s Network",
		"summary": "Define security requirements for connections within the provider's network, including when security zones are separated",
		"page": 158,
		"basic": ["COS-02.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"COS-03": {
		"title": "Monitoring of Connections in the Cloud Service Provider’s Network",
		"summary": "Separate trusted and untrusted networks into security zones and design physical and virtual networks to enforce the separation",
		"page": 158,
		"basic": ["COS-03.01B", "COS-03.02B", "COS-03.03B", "COS-03.04B", "COS-03.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"COS-04": {
		"title": "Cross-Network Access",
		"summary": "Control each network perimeter with security gateways and authorise cross-network access based on a security assessment",
		"page": 159,
		"basic": ["COS-04.01B", "COS-04.02B"],
		"additional_sharpening": ["COS-04.01AS"],
		"additional_complementing": [],
		"sharpens": [["COS-04.01AS", "COS-04.01B"]],
		"has_additional": true,
	},
	"COS-05": {
		"title": "Networks for Administration",
		"summary": "Use separate, protected networks with MFA for infrastructure administration and management consoles",
		"page": 160,
		"basic": ["COS-05.01B", "COS-05.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["COS-05.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"COS-06": {
		"title": "Separation of Data Traffic in Jointly Used Network Environments",
		"summary": "Separate customer data traffic in jointly used network environments at network level under a documented framework",
		"page": 161,
		"basic": ["COS-06.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["COS-06.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"COS-07": {
		"title": "Documentation of the Network Topology",
		"summary": "Keep traceable, up-to-date documentation of the logical network structure used to provide or operate the service",
		"page": 162,
		"basic": ["COS-07.01B", "COS-07.02B", "COS-07.03B", "COS-07.04B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"COS-08": {
		"title": "Policies for Data Transmission",
		"summary": "Document policies protecting data in transmission against interception, manipulation and other threats",
		"page": 163,
		"basic": ["COS-08.01B", "COS-08.02B"],
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
