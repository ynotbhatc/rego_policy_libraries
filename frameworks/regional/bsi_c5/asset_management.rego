# METADATA
# title: "BSI C5:2026 — Asset Management (AM), 12 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 13
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.asset_management

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.4 Asset Management (AM), p. 69.
# 12 criteria, ids exactly as printed in the catalogue; 26 basic, 2 additional (sharpening) and 9
# additional (complementing) subcriteria; 6 of the 12 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["AM-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "AM", "section": "5.4", "name": "Asset Management", "page": 69}

criteria := {
	"AM-01": {
		"title": "Asset Management Framework",
		"summary": "Document an asset management framework covering asset identification, protection-need scheme, asset types, lifecycles and inventory procedures",
		"page": 69,
		"basic": ["AM-01.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["AM-01.01AC", "AM-01.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"AM-02": {
		"title": "Asset Inventory",
		"summary": "Maintain a complete, accurate hardware and software asset inventory with risk information, change logging and asset users",
		"page": 71,
		"basic": ["AM-02.01B", "AM-02.02B", "AM-02.03B", "AM-02.04B", "AM-02.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-03": {
		"title": "Hardware Asset Inventory",
		"summary": "Record in the hardware inventory the information needed to identify, track the lifecycle of and control each hardware asset",
		"page": 72,
		"basic": ["AM-03.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-04": {
		"title": "Software Asset Inventory",
		"summary": "Maintain an inventory of all software assets, including their use by other assets, sufficient to control and risk-assess them",
		"page": 72,
		"basic": ["AM-04.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["AM-04.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"AM-05": {
		"title": "Policy for the Proper and Secure Use of Assets",
		"summary": "Document policies for proper and secure use of assets across their lifecycle, including approvals, classification and secure configuration",
		"page": 73,
		"basic": ["AM-05.01B", "AM-05.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-06": {
		"title": "Commissioning of Hardware",
		"summary": "Approve hardware commissioning only after risk analysis and verification of secure configuration of security mechanisms",
		"page": 74,
		"basic": ["AM-06.01B", "AM-06.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-07": {
		"title": "Decommissioning of Hardware",
		"summary": "Decommission hardware through an approved procedure that permanently deletes all data or properly destroys the media",
		"page": 75,
		"basic": ["AM-07.01B", "AM-07.02B"],
		"additional_sharpening": ["AM-07.01AS"],
		"additional_complementing": ["AM-07.01AC"],
		"sharpens": [["AM-07.01AS", "AM-07.01B"]],
		"has_additional": true,
	},
	"AM-08": {
		"title": "Commitment to Proper Use, Safe and Secure Handling and Return of Assets",
		"summary": "Commit personnel to proper and secure handling of assets where risk requires it, and ensure assets are returned on termination",
		"page": 76,
		"basic": ["AM-08.01B", "AM-08.02B", "AM-08.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-09": {
		"title": "Asset Classification and Labelling",
		"summary": "Classify and where possible label assets by the protection need of the data they handle, using a uniform schema reviewed at least annually",
		"page": 77,
		"basic": ["AM-09.01B", "AM-09.02B", "AM-09.03B", "AM-09.04B"],
		"additional_sharpening": [],
		"additional_complementing": ["AM-09.01AC", "AM-09.02AC", "AM-09.03AC", "AM-09.04AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"AM-10": {
		"title": "Protection of Hardware on Hold",
		"summary": "Protect production hardware that is temporarily not in use against unauthorised access or damage, based on a risk assessment",
		"page": 79,
		"basic": ["AM-10.01B"],
		"additional_sharpening": ["AM-10.01AS"],
		"additional_complementing": [],
		"sharpens": [["AM-10.01AS", "AM-10.01B"]],
		"has_additional": true,
	},
	"AM-11": {
		"title": "Transfer of Hardware",
		"summary": "Authorise and secure the transfer of production hardware to offsite or alternate locations, with chain of custody and verification on receipt",
		"page": 79,
		"basic": ["AM-11.01B", "AM-11.02B", "AM-11.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"AM-12": {
		"title": "Removable Media and Endpoint Devices",
		"summary": "Control endpoint devices and removable media based on a risk assessment, including restricted use, encryption and anti-malware",
		"page": 80,
		"basic": ["AM-12.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["AM-12.01AC"],
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
