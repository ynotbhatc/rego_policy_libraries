# METADATA
# title: "BSI C5:2026 — Control and Monitoring of Service Providers and Suppliers (SSO), 8 criteria"
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
package bsi_c5.supplier_control

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.12 Control and Monitoring of Service Providers and Suppliers (SSO), p. 181.
# 8 criteria, ids exactly as printed in the catalogue; 21 basic, 2 additional (sharpening) and 5
# additional (complementing) subcriteria; 4 of the 8 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["SSO-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "SSO", "section": "5.12", "name": "Control and Monitoring of Service Providers and Suppliers", "page": 181}

criteria := {
	"SSO-01": {
		"title": "Policies and Procedures for Controlling and Monitoring Service Organisations",
		"summary": "Document policies for controlling and monitoring service organisations that contribute to development or operation of the service",
		"page": 181,
		"basic": ["SSO-01.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["SSO-01.01AC", "SSO-01.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"SSO-02": {
		"title": "Risk Assessment of Service Organisations",
		"summary": "Risk-assess service organisations before they contribute to the service, covering protection needs, dependency and assumed subservice controls",
		"page": 183,
		"basic": ["SSO-02.01B", "SSO-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SSO-03": {
		"title": "Data Processing of Service Organisations",
		"summary": "Deny suppliers and subservice organisations access to customer, derived or account data unless risk-assessed, and obtain customer authorisation before engaging them",
		"page": 184,
		"basic": ["SSO-03.01B", "SSO-03.02B"],
		"additional_sharpening": ["SSO-03.01AS"],
		"additional_complementing": [],
		"sharpens": [["SSO-03.01AS", "SSO-03.01B"]],
		"has_additional": true,
	},
	"SSO-04": {
		"title": "Directory of Service Organisations",
		"summary": "Maintain a directory of service organisations (jurisdiction, data locations, service, risk class, compliance evidence), reviewed at least annually",
		"page": 185,
		"basic": ["SSO-04.01B", "SSO-04.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SSO-05": {
		"title": "Monitoring of Compliance with Requirements",
		"summary": "Monitor service organisations' compliance with security and legal requirements through regular review of evidence",
		"page": 185,
		"basic": ["SSO-05.01B", "SSO-05.02B", "SSO-05.03B", "SSO-05.04B", "SSO-05.05B", "SSO-05.06B", "SSO-05.07B"],
		"additional_sharpening": [],
		"additional_complementing": ["SSO-05.01AC", "SSO-05.02AC", "SSO-05.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"SSO-06": {
		"title": "Contract Termination Strategy for Service Organisations",
		"summary": "Define exit strategies for purchased services where the risk assessment shows very high dependency",
		"page": 188,
		"basic": ["SSO-06.01B", "SSO-06.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"SSO-07": {
		"title": "Ensuring Transparency within Service Organisations",
		"summary": "Ensure transparency of data flows, interfaces and controls with service organisations",
		"page": 189,
		"basic": ["SSO-07.01B", "SSO-07.02B"],
		"additional_sharpening": ["SSO-07.01AS"],
		"additional_complementing": [],
		"sharpens": [["SSO-07.01AS", "SSO-07.01B"]],
		"has_additional": true,
	},
	"SSO-08": {
		"title": "Controlling Exchanges with Suppliers of Functional Components",
		"summary": "Prevent direct exchanges between functional components that can access customer data and their suppliers",
		"page": 190,
		"basic": ["SSO-08.01B", "SSO-08.02B", "SSO-08.03B"],
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
