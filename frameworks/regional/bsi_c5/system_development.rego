# METADATA
# title: "BSI C5:2026 — Procurement, Development and Modification of Information Systems (DEV), 15 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 16
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.system_development

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.11 Procurement, Development and Modification of Information Systems (DEV), p. 168.
# 15 criteria, ids exactly as printed in the catalogue; 32 basic, 0 additional (sharpening) and 10
# additional (complementing) subcriteria; 8 of the 15 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["DEV-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "DEV", "section": "5.11", "name": "Procurement, Development and Modification of Information Systems", "page": 168}

criteria := {
	"DEV-01": {
		"title": "Policies for the Development/Procurement of System Components",
		"summary": "Document secure development policies covering the whole life cycle of the service's system components based on recognised standards",
		"page": 168,
		"basic": ["DEV-01.01B", "DEV-01.02B", "DEV-01.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-02": {
		"title": "Outsourcing of the Development",
		"summary": "Contractually agree security requirements for outsourced development and risk-assess the outsourcing beforehand",
		"page": 170,
		"basic": ["DEV-02.01B", "DEV-02.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-02.01AC", "DEV-02.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-03": {
		"title": "Policies for Changes to System Components",
		"summary": "Document change management policies covering risk categorisation, testing, approvals, segregation of duties, customer information and emergency changes",
		"page": 171,
		"basic": ["DEV-03.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-04": {
		"title": "Safety Training and Awareness Programme Regarding Continuous Software Delivery and Associated Systems, Components or Tools",
		"summary": "Provide regular role-based training on secure software development, delivery tooling and malicious-code risks",
		"page": 172,
		"basic": ["DEV-04.01B", "DEV-04.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-05": {
		"title": "Design Documentation for Security Features",
		"summary": "Base design documentation for security features on a security analysis, including expected inputs, outputs and errors",
		"page": 173,
		"basic": ["DEV-05.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-06": {
		"title": "Risk Assessment, Categorisation and Prioritisation of Changes",
		"summary": "Risk-assess, categorise and prioritise changes, including the combined effect of concurrent changes",
		"page": 174,
		"basic": ["DEV-06.01B", "DEV-06.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-06.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-07": {
		"title": "Testing Changes",
		"summary": "Test changes according to documented procedures, with test type and scope matched to the risk assessment",
		"page": 174,
		"basic": ["DEV-07.01B", "DEV-07.02B", "DEV-07.03B", "DEV-07.04B", "DEV-07.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-07.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-08": {
		"title": "Logging of Changes",
		"summary": "Restrict version control and deployment tooling by a role and rights framework and record every production change traceably to its contributors",
		"page": 176,
		"basic": ["DEV-08.01B", "DEV-08.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-08.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-09": {
		"title": "Version Control",
		"summary": "Use version control that protects source code confidentiality, integrity and authenticity and attributes every change",
		"page": 176,
		"basic": ["DEV-09.01B", "DEV-09.02B", "DEV-09.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-09.01AC", "DEV-09.02AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-10": {
		"title": "Approvals for Provision in the Production Environment",
		"summary": "Approve changes against defined criteria before production release, involving customers where agreed",
		"page": 177,
		"basic": ["DEV-10.01B", "DEV-10.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-10.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-11": {
		"title": "Protection of Development and Test Environments",
		"summary": "Risk-assess and protect development and test environments, including extending backups to them",
		"page": 178,
		"basic": ["DEV-11.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-12": {
		"title": "Separation of Environments",
		"summary": "Separate production from test and development environments and keep production customer data out of tests",
		"page": 178,
		"basic": ["DEV-12.01B", "DEV-12.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-13": {
		"title": "Transparency about Software Components",
		"summary": "Create and maintain an up-to-date list of software components for developed and integrated software",
		"page": 179,
		"basic": ["DEV-13.01B", "DEV-13.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"DEV-14": {
		"title": "Secure Use of Third Party Hardware and Software",
		"summary": "Document policies for third-party and open-source software and track dependencies on those products",
		"page": 180,
		"basic": ["DEV-14.01B", "DEV-14.02B", "DEV-14.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["DEV-14.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"DEV-15": {
		"title": "Exceptions to the Change Management Process",
		"summary": "Manage exceptions to change management, including emergency changes, so related risks are mitigated",
		"page": 181,
		"basic": ["DEV-15.01B"],
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
