# METADATA
# title: "BSI C5:2026 — Identity and Access Management (IAM), 9 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 10
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.identity_access_management

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.7 Identity and Access Management (IAM), p. 128.
# 9 criteria, ids exactly as printed in the catalogue; 49 basic, 6 additional (sharpening) and 14
# additional (complementing) subcriteria; 7 of the 9 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["IAM-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "IAM", "section": "5.7", "name": "Identity and Access Management", "page": 128}

criteria := {
	"IAM-01": {
		"title": "Policy for Identities and Access Rights",
		"summary": "Document a role-based authorisation framework and a policy for managing identities and access rights of personnel and technical components",
		"page": 128,
		"basic": ["IAM-01.01B", "IAM-01.02B", "IAM-01.03B"],
		"additional_sharpening": [],
		"additional_complementing": ["IAM-01.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"IAM-02": {
		"title": "Granting and Change of Identities and Access Rights",
		"summary": "Grant and change identities and access rights through specified procedures that enforce the role and rights policies",
		"page": 130,
		"basic": ["IAM-02.01B", "IAM-02.02B", "IAM-02.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"IAM-03": {
		"title": "Risk-Based Procedure for Locking and Withdrawal of Identities",
		"summary": "Apply a risk-based procedure to lock and withdraw identities on inactivity or brute-force indications",
		"page": 131,
		"basic": ["IAM-03.01B", "IAM-03.02B", "IAM-03.03B", "IAM-03.04B"],
		"additional_sharpening": ["IAM-03.03AS"],
		"additional_complementing": ["IAM-03.01AC", "IAM-03.02AC", "IAM-03.03AC"],
		"sharpens": [["IAM-03.03AS", "IAM-03.03B"]],
		"has_additional": true,
	},
	"IAM-04": {
		"title": "Withdrawal or Adjustment of Access Rights as the Task Area Changes",
		"summary": "Adjust or revoke access rights when responsibilities change, privileged rights within 48 hours and others within 14 days",
		"page": 132,
		"basic": ["IAM-04.01B", "IAM-04.02B", "IAM-04.03B", "IAM-04.04B", "IAM-04.05B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"IAM-05": {
		"title": "Regular Review of Access Rights",
		"summary": "Review identities and access rights at least annually and on significant change, by authorised persons, and remediate deviations",
		"page": 133,
		"basic": ["IAM-05.01B", "IAM-05.02B", "IAM-05.03B", "IAM-05.04B", "IAM-05.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["IAM-05.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"IAM-06": {
		"title": "Privileged Access Rights",
		"summary": "Assign privileged access rights per policy, personalised, time-limited and need-based; log and monitor their use and require MFA for administration interfaces",
		"page": 134,
		"basic": ["IAM-06.01B", "IAM-06.02B", "IAM-06.03B", "IAM-06.04B", "IAM-06.05B", "IAM-06.06B", "IAM-06.07B", "IAM-06.08B", "IAM-06.09B"],
		"additional_sharpening": [],
		"additional_complementing": ["IAM-06.01AC", "IAM-06.02AC", "IAM-06.03AC", "IAM-06.04AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"IAM-07": {
		"title": "Access to Cloud Service Customer Data",
		"summary": "Partition the service's components from other systems and between customers, and inform customers when provider personnel access their data",
		"page": 136,
		"basic": ["IAM-07.01B", "IAM-07.02B", "IAM-07.03B", "IAM-07.04B", "IAM-07.05B", "IAM-07.06B"],
		"additional_sharpening": ["IAM-07.03AS", "IAM-07.04AS", "IAM-07.06AS"],
		"additional_complementing": ["IAM-07.01AC", "IAM-07.02AC", "IAM-07.03AC", "IAM-07.04AC"],
		"sharpens": [["IAM-07.03AS", "IAM-07.03B"], ["IAM-07.04AS", "IAM-07.04B"], ["IAM-07.06AS", "IAM-07.06B"]],
		"has_additional": true,
	},
	"IAM-08": {
		"title": "Authentication Mechanisms",
		"summary": "Authenticate all users and technical components accessing provider system components and enforce MFA for production access",
		"page": 139,
		"basic": ["IAM-08.01B", "IAM-08.02B", "IAM-08.03B", "IAM-08.04B", "IAM-08.05B", "IAM-08.06B", "IAM-08.07B"],
		"additional_sharpening": ["IAM-08.02AS", "IAM-08.03AS"],
		"additional_complementing": [],
		"sharpens": [["IAM-08.02AS", "IAM-08.02B"], ["IAM-08.03AS", "IAM-08.03B"]],
		"has_additional": true,
	},
	"IAM-09": {
		"title": "Confidentiality of Authentication Information",
		"summary": "Allocate and manage authentication information confidentially, with credential protection matched to the access it grants",
		"page": 140,
		"basic": ["IAM-09.01B", "IAM-09.02B", "IAM-09.03B", "IAM-09.04B", "IAM-09.05B", "IAM-09.06B", "IAM-09.07B"],
		"additional_sharpening": [],
		"additional_complementing": ["IAM-09.01AC"],
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
