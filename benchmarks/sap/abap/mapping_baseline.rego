# METADATA
# title: "SAP Security Baseline Template v2.6 — requirement view of the ABAP catalog"
# custom:
#   class: security
#   framework: sap_abap_baseline
#   source: sap
#   domains: [sap, erp, crosswalk]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: false
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sap_abap_baseline.mappings.baseline

import rego.v1

import data.sap_abap_baseline.registry

# The Baseline Template's own structure: one requirement (PWDPOL-A, RFCGW-A ...) holding several checks. This
# mapping is derived from the registry, so it can never drift from it: every SAP check id belongs to exactly
# one requirement, and a requirement none of whose checks is assessable shows as not_assessable.

framework := {
	"id": "sap_security_baseline_2_6",
	"name": "SAP Security Baseline Template v2.6 (ABAP requirements)",
	"source": "SAP Note 2253549; checks as published in SAP-samples/frun-csa-policies-best-practices",
	"mapping": "derived from the registry (requirement = the Baseline policy a check belongs to)",
}

_unique_requirements := {c.requirement | some _, c in registry.checks}

references := [ref |
	some r in sort([x | some x in _unique_requirements])
	ref := {
		"ref": r,
		"title": _title(r),
		"canonical": [c.id | some _, c in registry.checks; c.requirement == r],
	}
]

# The first title seen in registry order (SAP's policy headers spell a requirement's title slightly differently
# between its CRITICAL / STANDARD / EXTENDED files).
_title(r) := t if {
	ts := [c.requirement_title | some _, c in registry.checks; c.requirement == r]
	t := ts[0]
}
