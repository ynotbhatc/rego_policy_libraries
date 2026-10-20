# METADATA
# title: "CIS Google Cloud Platform Foundation Benchmark v5.0.0 - Level 2 Additional Controls"
# custom:
#   class: security
#   framework: cis_gcp
#   source: cis
#   domains: [cloud, gcp]
#   coverage:
#     checks: 1
#     cited: 0
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_gcp.l2

# CIS Google Cloud Platform Foundation Benchmark v5.0.0 - Level 2 Additional Controls
# The 39 recommendations the v5.0.0 workbook assigns to the Level 2 profile (Level 2 extends
# Level 1; the Level 1 recommendations are reported by cis_gcp.main). Each is evaluated once, in
# cis_gcp_foundations.rego, against the input contract documented there; this module selects the
# Level 2 subset and reports it as "CIS L2 <id>: ...".
# Intended for regulated cloud workloads (FedRAMP High, PCI-DSS, HIPAA, DoD CC SRG IL4/IL5).

import rego.v1

import data.cis_gcp_foundations as bench

default compliant := false

compliant if { count(violations) == 0 }

l2_ids := {id | some id, c in bench.controls; c.level == 2}

# Same parse as the engine's control_id; kept local so this file checks on its own.
control_id(v) := regex.find_n(`^[0-9]+(\.[0-9]+)*`, v, 1)[0]

violations contains sprintf("CIS L2 %s", [v]) if {
	some v in bench.violations
	control_id(v) in l2_ids
}

# Distinct failing Level 2 recommendations (a control can emit one message per resource).
failing_l2_controls := {id | some v in bench.violations; id := control_id(v); id in l2_ids}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := count(l2_ids)

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Google Cloud Platform Foundation Benchmark v5.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(failing_l2_controls),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. Intended for regulated GCP workloads (FedRAMP High, PCI-DSS, HIPAA, DoD).",
}
