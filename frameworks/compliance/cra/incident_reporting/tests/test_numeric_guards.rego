package cra.incident_reporting_numeric_guards_test

import rego.v1

# "1" sorts above every number and null below: a non-number clock is evidence missing, not a timing verdict.
test_non_number_hours_since_aware_is_evidence_missing if {
	every v in ["1", null, "x"] {
		msgs := data.cra.incident_reporting.violation with input as {"incident_reporting": {
			"actively_exploited_vuln_known": true,
			"hours_since_aware_of_vuln": v,
		}}
		some m in msgs
		startswith(m, "CRA Art.14(2)(a): evidence missing")
		not "CRA Art.14(2)(a): no early warning submitted to the CSIRT coordinator and ENISA within 24h of awareness (current: 1h)" in msgs
	}
}

test_numeric_hours_since_aware_still_late if {
	msgs := data.cra.incident_reporting.violation with input as {"incident_reporting": {
		"actively_exploited_vuln_known": true,
		"hours_since_aware_of_vuln": 30,
	}}
	some m in msgs
	startswith(m, "CRA Art.14(2)(a): no early warning submitted to the CSIRT coordinator and ENISA within 24h of awareness (current: 30h)")
}
