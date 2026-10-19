package cis_pfsense_test

import rego.v1

wan_rule(src, dst) := {"filter": {"rule": [{"interface": "wan", "type": "pass", "source": src, "destination": dst}]}}

has(prefix, inp) if {
	v := data.cis_pfsense.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_wan_pass_any_present_objects_flagged if has("2.1.3", wan_rule({"any": ""}, {"any": ""}))

test_wan_pass_absent_sides_flagged if has("2.1.3", {"filter": {"rule": [{"interface": "wan", "type": "pass"}]}})

test_wan_pass_specific_source_not_flagged if not has("2.1.3", wan_rule({"network": "lan"}, {"any": ""}))

test_wan_pass_specific_destination_not_flagged if not has("2.1.3", wan_rule({"any": ""}, {"address": "10.0.0.5"}))

test_vuln_scan_missing_package_list_not_misleading if {
	inp := {"vulnerability_scan": {"performed": true}}
	not has("5.1.1 Packages with known", inp)
	has("5.1.1 UNABLE TO VERIFY", inp)
}

test_vuln_scan_with_packages_flagged if has("5.1.1 Packages with known", {"vulnerability_scan": {"performed": true}, "vulnerable_packages": ["openssl"]})

test_vuln_scan_clean_ok if {
	inp := {"vulnerability_scan": {"performed": true}, "vulnerable_packages": []}
	not has("5.1.1", inp)
}

# Decisions 2026-10-19: totals are computed from the evaluated controls.
test_summary_total_is_evaluated_control_count if {
	s := data.cis_pfsense.compliance_assessment.summary with input as {}
	s.total_controls == 16
	s.controls_evaluated == 16
	s.passing_controls + s.failing_controls == s.total_controls
}

test_every_failing_violation_id_is_an_evaluated_control if {
	v := data.cis_pfsense.violations with input as {}
	every x in v {
		split(x, " ")[0] in data.cis_pfsense.evaluated_controls
	}
}

test_summary_counts_distinct_failing_controls if {
	a := data.cis_pfsense.compliance_assessment.summary with input as {}
	a.failing_controls <= a.total_controls
	a.compliance_percentage >= 0
}
