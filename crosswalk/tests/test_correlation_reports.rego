package crosswalk.correlation_reports_test

import rego.v1

import data.crosswalk.correlation

_map := {
	"R-PASS": ["AC-2"],
	"R-OPEN": ["AC-2", "AU-3"],
	"R-NA": ["CM-6", "SC-8"],
	"R-PASS2": ["SC-8"],
	"R-REVIEW": ["IA-5"],
	"R-PASS3": ["IA-5", "SI-2"],
}

_report := {"facts_supplied": true, "rule_results": [
	{"rule": "R-PASS", "status": "Not_a_Finding"},
	{"rule": "R-OPEN", "status": "Open"},
	{"rule": "R-NA", "status": "Not_Applicable"},
	{"rule": "R-PASS2", "status": "Not_a_Finding"},
	{"rule": "R-REVIEW", "status": "Not_Reviewed"},
	{"rule": "R-PASS3", "status": "Not_a_Finding"},
	{"rule": "R-UNKNOWN", "status": "Not_a_Finding"},
]}

test_report_rollup if {
	cs := correlation.control_status with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
	cs == {
		"AC-2": "gap", "AU-3": "gap",
		"CM-6": "not_applicable", "SC-8": "satisfied",
		"IA-5": "not_reviewed", "SI-2": "satisfied",
	}
}

test_not_reviewed_never_satisfies_in_the_findings_shape if {
	cs := correlation.control_status with input as {"findings": [
		{"stig_id": "R-REVIEW", "status": "Not_Reviewed"},
		{"stig_id": "R-PASS3", "status": "Not_a_Finding"},
	]}
		with data.crosswalk.stig_800_53.map as _map
	cs["IA-5"] == "not_reviewed"
	cs["SI-2"] == "satisfied"
}

test_unknown_status_counts_as_open if {
	cs := correlation.control_status with input as {"findings": [{"stig_id": "R-PASS", "status": "pass"}]}
		with data.crosswalk.stig_800_53.map as _map
	cs["AC-2"] == "gap"
}

test_report_without_facts_is_all_open if {
	rep := object.union(_report, {"facts_supplied": false})
	cs := correlation.control_status with input as {"reports": [rep]}
		with data.crosswalk.stig_800_53.map as _map
	{s | some s in cs} == {"gap"}
}

test_two_reports_combine if {
	a := {"facts_supplied": true, "rule_results": [{"rule": "R-PASS", "status": "Not_a_Finding"}]}
	b := {"facts_supplied": true, "rule_results": [{"rule": "R-OPEN", "status": "Open"}]}
	cs := correlation.control_status with input as {"reports": [a, b]}
		with data.crosswalk.stig_800_53.map as _map
	cs["AC-2"] == "gap"
}

test_summary_counts_unmapped_rules if {
	s := correlation.summary with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
	s.rules_supplied == 7
	s.rules_unmapped == 1
	s.controls_evaluated == 6
	s.controls_satisfied == 2
	s.controls_with_gaps == 2
	s.controls_not_reviewed == 1
	s.controls_not_applicable == 1
}

test_malformed_rows_ignored if {
	s := correlation.summary with input as {"reports": [{"facts_supplied": true, "rule_results": [{"rule": 7, "status": "Not_a_Finding"}, "x"]}]}
		with data.crosswalk.stig_800_53.map as _map
	s.rules_supplied == 0
}
