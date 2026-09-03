package crosswalk.correlation_test

import rego.v1

import data.crosswalk.correlation

# Minimal deterministic crosswalk for the test — overrides the shipped data
# so the test does not depend on specific rule IDs surviving a re-crosswalk.
sample_map := {
	"RULE-A": ["AC-17", "SC-28"],
	"RULE-B": ["AC-17"],
	"RULE-C": ["AU-3"],
	"RULE-D": ["CM-6"],
}

findings := [
	{"stig_id": "RULE-A", "status": "Not_a_Finding"},
	{"stig_id": "RULE-B", "status": "Open"}, # also maps AC-17 → makes AC-17 a gap
	{"stig_id": "RULE-C", "status": "Not_a_Finding"},
	# RULE-D not supplied → CM-6 must be not_evaluated (absent), never satisfied
]

test_gap_wins_when_any_mapped_rule_open if {
	cs := correlation.control_status with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_map
	cs["AC-17"] == "gap" # RULE-A passed but RULE-B (also AC-17) is Open
}

test_satisfied_when_all_mapped_rules_pass if {
	cs := correlation.control_status with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_map
	cs["SC-28"] == "satisfied" # only RULE-A maps it, and it passed
	cs["AU-3"] == "satisfied"
}

test_unassessed_control_is_absent_not_passed if {
	cs := correlation.control_status with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_map
	not cs["CM-6"] # no supplied finding touches CM-6 → honest silence
}

test_summary_counts_and_families if {
	s := correlation.summary with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_map
	s.controls_evaluated == 3 # AC-17, SC-28, AU-3
	s.controls_satisfied == 2 # SC-28, AU-3
	s.controls_with_gaps == 1 # AC-17
	s.families_touched == 3 # AC, SC, AU
}

test_empty_findings_yields_empty_rollup if {
	s := correlation.summary with input as {"findings": []}
		with data.crosswalk.stig_800_53.map as sample_map
	s.controls_evaluated == 0
}

# Contract: the SHIPPED crosswalk is present and non-trivial.
test_shipped_crosswalk_populated if {
	count(data.crosswalk.stig_800_53.map) > 1000
	# a known RHEL 9 rule maps to at least one well-formed 800-53 control
	some ctrl in data.crosswalk.stig_800_53.map["RHEL-09-255010"]
	regex.match(`^[A-Z]{2}-[0-9]+$`, ctrl)
}
