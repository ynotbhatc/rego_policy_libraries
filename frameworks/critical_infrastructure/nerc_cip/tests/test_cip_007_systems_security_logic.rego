package nerc_cip.cip_007_test

import rego.v1

import data.nerc_cip.cip_007 as c

# Validation 2026-10-17: impact filter and missing-evidence handling.

systems := [
	{"system_id": "H1", "impact_categorization": "high"},
	{"system_id": "L1", "impact_categorization": "low"},
]

good := {
	"bes_cyber_systems": systems,
	"network_port_management": {"H1": {"physical_ports": {"unused_disabled": true}}},
	"system_configurations": {"H1": {"default_passwords": {"changed": true}}},
	"system_access_controls": {"H1": {"account_lockout_configured": true}},
}

test_low_impact_system_does_not_fail_requirements if {
	c.physical_io_ports_protected with input as good
	c.default_passwords_changed with input as good
	c.login_attempt_limiting with input as good
}

test_high_impact_failures_detected if {
	i1 := json.patch(good, [{"op": "replace", "path": "/network_port_management/H1/physical_ports/unused_disabled", "value": false}])
	not c.physical_io_ports_protected with input as i1
	i2 := json.patch(good, [{"op": "replace", "path": "/system_configurations/H1/default_passwords/changed", "value": false}])
	not c.default_passwords_changed with input as i2
	i3 := json.patch(good, [{"op": "replace", "path": "/system_access_controls/H1/account_lockout_configured", "value": false}])
	not c.login_attempt_limiting with input as i3
}

test_missing_records_fail_closed if {
	i := {"bes_cyber_systems": systems}
	not c.physical_io_ports_protected with input as i
	not c.default_passwords_changed with input as i
	not c.login_attempt_limiting with input as i
	not c.physical_io_ports_protected with input as {}
}

test_missing_inventory_fails_per_system_requirements if {
	not c.ports_and_services_minimized with input as {}
	not c.security_patches_applied with input as {}
	not c.malicious_code_prevention_implemented with input as {}
	not c.security_event_logging_enabled with input as {}
	not c.unique_authentication_credentials with input as {}
}

test_patch_evaluation_accepts_iso_dates if {
	p := {"applicable": true, "availability_date": "2026-01-01T00:00:00Z", "evaluation": {"completed": true, "completion_date": "2026-01-20T00:00:00Z"}}
	c.security_patch_evaluation_timely with input as {"security_patches": [p]}
	late := json.patch(p, [{"op": "replace", "path": "/evaluation/completion_date", "value": "2026-03-20T00:00:00Z"}])
	not c.security_patch_evaluation_timely with input as {"security_patches": [late]}
}

# ---- audit 2026-11-23: requirement parts follow CIP-007-6; fixed clock ---------

now := time.parse_rfc3339_ns("2026-11-23T00:00:00Z")

# Every part label a finding can carry exists in CIP-007-6 (R1 has two parts,
# R2 four, R3 three, R4 four, R5 seven).
test_every_label_is_a_cip_007_6_part if {
	valid := {"R1", "R1.1", "R1.2", "R2.1", "R2.2", "R2.3", "R2.4", "R3.1", "R3.2", "R3.3", "R4.1", "R4.2", "R4.3", "R4.4", "R5.1", "R5.2", "R5.3", "R5.4", "R5.5", "R5.6", "R5.7"}
	vs := c.violations with input as {"user_accounts": [{"shared": true}], "security_patches": [{"applicable": true}]}
	count(vs) > 10
	every v in vs {
		v.requirement in valid
	}
}

label_of(i, fragment) := {v.requirement | some v in c.violations with input as i; contains(v.description, fragment)}

test_parts_are_labelled_as_in_the_standard if {
	# 1.1 logical ports, 1.2 physical input/output ports (there is no Part 1.3)
	label_of({}, "Unnecessary ports or services") == {"R1.1"}
	label_of({}, "physical io ports") == {"R1.2"}

	# 5.3 shared accounts, 5.4 default passwords, 5.5 password parameters, 5.7 attempts
	label_of({"user_accounts": [{"shared": true}]}, "shared accounts") == {"R5.3"}
	label_of({}, "default passwords") == {"R5.4"}
	label_of({}, "Password policy") == {"R5.5"}
	label_of({}, "login attempt limiting") == {"R5.7"}

	# 3.1 malicious code prevention, 4.1 logging with 4.3 retention
	label_of({}, "Malicious code prevention") == {"R3.1"}
	label_of({}, "log retention") == {"R4.1"}
}

# Part 4.4: review at intervals no greater than 15 calendar days (not 15 months,
# and not Part 4.3, which is retention).
review(d) := {"bes_cyber_systems": systems, "security_event_alerting": {"last_review_date": d}}

test_log_review_within_15_days_passes if {
	c.security_log_review_current with input as review("2026-11-10T00:00:00Z") with time.now_ns as now
}

test_log_review_older_than_15_days_is_r4_4 if {
	i := review("2026-10-01T00:00:00Z")
	not c.security_log_review_current with input as i with time.now_ns as now
	label_of(i, "15 calendar days") == {"R4.4"} with time.now_ns as now
	c.report.requirements.R4_4_log_review_current == false with input as i with time.now_ns as now
}

test_future_log_review_date_is_a_finding if {
	i := review("2027-03-01T00:00:00Z")
	not c.security_log_review_current with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	some v in vs
	v.requirement == "R4.4"
	contains(v.description, "later than the evaluation time")
}

test_missing_or_unparseable_log_review_date_is_evidence_missing if {
	every i in [review("yesterday"), review(null), {"bes_cyber_systems": systems}, {}] {
		not c.security_log_review_current with input as i with time.now_ns as now
		vs := c.violations with input as i with time.now_ns as now
		"evidence missing — input.security_event_alerting.last_review_date not collected or not an RFC 3339 date" in {v.description | some v in vs}
	}
}

test_log_review_not_applicable_without_high_impact_systems if {
	i := {"bes_cyber_systems": [{"system_id": "M1", "impact_categorization": "medium"}]}
	c.security_log_review_current with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	not "R4.4" in {v.requirement | some v in vs}
}

# Part 2.2: an evaluation "completed" on a future date has not been completed.
patch(completion) := {"security_patches": [{
	"applicable": true,
	"availability_date": "2026-11-01T00:00:00Z",
	"evaluation": {"completed": true, "completion_date": completion},
}]}

test_patch_evaluation_dated_in_the_future_fails if {
	c.security_patch_evaluation_timely with input as patch("2026-11-20T00:00:00Z") with time.now_ns as now
	i := patch("2026-11-30T00:00:00Z")
	not c.security_patch_evaluation_timely with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	some v in vs
	v.requirement == "R2.2"
	contains(v.description, "security_patches[0].evaluation.completion_date")
	contains(v.description, "later than the evaluation time")
}

test_patch_evaluation_with_unusable_date_is_evidence_missing if {
	i := patch("soon")
	not c.security_patch_evaluation_timely with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	"evidence missing — input.security_patches[0].evaluation.completion_date not collected or not an RFC 3339 date" in {v.description | some v in vs}
}
