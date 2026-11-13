package cis_aws.l2_test

import rego.v1

# Generated smoke test for benchmarks/cis/aws/l2_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_l2_validation_loads_on_empty_input if {
	m := data.cis_aws.l2 with input as {}
	is_object(m)
}

test_l2_validation_report_wellformed_on_empty_input if {
	report := data.cis_aws.l2.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_l2_validation_fail_closed_on_empty_input if {
	report := data.cis_aws.l2.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_l2_validation_violations_on_empty_input if {
	v := data.cis_aws.l2.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.

test_pw_policy_fields_missing_violate if {
	v := data.cis_aws.l2.violations with input as {"iam": {"password_policy": {}}}
	some m1 in v
	startswith(m1, "CIS L2 1.9:")
	some m2 in v
	startswith(m2, "CIS L2 1.10:")
	some m3 in v
	startswith(m3, "CIS L2 1.11:")
}

test_pw_max_age_zero_violates if {
	v := data.cis_aws.l2.violations with input as {"iam": {"password_policy": {"max_age_days": 0, "min_length": 14, "reuse_prevention": 24}}}
	some m in v
	startswith(m, "CIS L2 1.11:")
}

test_pw_policy_compliant_no_1_9_to_1_11 if {
	v := data.cis_aws.l2.violations with input as {"iam": {"password_policy": {"max_age_days": 90, "min_length": 14, "reuse_prevention": 24}}}
	bad := {m | some m in v; some id in ["CIS L2 1.9:", "CIS L2 1.10:", "CIS L2 1.11:"]; startswith(m, id)}
	count(bad) == 0
}

test_nacl_allow_all_protocol_violates_5_1 if {
	v := data.cis_aws.l2.violations with input as {"vpc": {"network_acls": [{"inbound_rules": [{"cidr": "0.0.0.0/0", "action": "allow", "protocol": "-1"}]}]}}
	some m in v
	startswith(m, "CIS L2 5.1:")
}

test_nacl_specific_port_still_works if {
	v := data.cis_aws.l2.violations with input as {"vpc": {"network_acls": [{"inbound_rules": [{"cidr": "0.0.0.0/0", "action": "allow", "protocol": "6", "port_range": {"from": 443, "to": 443}}]}]}}
	bad := {m | some m in v; startswith(m, "CIS L2 5.1:")}
	count(bad) == 0
}

test_l2_total_controls_matches_rules if {
	r := data.cis_aws.l2.compliance_report with input as {}
	r.l2_controls == 41
}
