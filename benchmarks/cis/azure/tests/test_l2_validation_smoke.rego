package cis_azure.l2_test

import rego.v1

# Generated smoke test for benchmarks/cis/azure/l2_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_l2_validation_loads_on_empty_input if {
	m := data.cis_azure.l2 with input as {}
	is_object(m)
}

test_l2_validation_report_wellformed_on_empty_input if {
	report := data.cis_azure.l2.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_l2_validation_fail_closed_on_empty_input if {
	report := data.cis_azure.l2.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_l2_validation_violations_on_empty_input if {
	v := data.cis_azure.l2.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
_has(v, id) := count({m | some m in v; startswith(m, id)}) > 0

test_flow_log_retention_zero_is_forever_passes if {
	v := data.cis_azure.l2.violations with input as {"network": {"nsgs": [{"flow_log_retention_days": 0, "flow_logs_sent_to_log_analytics": true}]}}
	not _has(v, "CIS L2 6.4:")
}

test_flow_log_retention_exactly_90_violates if {
	v := data.cis_azure.l2.violations with input as {"network": {"nsgs": [{"flow_log_retention_days": 90, "flow_logs_sent_to_log_analytics": true}]}}
	_has(v, "CIS L2 6.4:")
}

test_flow_log_retention_91_passes if {
	v := data.cis_azure.l2.violations with input as {"network": {"nsgs": [{"flow_log_retention_days": 91, "flow_logs_sent_to_log_analytics": true}]}}
	not _has(v, "CIS L2 6.4:")
}

test_flow_log_retention_missing_violates if {
	v := data.cis_azure.l2.violations with input as {"network": {"nsgs": [{"flow_logs_sent_to_log_analytics": true}]}}
	_has(v, "CIS L2 6.4:")
}

test_monitor_retention_missing_violates_5_1_2 if {
	v := data.cis_azure.l2.violations with input as {"monitor": {}}
	_has(v, "CIS L2 5.1.2:")
}

test_monitor_retention_365_passes if {
	v := data.cis_azure.l2.violations with input as {"monitor": {"log_retention_days": 365}}
	not _has(v, "CIS L2 5.1.2:")
}

test_sspr_methods_missing_violates_1_5_1 if {
	v := data.cis_azure.l2.violations with input as {"aad": {}}
	_has(v, "CIS L2 1.5.1:")
}

test_sspr_methods_two_passes if {
	v := data.cis_azure.l2.violations with input as {"aad": {"sspr_methods_required": 2}}
	not _has(v, "CIS L2 1.5.1:")
}
