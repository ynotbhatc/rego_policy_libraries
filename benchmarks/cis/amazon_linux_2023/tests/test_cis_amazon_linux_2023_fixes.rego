package cis.amazon_linux_2023_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_al2023_compliant_defined_on_failing_input if {
	c := data.cis.amazon_linux_2023.compliant with input as {}
	c == false
}

test_al2023_summary_counts_only_evaluated_controls if {
	s := data.cis.amazon_linux_2023.compliance_summary with input as {}
	s.total_controls == 6
	object.get(s, "controls_evaluated", 0) == 6
	s.compliance_percentage == 50
}

test_al2023_cron_stopped_but_enabled_flagged if {
	i := {"ansible_facts": {"ansible_services": {"crond": {"state": "stopped", "enabled": true}}}}
	v := data.cis.amazon_linux_2023.access_auth_violations with input as i
	count(v) == 1
}

test_al2023_cron_missing_flagged if {
	v := data.cis.amazon_linux_2023.access_auth_violations with input as {"ansible_facts": {"ansible_services": {}}}
	count(v) == 1
}

test_al2023_cron_running_enabled_ok if {
	i := {"ansible_facts": {"ansible_services": {"crond": {"state": "running", "enabled": true}}}}
	v := data.cis.amazon_linux_2023.access_auth_violations with input as i
	count(v) == 0
}
