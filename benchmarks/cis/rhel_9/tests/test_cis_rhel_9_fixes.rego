package cis.rhel_9_test

import rego.v1

# Validation fixes 2026-10-17: crond AND/OR logic, compliant default, honest summary, evidence gates.

good := {"ansible_facts": {
	"ansible_modprobe_config": [{"filesystem": "squashfs", "state": "disabled"}],
	"ansible_packages": {"audit": {"version": "3.0"}},
	"ansible_interfaces": [{"name": "lo"}],
	"ansible_services": {"crond": {"state": "running", "enabled": true}},
	"system_files": [{"permissions_correct": true}],
}}

test_rhel9_good_input_compliant if {
	data.cis.rhel_9.compliant with input as good
}

test_rhel9_compliant_is_false_not_undefined_on_failure if {
	data.cis.rhel_9.compliant == false with input as {}
}

test_rhel9_crond_stopped_but_enabled_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/ansible_facts/ansible_services/crond/state", "value": "stopped"}])
	"5.1.1: Ensure cron daemon is enabled and running" in data.cis.rhel_9.violations with input as i
}

test_rhel9_crond_running_but_disabled_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/ansible_facts/ansible_services/crond/enabled", "value": false}])
	"5.1.1: Ensure cron daemon is enabled and running" in data.cis.rhel_9.violations with input as i
}

test_rhel9_crond_missing_is_violation if {
	i := json.remove(good, ["/ansible_facts/ansible_services"])
	"5.1.1: Ensure cron daemon is enabled and running" in data.cis.rhel_9.violations with input as i
}

test_rhel9_missing_package_inventory_is_violation if {
	i := json.remove(good, ["/ansible_facts/ansible_packages"])
	"2.1.1: evidence missing — ansible_packages not collected" in data.cis.rhel_9.violations with input as i
}

test_rhel9_missing_interfaces_is_violation if {
	i := json.remove(good, ["/ansible_facts/ansible_interfaces"])
	"3.1.1: evidence missing — ansible_interfaces not collected" in data.cis.rhel_9.violations with input as i
}

test_rhel9_missing_system_files_is_violation if {
	i := json.remove(good, ["/ansible_facts/system_files"])
	"6.1.1: evidence missing — system_files not collected" in data.cis.rhel_9.violations with input as i
}

test_rhel9_summary_is_honest_on_good_input if {
	s := data.cis.rhel_9.compliance_summary with input as good
	s.total_controls == 6
	s.failing_controls == 0
	s.compliance_percentage == 100
}

test_rhel9_summary_not_inflated_on_empty_input if {
	s := data.cis.rhel_9.compliance_summary with input as {}
	s.total_controls == 6
	s.failing_controls == 6
	s.passing_controls == 0
	s.compliance_percentage == 0
}

test_rhel9_summary_counts_distinct_controls if {
	i := json.patch(good, [{"op": "replace", "path": "/ansible_facts/system_files", "value": [{"permissions_correct": false}, {"permissions_correct": false}]}])
	s := data.cis.rhel_9.compliance_summary with input as i
	s.failing_controls == 1
}

# Decisions 2026-10-19: legacy stub summary is honest about its scope.
test_legacy_summary_counts_only_evaluated_controls if {
	s := data.cis.rhel_9.compliance_summary with input as {}
	s.total_controls == 6
	sum([x.total | some x in s.sections]) == s.total_controls
	s.passing_controls + s.failing_controls == s.total_controls
}
