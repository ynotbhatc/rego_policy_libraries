package cis.rhel_10_test

import rego.v1

has(msg, inp) if {
	v := data.cis.rhel_10.violations with input as inp
	msg in v
}

test_compliant_false_not_undefined if data.cis.rhel_10.compliant == false with input as {}

test_empty_input_does_not_score_high if {
	s := data.cis.rhel_10.compliance_summary with input as {}
	s.compliance_percentage < 50
}

test_summary_totals_reconcile if {
	s := data.cis.rhel_10.compliance_summary with input as {}
	s.total_controls == sum([x.total | some x in s.sections])
}

test_missing_crond_flagged if has("5.1.1: Ensure cron daemon is enabled and running", {"ansible_facts": {"ansible_services": {}}})

test_stopped_crond_flagged if has("5.1.1: Ensure cron daemon is enabled and running", {"ansible_facts": {"ansible_services": {"crond": {"state": "stopped", "enabled": true}}}})

test_running_enabled_crond_ok if not has("5.1.1: Ensure cron daemon is enabled and running", {"ansible_facts": {"ansible_services": {"crond": {"state": "running", "enabled": true}}}})

test_missing_system_files_flagged if has("6.1.0: evidence missing — ansible_facts.system_files not collected", {"ansible_facts": {}})

test_system_files_present_clears_evidence_violation if not has("6.1.0: evidence missing — ansible_facts.system_files not collected", {"ansible_facts": {"system_files": []}})

test_unwired_grub_check_evaluated if has("UNMAPPED-RHEL10-1.2: Ensure grub config is secure (root:root, mode 0600 or stricter)", {"ansible_facts": {}})

test_grub_mode_stricter_than_600_ok if not has("UNMAPPED-RHEL10-1.2: Ensure grub config is secure (root:root, mode 0600 or stricter)", {"ansible_facts": {"grub_config": {"owner": "root", "group": "root", "mode": "0400"}}})

test_grub_mode_644_flagged if has("UNMAPPED-RHEL10-1.2: Ensure grub config is secure (root:root, mode 0600 or stricter)", {"ansible_facts": {"grub_config": {"owner": "root", "group": "root", "mode": "0644"}}})

test_cron_allow_mode_600_ok if not has("UNMAPPED-RHEL10-5.2: Ensure cron access is restricted", {"ansible_facts": {"file_permissions": {"/etc/cron.allow": {"owner": "root", "group": "root", "mode": "0600"}}}})
