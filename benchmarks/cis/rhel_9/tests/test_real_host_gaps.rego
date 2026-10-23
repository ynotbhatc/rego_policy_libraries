package cis_rhel9.real_host_gaps_test

# Cases seen on a real RHEL 9.8 host (2026-10-22 lab run): stock cronie ships no /etc/cron.yearly,
# sudoers without `Defaults logfile`, and `augenrules --check` printing the /sbin path.

import rego.v1

test_cron_yearly_absent_passes if {
	vs := data.cis_rhel9.cron.violations with input as {"cron": {"cron_yearly_exists": false}}
	not any_starts(vs, "2.4.1.7:")
}

test_cron_yearly_present_bad_mode_fails if {
	vs := data.cis_rhel9.cron.violations with input as {"cron": {"cron_yearly_exists": true, "cron_yearly_mode": "0755", "cron_yearly_owner": "root", "cron_yearly_group": "root"}}
	any_starts(vs, "2.4.1.7:")
	not any_starts(vs, "2.4.1.7: evidence missing")
}

test_sudo_without_logfile_is_a_finding_not_missing_evidence if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"active_rules": ["-w /etc/sudoers -p wa -k scope"]}, "sudo": {"sudoers_content": "Defaults env_reset\nroot ALL=(ALL) ALL"}}
	any_starts(vs, "6.2.3.3:")
	not any_starts(vs, "6.2.3.3: evidence missing")
}

test_augenrules_sbin_path_passes if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"augenrules_check": "/sbin/augenrules: No change"}}
	not any_starts(vs, "6.2.3.36:")
}

test_augenrules_usr_sbin_path_passes if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"augenrules_check": "/usr/sbin/augenrules: No change"}}
	not any_starts(vs, "6.2.3.36:")
}

any_starts(vs, p) if {
	some v in vs
	startswith(v, p)
}
