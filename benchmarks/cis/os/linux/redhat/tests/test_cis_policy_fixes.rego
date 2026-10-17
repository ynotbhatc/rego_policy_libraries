package cis_redhat_legacy_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_cis_policy_allow_defined_when_selinux_disabled if {
	a := data.cis_redhat_legacy.allow with input as {"selinux_status": "disabled"}
	a == false
}

test_cis_policy_details_defined_when_selinux_disabled if {
	d := data.cis_redhat_legacy.compliance_details with input as {"selinux_status": "disabled", "ssh_port": 2222}
	d.selinux.status == false
	d.ssh.status == true
}

test_cis_policy_details_defined_on_empty_input if {
	d := data.cis_redhat_legacy.compliance_details with input as {}
	d.os.status == false
	d.firewall.status == false
}

test_cis_policy_failed_controls_lists_ssh if {
	f := data.cis_redhat_legacy.failed_controls with input as {"selinux_status": "enforcing", "firewall_enabled": true, "os_family": "Debian"}
	"ssh" in f
}

test_cis_policy_allow_true_when_all_pass if {
	i := {"selinux_status": "enforcing", "ssh_port": 2222, "firewall_enabled": true, "os_family": "Debian"}
	data.cis_redhat_legacy.allow with input as i
}
