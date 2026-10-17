package stig.rhel_8.services_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_stig_svc_empty_packages_cat_i_open if {
	r := data.stig.rhel_8.services.compliance_report with input as {"packages": {}}
	r.cat_i_open == 4
	r.compliant == false
}

test_stig_svc_no_input_cat_i_open if {
	v := data.stig.rhel_8.services.violations with input as {}
	"RHEL-08-040000" in v
	"RHEL-08-040040" in v
}

test_stig_svc_inventory_without_pkg_is_absent if {
	i := {"packages": {"bash": true}, "services": {"sshd": "active"}}
	v := data.stig.rhel_8.services.violations with input as i
	not "RHEL-08-040000" in v
	not "RHEL-08-040040" in v
}

test_stig_svc_installed_package_open if {
	i := {"packages": {"bash": true, "telnet-server": true}}
	v := data.stig.rhel_8.services.violations with input as i
	"RHEL-08-040000" in v
}

test_stig_svc_explicit_false_package_ok if {
	i := {"packages": {"telnet-server": false}}
	v := data.stig.rhel_8.services.violations with input as i
	not "RHEL-08-040000" in v
}

test_stig_svc_active_autofs_open if {
	v := data.stig.rhel_8.services.violations with input as {"services": {"autofs": "active", "sshd": "active"}}
	"RHEL-08-040040" in v
}

test_stig_svc_masked_autofs_ok if {
	v := data.stig.rhel_8.services.violations with input as {"services": {"autofs": "masked"}}
	not "RHEL-08-040040" in v
}
