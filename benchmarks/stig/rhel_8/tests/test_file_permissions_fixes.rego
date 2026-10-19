package stig.rhel_8.file_permissions_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_stig_fp_empty_section_cat_i_open if {
	r := data.stig.rhel_8.file_permissions.compliance_report with input as {"file_permissions": {}}
	r.cat_i_open == 2
	r.compliant == false
}

test_stig_fp_empty_lists_not_a_finding if {
	i := {"file_permissions": {"world_writable_files": [], "unowned_files": []}}
	r := data.stig.rhel_8.file_permissions.compliance_report with input as i
	r.cat_i_open == 0
	r.cat_i_compliant == true
}

test_stig_fp_world_writable_listed_open if {
	i := {"file_permissions": {"world_writable_files": ["/tmp/x"], "unowned_files": []}}
	r := data.stig.rhel_8.file_permissions.compliance_report with input as i
	r.cat_i_open == 1
}

test_stig_fp_missing_cat_ii_lists_open if {
	i := {"file_permissions": {"world_writable_files": [], "unowned_files": []}}
	v := data.stig.rhel_8.file_permissions.violations with input as i
	"RHEL-08-010250" in v
	"RHEL-08-010270" in v
}

test_stig_fp_passwd_0600_not_open if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"etc_passwd": {"mode": "0600"}, "etc_group": {"mode": "0640"}}}
	not "RHEL-08-010220" in v
	not "RHEL-08-010240" in v
}

test_stig_fp_passwd_0666_open if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"etc_passwd": {"mode": "0666"}, "etc_group": {"mode": "0664"}}}
	"RHEL-08-010220" in v
	"RHEL-08-010240" in v
}

test_stig_fp_passwd_644_unpadded_ok if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"etc_passwd": {"mode": "644"}}}
	not "RHEL-08-010220" in v
}
