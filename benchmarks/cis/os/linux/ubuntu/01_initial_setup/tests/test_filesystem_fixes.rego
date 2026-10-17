package cis.ubuntu.initial_setup_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_ubuntu_fs_tmp_options_array_ok if {
	i := {"mounts": {"/tmp": {"options": ["rw", "nodev", "nosuid", "noexec"]}}}
	data.cis.ubuntu.initial_setup.tmp_nodev with input as i
	data.cis.ubuntu.initial_setup.tmp_nosuid with input as i
	data.cis.ubuntu.initial_setup.tmp_noexec with input as i
}

test_ubuntu_fs_tmp_option_missing_flagged if {
	i := {"mounts": {"/tmp": {"options": ["rw", "nodev"]}}}
	not data.cis.ubuntu.initial_setup.tmp_noexec with input as i
}

test_ubuntu_fs_options_string_ok if {
	i := {"mounts": {"/tmp": {"options": "rw,nodev"}}}
	data.cis.ubuntu.initial_setup.tmp_nodev with input as i
}

test_ubuntu_fs_option_prefix_not_substring_match if {
	i := {"mounts": {"/tmp": {"options": ["nodevices"]}}}
	not data.cis.ubuntu.initial_setup.tmp_nodev with input as i
}

test_ubuntu_fs_module_disabled_with_arrays if {
	i := {"loaded_modules": [], "blacklisted_modules": ["cramfs", "udf"]}
	data.cis.ubuntu.initial_setup.cramfs_disabled with input as i
	data.cis.ubuntu.initial_setup.udf_disabled with input as i
}

test_ubuntu_fs_module_loaded_flagged if {
	i := {"loaded_modules": ["cramfs"], "blacklisted_modules": ["cramfs"]}
	not data.cis.ubuntu.initial_setup.cramfs_disabled with input as i
}

test_ubuntu_fs_module_not_blacklisted_flagged if {
	i := {"loaded_modules": [], "blacklisted_modules": ["udf"]}
	not data.cis.ubuntu.initial_setup.cramfs_disabled with input as i
}

test_ubuntu_fs_module_no_evidence_flagged if {
	not data.cis.ubuntu.initial_setup.cramfs_disabled with input as {}
}

test_ubuntu_fs_report_defined_on_empty_input if {
	r := data.cis.ubuntu.initial_setup.ubuntu_filesystem_compliance with input as {}
	count(r) == 29
	r.overall_compliant == false
}

test_ubuntu_fs_report_defined_when_check_fails if {
	r := data.cis.ubuntu.initial_setup.ubuntu_filesystem_compliance with input as {"mounts": {"/tmp": {"options": ["rw"]}}}
	r.tmp_nodev == false
}
