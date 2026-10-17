package cis.filesystem_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

mounts := {"/tmp": {"options": ["nodev", "nosuid", "noexec"]}}

test_fs_loaded_array_freevxfs_flagged if {
	not data.cis.filesystem.freevxfs_disabled with input as {"loaded_modules": ["freevxfs", "squashfs"]}
	not data.cis.filesystem.squashfs_disabled with input as {"loaded_modules": ["freevxfs", "squashfs"]}
}

test_fs_loaded_array_other_modules_ok if {
	data.cis.filesystem.freevxfs_disabled with input as {"loaded_modules": ["ext4"]}
}

test_fs_loaded_string_cramfs_flagged if {
	not data.cis.filesystem.cramfs_disabled with input as {"loaded_modules": "cramfs"}
	not data.cis.filesystem.udf_disabled with input as {"loaded_modules": "ext4 udf"}
}

test_fs_loaded_modules_absent_fails_closed if {
	not data.cis.filesystem.cramfs_disabled with input as {}
	not data.cis.filesystem.udf_disabled with input as {}
}

test_fs_all_clear_compliant if {
	data.cis.filesystem.filesystem_compliant with input as {"loaded_modules": ["ext4"], "mounts": mounts}
}

test_fs_compliance_report_defined_on_empty_input if {
	r := data.cis.filesystem.filesystem_compliance with input as {}
	count(r) == 12
	r.overall_compliant == false
}
