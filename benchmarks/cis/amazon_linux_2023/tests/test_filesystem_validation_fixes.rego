package cis_amazon_linux_2023.filesystem_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_fs_overall_compliant_false_on_empty_input if {
	s := data.cis_amazon_linux_2023.filesystem.compliance_summary with input as {}
	s.overall_compliant == false
}

test_fs_partition_missing_options_empty_still_flagged if {
	i := {"separate_partitions": {"analysis": [{
		"mount_point": "/var", "is_separate_partition": true,
		"has_all_required_options": false, "missing_options": [],
	}]}}
	v := data.cis_amazon_linux_2023.filesystem.partition_violations with input as i
	count(v) == 1
}

test_fs_partition_with_all_options_ok if {
	i := {"separate_partitions": {"analysis": [{
		"mount_point": "/var", "is_separate_partition": true,
		"has_all_required_options": true, "missing_options": [],
	}]}}
	v := data.cis_amazon_linux_2023.filesystem.partition_violations with input as i
	count(v) == 0
}

test_fs_usb_loaded_false_without_disabled_flagged if {
	v := data.cis_amazon_linux_2023.filesystem.usb_storage_violation with input as {"usb_storage": {"loaded": false}}
	count(v) == 1
}

test_fs_usb_disabled_ok if {
	v := data.cis_amazon_linux_2023.filesystem.usb_storage_violation with input as {"usb_storage": {"loaded": false, "disabled": true}}
	count(v) == 0
}

test_fs_usb_status_disabled_ok if {
	v := data.cis_amazon_linux_2023.filesystem.usb_storage_violation with input as {"usb_storage": {"status": "disabled"}}
	count(v) == 0
}

test_fs_usb_evidence_missing_flagged if {
	v := data.cis_amazon_linux_2023.filesystem.usb_storage_violation with input as {}
	"CIS 1.1.1.8: evidence missing - usb_storage not collected" in v
}
