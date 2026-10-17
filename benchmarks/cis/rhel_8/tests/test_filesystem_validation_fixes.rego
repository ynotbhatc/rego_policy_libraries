package cis_rhel8.filesystem_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "loaded": false, "disabled": true, "compliant": true}]},
	"separate_partitions": {"analysis": [{"mount_point": "/tmp", "is_separate_partition": true, "has_all_required_options": true, "missing_options": [], "compliant": true}]},
	"mount_options": {"tmp": {"exists": true, "has_nodev": true, "has_noexec": true, "has_nosuid": true}, "dev_shm": {"exists": true, "has_nodev": true, "has_noexec": true, "has_nosuid": true}},
	"sticky_bit": {"analysis": [], "world_writable_without_sticky": []},
	"usb_storage": {"loaded": false, "disabled": true, "status": "disabled"},
}

test_fs_fully_evidenced_is_compliant if {
	data.cis_rhel8.filesystem.compliant with input as good
}

test_fs_empty_mount_options_only_not_compliant if {
	not data.cis_rhel8.filesystem.compliant with input as {"mount_options": {}}
}

test_fs_each_missing_section_not_compliant if {
	every k in ["disabled_filesystem_modules", "separate_partitions", "mount_options", "sticky_bit", "usb_storage"] {
		not data.cis_rhel8.filesystem.compliant with input as json.remove(good, [k])
	}
}

test_fs_noncompliant_module_still_reported if {
	i := object.union(good, {"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "loaded": true, "disabled": false, "compliant": false}]}})
	count(data.cis_rhel8.filesystem.report.non_compliant_modules) == 1 with input as i
	not data.cis_rhel8.filesystem.compliant with input as i
}
