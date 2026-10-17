package cis_ubuntu_24_04.filesystem_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "loaded": false, "disabled": true, "compliant": true}]},
	"required_partitions": {"partitions": [{"cis_id": "2.1", "mount_point": "/tmp", "exists": true}]},
	"mount_options": {"mounts": [{"cis_id": "1.1.2", "mount_point": "/tmp", "compliant": true, "missing_options": []}]},
	"sticky_bit_check": {"world_writable_dirs": []},
	"usb_storage_disabled": {"loaded": false, "disabled": true},
}

test_fs_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.filesystem.compliant with input as good
}

test_fs_empty_input_is_not_compliant if {
	not data.cis_ubuntu_24_04.filesystem.compliant with input as {}
}

test_fs_each_missing_section_not_compliant if {
	every k in ["disabled_filesystem_modules", "required_partitions", "mount_options", "sticky_bit_check", "usb_storage_disabled"] {
		not data.cis_ubuntu_24_04.filesystem.compliant with input as json.remove(good, [k])
	}
}

test_fs_module_violation_survives_missing_loaded_disabled if {
	i := object.union(good, {"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "compliant": false}]}})
	v := data.cis_ubuntu_24_04.filesystem.filesystem_module_violations with input as i
	count(v) == 1
}

test_fs_usb_unknown_disabled_state_is_violation if {
	i := object.union(json.remove(good, ["usb_storage_disabled"]), {"usb_storage_disabled": {"loaded": false}})
	"CIS 1.1.24: evidence missing — usb_storage_disabled.disabled not collected" in data.cis_ubuntu_24_04.filesystem.usb_storage_violation with input as i
	not data.cis_ubuntu_24_04.filesystem.compliant with input as i
}

test_fs_mount_violation_survives_missing_ids if {
	i := object.union(good, {"mount_options": {"mounts": [{"compliant": false}]}})
	v := data.cis_ubuntu_24_04.filesystem.mount_option_violations with input as i
	count(v) == 1
}
