package cis_debian_11.filesystem_test

import rego.v1

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "compliant": true}]},
	"required_partitions": {"partitions": [{"cis_id": "2", "mount_point": "/tmp", "exists": true}]},
	"mount_options": {"mounts": [{"cis_id": "1.1.3", "mount_point": "/tmp", "compliant": true}]},
	"sticky_bit_check": {"world_writable_dirs": []},
	"usb_storage_disabled": {"loaded": false, "disabled": true},
}

test_good_compliant if {
	data.cis_debian_11.filesystem.compliance_report.compliant with input as good
}

test_empty_input_not_compliant if {
	r := data.cis_debian_11.filesystem.compliance_report with input as {}
	r.compliant == false
	r.total_violations == 5
}

test_each_missing_section_violates if {
	some k in ["disabled_filesystem_modules", "required_partitions", "mount_options", "sticky_bit_check", "usb_storage_disabled"]
	not data.cis_debian_11.filesystem.compliant with input as object.remove(good, [k])
}

test_mount_without_missing_options_still_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/mount_options/mounts/0", "value": {"compliant": false, "mount_point": "/tmp", "cis_id": "1.1.2"}}])
	count(data.cis_debian_11.filesystem.mount_option_violations) == 1 with input as i
}
