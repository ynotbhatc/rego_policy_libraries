package cis_ubuntu_20_04.filesystem_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "compliant": true, "loaded": false, "disabled": true}]},
	"required_partitions": {"partitions": [{"cis_id": "1.1.2", "mount_point": "/tmp", "exists": true}]},
	"mount_options": {"mounts": [{"cis_id": "1.1.3", "mount_point": "/tmp", "compliant": true, "missing_options": []}]},
	"sticky_bit_check": {"world_writable_dirs": []},
	"usb_storage_disabled": {"loaded": false, "disabled": true},
}

test_full_evidence_compliant if {
	data.cis_ubuntu_20_04.filesystem.compliant with input as good
}

test_empty_input_not_compliant_and_report_says_so if {
	not data.cis_ubuntu_20_04.filesystem.compliant with input as {}
	r := data.cis_ubuntu_20_04.filesystem.compliance_report with input as {}
	r.compliant == false
	r.total_violations == 5
}

test_each_missing_section_not_compliant if {
	every sec in ["disabled_filesystem_modules", "required_partitions", "mount_options", "sticky_bit_check", "usb_storage_disabled"] {
		not data.cis_ubuntu_20_04.filesystem.compliant with input as json.remove(good, [sec])
	}
}

test_empty_modules_list_is_not_evidence if {
	not data.cis_ubuntu_20_04.filesystem.compliant with input as object.union(object.remove(good, ["disabled_filesystem_modules"]), {"disabled_filesystem_modules": {"modules": []}})
}

test_failing_mount_still_reported if {
	inp := object.union(good, {"mount_options": {"mounts": [{"cis_id": "1.1.3", "mount_point": "/tmp", "compliant": false, "missing_options": ["noexec"]}]}})
	some v in data.cis_ubuntu_20_04.filesystem.violations with input as inp
	contains(v, "noexec")
}
