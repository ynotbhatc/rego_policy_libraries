package cis_ubuntu_22_04.filesystem_test

import rego.v1

# Validation fix 2026-10-17: compliant was true on empty input / when a section was not collected.

pkg := data.cis_ubuntu_22_04.filesystem

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "disabled": true, "loaded": false, "compliant": true}]},
	"required_partitions": {"partitions": [{"cis_id": "2", "mount_point": "/tmp", "exists": true}]},
	"mount_options": {"mounts": [{"cis_id": "1.1.2.1", "mount_point": "/tmp", "compliant": true, "missing_options": []}]},
	"sticky_bit_check": {"world_writable_dirs": [{"path": "/tmp", "has_sticky_bit": true}]},
	"usb_storage_disabled": {"loaded": false, "disabled": true},
}

test_empty_input_not_compliant if {
	not pkg.compliant with input as {}
	count(pkg.violations) == 5 with input as {}
}

test_good_compliant if {
	pkg.compliant with input as good
}

test_each_missing_section_violates if {
	every section in ["disabled_filesystem_modules", "required_partitions", "mount_options", "sticky_bit_check", "usb_storage_disabled"] {
		not pkg.compliant with input as object.remove(good, [section])
	}
}

test_real_violation_still_reported if {
	bad := object.union(good, {"usb_storage_disabled": {"loaded": true, "disabled": false}})
	count(pkg.violations) == 2 with input as bad
}

test_report_populated_on_empty_input if {
	r := pkg.compliance_report with input as {}
	r.compliant == false
	r.total_violations == 5
}
