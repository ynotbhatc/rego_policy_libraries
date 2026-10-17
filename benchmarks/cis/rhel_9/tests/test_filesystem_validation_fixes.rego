package cis_rhel9.filesystem_test

import rego.v1

# Validation fixes 2026-10-17: present-but-empty facts are not evidence.

good := {
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "compliant": true, "loaded": false, "disabled": true}], "all_compliant": true},
	"separate_partitions": {"analysis": [{"mount_point": "/tmp", "is_separate_partition": true, "has_all_required_options": true, "compliant": true, "missing_options": []}]},
	"mount_options": {"tmp": {"exists": true, "has_nodev": true, "has_nosuid": true, "has_noexec": true}},
	"sticky_bit": {"analysis": [], "all_compliant": true},
	"usb_storage": {"loaded": false, "disabled": true, "status": "disabled"},
}

test_filesystem_good_input_compliant if {
	data.cis_rhel9.filesystem.compliant with input as good
}

test_filesystem_empty_object_facts_not_compliant if {
	i := {"disabled_filesystem_modules": {}, "separate_partitions": {}, "mount_options": {}, "sticky_bit": {}, "usb_storage": {}}
	not data.cis_rhel9.filesystem.compliant with input as i
	some v in data.cis_rhel9.filesystem.violations with input as i
	contains(v, "FAIL-CLOSED")
}

test_filesystem_each_empty_fact_is_violation if {
	every key in ["disabled_filesystem_modules", "separate_partitions", "mount_options", "sticky_bit", "usb_storage"] {
		not data.cis_rhel9.filesystem.compliant with input as json.patch(good, [{"op": "replace", "path": concat("", ["/", key]), "value": {}}])
	}
}

test_filesystem_empty_module_list_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/disabled_filesystem_modules/modules", "value": []}])
	not data.cis_rhel9.filesystem.compliant with input as i
}

test_filesystem_empty_partition_analysis_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/separate_partitions/analysis", "value": []}])
	not data.cis_rhel9.filesystem.compliant with input as i
}
