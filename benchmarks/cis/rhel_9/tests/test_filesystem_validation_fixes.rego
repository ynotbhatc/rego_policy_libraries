package cis_rhel9.filesystem_test

import rego.v1

# Validation fixes 2026-10-17: present-but-empty facts are not evidence.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# /tmp and /dev/shm read the v2 mount_options object; the other partitions read ansible_facts.ansible_mounts
# (separate_partitions.analysis is no longer read).

good := {"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "disabled": true, "loaded": false}, {"module": "freevxfs", "disabled": true, "loaded": false}, {"module": "hfs", "disabled": true, "loaded": false}, {"module": "hfsplus", "disabled": true, "loaded": false}, {"module": "jffs2", "disabled": true, "loaded": false}, {"module": "overlay", "disabled": true, "loaded": false}, {"module": "squashfs", "disabled": true, "loaded": false}, {"module": "udf", "disabled": true, "loaded": false}, {"module": "firewire-core", "disabled": true, "loaded": false}, {"module": "usb-storage", "disabled": true, "loaded": false}]}, "attest": {"unused_filesystem_modules_reviewed": true}, "mount_options": {"tmp": {"exists": true, "has_nodev": true, "has_nosuid": true, "has_noexec": true}, "dev_shm": {"exists": true, "has_nodev": true, "has_nosuid": true, "has_noexec": true}}, "ansible_facts": {"ansible_mounts": [{"mount": "/", "fstype": "xfs", "options": "rw"}, {"mount": "/home", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/home", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/tmp", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/tmp", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log/audit", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log/audit", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}]}}

test_filesystem_good_input_compliant if {
	data.cis_rhel9.filesystem.compliant with input as good
}

test_filesystem_empty_object_facts_not_compliant if {
	i := {"disabled_filesystem_modules": {}, "separate_partitions": {}, "mount_options": {}, "sticky_bit": {}, "usb_storage": {}}
	not data.cis_rhel9.filesystem.compliant with input as i
	some v in data.cis_rhel9.filesystem.violations with input as i
	contains(v, "evidence missing")
}

test_filesystem_each_empty_fact_is_violation if {
	every key in ["disabled_filesystem_modules", "mount_options", "ansible_facts"] {
		not data.cis_rhel9.filesystem.compliant with input as json.patch(good, [{"op": "replace", "path": concat("", ["/", key]), "value": {}}])
	}
}

test_filesystem_empty_module_list_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/disabled_filesystem_modules/modules", "value": []}])
	not data.cis_rhel9.filesystem.compliant with input as i
}

test_filesystem_empty_partition_analysis_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/ansible_facts/ansible_mounts", "value": []}])
	not data.cis_rhel9.filesystem.compliant with input as i
}

# the mapper's module probe reports loaded "unknown": not evidence that the module is not loaded
test_filesystem_loaded_unknown_is_not_a_pass if {
	i := {"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "disabled": true, "loaded": "unknown", "compliant": true}]}}
	"1.1.1.1: evidence missing — disabled_filesystem_modules.modules[cramfs] not collected" in data.cis_rhel9.filesystem.violations with input as i
}

# usb-storage: the v2 usb_storage object decides only when the module list has no usb-storage entry
test_filesystem_v2_usb_storage_object if {
	vs := data.cis_rhel9.filesystem.violations with input as {"usb_storage": {"disabled": true, "loaded": false, "status": "disabled"}}
	count([v | some v in vs; startswith(v, "1.1.1.10: ")]) == 0
	vs2 := data.cis_rhel9.filesystem.violations with input as {"usb_storage": {"disabled": true, "loaded": false}, "disabled_filesystem_modules": {"modules": [{"module": "usb-storage", "disabled": false, "loaded": true}]}}
	"1.1.1.10: not met — Ensure usb-storage kernel module is not available" in vs2
}
