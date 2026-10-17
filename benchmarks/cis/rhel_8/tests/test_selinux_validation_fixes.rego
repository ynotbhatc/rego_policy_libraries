package cis_rhel8.selinux_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {"selinux": {"installed": true, "status": "enabled", "mode": "enforcing", "policy": "targeted", "grub_cmdline": ""}}

test_selinux_fully_evidenced_is_compliant if {
	data.cis_rhel8.selinux.compliant with input as good
}

test_selinux_enabled_without_mode_is_violation if {
	i := json.remove(good, ["selinux/mode"])
	"CIS 1.6.1.5: evidence missing — selinux.mode not collected" in data.cis_rhel8.selinux.violations with input as i
	not data.cis_rhel8.selinux.compliant with input as i
}

test_selinux_permissive_still_flagged if {
	i := object.union(good, {"selinux": {"mode": "permissive"}})
	"CIS 1.6.1.5: SELinux mode is permissive, should be enforcing" in data.cis_rhel8.selinux.violations with input as i
}

test_selinux_missing_grub_cmdline_is_violation if {
	i := json.remove(good, ["selinux/grub_cmdline"])
	not data.cis_rhel8.selinux.compliant with input as i
}
