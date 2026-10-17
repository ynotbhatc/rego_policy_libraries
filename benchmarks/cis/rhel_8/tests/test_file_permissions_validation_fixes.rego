package cis_rhel8.file_permissions_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {
	"critical_files": {"analysis": [{"file": "/etc/passwd", "exists": true, "fully_compliant": true, "mode_compliant": true}], "non_compliant_count": 0},
	"ssh_private_keys": {"all_compliant": true, "analysis": []},
	"world_writable": {"files": [], "count": 0, "compliant": true},
	"unowned_files": {"files": [], "count": 0, "compliant": true},
	"ungrouped_files": {"files": [], "count": 0, "compliant": true},
	"suid_files": {"unknown_binaries": [], "unknown_count": 0, "total_count": 10},
	"sgid_files": {"count": 3},
}

test_fileperms_fully_evidenced_is_compliant if {
	data.cis_rhel8.file_permissions.compliant with input as good
}

test_fileperms_only_ssh_keys_is_not_compliant if {
	not data.cis_rhel8.file_permissions.compliant with input as {"ssh_private_keys": {"all_compliant": true}}
}

test_fileperms_missing_world_writable_is_violation if {
	i := json.remove(good, ["world_writable"])
	v := data.cis_rhel8.file_permissions.violations with input as i
	"CIS 6.1.10: evidence missing — world_writable not collected" in v
	not data.cis_rhel8.file_permissions.compliant with input as i
}

test_fileperms_missing_critical_files_is_violation if {
	i := json.remove(good, ["critical_files"])
	not data.cis_rhel8.file_permissions.compliant with input as i
}

test_fileperms_missing_unowned_ungrouped_suid_sgid_are_violations if {
	every k in ["unowned_files", "ungrouped_files", "suid_files", "sgid_files"] {
		not data.cis_rhel8.file_permissions.compliant with input as json.remove(good, [k])
	}
}

test_fileperms_empty_sections_are_not_evidence if {
	not data.cis_rhel8.file_permissions.compliant with input as object.union(json.remove(good, ["world_writable"]), {"world_writable": {}})
}
