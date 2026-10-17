package cis_ubuntu_20_04.file_permissions_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {
	"critical_files": {"analysis": [{"file": "/etc/passwd", "exists": true, "fully_compliant": true, "mode_compliant": true}], "non_compliant_count": 0},
	"ssh_private_keys": {"all_compliant": true, "analysis": []},
	"world_writable": {"compliant": true, "count": 0, "files": []},
	"unowned_files": {"compliant": true, "count": 0, "files": []},
	"ungrouped_files": {"compliant": true, "count": 0, "files": []},
	"suid_files": {"total_count": 10, "unknown_count": 0, "unknown_binaries": []},
	"sgid_files": {"count": 3},
}

test_full_evidence_compliant if {
	data.cis_ubuntu_20_04.file_permissions.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_ubuntu_20_04.file_permissions.compliant with input as {}
	v := data.cis_ubuntu_20_04.file_permissions.violations with input as {}
	count({m | some m in v; contains(m, "evidence missing")}) == 6
}

test_each_missing_section_flagged if {
	every sec in ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "suid_files", "sgid_files"] {
		v := data.cis_ubuntu_20_04.file_permissions.violations with input as json.remove(good, [sec])
		some m in v
		contains(m, concat("", ["evidence missing — ", sec]))
	}
}

test_empty_object_section_is_not_evidence if {
	not data.cis_ubuntu_20_04.file_permissions.compliant with input as object.union(object.remove(good, ["world_writable"]), {"world_writable": {}})
}
