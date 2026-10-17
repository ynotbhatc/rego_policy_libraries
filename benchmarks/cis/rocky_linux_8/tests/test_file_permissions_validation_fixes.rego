package cis_rocky_linux_8.file_permissions_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_fileperms_risk_unknown_on_empty_input if {
	r := data.cis_rocky_linux_8.file_permissions.risk_level with input as {}
	r == "unknown"
}

test_fileperms_risk_low_with_full_evidence if {
	i := {
		"world_writable": {"count": 0},
		"critical_files": {"non_compliant_count": 0},
		"suid_files": {"unknown_count": 0},
		"unowned_files": {"count": 0},
	}
	r := data.cis_rocky_linux_8.file_permissions.risk_level with input as i
	r == "low"
}

test_fileperms_entry_without_exists_still_flagged if {
	i := {"critical_files": {"analysis": [{
		"file": "/etc/shadow", "fully_compliant": false, "mode_compliant": true,
		"actual_mode": "0644", "expected_mode": "0000", "actual_owner": "root", "expected_owner": "root",
		"actual_group": "root", "expected_group": "root",
	}]}}
	v := data.cis_rocky_linux_8.file_permissions.critical_file_violations with input as i
	some m in v
	startswith(m, "CIS 6.1.x: Critical file")
}

test_fileperms_nonexistent_file_not_flagged if {
	i := {"critical_files": {"analysis": [{"file": "/etc/x", "fully_compliant": false, "exists": false}]}}
	v := data.cis_rocky_linux_8.file_permissions.critical_file_violations with input as i
	count([m | some m in v; startswith(m, "CIS 6.1.x: Critical file")]) == 0
}

test_fileperms_missing_critical_files_evidence_flagged if {
	v := data.cis_rocky_linux_8.file_permissions.critical_file_violations with input as {}
	"CIS 6.1.x: evidence missing - critical_files.analysis not collected" in v
}
