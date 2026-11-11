package stig.rhel_8.file_permissions_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass, re-keyed to the V2R8 ids on 2026-11-10:
# the module carries RHEL-08-010780 (valid owner), RHEL-08-010330 (library modes) and
# RHEL-08-010730 (home directory modes); none is CAT I in V2R8.

test_stig_fp_empty_section_not_compliant if {
	r := data.stig.rhel_8.file_permissions.compliance_report with input as {"file_permissions": {}}
	r.open_findings == r.total_findings
	r.compliant == false
}

test_stig_fp_empty_unowned_list_not_a_finding if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"unowned_files": []}}
	not "RHEL-08-010780" in v
}

test_stig_fp_unowned_listed_open if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"unowned_files": ["/tmp/x"]}}
	"RHEL-08-010780" in v
}

test_stig_fp_missing_lists_open if {
	v := data.stig.rhel_8.file_permissions.violations with input as {"file_permissions": {"unowned_files": []}}
	"RHEL-08-010730" in v
	"RHEL-08-010330" in v
}

test_stig_fp_clean_evidence_compliant if {
	i := {"file_permissions": {"unowned_files": [], "insecure_home_dirs": [], "library_files_ok": true}}
	data.stig.rhel_8.file_permissions.compliant with input as i
}
