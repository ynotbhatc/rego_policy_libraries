package stig.rhel_8.decisions_scope_test

import rego.v1

# Decisions 2026-10-19 (theme A): `compliant` = no open finding at any category.

test_file_permissions_cat_ii_open_not_compliant if {
	i := {"file_permissions": {"world_writable_files": [], "unowned_files": []}}
	r := data.stig.rhel_8.file_permissions.compliance_report with input as i
	r.cat_i_compliant == true
	r.compliant == false
}
