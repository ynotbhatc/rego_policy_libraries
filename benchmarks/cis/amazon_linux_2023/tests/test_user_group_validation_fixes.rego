package cis_amazon_linux_2023.user_group_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_user_group_not_compliant_on_empty_input if {
	not data.cis_amazon_linux_2023.user_group.compliant with input as {}
}

test_user_group_not_compliant_on_empty_section if {
	not data.cis_amazon_linux_2023.user_group.compliant with input as {"user_group": {}}
}

test_user_group_evidence_missing_message if {
	v := data.cis_amazon_linux_2023.user_group.violations with input as {}
	"CIS 6.2: evidence missing - user_group not collected" in v
}

test_user_group_clean_section_compliant if {
	i := {"user_group": {"users_without_shadow": [], "uid_zero_accounts": ["root"], "root_path": "/usr/bin:/bin"}}
	data.cis_amazon_linux_2023.user_group.compliant with input as i
}

test_user_group_offender_flagged if {
	i := {"user_group": {"uid_zero_accounts": ["root", "toor"]}}
	not data.cis_amazon_linux_2023.user_group.compliant with input as i
}
