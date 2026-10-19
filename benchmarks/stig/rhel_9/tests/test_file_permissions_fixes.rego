package stig.rhel_9.file_permissions_fixes_test

import rego.v1

fp := data.stig.rhel_9.file_permissions

clean := {
	"world_writable_files": [],
	"unowned_files": [],
	"ungrouped_files": [],
}

test_empty_input_not_compliant if not fp.compliant with input as {}

test_empty_section_not_compliant if not fp.compliant with input as {"file_permissions": {}}

test_clean_evidence_compliant if fp.cat_i_compliant with input as {"file_permissions": clean}

test_offender_makes_noncompliant if not fp.compliant with input as {"file_permissions": object.union(clean, {"unowned_files": ["/tmp/x"]})}

test_missing_list_is_open if fp.status_rhel_09_232045 == "Open" with input as {"file_permissions": {}}

test_empty_suid_list_ok if fp.status_rhel_09_232045 == "Not_a_Finding" with input as {"file_permissions": {"undocumented_suid_files": []}}

test_missing_home_dirs_open if fp.status_rhel_09_232065 == "Open" with input as {}

test_passwd_stricter_0600_ok if fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "0600"}}}

test_passwd_0644_ok if fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "644"}}}

test_passwd_0666_open if not fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "0666"}}}

test_group_stricter_0640_ok if fp.group_permissions_ok with input as {"file_permissions": {"etc_group": {"mode": "0640"}}}

test_group_0664_open if not fp.group_permissions_ok with input as {"file_permissions": {"etc_group": {"mode": "0664"}}}

test_shadow_0000_ok if fp.shadow_permissions_ok with input as {"file_permissions": {"etc_shadow": {"mode": "0000"}}}

test_shadow_0640_open if not fp.shadow_permissions_ok with input as {"file_permissions": {"etc_shadow": {"mode": "0640"}}}

test_gshadow_0640_open if not fp.gshadow_permissions_ok with input as {"file_permissions": {"etc_gshadow": {"mode": "0640"}}}

test_cron_allow_absent_evidence_open if not fp.cron_allow_permissions_ok with input as {}

test_cron_allow_explicitly_absent_ok if fp.cron_allow_permissions_ok with input as {"cron_allow": {"file_exists": false}}

test_cron_allow_0600_ok if fp.cron_allow_permissions_ok with input as {"cron_allow": {"file_exists": true, "permissions": "0600"}}

test_cron_allow_0644_open if not fp.cron_allow_permissions_ok with input as {"cron_allow": {"file_exists": true, "permissions": "0644"}}
