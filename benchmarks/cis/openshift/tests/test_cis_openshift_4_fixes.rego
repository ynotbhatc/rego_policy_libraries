package cis_openshift_4_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_openshift_empty_openshift_object_not_compliant if {
	not data.cis_openshift_4.compliant with input as {"openshift": {}}
}

test_openshift_empty_object_emits_violations if {
	v := data.cis_openshift_4.violations with input as {"openshift": {}}
	count(v) == 156
}

test_openshift_permissive_api_server_mode_flagged if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"master_node": {"api_server": {"permissions": 700, "owner": "root", "group": "root"}}}}
	has("1.1.1 ", v)
}

test_openshift_mode_642_flagged_as_octal if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"master_node": {"api_server": {"permissions": 642}}}}
	has("1.1.1 ", v)
}

test_openshift_mode_600_string_ok if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"master_node": {"api_server": {"permissions": "0600", "owner": "root", "group": "root"}}}}
	not has("1.1.1 ", v)
}

test_openshift_mode_644_ok if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"master_node": {"api_server": {"permissions": 644}}}}
	not has("1.1.1 ", v)
}

test_openshift_authz_list_with_alwaysallow_flagged if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"control_plane": {"authorization_mode": ["Node", "RBAC", "AlwaysAllow"]}}}
	has("3.1.7 ", v)
}

test_openshift_authz_csv_with_alwaysallow_flagged if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"control_plane": {"authorization_mode": "Node,RBAC,AlwaysAllow"}}}
	has("3.1.7 ", v)
}

test_openshift_authz_node_rbac_ok if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"control_plane": {"authorization_mode": ["Node", "RBAC"]}}}
	not has("3.1.7 ", v)
	not has("3.1.8 ", v)
	not has("3.1.9 ", v)
}

test_openshift_authz_missing_flagged if {
	v := data.cis_openshift_4.violations with input as {"openshift": {"control_plane": {}}}
	has("3.1.7 ", v)
}
