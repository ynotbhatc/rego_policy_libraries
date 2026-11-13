package cis_palo_alto_panos_test

import rego.v1

# Generated smoke test for benchmarks/cis/network_devices/palo_alto/cis_palo_alto_panos.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_palo_alto_panos_loads_on_empty_input if {
	m := data.cis_palo_alto_panos with input as {}
	is_object(m)
}

test_cis_palo_alto_panos_violations_on_empty_input if {
	v := data.cis_palo_alto_panos.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
test_max_concurrent_admins_50_violates if {
	v := data.cis_palo_alto_panos.admin_access_violations with input as {"panos_config": {"mgt_config": {"max_concurrent_admins": 50}}}
	count(v) == 1
}

test_max_concurrent_admins_5_passes if {
	v := data.cis_palo_alto_panos.admin_access_violations with input as {"panos_config": {"mgt_config": {"max_concurrent_admins": 5}}}
	count(v) == 0
}

test_max_concurrent_admins_missing_violates if {
	v := data.cis_palo_alto_panos.admin_access_violations with input as {"panos_config": {"mgt_config": {}}}
	count(v) == 1
}

test_missing_admin_users_violates_1_1_and_2_1 if {
	a := data.cis_palo_alto_panos.management_interface_violations with input as {"panos_config": {"mgt_config": {}}}
	b := data.cis_palo_alto_panos.authentication_violations with input as {"panos_config": {"mgt_config": {}}}
	count(a) == 1
	count(b) == 1
}

test_present_admin_users_no_evidence_missing if {
	cfg := {"panos_config": {"mgt_config": {"users": {"entry": [{"name": "a", "allowed_ips": ["10.0.0.1"], "authentication_profile": "p"}]}}}}
	a := data.cis_palo_alto_panos.management_interface_violations with input as cfg
	b := data.cis_palo_alto_panos.authentication_violations with input as cfg
	count(a) + count(b) == 0
}
