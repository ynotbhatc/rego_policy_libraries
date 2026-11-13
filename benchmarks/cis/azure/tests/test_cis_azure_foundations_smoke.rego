package cis_azure_test

import rego.v1

# Generated smoke test for benchmarks/cis/azure/cis_azure_foundations.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_azure_foundations_loads_on_empty_input if {
	m := data.cis_azure with input as {}
	is_object(m)
}

test_cis_azure_foundations_violations_on_empty_input if {
	v := data.cis_azure.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
_nsg(rule) := {"network_security_groups": [{"security_rules": [rule]}]}

test_rdp_wildcard_port_from_any_violates if {
	v := data.cis_azure.networking_violations with input as _nsg({"direction": "Inbound", "access": "Allow", "destination_port_range": "*", "source_address_prefixes": ["*"]})
	count(v) == 1
}

test_rdp_port_range_from_internet_violates if {
	v := data.cis_azure.networking_violations with input as _nsg({"direction": "Inbound", "access": "Allow", "destination_port_range": "3380-3400", "source_address_prefixes": ["Internet"]})
	count(v) == 1
}

test_rdp_plain_3389_still_violates if {
	v := data.cis_azure.networking_violations with input as _nsg({"direction": "Inbound", "access": "Allow", "destination_port_range": "3389", "source_address_prefixes": ["0.0.0.0/0"]})
	count(v) == 1
}

test_rdp_other_port_or_private_source_passes if {
	a := data.cis_azure.networking_violations with input as _nsg({"direction": "Inbound", "access": "Allow", "destination_port_range": "443", "source_address_prefixes": ["*"]})
	b := data.cis_azure.networking_violations with input as _nsg({"direction": "Inbound", "access": "Allow", "destination_port_range": "3389", "source_address_prefixes": ["10.0.0.0/8"]})
	count(a) + count(b) == 0
}

test_defender_servers_missing_plan_violates if {
	v := data.cis_azure.security_center_violations with input as {"defender_plans": []}
	count(v) == 1
}

test_defender_servers_standard_passes if {
	v := data.cis_azure.security_center_violations with input as {"defender_plans": [{"resource_type": "VirtualMachines", "pricing_tier": "Standard"}]}
	count(v) == 0
}
