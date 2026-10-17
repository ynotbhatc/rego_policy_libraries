package cis_juniper_junos_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_juniper_junos.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_compliant_false_on_empty if data.cis_juniper_junos.compliant == false with input as {}

test_weak_ssh_flagged if {
	inp := {"junos_config": {"system": {"services": {"ssh": {"protocol_version": "v1", "root_login": "allow"}}}}}
	"UNMAPPED-JUNOS-1.2: Ensure SSH is configured securely (protocol v2, root login denied)" in data.cis_juniper_junos.violations with input as inp
}

test_strong_ssh_ok if {
	inp := {"junos_config": {"system": {"services": {"ssh": {"protocol_version": "v2", "root_login": "deny"}}}}}
	not "UNMAPPED-JUNOS-1.2: Ensure SSH is configured securely (protocol v2, root login denied)" in data.cis_juniper_junos.violations with input as inp
}

test_interface_without_unit0_flagged if has("3.1.1", {"external_interfaces": [{"name": "ge-0/0/0"}]})

test_interface_with_filter_ok if not has("3.1.1", {"external_interfaces": [{"name": "ge-0/0/0", "unit": {"0": {"family": {"inet": {"filter": {"input": "F"}}}}}}]})

test_radius_alone_satisfies_remote_aaa if {
	inp := {"junos_config": {"system": {"radius_server": ["10.0.0.1"]}}}
	not has("UNMAPPED-JUNOS-1.1", inp)
}

test_no_remote_aaa_flagged if has("UNMAPPED-JUNOS-1.1", {"junos_config": {"system": {}}})

test_ospf_without_auth_flagged if has("2.2.1", {"junos_config": {"protocols": {"ospf": {"area": {"0.0.0.0": {}}}}}})
test_no_routing_protocol_not_flagged if not has("2.2.1", {"junos_config": {"protocols": {}}})
