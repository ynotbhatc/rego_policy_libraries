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
	"UNMAPPED-JUNOS-1.2: SSH must be explicitly configured securely (protocol v2, root login denied)" in data.cis_juniper_junos.violations with input as inp
}

test_strong_ssh_ok if {
	inp := {"junos_config": {"system": {"services": {"ssh": {"protocol_version": "v2", "root_login": "deny"}}}}}
	not "UNMAPPED-JUNOS-1.2: SSH must be explicitly configured securely (protocol v2, root login denied)" in data.cis_juniper_junos.violations with input as inp
}

test_interface_without_unit0_flagged if has("3.1.1", {"external_interfaces": [{"name": "ge-0/0/0"}]})

test_interface_with_filter_ok if not has("3.1.1: ingress", {"external_interfaces": [{"name": "ge-0/0/0", "unit": {"0": {"family": {"inet": {"filter": {"input": "F"}}}}}}]})

test_radius_alone_satisfies_remote_aaa if {
	inp := {"junos_config": {"system": {"radius_server": ["10.0.0.1"]}}}
	not has("UNMAPPED-JUNOS-1.1", inp)
}

test_no_remote_aaa_flagged if has("UNMAPPED-JUNOS-1.1", {"junos_config": {"system": {}}})

test_ospf_without_auth_flagged if has("2.2.1", {"junos_config": {"protocols": {"ospf": {"area": {"0.0.0.0": {}}}}}})
test_no_routing_protocol_not_flagged if not has("2.2.1", {"junos_config": {"protocols": {}}})

# ── Evidence rule (audit 2026-11-24) ─────────────────────────────────────────

good_input := {
	"junos_config": {
		"system": {
			"login": {"user": [{"name": "root", "authentication": {"encrypted_password": "$6$salt$hash"}}]},
			"services": {"ssh": {"protocol_version": "v2", "root_login": "deny"}},
			"syslog": {"file": [{"name": "security", "contents": [{"name": "authorization"}]}]},
			"ntp": {"authentication_key": [{"name": "1", "type": "sha256"}], "trusted_key": ["1"]},
			"tacplus_server": [{"name": "192.0.2.10"}],
		},
		"firewall": {"family": {"inet": {"filter": [
			{"name": "CONTROL_PLANE_FILTER"},
			{"name": "ANTI_SPOOFING", "term": [{"from": {"source_address": "0.0.0.0/8"}, "then": "discard"}]},
		]}}},
		"interfaces": {"lo0": {"unit": {"0": {"family": {"inet": {"filter": {"input": "CONTROL_PLANE_FILTER"}}}}}}},
		"protocols": {
			"rstp": {"bpdu_block_on_edge": true},
			"bgp": {"group": [{"name": "ebgp", "authentication_key": "$9$examplekey"}]},
		},
	},
	"external_interfaces": [{"name": "ge-0/0/0", "unit": {"0": {"family": {"inet": {"filter": {"input": "INGRESS"}}}}}}],
}

_v(inp) := v if {
	v := data.cis_juniper_junos.violations with input as inp
}

test_good_input_is_compliant if {
	_v(good_input) == []
	data.cis_juniper_junos.compliant with input as good_input
}

test_empty_input_fails_every_check if count(_v({})) == 10

# [message prefix, JSON pointer of a fact the check reads]
_facts := [
	["1.1.1", "/junos_config/system/login/user/0/authentication"],
	["UNMAPPED-JUNOS-1.1", "/junos_config/system/tacplus_server"],
	["UNMAPPED-JUNOS-1.2", "/junos_config/system/services/ssh/protocol_version"],
	["UNMAPPED-JUNOS-1.2", "/junos_config/system/services/ssh/root_login"],
	["UNMAPPED-JUNOS-1.3", "/junos_config/system/syslog/file"],
	["UNMAPPED-JUNOS-1.4", "/junos_config/system/ntp/authentication_key"],
	["UNMAPPED-JUNOS-1.4", "/junos_config/system/ntp/trusted_key"],
	["2.1.1", "/junos_config/interfaces/lo0/unit/0/family/inet/filter/input"],
	["2.2.1", "/junos_config/protocols/bgp/group/0/authentication_key"],
	["2.2.1", "/junos_config/protocols"],
	["3.1.1", "/external_interfaces"],
	["3.1.1", "/external_interfaces/0/unit/0/family/inet/filter/input"],
	["UNMAPPED-JUNOS-3.2", "/junos_config/firewall/family/inet/filter/1/term/0/then"],
	["UNMAPPED-JUNOS-3.3", "/junos_config/protocols/rstp/bpdu_block_on_edge"],
]

test_each_fact_of_a_wrong_type_fails_its_check if {
	every f in _facts {
		every bad in ["true", "false", "no", null, false, ""] {
			has(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": bad}]))
		}
	}
}

test_each_fact_removed_fails_its_check if {
	every f in _facts {
		has(f[0], json.remove(good_input, [f[1]]))
	}
}

test_no_external_interfaces_is_a_statement_not_a_gap if {
	not has("3.1.1", json.patch(good_input, [{"op": "replace", "path": "/external_interfaces", "value": []}]))
}
