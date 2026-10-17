package cis_arista_eos_test

import rego.v1

good := {
	"external_interfaces": [{"access_group": {"in": "ACL1"}}],
	"eos_config": {
		"aaa": {
			"authentication": {"default": ["local"]},
			"authorization": {"exec": {"default": "local"}},
			"accounting": {"exec": {"default": "start-stop"}},
		},
		"logging": {"on": true},
		"management": {"console": {"idle_timeout": 5}},
		"control_plane": {"service_policy": {"input": "COPP"}},
		"policy_map": [{"class": [{"police": {"rate": 1}}]}],
		"ip": {
			"source_route": false,
			"access_list": {"extended": [{"name": "ANTI_SPOOFING", "rule": [{"source": "10.0.0.0/8", "action": "deny"}]}]},
			"dhcp": {"snooping": true},
			"arp": {"inspection": {"vlan": [{"enabled": true}]}},
		},
		"event_monitor": {"enabled": true},
	},
}

test_full_config_compliant if data.cis_arista_eos.compliant with input as good

test_partial_facts_not_compliant if {
	inp := {"eos_config": {"aaa": {"authentication": {"default": ["local"]}}, "logging": {"on": true}}}
	not data.cis_arista_eos.compliant with input as inp
}

test_compliant_is_false_not_undefined if {
	data.cis_arista_eos.compliant == false with input as {}
}

test_missing_interfaces_fail_closed if {
	inp := object.remove(good, ["external_interfaces"])
	not data.cis_arista_eos.compliant with input as inp
}

test_long_vty_timeout_flagged if {
	inp := object.union(good, {"eos_config": {"management": {"console": {"idle_timeout": 60}}}})
	v := data.cis_arista_eos.violations with input as inp
	"1.2.1: Ensure VTY/console idle timeout is configured and at most 10 minutes" in v
}

test_dhcp_snooping_missing_flagged if {
	inp := json.remove(good, ["eos_config/ip/dhcp"])
	v := data.cis_arista_eos.violations with input as inp
	"3.3.1: Ensure DHCP snooping is enabled" in v
}
