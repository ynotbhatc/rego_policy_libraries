package cis_vyos_test

import rego.v1

# Evidence rule (audit 2026-11-24): a hardened router in the shape `show configuration json` gives passes every
# control; the same document with one fact removed or replaced by something VyOS never writes does not.

good_input := {
	"system": {
		"host-name": "edge-router-01",
		"domain-name": "example.com",
		"time-zone": "Etc/UTC",
		"name-server": ["192.0.2.53", "198.51.100.53"],
		"ip": {"disable-source-route": {}},
		"login": {
			"banner": "Authorized use only. Activity is monitored.",
			"user": {"netadmin": {"level": "admin", "authentication": {"encrypted-password": "$6$rounds=656000$examplesalt$examplehash", "plaintext-password": ""}}},
		},
		"ntp": {"server": {"time.example.com": {}}},
		"syslog": {"host": {"192.0.2.20": {"facility": {"all": {"level": "info"}}}}},
		"console": {"device": {"ttyS0": {"speed": "115200", "timeout-login": "300"}}},
	},
	"service": {"ssh": {"port": "22", "client-keepalive-interval": "60", "disable-password-authentication": {}}},
	"firewall": {"name": {"WAN-IN": {
		"default-action": "drop",
		"rule": {
			"10": {"action": "accept", "state": {"established": {"action": "accept"}, "related": {"action": "accept"}}},
			"20": {"action": "drop", "log": {}},
		},
	}}},
	"interfaces": {"ethernet": {"eth0": {"address": "dhcp", "description": "WAN", "firewall": {"in": {"name": "WAN-IN"}}}}},
	"version": "VyOS 1.4.0",
}

_report(inp) := r if {
	r := data.cis_vyos.main.compliance_report with input as inp
}

_ids(inp) := {split(v, " ")[0] | some v in _report(inp).violations}

test_hardened_router_passes if {
	r := _report(good_input)
	r.compliant == true
	r.violations == []
	r.total_controls == 23
	r.passed_controls == 23
	r.failed_controls == 0
}

test_empty_input_fails if {
	r := _report({})
	r.compliant == false
	r.failed_controls == 23
	r.passed_controls == 0
}

# [control the mutation must fail, JSON pointer, what to do]
_facts := [
	["1.1.1", "/service/ssh"],
	["1.1.3", "/service/ssh/disable-password-authentication"],
	["1.1.4", "/service/ssh/client-keepalive-interval"],
	["1.1.6", "/system/login/banner"],
	["2.1.4", "/system/ntp/server"],
	["2.1.5", "/system/syslog/host"],
	["2.1.6", "/system/name-server"],
	["3.1.1", "/firewall/name"],
	["3.1.2", "/interfaces/ethernet/eth0/firewall/in/name"],
	["3.1.3", "/firewall/name/WAN-IN/default-action"],
	["3.1.5", "/firewall/name/WAN-IN/rule/20/log"],
	["3.1.6", "/system/ip/disable-source-route"],
	["4.1.2", "/system/login/user/netadmin/authentication/encrypted-password"],
	["5.1.1", "/system/host-name"],
	["5.1.2", "/system/time-zone"],
	["5.1.3", "/system/console/device/ttyS0/timeout-login"],
]

# values no VyOS configuration holds in these places
_bad_values := [false, 2.5e9, [1]]

test_each_fact_removed_fails_its_control if {
	every f in _facts {
		inp := json.remove(good_input, [f[1]])
		f[0] in _ids(inp)
		_report(inp).compliant == false
	}
}

test_each_fact_of_another_type_fails_its_control if {
	every f in _facts {
		every bad in _bad_values {
			inp := json.patch(good_input, [{"op": "replace", "path": f[1], "value": bad}])
			f[0] in _ids(inp)
		}
	}
}

# the strings a careless collector sends for a yes/no: none of them is a valueless node, a subtree, a list or a number
_typed_facts := [f | some f in _facts; not f[0] in {"1.1.6", "5.1.1", "5.1.2"}]

test_string_booleans_never_pass if {
	every f in _typed_facts {
		every bad in ["true", "false", "no", "yes"] {
			inp := json.patch(good_input, [{"op": "replace", "path": f[1], "value": bad}])
			f[0] in _ids(inp)
		}
	}
}

test_null_is_not_a_value if {
	# null is how an empty node may be serialised, so the node facts are left out
	every f in [f | some f in _facts; not f[0] in {"1.1.1", "1.1.3", "3.1.5", "3.1.6"}] {
		inp := json.patch(good_input, [{"op": "replace", "path": f[1], "value": null}])
		f[0] in _ids(inp)
	}
}

test_default_user_needs_a_real_hash if {
	base := json.patch(good_input, [{"op": "add", "path": "/system/login/user/vyos", "value": {"authentication": {"encrypted-password": "$6$salt$hash"}}}])
	not "4.1.1" in _ids(base)
	every bad in ["$6$defaultvyos", "true", "false", "", null, false, true, 1] {
		inp := json.patch(base, [{"op": "replace", "path": "/system/login/user/vyos/authentication/encrypted-password", "value": bad}])
		"4.1.1" in _ids(inp)
	}
}

test_name_server_is_an_address_or_an_interface if {
	every ok in [["2001:db8::53"], ["eth0"], ["192.0.2.53", "eth1.100"]] {
		not "2.1.6" in _ids(json.patch(good_input, [{"op": "replace", "path": "/system/name-server", "value": ok}]))
	}
	every bad in [["true"], ["false"], ["no"], [""], [false], []] {
		"2.1.6" in _ids(json.patch(good_input, [{"op": "replace", "path": "/system/name-server", "value": bad}]))
	}
}

test_wan_ruleset_must_exist if {
	inp := json.patch(good_input, [{"op": "replace", "path": "/interfaces/ethernet/eth0/firewall/in/name", "value": "NO-SUCH"}])
	"3.1.2" in _ids(inp)
}

# nodes that must be absent: present in any form fails, and a form VyOS never writes says so
_forbidden := [
	["1.1.2", "/service/ssh/v1-enabled", {}],
	["1.1.5", "/service/ssh/allow-root", {}],
	["2.1.1", "/service/telnet", {"port": "23"}],
	["2.1.2", "/service/http", {}],
	["2.1.3", "/service/snmp", {"community": {"public": {"authorization": "ro"}}}],
]

test_forbidden_nodes_fail_when_present if {
	every f in _forbidden {
		every v in [f[2], null, "true", "false", "no", 1] {
			inp := json.patch(good_input, [{"op": "add", "path": f[1], "value": v}])
			f[0] in _ids(inp)
		}
	}
}

test_forbidden_node_of_another_type_is_named if {
	inp := json.patch(good_input, [{"op": "add", "path": "/service/telnet", "value": "false"}])
	"2.1.1 evidence invalid — service.telnet must be an object, got string" in _report(inp).violations
	inp2 := json.patch(good_input, [{"op": "add", "path": "/service/ssh/v1-enabled", "value": "false"}])
	"1.1.2 evidence invalid — service.ssh.v1-enabled must be a valueless node ({}), got string" in _report(inp2).violations
}

test_explicit_false_is_not_configured if {
	inp := json.patch(good_input, [
		{"op": "add", "path": "/service/telnet", "value": false},
		{"op": "add", "path": "/service/ssh/allow-root", "value": false},
	])
	_report(inp).compliant == true
}

test_service_not_collected_is_missing_evidence if {
	inp := json.remove(good_input, ["/service"])
	v := _report(inp).violations
	every id in ["2.1.1", "2.1.2", "2.1.3"] {
		sprintf("%s evidence missing — input.service not collected", [id]) in v
	}
}

test_snmp_v3_without_community_passes if {
	inp := json.patch(good_input, [{"op": "add", "path": "/service/snmp", "value": {"v3": {"user": {"monitor": {}}}}}])
	_report(inp).compliant == true
}

test_users_not_collected_is_not_a_renamed_default_user if {
	inp := json.remove(good_input, ["/system/login/user"])
	{"4.1.1", "4.1.2"} & _ids(inp) == {"4.1.1", "4.1.2"}
}

test_real_plaintext_password_fails if {
	inp := json.patch(good_input, [{"op": "replace", "path": "/system/login/user/netadmin/authentication/plaintext-password", "value": "hunter2"}])
	"4.1.2" in _ids(inp)
}

test_counts_hold_on_bad_input if {
	every bad in ["true", "false", null] {
		inp := {"system": bad, "service": bad, "firewall": bad, "interfaces": bad}
		r := _report(inp)
		r.compliant == false
		r.passed_controls + r.failed_controls == r.total_controls
		r.failed_controls <= r.total_controls
	}
}
