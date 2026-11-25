package cis_pfsense_test

import rego.v1

# Evidence rule (audit 2026-11-24). config.xml checkbox flags are present-or-absent, so a present flag is set;
# the explicit "off" spellings a normalising collector sends, the string "false" included, are not.

_flag_facts := [
	["2.3", "/system/disableconsolemenu"],
	["5.1.1", "/snmpd/trapenable"],
	["5.1.2", "/snmpd/trapenable"],
	["5.3.1", "/unbound/dnssec"],
	["6.1", "/syslogd/enable"],
	["4.1.5", "/filter/rule/0/log"],
]

test_off_spellings_of_a_required_flag_fail if {
	every f in _flag_facts {
		every off in ["false", "False", " FALSE ", "no", "off", "disabled", "0", false, 0] {
			fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": off}]))
		}
		fails(f[0], json.remove(good_input, [f[1]]))
	}
}

test_present_flag_encodings_are_set if {
	every f in _flag_facts {
		every on in ["", null, {}, "1", "yes", "on", "enabled", true] {
			not fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": on}]))
		}
	}
}

# flags the benchmark wants cleared: any present form but an "off" spelling fails
test_flags_that_must_be_clear if {
	every f in [["1.6", "/system/ipv6allow"], ["1.7", "/system/webgui/nodnsrebindcheck"]] {
		every on in ["", null, "true", "yes", true] {
			fails(f[0], json.patch(good_input, [{"op": "add", "path": f[1], "value": on}]))
		}
		every off in ["false", "no", false, 0] {
			not fails(f[0], json.patch(good_input, [{"op": "add", "path": f[1], "value": off}]))
		}
	}
}

# a rule or VPN server "disabled" with an off spelling is still active and still judged
test_disabled_false_does_not_hide_a_rule_or_server if {
	every off in ["false", "no", false] {
		rule := json.patch(good_input, [
			{"op": "add", "path": "/filter/rule/0/disabled", "value": off},
			{"op": "remove", "path": "/filter/rule/0/log"},
		])
		fails("4.1.5", rule)
		vpn := json.patch(good_input, [
			{"op": "add", "path": "/openvpn/openvpn-server/0/disabled", "value": off},
			{"op": "replace", "path": "/openvpn/openvpn-server/0/mode", "value": "p2p_shared_key"},
		])
		fails("5.4.3", vpn)
	}
}

# 1.5 and 1.9 read addresses: a word in their place is not a configured DNS server or sync peer
test_dns_server_and_sync_peer_are_addresses if {
	every bad in ["true", "false", "no", "yes", "", null, true, 1] {
		fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": [bad]}]))
		fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": bad}]))
		fails("1.9", json.patch(good_input, [{"op": "replace", "path": "/hasync/synchronizetoip", "value": bad}]))
	}
	every ok in ["192.0.2.53", "2001:db8::53", " 10.0.0.2 "] {
		not fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": ok}]))
		not fails("1.9", json.patch(good_input, [{"op": "replace", "path": "/hasync/synchronizetoip", "value": ok}]))
	}
}

test_attestations_of_a_wrong_type_fail if {
	every key, _ in good_input.attest {
		every bad in ["true", "false", 1, null] {
			inp := json.patch(good_input, [{"op": "replace", "path": sprintf("/attest/%s", [key]), "value": bad}])
			not data.cis_pfsense.compliant with input as inp
		}
	}
}
