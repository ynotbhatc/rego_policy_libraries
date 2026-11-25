package cis_opnsense_test

import rego.v1

# Evidence rule (audit 2026-11-24). Legacy checkboxes are present-or-absent, so a present flag is set unless it
# holds an "off" spelling, the string "false" included. MVC BooleanFields are "1" / "0": the string "true" is
# not a BooleanField value.

test_off_spellings_of_a_required_legacy_flag_fail if {
	every f in [["2.3", "/system/disableconsolemenu"], ["1.8", "/system/webgui/ssl-hsts"]] {
		every off in ["false", "False", " FALSE ", "no", "off", "disabled", "0", false, 0] {
			fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": off}]))
		}
		every on in ["", null, "1", "yes", true] {
			not fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": on}]))
		}
	}
}

_mvc_facts := [
	["1.6", "/OPNsense/Interfaces/settings/disableipv6"],
	["5.2.1", "/OPNsense/unboundplus/general/dnssec"],
	["6.3", "/OPNsense/Syslog/destinations/destination/0/enabled"],
]

test_mvc_boolean_is_on_only_as_1 if {
	every f in _mvc_facts {
		every bad in ["true", "True", "yes", "on", "enabled", "false", "no", "0", "", null, false, 0, 2, [1]] {
			fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": bad}]))
		}
		every on in ["1", 1, true] {
			not fails(f[0], json.patch(good_input, [{"op": "replace", "path": f[1], "value": on}]))
		}
	}
}

# 1.5 reads addresses: a word in their place is not a configured DNS server
test_dns_server_is_an_address if {
	every bad in ["true", "false", "no", "yes", "", null, true, 1] {
		fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": [bad]}]))
		fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": bad}]))
	}
	every ok in ["192.0.2.53", "2001:db8::53"] {
		not fails("1.5", json.patch(good_input, [{"op": "replace", "path": "/system/dnsserver", "value": ok}]))
	}
}

test_attestations_of_a_wrong_type_fail if {
	every key, _ in good_input.attest {
		every bad in ["true", "false", 1, null] {
			inp := json.patch(good_input, [{"op": "replace", "path": sprintf("/attest/%s", [key]), "value": bad}])
			not data.cis_opnsense.compliant with input as inp
		}
	}
}
