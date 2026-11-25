package cis_cisco_ios_test

import rego.v1

three := ["aaa new-model", "no service finger", "no ip source-route"]

test_three_lines_not_compliant if {
	not data.cis_cisco_ios.compliant with input as {"cisco_config": three}
}

test_compliant_is_false_not_undefined if {
	data.cis_cisco_ios.compliant == false with input as {}
}

test_missing_config_is_evidence_violation if {
	v := data.cis_cisco_ios.violations with input as {}
	"0.0: evidence missing — cisco_config not collected" in v
}

test_unwired_controls_now_evaluated if {
	v := data.cis_cisco_ios.violations with input as {"cisco_config": three}
	"UNMAPPED-CISCO-1.22: logging on must be explicitly configured" in v
	"UNMAPPED-CISCO-1.19: ssh version 2 must be explicitly configured" in v
	"UNMAPPED-CISCO-2.2: service pad must be turned off" in v
}

test_present_line_clears_violation if {
	inp := {"cisco_config": array.concat(three, ["logging on", "ip ssh version 2", "no service pad"])}
	v := data.cis_cisco_ios.violations with input as inp
	not "UNMAPPED-CISCO-1.22: logging on must be explicitly configured" in v
	not "UNMAPPED-CISCO-1.19: ssh version 2 must be explicitly configured" in v
	not "UNMAPPED-CISCO-2.2: service pad must be turned off" in v
}

test_report_populated_when_failing if {
	r := data.cis_cisco_ios.compliance_summary with input as {"cisco_config": three}
	r.failing_controls > 0
	r.sections.management_plane.violations > 0
}

# ── Evidence rule (audit 2026-11-24): an all-pass fixture, and the same fixture with facts of the wrong type ──

good_input := {
	"cisco_config": [
		"aaa new-model",
		"aaa authentication login default group tacacs+ local",
		"aaa authorization exec default group tacacs+ local",
		"aaa accounting exec default start-stop group tacacs+",
		"aaa accounting commands 15 default start-stop group tacacs+",
		"aaa accounting connection default start-stop group tacacs+",
		"aaa accounting system default start-stop group tacacs+",
		"enable secret 9 $9$example",
		"service password-encryption",
		"banner motd ^Authorized use only^",
		"banner login ^Authorized use only^",
		"banner exec ^Authorized use only^",
		"ip ssh version 2",
		"ip ssh time-out 60",
		"ip ssh authentication-retries 3",
		"logging on",
		"logging buffered 64000",
		"logging console critical",
		"logging host 192.0.2.20",
		"logging trap informational",
		"service timestamps log datetime msec",
		"service timestamps debug datetime msec",
		"ntp authenticate",
		"ntp authentication-key 1 md5 example",
		"ntp trusted-key 1",
		"ntp server 192.0.2.30 key 1",
		"snmp-server location dc1",
		"snmp-server contact noc@example.com",
		"no service finger",
		"no service pad",
		"no service udp-small-servers",
		"no service tcp-small-servers",
		"no cdp run",
		"no lldp run",
		"no service dhcp",
		"no ip bootp server",
		"no ip http server",
		"no ip http secure-server",
		"control-plane",
		"no ip source-route",
	],
	"vty_config": ["transport input ssh", "exec-timeout 10 0", "logging synchronous", "access-class 10 in"],
	"console_config": ["exec-timeout 10 0", "logging synchronous"],
	"access_lists": [{"type": "extended", "name": "INFRASTRUCTURE_ACL"}],
}

_v(inp) := v if {
	v := data.cis_cisco_ios.violations with input as inp
}

test_good_input_is_compliant if {
	_v(good_input) == []
	data.cis_cisco_ios.compliant with input as good_input
}

# every configuration line carries a check: removing any one opens a finding
test_each_line_removed_fails if {
	every key in ["cisco_config", "vty_config", "console_config", "access_lists"] {
		every i, _ in good_input[key] {
			count(_v(json.remove(good_input, [sprintf("/%s/%d", [key, i])]))) > 0
		}
	}
}

# a section that is missing, null, or a string / boolean where the list of lines belongs never passes
test_each_section_of_a_wrong_type_fails if {
	every key in ["cisco_config", "vty_config", "console_config", "access_lists"] {
		count(_v(json.remove(good_input, [sprintf("/%s", [key])]))) > 0
		every bad in ["true", "false", "no", null, true, false, 1, {}, []] {
			inp := json.patch(good_input, [{"op": "replace", "path": sprintf("/%s", [key]), "value": bad}])
			count(_v(inp)) > 0
			not data.cis_cisco_ios.compliant with input as inp
		}
	}
}

# lines that are not strings are not configuration
test_non_string_lines_fail if {
	inp := json.patch(good_input, [{"op": "replace", "path": "/cisco_config", "value": [true, "true", 1, null]}])
	count(_v(inp)) >= 40
}

test_numeric_ssh_settings_are_read_from_the_line if {
	"UNMAPPED-CISCO-1.20: ssh timeout must be explicitly configured" in _v(json.patch(good_input, [{"op": "replace", "path": "/cisco_config/13", "value": "ip ssh time-out 120"}]))
	"UNMAPPED-CISCO-1.20: ssh timeout must be explicitly configured" in _v(json.patch(good_input, [{"op": "replace", "path": "/cisco_config/13", "value": "ip ssh time-out true"}]))
	"UNMAPPED-CISCO-1.21: ssh auth retries must be explicitly configured" in _v(json.patch(good_input, [{"op": "replace", "path": "/cisco_config/14", "value": "ip ssh authentication-retries 5"}]))
}
