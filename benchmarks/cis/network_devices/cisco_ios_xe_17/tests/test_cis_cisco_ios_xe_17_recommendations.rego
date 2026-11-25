package cis_cisco_ios_xe_17_test

import rego.v1

import data.cis_cisco_ios_xe_17 as b

# Generated per-recommendation tests for CIS Cisco IOS XE 17.x Benchmark v2.2.2 (tools/cis_generators/gen_cisco_ios_xe_17.py): every recommendation
# has a pass test (green input) and a fail test; configuration checks also have an evidence-missing test;
# attestations fail when false or absent. Hand-written tests live in test_cis_cisco_ios_xe_17_controls.rego.

green := {"ios_xe_config": {
	"lines": [
		"hostname edge-r1",
		"aaa new-model",
		"aaa authentication login default group tacacs+ local",
		"aaa authentication enable default group tacacs+ enable",
		"aaa accounting commands 15 default start-stop group tacacs+",
		"aaa accounting connection default start-stop group tacacs+",
		"aaa accounting exec default start-stop group tacacs+",
		"aaa accounting network default start-stop group tacacs+",
		"aaa accounting system default start-stop group tacacs+",
		"enable secret 9 $9$abcdef",
		"service password-encryption",
		"username admin privilege 1 secret 9 $9$ghijkl",
		"ip domain name example.net",
		"ip ssh time-out 60",
		"ip ssh authentication-retries 3",
		"ip ssh version 2",
		"no cdp run",
		"no ip bootp server",
		"no service dhcp",
		"service tcp-keepalives-in",
		"service tcp-keepalives-out",
		"no service pad",
		"login on-failure log",
		"login on-success log",
		"logging buffered 64000",
		"logging console critical",
		"logging host 10.20.30.40",
		"logging trap informational",
		"service timestamps debug datetime msec show-timezone",
		"logging source-interface Loopback0",
		"ntp authenticate",
		"ntp authentication-key 1 md5 0a1b2c",
		"ntp trusted-key 1",
		"ntp server 10.20.30.41 key 1",
		"ntp source Loopback0",
		"ip tftp source-interface Loopback0",
		"ip radius source-interface Loopback0",
		"no ip source-route",
		"ip http secure-server",
		"ip http max-connections 2",
		"ip http authentication aaa",
		"ip http timeout-policy idle 600 life 86400 requests 3",
		"ip admission auth-proxy-banner http ^Cauthorised use only^C",
		"snmp-server community s3cr3t RO 10",
		"snmp-server host 10.20.30.42 version 2c s3cr3t",
		"snmp-server enable traps snmp authentication linkup linkdown coldstart",
		"snmp-server group NMS v3 priv",
		"archive",
		"interface Loopback0",
		"interface GigabitEthernet0/0/0",
		"line con 0",
		"line aux 0",
		"line vty 0 4",
		"line vty 5 15",
	],
	"sections": [
		{
			"header": "archive",
			"lines": [
				"log config",
				"logging enable",
			],
		},
		{
			"header": "interface Loopback0",
			"lines": ["ip address 10.255.255.1 255.255.255.255"],
		},
		{
			"header": "interface GigabitEthernet0/0/0",
			"lines": [
				"ip address 192.0.2.1 255.255.255.0",
				"no ip proxy-arp",
			],
		},
		{
			"header": "line con 0",
			"lines": ["exec-timeout 5 0"],
		},
		{
			"header": "line aux 0",
			"lines": [
				"no exec",
				"exec-timeout 5 0",
			],
		},
		{
			"header": "line vty 0 4",
			"lines": [
				"exec-timeout 10 0",
				"access-class 10 in",
				"login authentication default",
				"transport input ssh",
			],
		},
		{
			"header": "line vty 5 15",
			"lines": [
				"exec-timeout 10 0",
				"access-class 10 in",
				"login authentication default",
				"transport input ssh",
			],
		},
	],
	"banners": {
		"exec": "Authorised use only.",
		"login": "Authorised use only.",
		"motd": "Authorised use only.",
	},
	"attest": {
		"vty_acl_defined": true,
		"snmp_disabled_when_unused": true,
		"snmp_acl_defined": true,
		"snmpv3_user_aes128_minimum": true,
		"rsa_modulus_2048_or_more": true,
		"urpf_on_untrusted_interfaces": true,
		"private_source_acl_defined": true,
		"external_interface_acl_inbound": true,
		"eigrp_key_chain_defined": true,
		"eigrp_key_defined": true,
		"eigrp_key_string_set": true,
		"eigrp_address_family_set": true,
		"eigrp_af_interface_default": true,
		"eigrp_af_key_chain": true,
		"eigrp_af_auth_md5": true,
		"eigrp_interface_key_chain": true,
		"eigrp_interface_auth_mode": true,
		"ospf_area_message_digest": true,
		"ospf_interface_md5_key": true,
		"bgp_neighbor_password": true,
	},
}}

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

test_green_input_is_compliant if {
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	s := b.compliance_summary with input as green
	s.passing_controls == 84
	s.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 84
	count([id | some id, r in b.recommendations; r.level == 2]) == 9
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 51
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == 20
}

test_empty_input_fails_every_recommendation if {
	r := b.compliance_report with input as {}
	r.total_controls == 84
	r.failed_controls == 84
	r.compliant == false
}

test_level_1_profile_scopes_the_report if {
	inp := json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": 1}}])
	r := b.compliance_report with input as inp
	r.total_controls == 75
	r.failed_controls == 0
	e := b.compliance_report with input as {"cis_profile": {"level": 1}}
	e.total_controls == 75
	e.failed_controls == 75
}

# cis_profile.level must be the number 1 or 2: anything else is reported, the report is scoped at Level 2 and
# the Level 2 recommendations fail, so a mistyped level can never shrink the assessment into a pass
test_level_must_be_the_number_1_or_2 if {
	every lv in ["1", "2", "high", 0, 3, 1.5, true, false, null, [1], {"level": 1}] {
		r := b.compliance_report with input as json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": lv}}])
		r.compliant == false
		r.level == 2
		r.total_controls == 84
		r.failed_controls == 9
		r.passed_controls + r.failed_controls == r.total_controls
		some v in r.violations
		startswith(v, "cis_profile.level: evidence invalid — cis_profile.level must be the number 1 or 2, got ")
	}
	every cp in ["1", 1, null, [1], true] {
		r := b.compliance_report with input as json.patch(green, [{"op": "add", "path": "/cis_profile", "value": cp}])
		r.compliant == false
		r.failed_controls == 9
	}
}

test_level_numbers_and_absent_level_are_valid if {
	l2 := b.compliance_report with input as json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": 2}}])
	l2.compliant == true
	l2.total_controls == 84
	none := b.compliance_report with input as json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {}}])
	none.compliant == true
	none.total_controls == 84
}

test_level_2_only_recommendation_skipped_at_level_1 if {
	inp := json.patch(green, [
		{"op": "add", "path": "/cis_profile", "value": {"level": 1}},
		{"op": "replace", "path": "/ios_xe_config/sections/2/lines/1", "value": "ip proxy-arp"},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "3.1.2")
}

test_1_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.1")
}

test_1_1_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/1"}])
	vs := b.violations with input as inp
	"1.1.1: AAA must be turned on globally (aaa new-model)" in vs
}

test_1_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.1: AAA must be turned on globally (aaa new-model)" in vs
}

test_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.2")
}

test_1_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/2"}])
	vs := b.violations with input as inp
	"1.1.2: a login authentication method list must be configured" in vs
}

test_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.2: a login authentication method list must be configured" in vs
}

test_1_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.3")
}

test_1_1_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/3"}])
	vs := b.violations with input as inp
	"1.1.3: enable-mode authentication must use an AAA default method list" in vs
}

test_1_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.3: enable-mode authentication must use an AAA default method list" in vs
}

test_1_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.4")
}

test_1_1_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections/6/lines/2"}, {"op": "remove", "path": "/ios_xe_config/sections/5/lines/2"}])
	vs := b.violations with input as inp
	"1.1.4: every vty line block must set login authentication" in vs
}

test_1_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.1.4: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.1.4: every vty line block must set login authentication" in vs
}

test_1_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.5")
}

test_1_1_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/40"}])
	vs := b.violations with input as inp
	"1.1.5: when the HTTP server is on, ip http authentication must be set" in vs
}

test_1_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.5: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.5: when the HTTP server is on, ip http authentication must be set" in vs
}

test_1_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.6")
}

test_1_1_6_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/4"}])
	vs := b.violations with input as inp
	"1.1.6: privilege 15 command accounting must be configured" in vs
}

test_1_1_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.6: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.6: privilege 15 command accounting must be configured" in vs
}

test_1_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.7")
}

test_1_1_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/5"}])
	vs := b.violations with input as inp
	"1.1.7: connection accounting must be configured" in vs
}

test_1_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.7: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.7: connection accounting must be configured" in vs
}

test_1_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.8")
}

test_1_1_8_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/6"}])
	vs := b.violations with input as inp
	"1.1.8: EXEC session accounting must be configured" in vs
}

test_1_1_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.8: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.8: EXEC session accounting must be configured" in vs
}

test_1_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.9")
}

test_1_1_9_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/7"}])
	vs := b.violations with input as inp
	"1.1.9: network accounting must be configured" in vs
}

test_1_1_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.9: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.9: network accounting must be configured" in vs
}

test_1_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.10")
}

test_1_1_10_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/8"}])
	vs := b.violations with input as inp
	"1.1.10: system accounting must be configured" in vs
}

test_1_1_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.1.10: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.1.10: system accounting must be configured" in vs
}

test_1_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.1")
}

test_1_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "username ops privilege 15 secret 9 $9$zzzzzz"}])
	vs := b.violations with input as inp
	"1.2.1: every local username must be at privilege level 1 (none above)" in vs
}

test_1_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.2.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.2.1: every local username must be at privilege level 1 (none above)" in vs
}

test_1_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.2")
}

test_1_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/sections/5/lines/3", "value": "transport input ssh telnet"}])
	vs := b.violations with input as inp
	"1.2.2: every vty line block must allow only ssh for transport input" in vs
}

test_1_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.2: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.2: every vty line block must allow only ssh for transport input" in vs
}

test_1_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.3")
}

test_1_2_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections/4/lines/0"}])
	vs := b.violations with input as inp
	"1.2.3: the aux line must have no exec (a device with no aux line passes)" in vs
}

test_1_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.3: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.3: the aux line must have no exec (a device with no aux line passes)" in vs
}

test_1_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.4")
}

test_1_2_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/vty_acl_defined", "value": false}])
	vs := b.violations with input as inp
	"1.2.4: an access list for the vty lines must exist and be appropriate (manual review not attested)" in vs
}

test_1_2_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/vty_acl_defined"}])
	vs := b.violations with input as inp
	"1.2.4: an access list for the vty lines must exist and be appropriate (manual review not attested)" in vs
}

test_1_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.5")
}

test_1_2_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections/6/lines/1"}, {"op": "remove", "path": "/ios_xe_config/sections/5/lines/1"}])
	vs := b.violations with input as inp
	"1.2.5: every vty line block must set an inbound access-class" in vs
}

test_1_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.5: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.5: every vty line block must set an inbound access-class" in vs
}

test_1_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.6")
}

test_1_2_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/sections/4/lines/1", "value": "exec-timeout 0 0"}])
	vs := b.violations with input as inp
	"1.2.6: the aux line exec-timeout must be 1 to 10 minutes (a device with no aux line passes)" in vs
}

test_1_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.6: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.6: the aux line exec-timeout must be 1 to 10 minutes (a device with no aux line passes)" in vs
}

test_1_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.7")
}

test_1_2_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/sections/3/lines/0", "value": "exec-timeout 30 0"}])
	vs := b.violations with input as inp
	"1.2.7: the console line exec-timeout must be 1 to 10 minutes" in vs
}

test_1_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.7: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.7: the console line exec-timeout must be 1 to 10 minutes" in vs
}

test_1_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.8")
}

test_1_2_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/sections/5/lines/0", "value": "exec-timeout 0 0"}])
	vs := b.violations with input as inp
	"1.2.8: every vty line block must have an exec-timeout of 1 to 10 minutes" in vs
}

test_1_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"1.2.8: evidence missing — ios_xe_config.sections not collected" in vs
	not "1.2.8: every vty line block must have an exec-timeout of 1 to 10 minutes" in vs
}

test_1_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.9")
}

test_1_2_9_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/39", "value": "ip http max-connections 10"}])
	vs := b.violations with input as inp
	"1.2.9: when the HTTP server is on, ip http max-connections must be 1 or 2" in vs
}

test_1_2_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.2.9: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.2.9: when the HTTP server is on, ip http max-connections must be 1 or 2" in vs
}

test_1_2_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.10")
}

test_1_2_10_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/41", "value": "ip http timeout-policy idle 0 life 86400 requests 3"}])
	vs := b.violations with input as inp
	"1.2.10: when the HTTP server is on, the ip http idle timeout must be 1 to 600 seconds" in vs
}

test_1_2_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.2.10: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.2.10: when the HTTP server is on, the ip http idle timeout must be 1 to 600 seconds" in vs
}

test_1_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.1")
}

test_1_3_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/banners/exec", "value": " "}])
	vs := b.violations with input as inp
	"1.3.1: a exec banner with text must be configured" in vs
}

test_1_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/banners"}])
	vs := b.violations with input as inp
	"1.3.1: evidence missing — ios_xe_config.banners not collected" in vs
	not "1.3.1: a exec banner with text must be configured" in vs
}

test_1_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.2")
}

test_1_3_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/banners/login", "value": " "}])
	vs := b.violations with input as inp
	"1.3.2: a login banner with text must be configured" in vs
}

test_1_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/banners"}])
	vs := b.violations with input as inp
	"1.3.2: evidence missing — ios_xe_config.banners not collected" in vs
	not "1.3.2: a login banner with text must be configured" in vs
}

test_1_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.3")
}

test_1_3_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/banners/motd", "value": " "}])
	vs := b.violations with input as inp
	"1.3.3: a motd banner with text must be configured" in vs
}

test_1_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/banners"}])
	vs := b.violations with input as inp
	"1.3.3: evidence missing — ios_xe_config.banners not collected" in vs
	not "1.3.3: a motd banner with text must be configured" in vs
}

test_1_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.4")
}

test_1_3_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/42"}])
	vs := b.violations with input as inp
	"1.3.4: a webauth (auth-proxy) banner must be configured" in vs
}

test_1_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.3.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.3.4: a webauth (auth-proxy) banner must be configured" in vs
}

test_1_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.1")
}

test_1_4_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/9"}])
	vs := b.violations with input as inp
	"1.4.1: an enable secret of hash type 5, 8 or 9 must be set" in vs
}

test_1_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.4.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.4.1: an enable secret of hash type 5, 8 or 9 must be set" in vs
}

test_1_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.2")
}

test_1_4_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/10"}])
	vs := b.violations with input as inp
	"1.4.2: service password-encryption must be on" in vs
}

test_1_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.4.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.4.2: service password-encryption must be on" in vs
}

test_1_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.3")
}

test_1_4_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "username bob password 7 0822455D0A16"}])
	vs := b.violations with input as inp
	"1.4.3: every local user must have a type 5, 8 or 9 secret" in vs
}

test_1_4_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.4.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.4.3: every local user must have a type 5, 8 or 9 secret" in vs
}

test_1_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.1")
}

test_1_5_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/snmp_disabled_when_unused", "value": false}])
	vs := b.violations with input as inp
	"1.5.1: SNMP must be off when unused (manual review not attested)" in vs
}

test_1_5_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/snmp_disabled_when_unused"}])
	vs := b.violations with input as inp
	"1.5.1: SNMP must be off when unused (manual review not attested)" in vs
}

test_1_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.2")
}

test_1_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "snmp-server community private RO"}])
	vs := b.violations with input as inp
	"1.5.2: an snmp-server community named private must not exist" in vs
}

test_1_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.2: an snmp-server community named private must not exist" in vs
}

test_1_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.3")
}

test_1_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "snmp-server community public RO"}])
	vs := b.violations with input as inp
	"1.5.3: an snmp-server community named public must not exist" in vs
}

test_1_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.3: an snmp-server community named public must not exist" in vs
}

test_1_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.4")
}

test_1_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "snmp-server community s3cr3t2 RW 10"}])
	vs := b.violations with input as inp
	"1.5.4: no snmp-server community must grant RW access" in vs
}

test_1_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.4: no snmp-server community must grant RW access" in vs
}

test_1_5_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.5")
}

test_1_5_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "snmp-server community s3cr3t2 RO"}])
	vs := b.violations with input as inp
	"1.5.5: every snmp-server community must carry an ACL" in vs
}

test_1_5_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.5: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.5: every snmp-server community must carry an ACL" in vs
}

test_1_5_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.6")
}

test_1_5_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/snmp_acl_defined", "value": false}])
	vs := b.violations with input as inp
	"1.5.6: an access list for SNMP must exist and be appropriate (manual review not attested)" in vs
}

test_1_5_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/snmp_acl_defined"}])
	vs := b.violations with input as inp
	"1.5.6: an access list for SNMP must exist and be appropriate (manual review not attested)" in vs
}

test_1_5_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.7")
}

test_1_5_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/44"}])
	vs := b.violations with input as inp
	"1.5.7: when SNMP is in use, an snmp-server host must be set" in vs
}

test_1_5_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.7: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.7: when SNMP is in use, an snmp-server host must be set" in vs
}

test_1_5_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.8")
}

test_1_5_8_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/45"}])
	vs := b.violations with input as inp
	"1.5.8: when SNMP is in use, snmp-server enable traps snmp must be set" in vs
}

test_1_5_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.8: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.8: when SNMP is in use, snmp-server enable traps snmp must be set" in vs
}

test_1_5_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.9")
}

test_1_5_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "snmp-server group OPS v3 auth"}])
	vs := b.violations with input as inp
	"1.5.9: every SNMPv3 group must use the priv security level" in vs
}

test_1_5_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"1.5.9: evidence missing — ios_xe_config.lines not collected" in vs
	not "1.5.9: every SNMPv3 group must use the priv security level" in vs
}

test_1_5_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.10")
}

test_1_5_10_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/snmpv3_user_aes128_minimum", "value": false}])
	vs := b.violations with input as inp
	"1.5.10: SNMPv3 users must use at least AES-128 privacy (manual review not attested)" in vs
}

test_1_5_10_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/snmpv3_user_aes128_minimum"}])
	vs := b.violations with input as inp
	"1.5.10: SNMPv3 users must use at least AES-128 privacy (manual review not attested)" in vs
}

test_2_1_1_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.1.1")
}

test_2_1_1_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/0", "value": "hostname Router"}])
	vs := b.violations with input as inp
	"2.1.1.1.1: a hostname other than the factory default must be set" in vs
}

test_2_1_1_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.1.1.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.1.1.1: a hostname other than the factory default must be set" in vs
}

test_2_1_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.1.2")
}

test_2_1_1_1_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/12", "value": "ip domain name vrf MGMT example.net"}])
	vs := b.violations with input as inp
	"2.1.1.1.2: a global ip domain name must be set" in vs
}

test_2_1_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.1.1.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.1.1.2: a global ip domain name must be set" in vs
}

test_2_1_1_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.1.3")
}

test_2_1_1_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/rsa_modulus_2048_or_more", "value": false}])
	vs := b.violations with input as inp
	"2.1.1.1.3: the RSA key modulus must be at least 2048 bits (manual review not attested)" in vs
}

test_2_1_1_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/rsa_modulus_2048_or_more"}])
	vs := b.violations with input as inp
	"2.1.1.1.3: the RSA key modulus must be at least 2048 bits (manual review not attested)" in vs
}

test_2_1_1_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.1.4")
}

test_2_1_1_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/13", "value": "ip ssh time-out 120"}])
	vs := b.violations with input as inp
	"2.1.1.1.4: ip ssh time-out must be 1 to 60 seconds" in vs
}

test_2_1_1_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.1.1.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.1.1.4: ip ssh time-out must be 1 to 60 seconds" in vs
}

test_2_1_1_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.1.5")
}

test_2_1_1_1_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/14", "value": "ip ssh authentication-retries 5"}])
	vs := b.violations with input as inp
	"2.1.1.1.5: ip ssh authentication-retries must be at most 3 (unset is the default 3)" in vs
}

test_2_1_1_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.1.1.5: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.1.1.5: ip ssh authentication-retries must be at most 3 (unset is the default 3)" in vs
}

test_2_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1.2")
}

test_2_1_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/15"}])
	vs := b.violations with input as inp
	"2.1.1.2: ip ssh version 2 must be set" in vs
}

test_2_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.1.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.1.2: ip ssh version 2 must be set" in vs
}

test_2_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.2")
}

test_2_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/16"}])
	vs := b.violations with input as inp
	"2.1.2: CDP must be turned off globally (no cdp run)" in vs
}

test_2_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.2: CDP must be turned off globally (no cdp run)" in vs
}

test_2_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.3")
}

test_2_1_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/17"}])
	vs := b.violations with input as inp
	"2.1.3: the BOOTP server must be off" in vs
}

test_2_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.3: the BOOTP server must be off" in vs
}

test_2_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.4")
}

test_2_1_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/18"}])
	vs := b.violations with input as inp
	"2.1.4: the DHCP service must be off (no service dhcp)" in vs
}

test_2_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.4: the DHCP service must be off (no service dhcp)" in vs
}

test_2_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.5")
}

test_2_1_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/19"}])
	vs := b.violations with input as inp
	"2.1.5: service tcp-keepalives-in must be on" in vs
}

test_2_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.5: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.5: service tcp-keepalives-in must be on" in vs
}

test_2_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.6")
}

test_2_1_6_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/20"}])
	vs := b.violations with input as inp
	"2.1.6: service tcp-keepalives-out must be on" in vs
}

test_2_1_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.6: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.6: service tcp-keepalives-out must be on" in vs
}

test_2_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.7")
}

test_2_1_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/21"}])
	vs := b.violations with input as inp
	"2.1.7: the PAD service must be off (no service pad)" in vs
}

test_2_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.1.7: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.1.7: the PAD service must be off (no service pad)" in vs
}

test_2_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.1")
}

test_2_2_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections/0/lines/1"}])
	vs := b.violations with input as inp
	"2.2.1: archive configuration-change logging must be enabled" in vs
}

test_2_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"2.2.1: evidence missing — ios_xe_config.sections not collected" in vs
	not "2.2.1: archive configuration-change logging must be enabled" in vs
}

test_2_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.2")
}

test_2_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/24", "value": "logging buffered 4096"}])
	vs := b.violations with input as inp
	"2.2.2: logging buffered must set a size of at least 64000 bytes" in vs
}

test_2_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.2: logging buffered must set a size of at least 64000 bytes" in vs
}

test_2_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.3")
}

test_2_2_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/25"}])
	vs := b.violations with input as inp
	"2.2.3: console logging must be limited to level critical" in vs
}

test_2_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.3: console logging must be limited to level critical" in vs
}

test_2_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.4")
}

test_2_2_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/26"}])
	vs := b.violations with input as inp
	"2.2.4: a syslog host must be set by IP address" in vs
}

test_2_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.4: a syslog host must be set by IP address" in vs
}

test_2_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.5")
}

test_2_2_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/27"}])
	vs := b.violations with input as inp
	"2.2.5: logging trap must be at level informational" in vs
}

test_2_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.5: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.5: logging trap must be at level informational" in vs
}

test_2_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.6")
}

test_2_2_6_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/28"}])
	vs := b.violations with input as inp
	"2.2.6: debug timestamps must carry the date and time" in vs
}

test_2_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.6: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.6: debug timestamps must carry the date and time" in vs
}

test_2_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.7")
}

test_2_2_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/29"}])
	vs := b.violations with input as inp
	"2.2.7: a logging source-interface must be set" in vs
}

test_2_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.7: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.7: a logging source-interface must be set" in vs
}

test_2_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.8")
}

test_2_2_8_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/23"}])
	vs := b.violations with input as inp
	"2.2.8: login success and failure logging must both be on" in vs
}

test_2_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.2.8: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.2.8: login success and failure logging must both be on" in vs
}

test_2_3_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1.1")
}

test_2_3_1_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/30"}])
	vs := b.violations with input as inp
	"2.3.1.1: ntp authenticate must be on" in vs
}

test_2_3_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.3.1.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.3.1.1: ntp authenticate must be on" in vs
}

test_2_3_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1.2")
}

test_2_3_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/31"}])
	vs := b.violations with input as inp
	"2.3.1.2: an ntp authentication-key must be defined" in vs
}

test_2_3_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.3.1.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.3.1.2: an ntp authentication-key must be defined" in vs
}

test_2_3_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1.3")
}

test_2_3_1_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/32"}])
	vs := b.violations with input as inp
	"2.3.1.3: an ntp trusted-key must be defined" in vs
}

test_2_3_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.3.1.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.3.1.3: an ntp trusted-key must be defined" in vs
}

test_2_3_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1.4")
}

test_2_3_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/lines/33", "value": "ntp server 10.20.30.41"}])
	vs := b.violations with input as inp
	"2.3.1.4: every ntp server must name an authentication key (at least one server)" in vs
}

test_2_3_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.3.1.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.3.1.4: every ntp server must name an authentication key (at least one server)" in vs
}

test_2_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.2")
}

test_2_3_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/33"}])
	vs := b.violations with input as inp
	"2.3.2: an ntp server must be set by IP address" in vs
}

test_2_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.3.2: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.3.2: an ntp server must be set by IP address" in vs
}

test_2_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.1")
}

test_2_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "interface Loopback1"}])
	vs := b.violations with input as inp
	"2.4.1: exactly one loopback interface must exist and carry an IP address" in vs
}

test_2_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"2.4.1: evidence missing — ios_xe_config.{lines,sections} not collected" in vs
	not "2.4.1: exactly one loopback interface must exist and carry an IP address" in vs
}

test_2_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.2")
}

test_2_4_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/36"}])
	vs := b.violations with input as inp
	"2.4.2: AAA (radius or tacacs) must have a source-interface" in vs
}

test_2_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"2.4.2: evidence missing — ios_xe_config.{lines,sections} not collected" in vs
	not "2.4.2: AAA (radius or tacacs) must have a source-interface" in vs
}

test_2_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.3")
}

test_2_4_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/34"}])
	vs := b.violations with input as inp
	"2.4.3: ntp source must be a loopback interface" in vs
}

test_2_4_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.4.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.4.3: ntp source must be a loopback interface" in vs
}

test_2_4_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.4")
}

test_2_4_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/35"}])
	vs := b.violations with input as inp
	"2.4.4: the tftp source-interface must be a loopback interface" in vs
}

test_2_4_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"2.4.4: evidence missing — ios_xe_config.lines not collected" in vs
	not "2.4.4: the tftp source-interface must be a loopback interface" in vs
}

test_3_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.1")
}

test_3_1_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines/37"}])
	vs := b.violations with input as inp
	"3.1.1: IP source routing must be off (no ip source-route)" in vs
}

test_3_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"3.1.1: evidence missing — ios_xe_config.lines not collected" in vs
	not "3.1.1: IP source routing must be off (no ip source-route)" in vs
}

test_3_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.2")
}

test_3_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections/2/lines/1"}])
	vs := b.violations with input as inp
	"3.1.2: every routed non-loopback interface must have no ip proxy-arp" in vs
}

test_3_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/sections"}])
	vs := b.violations with input as inp
	"3.1.2: evidence missing — ios_xe_config.sections not collected" in vs
	not "3.1.2: every routed non-loopback interface must have no ip proxy-arp" in vs
}

test_3_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.3")
}

test_3_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/ios_xe_config/lines/-", "value": "interface Tunnel0"}])
	vs := b.violations with input as inp
	"3.1.3: tunnel interfaces must not be defined" in vs
}

test_3_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/lines"}])
	vs := b.violations with input as inp
	"3.1.3: evidence missing — ios_xe_config.lines not collected" in vs
	not "3.1.3: tunnel interfaces must not be defined" in vs
}

test_3_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.4")
}

test_3_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/urpf_on_untrusted_interfaces", "value": false}])
	vs := b.violations with input as inp
	"3.1.4: uRPF must be set on the appropriate interfaces (manual review not attested)" in vs
}

test_3_1_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/urpf_on_untrusted_interfaces"}])
	vs := b.violations with input as inp
	"3.1.4: uRPF must be set on the appropriate interfaces (manual review not attested)" in vs
}

test_3_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2.1")
}

test_3_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/private_source_acl_defined", "value": false}])
	vs := b.violations with input as inp
	"3.2.1: an ACL must forbid private source addresses from external networks (manual review not attested)" in vs
}

test_3_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/private_source_acl_defined"}])
	vs := b.violations with input as inp
	"3.2.1: an ACL must forbid private source addresses from external networks (manual review not attested)" in vs
}

test_3_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2.2")
}

test_3_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/external_interface_acl_inbound", "value": false}])
	vs := b.violations with input as inp
	"3.2.2: an inbound ACL must be applied on the external interface (manual review not attested)" in vs
}

test_3_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/external_interface_acl_inbound"}])
	vs := b.violations with input as inp
	"3.2.2: an inbound ACL must be applied on the external interface (manual review not attested)" in vs
}

test_3_3_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.1")
}

test_3_3_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_key_chain_defined", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.1: an EIGRP key chain must be defined (manual review not attested)" in vs
}

test_3_3_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_key_chain_defined"}])
	vs := b.violations with input as inp
	"3.3.1.1: an EIGRP key chain must be defined (manual review not attested)" in vs
}

test_3_3_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.2")
}

test_3_3_1_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_key_defined", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.2: the EIGRP key chain must define keys (manual review not attested)" in vs
}

test_3_3_1_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_key_defined"}])
	vs := b.violations with input as inp
	"3.3.1.2: the EIGRP key chain must define keys (manual review not attested)" in vs
}

test_3_3_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.3")
}

test_3_3_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_key_string_set", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.3: each EIGRP key must have a key-string (manual review not attested)" in vs
}

test_3_3_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_key_string_set"}])
	vs := b.violations with input as inp
	"3.3.1.3: each EIGRP key must have a key-string (manual review not attested)" in vs
}

test_3_3_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.4")
}

test_3_3_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_address_family_set", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.4: the EIGRP address family must be configured (manual review not attested)" in vs
}

test_3_3_1_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_address_family_set"}])
	vs := b.violations with input as inp
	"3.3.1.4: the EIGRP address family must be configured (manual review not attested)" in vs
}

test_3_3_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.5")
}

test_3_3_1_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_af_interface_default", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.5: the EIGRP af-interface default must be configured (manual review not attested)" in vs
}

test_3_3_1_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_af_interface_default"}])
	vs := b.violations with input as inp
	"3.3.1.5: the EIGRP af-interface default must be configured (manual review not attested)" in vs
}

test_3_3_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.6")
}

test_3_3_1_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_af_key_chain", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.6: EIGRP af-interfaces must authenticate with a key chain (manual review not attested)" in vs
}

test_3_3_1_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_af_key_chain"}])
	vs := b.violations with input as inp
	"3.3.1.6: EIGRP af-interfaces must authenticate with a key chain (manual review not attested)" in vs
}

test_3_3_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.7")
}

test_3_3_1_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_af_auth_md5", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.7: EIGRP af-interfaces must use authentication mode md5 (manual review not attested)" in vs
}

test_3_3_1_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_af_auth_md5"}])
	vs := b.violations with input as inp
	"3.3.1.7: EIGRP af-interfaces must use authentication mode md5 (manual review not attested)" in vs
}

test_3_3_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.8")
}

test_3_3_1_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_interface_key_chain", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.8: EIGRP interfaces must set an authentication key-chain (manual review not attested)" in vs
}

test_3_3_1_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_interface_key_chain"}])
	vs := b.violations with input as inp
	"3.3.1.8: EIGRP interfaces must set an authentication key-chain (manual review not attested)" in vs
}

test_3_3_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.1.9")
}

test_3_3_1_9_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/eigrp_interface_auth_mode", "value": false}])
	vs := b.violations with input as inp
	"3.3.1.9: EIGRP interfaces must set an authentication mode (manual review not attested)" in vs
}

test_3_3_1_9_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/eigrp_interface_auth_mode"}])
	vs := b.violations with input as inp
	"3.3.1.9: EIGRP interfaces must set an authentication mode (manual review not attested)" in vs
}

test_3_3_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.2.1")
}

test_3_3_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/ospf_area_message_digest", "value": false}])
	vs := b.violations with input as inp
	"3.3.2.1: OSPF areas must use message-digest authentication (manual review not attested)" in vs
}

test_3_3_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/ospf_area_message_digest"}])
	vs := b.violations with input as inp
	"3.3.2.1: OSPF areas must use message-digest authentication (manual review not attested)" in vs
}

test_3_3_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.2.2")
}

test_3_3_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/ospf_interface_md5_key", "value": false}])
	vs := b.violations with input as inp
	"3.3.2.2: OSPF interfaces must set an md5 message-digest key (manual review not attested)" in vs
}

test_3_3_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/ospf_interface_md5_key"}])
	vs := b.violations with input as inp
	"3.3.2.2: OSPF interfaces must set an md5 message-digest key (manual review not attested)" in vs
}

test_3_3_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3.3.1")
}

test_3_3_3_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/ios_xe_config/attest/bgp_neighbor_password", "value": false}])
	vs := b.violations with input as inp
	"3.3.3.1: BGP neighbors must have a password (manual review not attested)" in vs
}

test_3_3_3_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/ios_xe_config/attest/bgp_neighbor_password"}])
	vs := b.violations with input as inp
	"3.3.3.1: BGP neighbors must have a password (manual review not attested)" in vs
}
