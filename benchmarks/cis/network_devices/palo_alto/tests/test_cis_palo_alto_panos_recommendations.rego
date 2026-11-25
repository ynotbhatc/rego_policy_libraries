package cis_palo_alto_panos_test

import rego.v1

import data.cis_palo_alto_panos as b

# Generated per-recommendation tests for CIS Palo Alto Firewall 11 Benchmark v1.2.1 (tools/cis_generators/gen_palo_alto.py): every recommendation
# has a pass test (green input) and a fail test; configuration checks also have an evidence-missing test;
# attestations fail when false or absent. Hand-written tests live in test_cis_palo_alto_panos_controls.rego.

green := {"panos_config": {
	"deviceconfig": {
		"system": {
			"login_banner": "Authorised use only.",
			"server_verification": "yes",
			"service": {
				"disable_http": "yes",
				"disable_telnet": "yes",
			},
			"snmp_setting": {"access_setting": {"version": "v3"}},
			"ntp_servers": {
				"primary_ntp_server": {"ntp_server_address": "10.0.0.123"},
				"secondary_ntp_server": {"ntp_server_address": "10.0.1.123"},
			},
			"update_schedule": {
				"anti_virus": {
					"action": "download-and-install",
					"recurrence": "hourly",
				},
				"threats": {
					"action": "download-and-install",
					"recurrence": "every-30-mins",
				},
				"wildfire": {
					"action": "download-and-install",
					"recurrence": "real-time",
				},
			},
		},
		"setting": {
			"management": {
				"enable_log_high_dp_load": "yes",
				"idle_timeout": 10,
			},
			"ssl_decrypt": {"allow_forward_decrypted_content": "yes"},
			"wildfire": {"session_info_select": {"exclude_src_ip": "no"}},
		},
		"high_availability": {
			"enabled": "yes",
			"interface": {"ha2": {"port": "ethernet1/5"}},
			"state_synchronization": {"enabled": "yes"},
			"link_monitoring": {
				"enabled": "yes",
				"failure_condition": "any",
				"link_group": [{
					"name": "uplinks",
					"enabled": "yes",
					"failure_condition": "any",
					"interface": [
						"ethernet1/1",
						"ethernet1/2",
					],
				}],
			},
			"active_passive": {"passive_link_state": "auto"},
			"election_option": {"preemptive": "no"},
		},
	},
	"mgt_config": {
		"password_complexity": {
			"enabled": "yes",
			"block_username_inclusion": "yes",
			"minimum_length": 14,
			"minimum_uppercase_letters": 1,
			"minimum_lowercase_letters": 1,
			"minimum_numeric_letters": 1,
			"minimum_special_characters": 1,
			"new_password_differs_by_characters": 3,
			"password_history_count": 24,
			"password_change": {"expiration_period": 90},
		},
		"password_profile": [{
			"name": "svc",
			"password_change": {"expiration_period": 60},
		}],
	},
	"shared": {
		"server_profile": {
			"syslog": [{
				"name": "syslog-siem",
				"server": [{
					"name": "siem",
					"server": "10.0.0.30",
				}],
			}],
			"snmptrap": [{
				"name": "trap-v3",
				"version": "v3",
				"server": [{
					"name": "nms",
					"manager": "10.0.0.20",
					"user": "trapper",
					"engineid": "0x80001f88",
					"authpwd": "-AQ==hashed",
				}],
			}],
		},
		"log_settings": {
			"system": {"match_list": [{
				"name": "all",
				"filter": "All Logs",
				"send_syslog": ["syslog-siem"],
				"send_snmptrap": ["trap-v3"],
			}]},
			"config": {"match_list": [{
				"name": "all",
				"filter": "All Logs",
				"send_syslog": ["syslog-siem"],
				"send_snmptrap": ["trap-v3"],
			}]},
			"userid": {"match_list": [{
				"name": "all",
				"filter": "All Logs",
				"send_syslog": ["syslog-siem"],
				"send_snmptrap": ["trap-v3"],
			}]},
			"hipmatch": {"match_list": [{
				"name": "all",
				"filter": "All Logs",
				"send_syslog": ["syslog-siem"],
				"send_snmptrap": ["trap-v3"],
			}]},
			"iptag": {"match_list": [{
				"name": "all",
				"filter": "All Logs",
				"send_syslog": ["syslog-siem"],
				"send_snmptrap": ["trap-v3"],
			}]},
		},
		"authentication_profile": [{
			"name": "admin-auth",
			"lockout": {
				"failed_attempts": 5,
				"lockout_time": 15,
			},
		}],
		"log_forwarding_profile": [{
			"name": "lf-default",
			"match_list": [{
				"name": "wf",
				"log_type": "wildfire",
				"send_syslog": ["syslog-siem"],
			}],
		}],
	},
	"network": {"profiles": {
		"interface_management": [{
			"name": "mgmt-ping",
			"ping": "yes",
			"https": "yes",
			"permitted_ip": ["10.0.0.0/24"],
		}],
		"zone_protection": [{
			"name": "zp-strict",
			"flood": {
				"tcp_syn": {
					"enable": "yes",
					"alarm_rate": 10000,
					"activate_rate": 10000,
					"maximal_rate": 40000,
					"action": "syn-cookies",
				},
				"udp": {
					"enable": "yes",
					"alarm_rate": 10000,
					"activate_rate": 10000,
					"maximal_rate": 40000,
				},
				"icmp": {
					"enable": "yes",
					"alarm_rate": 10000,
					"activate_rate": 10000,
					"maximal_rate": 40000,
				},
				"icmpv6": {
					"enable": "yes",
					"alarm_rate": 10000,
					"activate_rate": 10000,
					"maximal_rate": 40000,
				},
				"other_ip": {
					"enable": "yes",
					"alarm_rate": 10000,
					"activate_rate": 10000,
					"maximal_rate": 40000,
				},
			},
			"scan": {
				"tcp_port_scan": {
					"enable": "yes",
					"action": "block-ip",
					"track_by": "source",
					"duration": 600,
					"interval": 5,
					"threshold": 20,
				},
				"host_sweep": {
					"enable": "yes",
					"action": "block",
					"interval": 10,
					"threshold": 30,
				},
				"udp_port_scan": {
					"enable": "yes",
					"action": "alert",
					"interval": 10,
					"threshold": 20,
				},
			},
			"discard_ip_spoof": "yes",
			"discard_overlapping_tcp_segment_mismatch": "yes",
			"discard_strict_source_routing": "yes",
			"discard_loose_source_routing": "yes",
			"discard_malformed_option": "yes",
		}],
	}},
	"user_id": {
		"setting": {"enable_probing": "no"},
		"include_exclude_network": [
			{
				"name": "corp",
				"discovery": "include",
				"network_address": "10.0.0.0/8",
			},
			{
				"name": "guest-wifi",
				"discovery": "exclude",
				"network_address": "172.16.0.0/16",
			},
		],
	},
	"zone": [
		{
			"name": "trust",
			"zone_protection_profile": "zp-strict",
			"enable_user_identification": "yes",
		},
		{
			"name": "untrust",
			"zone_protection_profile": "zp-strict",
		},
		{
			"name": "guest",
			"zone_protection_profile": "zp-strict",
		},
		{
			"name": "dmz",
			"zone_protection_profile": "zp-strict",
		},
	],
	"site": {
		"untrusted_zones": [
			"untrust",
			"guest",
		],
		"internet_zones": ["untrust"],
		"url_block_categories": [
			"malware",
			"phishing",
			"command-and-control",
		],
	},
	"profile_group": [{
		"name": "pg-strict",
		"virus": ["av-strict"],
		"spyware": ["as-strict"],
		"vulnerability": ["vp-strict"],
		"url_filtering": ["url-strict"],
		"data_filtering": ["df-strict"],
		"wildfire_analysis": ["wf-strict"],
	}],
	"profiles": {
		"virus": [{
			"name": "av-strict",
			"decoder": [
				{
					"name": "http",
					"action": "reset-both",
					"wildfire_action": "reset-both",
					"mlav_action": "reset-both",
				},
				{
					"name": "smtp",
					"action": "reset-both",
					"wildfire_action": "reset-both",
					"mlav_action": "reset-both",
				},
				{
					"name": "imap",
					"action": "alert",
					"wildfire_action": "alert",
					"mlav_action": "alert",
				},
				{
					"name": "pop3",
					"action": "alert",
					"wildfire_action": "alert",
					"mlav_action": "alert",
				},
			],
			"mlav_engine_filebased_enabled": [
				{
					"name": "Windows Executables",
					"mlav_policy_action": "enable",
				},
				{
					"name": "PowerShell Script 1",
					"mlav_policy_action": "enable",
				},
				{
					"name": "Executable Linked Format",
					"mlav_policy_action": "enable",
				},
			],
		}],
		"spyware": [{
			"name": "as-strict",
			"rules": [{
				"name": "block-chm",
				"severity": [
					"critical",
					"high",
					"medium",
				],
				"category": "any",
				"threat_name": "any",
				"action": {"reset-both": {}},
			}],
			"botnet_domains": {
				"lists": [{
					"name": "default-paloalto-dns",
					"action": {"sinkhole": {}},
				}],
				"sinkhole": {
					"ipv4_address": "sinkhole.paloaltonetworks.com",
					"ipv6_address": "::1",
				},
				"dns_security_categories": [
					{
						"name": "pan-dns-sec-cc",
						"action": "sinkhole",
						"packet_capture": "extended-capture",
					},
					{
						"name": "pan-dns-sec-malware",
						"action": "sinkhole",
					},
				],
			},
			"cloud_inline_analysis": "yes",
			"mica_engine_spyware_enabled": [{
				"name": "HTTP Command and Control detector",
				"inline_policy_action": "reset-both",
			}],
		}],
		"vulnerability": [{
			"name": "vp-strict",
			"rules": [
				{
					"name": "block-ch",
					"severity": [
						"critical",
						"high",
					],
					"action": {"reset-both": {}},
				},
				{
					"name": "default-mli",
					"severity": [
						"medium",
						"low",
						"informational",
					],
					"action": {"default": {}},
				},
			],
			"cloud_inline_analysis": "yes",
			"mica_engine_vulnerability_enabled": [{
				"name": "SQL Injection",
				"inline_policy_action": "alert",
			}],
		}],
		"url_filtering": [{
			"name": "url-strict",
			"block": [
				"malware",
				"phishing",
			],
			"override": ["command-and-control"],
			"alert": [
				"news",
				"business-and-economy",
			],
			"log_container_page_only": "no",
			"log_http_hdr_user_agent": "yes",
			"log_http_hdr_referer": "yes",
			"log_http_hdr_xff": "yes",
			"local_inline_cat": "yes",
			"cloud_inline_cat": "yes",
			"credential_enforcement": {
				"mode": "ip-user",
				"log_severity": "medium",
				"block": [
					"malware",
					"phishing",
					"command-and-control",
				],
				"continue": [
					"news",
					"business-and-economy",
				],
			},
		}],
		"data_filtering": [{
			"name": "df-strict",
			"rules": [{
				"name": "cc",
				"data_object": ["credit-card-numbers"],
				"alert_threshold": 20,
				"block_threshold": 0,
			}],
		}],
		"wildfire_analysis": [{
			"name": "wf-strict",
			"rules": [{
				"name": "all",
				"application": ["any"],
				"file_type": ["any"],
			}],
			"cloud_inline_analysis": "yes",
			"inline_cloud_rules": [{
				"name": "pe",
				"application": ["any"],
				"file_type": ["pe"],
				"direction": "both",
				"action": "block",
			}],
		}],
	},
	"rulebase": {
		"security": [
			{
				"name": "outbound-web",
				"from": ["trust"],
				"to": ["untrust"],
				"source": ["any"],
				"destination": ["any"],
				"application": [
					"web-browsing",
					"ssl",
				],
				"service": ["application-default"],
				"action": "allow",
				"profile_setting": {"profiles": {
					"virus": ["av-strict"],
					"spyware": ["as-strict"],
					"vulnerability": ["vp-strict"],
					"url_filtering": ["url-strict"],
					"data_filtering": ["df-strict"],
					"wildfire_analysis": ["wf-strict"],
				}},
			},
			{
				"name": "outbound-dns",
				"from": ["trust"],
				"to": ["untrust"],
				"source": ["any"],
				"destination": ["any"],
				"application": ["dns"],
				"service": ["application-default"],
				"action": "allow",
				"profile_setting": {"group": ["pg-strict"]},
			},
			{
				"name": "deny-msrpc-untrusted",
				"from": ["trust"],
				"to": [
					"untrust",
					"guest",
				],
				"source": ["uid-agent"],
				"destination": ["any"],
				"application": ["msrpc"],
				"service": ["application-default"],
				"action": "deny",
			},
			{
				"name": "dmz-web-in",
				"from": ["untrust"],
				"to": ["dmz"],
				"source": ["any"],
				"destination": ["web01"],
				"application": ["web-browsing"],
				"service": ["application-default"],
				"action": "allow",
				"profile_setting": {"group": ["pg-strict"]},
			},
			{
				"name": "deny-to-malicious",
				"from": ["any"],
				"to": ["any"],
				"source": ["any"],
				"destination": [
					"panw-known-ip-list",
					"panw-highrisk-ip-list",
					"panw-torexit-ip-list",
					"panw-bulletproof-ip-list",
				],
				"application": ["any"],
				"service": ["any"],
				"action": "deny",
			},
			{
				"name": "deny-from-malicious",
				"from": ["any"],
				"to": ["any"],
				"source": [
					"panw-known-ip-list",
					"panw-highrisk-ip-list",
					"panw-torexit-ip-list",
					"panw-bulletproof-ip-list",
				],
				"destination": ["any"],
				"application": ["any"],
				"service": ["any"],
				"action": "drop",
			},
		],
		"default_security_rules": [
			{
				"name": "intrazone-default",
				"action": "allow",
				"log_end": "yes",
			},
			{
				"name": "interzone-default",
				"action": "deny",
				"log_end": "yes",
			},
		],
		"decryption": [{
			"name": "decrypt-outbound",
			"from": ["trust"],
			"to": ["untrust"],
			"action": "decrypt",
			"type": {"ssl-forward-proxy": {}},
			"category": ["any"],
		}],
	},
	"licenses": [
		{
			"feature": "PAN-DB URL Filtering",
			"expired": "no",
		},
		{
			"feature": "Advanced Threat Prevention",
			"expired": "no",
		},
		{
			"feature": "DNS Security",
			"expired": "no",
		},
	],
	"attest": {
		"management_permitted_ips_reviewed": true,
		"management_profile_permitted_ips_reviewed": true,
		"admin_web_certificate_valid": true,
		"vpn_certificate_valid": true,
		"ikev2_post_quantum_ppk_enabled": true,
		"user_mapping_verified_in_logs": true,
		"userid_account_minimal_groups": true,
		"userid_account_no_interactive_logon": true,
		"userid_account_no_remote_access": true,
		"wildfire_file_size_limits_reviewed": true,
		"wildfire_cloud_region_approved": true,
		"ssl_inbound_inspection_reviewed": true,
		"decryption_certificate_trusted": true,
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
	s.passing_controls == 79
	s.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 79
	count([id | some id, r in b.recommendations; r.level == 2]) == 10
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 62
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == 13
}

test_empty_input_fails_every_recommendation if {
	r := b.compliance_report with input as {}
	r.total_controls == 79
	r.failed_controls == 79
	r.compliant == false
}

test_level_1_profile_scopes_the_report if {
	inp := json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": 1}}])
	r := b.compliance_report with input as inp
	r.total_controls == 69
	r.failed_controls == 0
	e := b.compliance_report with input as {"cis_profile": {"level": 1}}
	e.total_controls == 69
	e.failed_controls == 69
}

test_level_2_only_recommendation_skipped_at_level_1 if {
	inp := json.patch(green, [
		{"op": "add", "path": "/cis_profile", "value": {"level": 1}},
		{"op": "add", "path": "/panos_config/user_id/setting/enable_probing", "value": "yes"},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "2.2")
}

test_1_1_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.1.1")
}

test_1_1_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/shared/log_settings/system/match_list/0/send_syslog", "value": ["no-such-profile"]}])
	vs := b.violations with input as inp
	"1.1.1.1: system, config, User-ID, HIP-match and IP-tag logs must all forward to a valid syslog server profile" in vs
}

test_1_1_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/shared/server_profile/syslog"}])
	vs := b.violations with input as inp
	"1.1.1.1: evidence missing — panos_config.shared.{server_profile.syslog,log_settings} not collected" in vs
	not "1.1.1.1: system, config, User-ID, HIP-match and IP-tag logs must all forward to a valid syslog server profile" in vs
}

test_1_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.1.2")
}

test_1_1_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/shared/server_profile/snmptrap/0/version", "value": "v2c"}])
	vs := b.violations with input as inp
	"1.1.1.2: system, config, User-ID, HIP-match and IP-tag logs must all send traps to an SNMP v3 trap profile" in vs
}

test_1_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/shared/server_profile/snmptrap"}])
	vs := b.violations with input as inp
	"1.1.1.2: evidence missing — panos_config.shared.{server_profile.snmptrap,log_settings} not collected" in vs
	not "1.1.1.2: system, config, User-ID, HIP-match and IP-tag logs must all send traps to an SNMP v3 trap profile" in vs
}

test_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.2")
}

test_1_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/login_banner", "value": " "}])
	vs := b.violations with input as inp
	"1.1.2: a login banner must be configured" in vs
}

test_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system"}])
	vs := b.violations with input as inp
	"1.1.2: evidence missing — panos_config.deviceconfig.system not collected" in vs
	not "1.1.2: a login banner must be configured" in vs
}

test_1_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.3")
}

test_1_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/setting/management/enable_log_high_dp_load", "value": "no"}])
	vs := b.violations with input as inp
	"1.1.3: logging under high dataplane load must be turned on" in vs
}

test_1_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/setting/management"}])
	vs := b.violations with input as inp
	"1.1.3: evidence missing — panos_config.deviceconfig.setting.management not collected" in vs
	not "1.1.3: logging under high dataplane load must be turned on" in vs
}

test_1_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.1")
}

test_1_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/management_permitted_ips_reviewed", "value": false}])
	vs := b.violations with input as inp
	"1.2.1: management interface permitted IPs must be limited to the management hosts (manual review not attested)" in vs
}

test_1_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/management_permitted_ips_reviewed"}])
	vs := b.violations with input as inp
	"1.2.1: management interface permitted IPs must be limited to the management hosts (manual review not attested)" in vs
}

test_1_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.2")
}

test_1_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/management_profile_permitted_ips_reviewed", "value": false}])
	vs := b.violations with input as inp
	"1.2.2: interface management profiles offering SSH, HTTPS or SNMP must restrict permitted IPs (manual review not attested)" in vs
}

test_1_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/management_profile_permitted_ips_reviewed"}])
	vs := b.violations with input as inp
	"1.2.2: interface management profiles offering SSH, HTTPS or SNMP must restrict permitted IPs (manual review not attested)" in vs
}

test_1_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.3")
}

test_1_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/service/disable_telnet", "value": "no"}])
	vs := b.violations with input as inp
	"1.2.3: the management interface must not offer HTTP or Telnet" in vs
}

test_1_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/service"}])
	vs := b.violations with input as inp
	"1.2.3: evidence missing — panos_config.deviceconfig.system.service not collected" in vs
	not "1.2.3: the management interface must not offer HTTP or Telnet" in vs
}

test_1_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.4")
}

test_1_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/network/profiles/interface_management/0/http", "value": "yes"}])
	vs := b.violations with input as inp
	"1.2.4: interface management profiles must not offer HTTP or Telnet" in vs
}

test_1_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/network/profiles/interface_management"}])
	vs := b.violations with input as inp
	"1.2.4: evidence missing — panos_config.network.profiles.interface_management not collected" in vs
	not "1.2.4: interface management profiles must not offer HTTP or Telnet" in vs
}

test_1_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.5")
}

test_1_2_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/admin_web_certificate_valid", "value": false}])
	vs := b.violations with input as inp
	"1.2.5: the web admin interface certificate must be valid and trusted (manual review not attested)" in vs
}

test_1_2_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/admin_web_certificate_valid"}])
	vs := b.violations with input as inp
	"1.2.5: the web admin interface certificate must be valid and trusted (manual review not attested)" in vs
}

test_1_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.1")
}

test_1_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/enabled", "value": "no"}])
	vs := b.violations with input as inp
	"1.3.1: admin password complexity must be enforced with username inclusion blocked" in vs
}

test_1_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.1: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.1: admin password complexity must be enforced with username inclusion blocked" in vs
}

test_1_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.2")
}

test_1_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/minimum_length", "value": 8}])
	vs := b.violations with input as inp
	"1.3.2: admin passwords must be at least 12 characters long" in vs
}

test_1_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.2: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.2: admin passwords must be at least 12 characters long" in vs
}

test_1_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.3")
}

test_1_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/minimum_uppercase_letters", "value": 0}])
	vs := b.violations with input as inp
	"1.3.3: admin passwords must contain at least 1 upper-case letter" in vs
}

test_1_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.3: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.3: admin passwords must contain at least 1 upper-case letter" in vs
}

test_1_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.4")
}

test_1_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/minimum_lowercase_letters", "value": 0}])
	vs := b.violations with input as inp
	"1.3.4: admin passwords must contain at least 1 lower-case letter" in vs
}

test_1_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.4: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.4: admin passwords must contain at least 1 lower-case letter" in vs
}

test_1_3_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.5")
}

test_1_3_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/minimum_numeric_letters", "value": 0}])
	vs := b.violations with input as inp
	"1.3.5: admin passwords must contain at least 1 digit" in vs
}

test_1_3_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.5: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.5: admin passwords must contain at least 1 digit" in vs
}

test_1_3_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.6")
}

test_1_3_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/minimum_special_characters", "value": 0}])
	vs := b.violations with input as inp
	"1.3.6: admin passwords must contain at least 1 special character" in vs
}

test_1_3_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.6: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.6: admin passwords must contain at least 1 special character" in vs
}

test_1_3_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.7")
}

test_1_3_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/password_change/expiration_period", "value": 0}])
	vs := b.violations with input as inp
	"1.3.7: admin passwords must expire within 1 to 90 days" in vs
}

test_1_3_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.7: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.7: admin passwords must expire within 1 to 90 days" in vs
}

test_1_3_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.8")
}

test_1_3_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/new_password_differs_by_characters", "value": 2}])
	vs := b.violations with input as inp
	"1.3.8: a new admin password must differ from the old one by at least 3 characters" in vs
}

test_1_3_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.8: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.8: a new admin password must differ from the old one by at least 3 characters" in vs
}

test_1_3_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.9")
}

test_1_3_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_complexity/password_history_count", "value": 10}])
	vs := b.violations with input as inp
	"1.3.9: admin passwords must not repeat any of the last 24" in vs
}

test_1_3_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_complexity"}])
	vs := b.violations with input as inp
	"1.3.9: evidence missing — panos_config.mgt_config.password_complexity not collected" in vs
	not "1.3.9: admin passwords must not repeat any of the last 24" in vs
}

test_1_3_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.10")
}

test_1_3_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/mgt_config/password_profile/0/password_change/expiration_period", "value": 0}])
	vs := b.violations with input as inp
	"1.3.10: password profiles must not be weaker than the global rules (expiry 1 to 90 days)" in vs
}

test_1_3_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/mgt_config/password_profile"}])
	vs := b.violations with input as inp
	"1.3.10: evidence missing — panos_config.mgt_config.password_profile not collected" in vs
	not "1.3.10: password profiles must not be weaker than the global rules (expiry 1 to 90 days)" in vs
}

test_1_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.1")
}

test_1_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/setting/management/idle_timeout", "value": 0}])
	vs := b.violations with input as inp
	"1.4.1: management idle timeout must be 1 to 10 minutes" in vs
}

test_1_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/setting/management"}])
	vs := b.violations with input as inp
	"1.4.1: evidence missing — panos_config.deviceconfig.setting.management not collected" in vs
	not "1.4.1: management idle timeout must be 1 to 10 minutes" in vs
}

test_1_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.2")
}

test_1_4_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/shared/authentication_profile/0/lockout/lockout_time", "value": 0}])
	vs := b.violations with input as inp
	"1.4.2: authentication profiles must lock out after failed attempts for a non-zero time" in vs
}

test_1_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/shared/authentication_profile"}])
	vs := b.violations with input as inp
	"1.4.2: evidence missing — panos_config.shared.authentication_profile not collected" in vs
	not "1.4.2: authentication profiles must lock out after failed attempts for a non-zero time" in vs
}

test_1_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5.1")
}

test_1_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/snmp_setting/access_setting/version", "value": "v2c"}])
	vs := b.violations with input as inp
	"1.5.1: SNMP polling must use version 3" in vs
}

test_1_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/snmp_setting"}])
	vs := b.violations with input as inp
	"1.5.1: evidence missing — panos_config.deviceconfig.system.snmp_setting not collected" in vs
	not "1.5.1: SNMP polling must use version 3" in vs
}

test_1_6_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.6.1")
}

test_1_6_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/server_verification", "value": "no"}])
	vs := b.violations with input as inp
	"1.6.1: the update server identity must be verified" in vs
}

test_1_6_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system"}])
	vs := b.violations with input as inp
	"1.6.1: evidence missing — panos_config.deviceconfig.system not collected" in vs
	not "1.6.1: the update server identity must be verified" in vs
}

test_1_6_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.6.2")
}

test_1_6_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/ntp_servers/secondary_ntp_server/ntp_server_address", "value": "10.0.0.123"}])
	vs := b.violations with input as inp
	"1.6.2: two distinct NTP servers must be configured" in vs
}

test_1_6_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/ntp_servers"}])
	vs := b.violations with input as inp
	"1.6.2: evidence missing — panos_config.deviceconfig.system.ntp_servers not collected" in vs
	not "1.6.2: two distinct NTP servers must be configured" in vs
}

test_1_6_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.6.3")
}

test_1_6_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/vpn_certificate_valid", "value": false}])
	vs := b.violations with input as inp
	"1.6.3: the remote access VPN certificate and its TLS minimum must be valid (manual review not attested)" in vs
}

test_1_6_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/vpn_certificate_valid"}])
	vs := b.violations with input as inp
	"1.6.3: the remote access VPN certificate and its TLS minimum must be valid (manual review not attested)" in vs
}

test_1_7_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.7.1")
}

test_1_7_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/ikev2_post_quantum_ppk_enabled", "value": false}])
	vs := b.violations with input as inp
	"1.7.1: IKEv2 VPN gateways must use a post-quantum pre-shared key (manual review not attested)" in vs
}

test_1_7_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/ikev2_post_quantum_ppk_enabled"}])
	vs := b.violations with input as inp
	"1.7.1: IKEv2 VPN gateways must use a post-quantum pre-shared key (manual review not attested)" in vs
}

test_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1")
}

test_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/user_mapping_verified_in_logs", "value": false}])
	vs := b.violations with input as inp
	"2.1: traffic from trusted zones must carry a mapped user name (manual review not attested)" in vs
}

test_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/user_mapping_verified_in_logs"}])
	vs := b.violations with input as inp
	"2.1: traffic from trusted zones must carry a mapped user name (manual review not attested)" in vs
}

test_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2")
}

test_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/user_id/setting/enable_probing", "value": "yes"}])
	vs := b.violations with input as inp
	"2.2: User-ID client (WMI) probing must be off" in vs
}

test_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/user_id/setting"}])
	vs := b.violations with input as inp
	"2.2: evidence missing — panos_config.user_id.setting not collected" in vs
	not "2.2: User-ID client (WMI) probing must be off" in vs
}

test_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3")
}

test_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/zone/1/enable_user_identification", "value": "yes"}])
	vs := b.violations with input as inp
	"2.3: User-ID must be on only for trusted internal zones" in vs
}

test_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/untrusted_zones"}])
	vs := b.violations with input as inp
	"2.3: evidence missing — panos_config.{zone,site.untrusted_zones} not collected" in vs
	not "2.3: User-ID must be on only for trusted internal zones" in vs
}

test_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4")
}

test_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/user_id/include_exclude_network/0/discovery", "value": "exclude"}])
	vs := b.violations with input as inp
	"2.4: with User-ID on, the user mapping must name its trusted networks as include entries" in vs
}

test_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/user_id/include_exclude_network"}])
	vs := b.violations with input as inp
	"2.4: evidence missing — panos_config.{zone,user_id.include_exclude_network} not collected" in vs
	not "2.4: with User-ID on, the user mapping must name its trusted networks as include entries" in vs
}

test_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5")
}

test_2_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/userid_account_minimal_groups", "value": false}])
	vs := b.violations with input as inp
	"2.5: the User-ID agent account must hold only the minimal group memberships (manual review not attested)" in vs
}

test_2_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/userid_account_minimal_groups"}])
	vs := b.violations with input as inp
	"2.5: the User-ID agent account must hold only the minimal group memberships (manual review not attested)" in vs
}

test_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.6")
}

test_2_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/userid_account_no_interactive_logon", "value": false}])
	vs := b.violations with input as inp
	"2.6: the User-ID service account must be denied interactive logon (manual review not attested)" in vs
}

test_2_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/userid_account_no_interactive_logon"}])
	vs := b.violations with input as inp
	"2.6: the User-ID service account must be denied interactive logon (manual review not attested)" in vs
}

test_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.7")
}

test_2_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/userid_account_no_remote_access", "value": false}])
	vs := b.violations with input as inp
	"2.7: the User-ID service account must have no remote access rights (manual review not attested)" in vs
}

test_2_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/userid_account_no_remote_access"}])
	vs := b.violations with input as inp
	"2.7: the User-ID service account must have no remote access rights (manual review not attested)" in vs
}

test_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.8")
}

test_2_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/security/2/application", "value": ["dns"]}])
	vs := b.violations with input as inp
	"2.8: a rule must block msrpc from the User-ID agent toward every untrusted zone" in vs
}

test_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security"}])
	vs := b.violations with input as inp
	"2.8: evidence missing — panos_config.{rulebase.security,site.untrusted_zones} not collected" in vs
	not "2.8: a rule must block msrpc from the User-ID agent toward every untrusted zone" in vs
}

test_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1")
}

test_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/high_availability/state_synchronization/enabled", "value": "no"}])
	vs := b.violations with input as inp
	"3.1: HA must be on with an HA2 data link and session synchronization" in vs
}

test_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/high_availability"}])
	vs := b.violations with input as inp
	"3.1: evidence missing — panos_config.deviceconfig.high_availability not collected" in vs
	not "3.1: HA must be on with an HA2 data link and session synchronization" in vs
}

test_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2")
}

test_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/high_availability/link_monitoring/enabled", "value": "no"}])
	vs := b.violations with input as inp
	"3.2: HA must fail over on link or path monitoring (failure condition any)" in vs
}

test_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/high_availability"}])
	vs := b.violations with input as inp
	"3.2: evidence missing — panos_config.deviceconfig.high_availability not collected" in vs
	not "3.2: HA must fail over on link or path monitoring (failure condition any)" in vs
}

test_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3")
}

test_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/high_availability/election_option/preemptive", "value": "yes"}])
	vs := b.violations with input as inp
	"3.3: HA passive link state must be auto and preemption must be off" in vs
}

test_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/high_availability"}])
	vs := b.violations with input as inp
	"3.3: evidence missing — panos_config.deviceconfig.high_availability not collected" in vs
	not "3.3: HA passive link state must be auto and preemption must be off" in vs
}

test_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1")
}

test_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/update_schedule/anti_virus/recurrence", "value": "daily"}])
	vs := b.violations with input as inp
	"4.1: antivirus content must download and install hourly" in vs
}

test_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/update_schedule"}])
	vs := b.violations with input as inp
	"4.1: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" in vs
	not "4.1: antivirus content must download and install hourly" in vs
}

test_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2")
}

test_4_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/update_schedule/threats/recurrence", "value": "weekly"}])
	vs := b.violations with input as inp
	"4.2: application and threat content must download and install at least daily" in vs
}

test_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/update_schedule"}])
	vs := b.violations with input as inp
	"4.2: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" in vs
	not "4.2: application and threat content must download and install at least daily" in vs
}

test_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1")
}

test_5_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/wildfire_file_size_limits_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1: WildFire upload size limits must be at or above the defaults (manual review not attested)" in vs
}

test_5_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/wildfire_file_size_limits_reviewed"}])
	vs := b.violations with input as inp
	"5.1: WildFire upload size limits must be at or above the defaults (manual review not attested)" in vs
}

test_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2")
}

test_5_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/wildfire_analysis"}])
	vs := b.violations with input as inp
	"5.2: every allow rule must carry a WildFire analysis profile" in vs
}

test_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/wildfire_analysis"}])
	vs := b.violations with input as inp
	"5.2: evidence missing — panos_config.{rulebase.security,profiles.wildfire_analysis} not collected" in vs
	not "5.2: every allow rule must carry a WildFire analysis profile" in vs
}

test_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3")
}

test_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/setting/ssl_decrypt/allow_forward_decrypted_content", "value": "no"}])
	vs := b.violations with input as inp
	"5.3: decrypted content must be forwarded to WildFire" in vs
}

test_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/setting/ssl_decrypt"}])
	vs := b.violations with input as inp
	"5.3: evidence missing — panos_config.deviceconfig.setting.ssl_decrypt not collected" in vs
	not "5.3: decrypted content must be forwarded to WildFire" in vs
}

test_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.4")
}

test_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/setting/wildfire/session_info_select/exclude_username", "value": "yes"}])
	vs := b.violations with input as inp
	"5.4: WildFire session information must include every field" in vs
}

test_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/setting/wildfire"}])
	vs := b.violations with input as inp
	"5.4: evidence missing — panos_config.deviceconfig.setting.wildfire not collected" in vs
	not "5.4: WildFire session information must include every field" in vs
}

test_5_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.5")
}

test_5_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/shared/log_forwarding_profile/0/match_list/0/log_type", "value": "traffic"}])
	vs := b.violations with input as inp
	"5.5: WildFire logs must be forwarded to an alerting destination" in vs
}

test_5_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/shared/log_forwarding_profile"}])
	vs := b.violations with input as inp
	"5.5: evidence missing — panos_config.shared.log_forwarding_profile not collected" in vs
	not "5.5: WildFire logs must be forwarded to an alerting destination" in vs
}

test_5_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6")
}

test_5_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/deviceconfig/system/update_schedule/wildfire/recurrence", "value": "every-min"}])
	vs := b.violations with input as inp
	"5.6: WildFire content must update in real time" in vs
}

test_5_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/deviceconfig/system/update_schedule"}])
	vs := b.violations with input as inp
	"5.6: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" in vs
	not "5.6: WildFire content must update in real time" in vs
}

test_5_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.7")
}

test_5_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/wildfire_cloud_region_approved", "value": false}])
	vs := b.violations with input as inp
	"5.7: the WildFire public cloud region must be the approved one (manual review not attested)" in vs
}

test_5_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/wildfire_cloud_region_approved"}])
	vs := b.violations with input as inp
	"5.7: the WildFire public cloud region must be the approved one (manual review not attested)" in vs
}

test_5_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.8")
}

test_5_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/wildfire_analysis/0/cloud_inline_analysis", "value": "no"}])
	vs := b.violations with input as inp
	"5.8: WildFire profiles must block PE files through inline cloud analysis" in vs
}

test_5_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/wildfire_analysis"}])
	vs := b.violations with input as inp
	"5.8: evidence missing — panos_config.profiles.wildfire_analysis not collected" in vs
	not "5.8: WildFire profiles must block PE files through inline cloud analysis" in vs
}

test_6_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.1")
}

test_6_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/virus/0/decoder/0/wildfire_action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.1: antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert)" in vs
}

test_6_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/virus"}])
	vs := b.violations with input as inp
	"6.1: evidence missing — panos_config.profiles.virus not collected" in vs
	not "6.1: antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert)" in vs
}

test_6_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.2")
}

test_6_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/virus"}])
	vs := b.violations with input as inp
	"6.2: every allow rule must carry an antivirus profile" in vs
}

test_6_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/virus"}])
	vs := b.violations with input as inp
	"6.2: evidence missing — panos_config.{rulebase.security,profiles.virus} not collected" in vs
	not "6.2: every allow rule must carry an antivirus profile" in vs
}

test_6_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.3")
}

test_6_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/spyware/0/rules/0/action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.3: an anti-spyware profile must reset critical, high and medium threats of any category" in vs
}

test_6_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/spyware"}])
	vs := b.violations with input as inp
	"6.3: evidence missing — panos_config.profiles.spyware not collected" in vs
	not "6.3: an anti-spyware profile must reset critical, high and medium threats of any category" in vs
}

test_6_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.4")
}

test_6_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/spyware/0/botnet_domains/lists/0/action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.4: anti-spyware profiles in use must sinkhole the Palo Alto DNS list with IPv4 and IPv6 sinkhole addresses" in vs
}

test_6_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/spyware"}])
	vs := b.violations with input as inp
	"6.4: evidence missing — panos_config.{rulebase.security,profiles.spyware} not collected" in vs
	not "6.4: anti-spyware profiles in use must sinkhole the Palo Alto DNS list with IPv4 and IPv6 sinkhole addresses" in vs
}

test_6_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5")
}

test_6_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/spyware"}])
	vs := b.violations with input as inp
	"6.5: every allow rule toward the Internet must carry an anti-spyware profile" in vs
}

test_6_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/internet_zones"}])
	vs := b.violations with input as inp
	"6.5: evidence missing — panos_config.{rulebase.security,site.internet_zones,profiles.spyware} not collected" in vs
	not "6.5: every allow rule toward the Internet must carry an anti-spyware profile" in vs
}

test_6_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.6")
}

test_6_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/vulnerability/0/rules/0/action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.6: a vulnerability profile must block critical and high threats and keep at least the default action below" in vs
}

test_6_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/vulnerability"}])
	vs := b.violations with input as inp
	"6.6: evidence missing — panos_config.profiles.vulnerability not collected" in vs
	not "6.6: a vulnerability profile must block critical and high threats and keep at least the default action below" in vs
}

test_6_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.7")
}

test_6_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/vulnerability"}])
	vs := b.violations with input as inp
	"6.7: every allow rule must carry a vulnerability protection profile" in vs
}

test_6_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security"}])
	vs := b.violations with input as inp
	"6.7: evidence missing — panos_config.rulebase.security not collected" in vs
	not "6.7: every allow rule must carry a vulnerability protection profile" in vs
}

test_6_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.8")
}

test_6_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/licenses/0/expired", "value": "yes"}])
	vs := b.violations with input as inp
	"6.8: a PAN-DB URL filtering license must be active" in vs
}

test_6_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}])
	vs := b.violations with input as inp
	"6.8: evidence missing — panos_config.licenses not collected" in vs
	not "6.8: a PAN-DB URL filtering license must be active" in vs
}

test_6_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.9")
}

test_6_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/url_filtering/0/block", "value": ["malware"]}])
	vs := b.violations with input as inp
	"6.9: URL filtering profiles must block or override every organisation-designated category" in vs
}

test_6_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/url_block_categories"}])
	vs := b.violations with input as inp
	"6.9: evidence missing — panos_config.{profiles.url_filtering,site.url_block_categories} not collected" in vs
	not "6.9: URL filtering profiles must block or override every organisation-designated category" in vs
}

test_6_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.10")
}

test_6_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/url_filtering/0/allow", "value": ["news"]}])
	vs := b.violations with input as inp
	"6.10: URL filtering profiles must log (alert) every category they let through" in vs
}

test_6_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/url_filtering"}])
	vs := b.violations with input as inp
	"6.10: evidence missing — panos_config.profiles.url_filtering not collected" in vs
	not "6.10: URL filtering profiles must log (alert) every category they let through" in vs
}

test_6_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.11")
}

test_6_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/url_filtering/0/log_http_hdr_xff", "value": "no"}])
	vs := b.violations with input as inp
	"6.11: URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page" in vs
}

test_6_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/url_filtering"}])
	vs := b.violations with input as inp
	"6.11: evidence missing — panos_config.profiles.url_filtering not collected" in vs
	not "6.11: URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page" in vs
}

test_6_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.12")
}

test_6_12_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/url_filtering"}])
	vs := b.violations with input as inp
	"6.12: every allow rule toward the Internet must carry a URL filtering profile" in vs
}

test_6_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/internet_zones"}])
	vs := b.violations with input as inp
	"6.12: evidence missing — panos_config.{rulebase.security,site.internet_zones} not collected" in vs
	not "6.12: every allow rule toward the Internet must carry a URL filtering profile" in vs
}

test_6_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.13")
}

test_6_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/data_filtering/0/rules/0/alert_threshold", "value": 0}])
	vs := b.violations with input as inp
	"6.13: a data filtering profile must alert on sensitive data patterns above a threshold" in vs
}

test_6_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/data_filtering"}])
	vs := b.violations with input as inp
	"6.13: evidence missing — panos_config.profiles.data_filtering not collected" in vs
	not "6.13: a data filtering profile must alert on sensitive data patterns above a threshold" in vs
}

test_6_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.14")
}

test_6_14_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security/0/profile_setting/profiles/data_filtering"}])
	vs := b.violations with input as inp
	"6.14: every allow rule to or from the Internet must carry a data filtering profile" in vs
}

test_6_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/internet_zones"}])
	vs := b.violations with input as inp
	"6.14: evidence missing — panos_config.{rulebase.security,site.internet_zones} not collected" in vs
	not "6.14: every allow rule to or from the Internet must carry a data filtering profile" in vs
}

test_6_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.15")
}

test_6_15_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/network/profiles/zone_protection/0/flood/tcp_syn/action", "value": "red"}])
	vs := b.violations with input as inp
	"6.15: untrusted zones must have a zone protection profile answering SYN floods with SYN cookies" in vs
}

test_6_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/network/profiles/zone_protection"}])
	vs := b.violations with input as inp
	"6.15: evidence missing — panos_config.{zone,site.untrusted_zones,network.profiles.zone_protection} not collected" in vs
	not "6.15: untrusted zones must have a zone protection profile answering SYN floods with SYN cookies" in vs
}

test_6_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.16")
}

test_6_16_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/network/profiles/zone_protection/0/flood/udp/enable", "value": "no"}])
	vs := b.violations with input as inp
	"6.16: untrusted zones must have zone protection flood limits on for every flood type" in vs
}

test_6_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/network/profiles/zone_protection"}])
	vs := b.violations with input as inp
	"6.16: evidence missing — panos_config.{zone,site.untrusted_zones,network.profiles.zone_protection} not collected" in vs
	not "6.16: untrusted zones must have zone protection flood limits on for every flood type" in vs
}

test_6_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.17")
}

test_6_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/network/profiles/zone_protection/0/scan/host_sweep/action", "value": "allow"}])
	vs := b.violations with input as inp
	"6.17: every zone must have zone protection with TCP and UDP port scan and host sweep detection on" in vs
}

test_6_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/network/profiles/zone_protection"}])
	vs := b.violations with input as inp
	"6.17: evidence missing — panos_config.{zone,network.profiles.zone_protection} not collected" in vs
	not "6.17: every zone must have zone protection with TCP and UDP port scan and host sweep detection on" in vs
}

test_6_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.18")
}

test_6_18_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/network/profiles/zone_protection/0/discard_ip_spoof", "value": "no"}])
	vs := b.violations with input as inp
	"6.18: every zone must have zone protection dropping spoofed, mismatched-overlap, source-routed and malformed packets" in vs
}

test_6_18_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/network/profiles/zone_protection"}])
	vs := b.violations with input as inp
	"6.18: evidence missing — panos_config.{zone,network.profiles.zone_protection} not collected" in vs
	not "6.18: every zone must have zone protection dropping spoofed, mismatched-overlap, source-routed and malformed packets" in vs
}

test_6_19_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.19")
}

test_6_19_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/url_filtering/0/credential_enforcement/mode", "value": "disabled"}])
	vs := b.violations with input as inp
	"6.19: URL filtering profiles must block or continue credential submission and keep credential detection on" in vs
}

test_6_19_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/url_filtering"}])
	vs := b.violations with input as inp
	"6.19: evidence missing — panos_config.profiles.url_filtering not collected" in vs
	not "6.19: URL filtering profiles must block or continue credential submission and keep credential detection on" in vs
}

test_6_20_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.20")
}

test_6_20_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/virus/0/decoder/0/mlav_action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.20: the antivirus WildFire inline ML action must reset both ends (imap and pop3 may alert)" in vs
}

test_6_20_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/virus"}])
	vs := b.violations with input as inp
	"6.20: evidence missing — panos_config.profiles.virus not collected" in vs
	not "6.20: the antivirus WildFire inline ML action must reset both ends (imap and pop3 may alert)" in vs
}

test_6_21_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.21")
}

test_6_21_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/virus/0/mlav_engine_filebased_enabled/0/mlav_policy_action", "value": "disable"}])
	vs := b.violations with input as inp
	"6.21: antivirus WildFire inline ML must be on for every file model" in vs
}

test_6_21_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/virus"}])
	vs := b.violations with input as inp
	"6.21: evidence missing — panos_config.profiles.virus not collected" in vs
	not "6.21: antivirus WildFire inline ML must be on for every file model" in vs
}

test_6_22_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.22")
}

test_6_22_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/vulnerability/0/cloud_inline_analysis", "value": "no"}])
	vs := b.violations with input as inp
	"6.22: with Advanced Threat Prevention, vulnerability profiles must run inline cloud analysis (models alert)" in vs
}

test_6_22_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}])
	vs := b.violations with input as inp
	"6.22: evidence missing — panos_config.{licenses,profiles.vulnerability} not collected" in vs
	not "6.22: with Advanced Threat Prevention, vulnerability profiles must run inline cloud analysis (models alert)" in vs
}

test_6_23_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.23")
}

test_6_23_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/url_filtering/0/cloud_inline_cat", "value": "no"}])
	vs := b.violations with input as inp
	"6.23: with an advanced license, URL filtering profiles must run local and cloud inline categorization" in vs
}

test_6_23_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}])
	vs := b.violations with input as inp
	"6.23: evidence missing — panos_config.{licenses,profiles.url_filtering} not collected" in vs
	not "6.23: with an advanced license, URL filtering profiles must run local and cloud inline categorization" in vs
}

test_6_24_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.24")
}

test_6_24_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/spyware/0/mica_engine_spyware_enabled/0/inline_policy_action", "value": "alert"}])
	vs := b.violations with input as inp
	"6.24: with Advanced Threat Prevention, anti-spyware profiles must run inline cloud analysis (models reset both)" in vs
}

test_6_24_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}])
	vs := b.violations with input as inp
	"6.24: evidence missing — panos_config.{licenses,profiles.spyware} not collected" in vs
	not "6.24: with Advanced Threat Prevention, anti-spyware profiles must run inline cloud analysis (models reset both)" in vs
}

test_6_25_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.25")
}

test_6_25_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/profiles/spyware/0/botnet_domains/dns_security_categories/0/packet_capture", "value": "disable"}])
	vs := b.violations with input as inp
	"6.25: with DNS Security, anti-spyware profiles must sinkhole every DNS Security category (C2 with extended capture)" in vs
}

test_6_25_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}])
	vs := b.violations with input as inp
	"6.25: evidence missing — panos_config.{licenses,profiles.spyware} not collected" in vs
	not "6.25: with DNS Security, anti-spyware profiles must sinkhole every DNS Security category (C2 with extended capture)" in vs
}

test_7_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.1")
}

test_7_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/security/3/application", "value": ["any"]}])
	vs := b.violations with input as inp
	"7.1: allow rules from an untrusted to a more trusted zone must name the application and the service" in vs
}

test_7_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/site/untrusted_zones"}])
	vs := b.violations with input as inp
	"7.1: evidence missing — panos_config.{rulebase.security,site.untrusted_zones} not collected" in vs
	not "7.1: allow rules from an untrusted to a more trusted zone must name the application and the service" in vs
}

test_7_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.2")
}

test_7_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/security/0/service", "value": ["any"]}])
	vs := b.violations with input as inp
	"7.2: allow rules must not use service any" in vs
}

test_7_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security"}])
	vs := b.violations with input as inp
	"7.2: evidence missing — panos_config.rulebase.security not collected" in vs
	not "7.2: allow rules must not use service any" in vs
}

test_7_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3")
}

test_7_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/security/4/destination", "value": ["any"]}])
	vs := b.violations with input as inp
	"7.3: deny rules must block traffic to and from the Palo Alto malicious, high-risk, Tor-exit and bulletproof IP lists" in vs
}

test_7_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/security"}])
	vs := b.violations with input as inp
	"7.3: evidence missing — panos_config.rulebase.security not collected" in vs
	not "7.3: deny rules must block traffic to and from the Palo Alto malicious, high-risk, Tor-exit and bulletproof IP lists" in vs
}

test_7_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.4")
}

test_7_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/default_security_rules/0/log_end", "value": "no"}])
	vs := b.violations with input as inp
	"7.4: the intrazone and interzone default rules must log at session end" in vs
}

test_7_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/default_security_rules"}])
	vs := b.violations with input as inp
	"7.4: evidence missing — panos_config.rulebase.default_security_rules not collected" in vs
	not "7.4: the intrazone and interzone default rules must log at session end" in vs
}

test_8_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.1")
}

test_8_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/panos_config/rulebase/decryption/0/type", "value": "ssl-inbound-inspection"}])
	vs := b.violations with input as inp
	"8.1: an SSL forward proxy decryption rule must cover traffic toward the Internet" in vs
}

test_8_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/rulebase/decryption"}])
	vs := b.violations with input as inp
	"8.1: evidence missing — panos_config.{rulebase.decryption,site.internet_zones} not collected" in vs
	not "8.1: an SSL forward proxy decryption rule must cover traffic toward the Internet" in vs
}

test_8_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.2")
}

test_8_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/ssl_inbound_inspection_reviewed", "value": false}])
	vs := b.violations with input as inp
	"8.2: inbound TLS to published servers must pass through SSL inbound inspection (manual review not attested)" in vs
}

test_8_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/ssl_inbound_inspection_reviewed"}])
	vs := b.violations with input as inp
	"8.2: inbound TLS to published servers must pass through SSL inbound inspection (manual review not attested)" in vs
}

test_8_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.3")
}

test_8_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/panos_config/attest/decryption_certificate_trusted", "value": false}])
	vs := b.violations with input as inp
	"8.3: the decryption certificate must be trusted and valid (manual review not attested)" in vs
}

test_8_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/panos_config/attest/decryption_certificate_trusted"}])
	vs := b.violations with input as inp
	"8.3: the decryption certificate must be trusted and valid (manual review not attested)" in vs
}
