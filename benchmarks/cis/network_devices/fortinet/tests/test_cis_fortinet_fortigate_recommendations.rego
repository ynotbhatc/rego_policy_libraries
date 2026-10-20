package cis_fortinet_fortigate_test

import rego.v1

import data.cis_fortinet_fortigate as b

# Generated per-recommendation tests for CIS FortiGate 7.4.x Benchmark v1.0.1: every recommendation has a pass test (green input) and a
# fail test; configuration checks also have an evidence-missing test; attestations fail when false or absent.

green := {
	"fortigate_config": {
		"system": {
			"dns": {
				"primary": "10.0.0.53",
				"secondary": "10.0.1.53"
			},
			"zone": [
				{
					"name": "DMZ",
					"intrazone": "deny"
				}
			],
			"interface": [
				{
					"name": "wan1",
					"role": "wan",
					"allowaccess": ""
				},
				{
					"name": "mgmt",
					"role": "lan",
					"allowaccess": "https ssh"
				}
			],
			"global": {
				"pre_login_banner": "enable",
				"post_login_banner": "enable",
				"timezone": "US/Eastern",
				"hostname": "fw-edge-01",
				"ssl_static_key_ciphers": "disable",
				"strong_crypto": "enable",
				"admin_https_ssl_versions": "tlsv1-3",
				"gui_cdn_usage": "enable",
				"log_single_cpu_high": "enable",
				"gui_display_hostname": "disable",
				"admin_lockout_threshold": 3,
				"admin_lockout_duration": 900,
				"admintimeout": 5,
				"admin_port": 8082,
				"admin_sport": 4343,
				"admin_https_redirect": "disable"
			},
			"ntp": {
				"ntpsync": "enable"
			},
			"auto_install": {
				"auto_install_config": "disable",
				"auto_install_image": "disable"
			},
			"password_policy": {
				"status": "enable",
				"minimum_length": 14,
				"apply_to": "admin-password ipsec-preshared-key"
			},
			"snmp": {
				"sysinfo": {
					"status": "enable",
					"trap_free_memory_threshold": 20,
					"trap_freeable_memory_threshold": 50
				},
				"community": [],
				"user": [
					{
						"name": "snmp_ops",
						"notify_hosts": [
							"10.0.0.20"
						],
						"queries": "disable"
					}
				]
			},
			"admin": [
				{
					"name": "fw_ops",
					"trusthosts": [
						"10.0.0.0 255.255.255.0"
					]
				}
			],
			"ha": {
				"mode": "a-p",
				"group_name": "FGT-HA",
				"group_id": 10,
				"hbdev": [
					"port10"
				],
				"monitor": [
					"port6",
					"port7"
				],
				"ha_mgmt_status": "enable",
				"ha_mgmt_interfaces": [
					{
						"interface": "port8",
						"gateway": "10.10.10.1"
					}
				]
			},
			"autoupdate": {
				"schedule": {
					"frequency": "automatic"
				}
			},
			"fortiguard": {
				"sandbox_inline_scan": "enable"
			},
			"automation_stitch": [
				{
					"name": "Compromised Host Quarantine",
					"status": "enable",
					"trigger": "Compromised Host - High",
					"actions": [
						"Quarantine on FortiSwitch + FortiAP",
						"Quarantine FortiClient EMS Endpoint"
					]
				}
			],
			"csf": {
				"status": "enable",
				"group_name": "fabric-01"
			}
		},
		"firewall": {
			"local_in_policy": [
				{
					"policyid": 1,
					"action": "accept",
					"virtual_patch": "enable"
				},
				{
					"policyid": 2,
					"action": "deny"
				}
			],
			"policy": [
				{
					"policyid": 1,
					"srcintf": [
						"mgmt"
					],
					"dstintf": [
						"wan1"
					],
					"action": "accept",
					"service": [
						"HTTPS",
						"DNS"
					],
					"logtraffic": "all",
					"ips_sensor": "botnet-block",
					"av_profile": "av-default",
					"dnsfilter_profile": "dns-default",
					"application_list": "app-default"
				},
				{
					"policyid": 2,
					"srcintf": [
						"wan1"
					],
					"dstintf": [
						"mgmt"
					],
					"action": "deny",
					"service": [
						"ALL_TCP"
					],
					"logtraffic": "all",
					"internet_service_src": "enable",
					"internet_service_src_name": [
						"Tor-Exit.Node",
						"Tor-Relay.Node",
						"Censys-Scanner",
						"Shodan-Scanner",
						"Botnet-C&C.Server",
						"Phishing-Phishing.Server",
						"Proxy-Proxy.Server",
						"Spam-Spamming.Server",
						"VPN-Anonymous.VPN",
						"Malicious-Malicious.Server"
					]
				},
				{
					"policyid": 3,
					"srcintf": [
						"mgmt"
					],
					"dstintf": [
						"wan1"
					],
					"action": "deny",
					"service": [
						"HTTPS"
					],
					"logtraffic": "all",
					"internet_service": "enable",
					"internet_service_name": [
						"Tor-Relay.Node",
						"Botnet-C&C.Server",
						"Phishing-Phishing.Server",
						"Proxy-Proxy.Server",
						"Spam-Spamming.Server",
						"VPN-Anonymous.VPN",
						"Malicious-Malicious.Server"
					]
				}
			]
		},
		"ips": {
			"sensor": [
				{
					"name": "botnet-block",
					"scan_botnet_connections": "block"
				}
			]
		},
		"antivirus": {
			"settings": {
				"machine_learning_detection": "enable",
				"grayware": "enable"
			},
			"profile": [
				{
					"name": "av-default",
					"feature_set": "proxy",
					"fortisandbox_mode": "inline",
					"http": {
						"outbreak_prevention": "block",
						"content_disarm": "enable"
					},
					"smtp": {
						"outbreak_prevention": "block",
						"content_disarm": "enable"
					}
				}
			]
		},
		"dnsfilter": {
			"profile": [
				{
					"name": "dns-default",
					"block_botnet": "enable",
					"log_all_domain": "enable"
				}
			]
		},
		"webfilter": {
			"profile": [
				{
					"name": "web-default",
					"ftgd_wf": {
						"filters": [
							{
								"category": 26,
								"action": "block"
							},
							{
								"category": 61,
								"action": "block"
							},
							{
								"category": 86,
								"action": "block"
							}
						]
					}
				}
			]
		},
		"application": {
			"list": [
				{
					"name": "app-default",
					"enforce_default_app_port": "enable",
					"entries": [
						{
							"category": [
								2,
								6
							],
							"action": "block"
						},
						{
							"category": [
								5
							],
							"action": "monitor"
						}
					]
				}
			]
		},
		"vpn": {
			"ssl": {
				"settings": {
					"servercert": "vpn.example.com",
					"ssl_max_proto_ver": "tls1-3",
					"ssl_min_proto_ver": "tls1-2",
					"algorithm": "high"
				}
			}
		},
		"log": {
			"eventfilter": {
				"event": "enable",
				"system": "enable",
				"vpn": "enable",
				"user": "enable",
				"router": "enable",
				"wireless_activity": "enable",
				"wan_opt": "enable",
				"endpoint": "enable",
				"ha": "enable",
				"security_rating": "enable",
				"fortiextender": "enable",
				"connector": "enable",
				"sdwan": "enable",
				"cifs": "enable",
				"switch_controller": "enable",
				"rest_api": "enable",
				"webproxy": "enable"
			},
			"syslogd": {
				"setting": {
					"status": "enable",
					"server": "10.0.0.30",
					"enc_algorithm": "high",
					"reliable": "enable"
				}
			},
			"fortianalyzer": {
				"setting": {
					"status": "enable",
					"server": "10.0.0.31",
					"enc_algorithm": "high",
					"reliable": "enable"
				}
			}
		},
		"attest": {
			"latest_firmware_installed": true,
			"admin_profiles_reviewed": true,
			"unused_policies_reviewed": true
		}
	}
}

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

test_green_input_is_compliant if {
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	s := b.compliance_summary with input as green
	s.passing_controls == 64
	s.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 64
	count([id | some id, r in b.recommendations; r.level == 2]) == 25
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 48
}

test_summary_counts_recommendations_not_messages if {
	s := b.compliance_summary with input as {}
	s.failing_controls == 64
	s.passing_controls == 0
	s.compliance_percentage == 0
	r := b.compliance_report with input as {}
	r.failed_controls == 64
	r.compliant == false
}

test_3_2_deny_all_service_allowed_accept_all_flagged if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy/1/service", "value": ["ALL"]}])
	vs := b.violations with input as inp
	not _has_id(vs, "3.2")
	inp2 := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy/0/service", "value": ["ALL"]}])
	vs2 := b.violations with input as inp2
	_has_id(vs2, "3.2")
}

test_empty_policy_list_is_not_evidence if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy", "value": []}])
	vs := b.violations with input as inp
	"3.4: evidence missing — fortigate_config.firewall.policy not collected" in vs
}

test_standalone_unit_passes_ha_cluster_checks if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ha", "value": {"mode": "standalone"}}])
	vs := b.violations with input as inp
	not _has_id(vs, "2.5.2")
	not _has_id(vs, "2.5.3")
	_has_id(vs, "2.5.1")
}

test_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1")
}

test_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/dns/primary", "value": "0.0.0.0"}])
	vs := b.violations with input as inp
	"1.1: Ensure DNS server is configured" in vs
}

test_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/dns"}])
	vs := b.violations with input as inp
	"1.1: evidence missing — fortigate_config.system.dns not collected" in vs
	not "1.1: Ensure DNS server is configured" in vs
}

test_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2")
}

test_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/zone/0/intrazone", "value": "allow"}])
	vs := b.violations with input as inp
	"1.2: Ensure intra-zone traffic is not always allowed" in vs
}

test_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/zone"}])
	vs := b.violations with input as inp
	"1.2: evidence missing — fortigate_config.system.zone not collected" in vs
	not "1.2: Ensure intra-zone traffic is not always allowed" in vs
}

test_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3")
}

test_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/interface/0/allowaccess", "value": "ping https"}])
	vs := b.violations with input as inp
	"1.3: Disable all management related services on WAN port" in vs
}

test_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/interface/0/role"}])
	vs := b.violations with input as inp
	"1.3: evidence missing — fortigate_config.system.interface (a WAN-role interface) not collected" in vs
	not "1.3: Disable all management related services on WAN port" in vs
}

test_2_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1")
}

test_2_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/pre_login_banner", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.1: Ensure 'Pre-Login Banner' is set" in vs
}

test_2_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.1: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.1: Ensure 'Pre-Login Banner' is set" in vs
}

test_2_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.2")
}

test_2_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/post_login_banner", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.2: Ensure 'Post-Login-Banner' is set" in vs
}

test_2_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.2: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.2: Ensure 'Post-Login-Banner' is set" in vs
}

test_2_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.3")
}

test_2_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/timezone", "value": ""}])
	vs := b.violations with input as inp
	"2.1.3: Ensure timezone is properly configured" in vs
}

test_2_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.3: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.3: Ensure timezone is properly configured" in vs
}

test_2_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.4")
}

test_2_1_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ntp/ntpsync", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.4: Ensure correct system time is configured through NTP" in vs
}

test_2_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/ntp"}])
	vs := b.violations with input as inp
	"2.1.4: evidence missing — fortigate_config.system.ntp not collected" in vs
	not "2.1.4: Ensure correct system time is configured through NTP" in vs
}

test_2_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.5")
}

test_2_1_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/hostname", "value": ""}])
	vs := b.violations with input as inp
	"2.1.5: Ensure hostname is set" in vs
}

test_2_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.5: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.5: Ensure hostname is set" in vs
}

test_2_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.6")
}

test_2_1_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/fortigate_config/attest/latest_firmware_installed", "value": false}])
	vs := b.violations with input as inp
	"2.1.6: Ensure the latest firmware is installed (manual review not attested)" in vs
}

test_2_1_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/attest/latest_firmware_installed"}])
	vs := b.violations with input as inp
	"2.1.6: Ensure the latest firmware is installed (manual review not attested)" in vs
}

test_2_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.7")
}

test_2_1_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/auto_install/auto_install_image", "value": "enable"}])
	vs := b.violations with input as inp
	"2.1.7: Disable USB Firmware and configuration installation" in vs
}

test_2_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/auto_install"}])
	vs := b.violations with input as inp
	"2.1.7: evidence missing — fortigate_config.system.auto_install not collected" in vs
	not "2.1.7: Disable USB Firmware and configuration installation" in vs
}

test_2_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.8")
}

test_2_1_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/ssl_static_key_ciphers", "value": "enable"}])
	vs := b.violations with input as inp
	"2.1.8: Disable static keys for TLS" in vs
}

test_2_1_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.8: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.8: Disable static keys for TLS" in vs
}

test_2_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.9")
}

test_2_1_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/strong_crypto", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.9: Enable Global Strong Encryption" in vs
}

test_2_1_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.9: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.9: Enable Global Strong Encryption" in vs
}

test_2_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.10")
}

test_2_1_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/admin_https_ssl_versions", "value": "tlsv1-2 tlsv1-3"}])
	vs := b.violations with input as inp
	"2.1.10: Ensure management GUI listens on secure TLS version" in vs
}

test_2_1_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.10: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.10: Ensure management GUI listens on secure TLS version" in vs
}

test_2_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.11")
}

test_2_1_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/gui_cdn_usage", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.11: Ensure CDN is enabled for improved GUI performance" in vs
}

test_2_1_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.11: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.11: Ensure CDN is enabled for improved GUI performance" in vs
}

test_2_1_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.12")
}

test_2_1_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/log_single_cpu_high", "value": "disable"}])
	vs := b.violations with input as inp
	"2.1.12: Ensure single CPU core overloaded event is logged" in vs
}

test_2_1_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.12: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.12: Ensure single CPU core overloaded event is logged" in vs
}

test_2_1_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.13")
}

test_2_1_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/gui_display_hostname", "value": "enable"}])
	vs := b.violations with input as inp
	"2.1.13: Ensure Hostname is Not Displayed On Login GUI" in vs
}

test_2_1_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.1.13: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.1.13: Ensure Hostname is Not Displayed On Login GUI" in vs
}

test_2_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.1")
}

test_2_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/password_policy/minimum_length", "value": 8}])
	vs := b.violations with input as inp
	"2.2.1: Ensure 'Password Policy' is enabled" in vs
}

test_2_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/password_policy"}])
	vs := b.violations with input as inp
	"2.2.1: evidence missing — fortigate_config.system.password_policy not collected" in vs
	not "2.2.1: Ensure 'Password Policy' is enabled" in vs
}

test_2_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.2")
}

test_2_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/admin_lockout_threshold", "value": 5}])
	vs := b.violations with input as inp
	"2.2.2: Ensure administrator password retries and lockout time are configured" in vs
}

test_2_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.2.2: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.2.2: Ensure administrator password retries and lockout time are configured" in vs
}

test_2_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1")
}

test_2_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/snmp/community", "value": [{"name": "public"}]}])
	vs := b.violations with input as inp
	"2.3.1: Ensure only SNMPv3 is enabled" in vs
}

test_2_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/snmp/community"}])
	vs := b.violations with input as inp
	"2.3.1: evidence missing — fortigate_config.system.snmp.{sysinfo,community,user} not collected" in vs
	not "2.3.1: Ensure only SNMPv3 is enabled" in vs
}

test_2_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.2")
}

test_2_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/snmp/user/0/notify_hosts", "value": ["0.0.0.0"]}])
	vs := b.violations with input as inp
	"2.3.2: Allow only trusted hosts in SNMPv3" in vs
}

test_2_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/snmp/user"}])
	vs := b.violations with input as inp
	"2.3.2: evidence missing — fortigate_config.system.snmp.user not collected" in vs
	not "2.3.2: Allow only trusted hosts in SNMPv3" in vs
}

test_2_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.3")
}

test_2_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/snmp/user/0/queries", "value": "enable"}])
	vs := b.violations with input as inp
	"2.3.3: Disable SNMPv3 Query Per User" in vs
}

test_2_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/snmp/user"}])
	vs := b.violations with input as inp
	"2.3.3: evidence missing — fortigate_config.system.snmp.user not collected" in vs
	not "2.3.3: Disable SNMPv3 Query Per User" in vs
}

test_2_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.4")
}

test_2_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/snmp/sysinfo/trap_free_memory_threshold", "value": 5}])
	vs := b.violations with input as inp
	"2.3.4: Enabling SNMP trap for memory usage" in vs
}

test_2_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/snmp/sysinfo"}])
	vs := b.violations with input as inp
	"2.3.4: evidence missing — fortigate_config.system.snmp.sysinfo not collected" in vs
	not "2.3.4: Enabling SNMP trap for memory usage" in vs
}

test_2_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.1")
}

test_2_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/admin/0/name", "value": "admin"}])
	vs := b.violations with input as inp
	"2.4.1: Remove default admin user and create one with other name" in vs
}

test_2_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/admin"}])
	vs := b.violations with input as inp
	"2.4.1: evidence missing — fortigate_config.system.admin not collected" in vs
	not "2.4.1: Remove default admin user and create one with other name" in vs
}

test_2_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.2")
}

test_2_4_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/admin/0/trusthosts", "value": []}])
	vs := b.violations with input as inp
	"2.4.2: Ensure all the login accounts having specific trusted hosts enabled" in vs
}

test_2_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/admin"}])
	vs := b.violations with input as inp
	"2.4.2: evidence missing — fortigate_config.system.admin not collected" in vs
	not "2.4.2: Ensure all the login accounts having specific trusted hosts enabled" in vs
}

test_2_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.3")
}

test_2_4_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/fortigate_config/attest/admin_profiles_reviewed", "value": false}])
	vs := b.violations with input as inp
	"2.4.3: Ensure admin accounts with different privileges have their correct profiles assigned (manual review not attested)" in vs
}

test_2_4_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/attest/admin_profiles_reviewed"}])
	vs := b.violations with input as inp
	"2.4.3: Ensure admin accounts with different privileges have their correct profiles assigned (manual review not attested)" in vs
}

test_2_4_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.4")
}

test_2_4_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/admintimeout", "value": 30}])
	vs := b.violations with input as inp
	"2.4.4: Ensure Admin idle timeout time is configured" in vs
}

test_2_4_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.4.4: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.4.4: Ensure Admin idle timeout time is configured" in vs
}

test_2_4_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.5")
}

test_2_4_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/interface/1/allowaccess", "value": "https ssh http"}])
	vs := b.violations with input as inp
	"2.4.5: Ensure only encrypted access channels are enabled" in vs
}

test_2_4_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/interface"}])
	vs := b.violations with input as inp
	"2.4.5: evidence missing — fortigate_config.system.interface not collected" in vs
	not "2.4.5: Ensure only encrypted access channels are enabled" in vs
}

test_2_4_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.6")
}

test_2_4_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/local_in_policy", "value": []}])
	vs := b.violations with input as inp
	"2.4.6: Apply Local-in Policies" in vs
}

test_2_4_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/local_in_policy"}])
	vs := b.violations with input as inp
	"2.4.6: evidence missing — fortigate_config.firewall.local_in_policy not collected" in vs
	not "2.4.6: Apply Local-in Policies" in vs
}

test_2_4_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.7")
}

test_2_4_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/global/admin_sport", "value": 443}])
	vs := b.violations with input as inp
	"2.4.7: Ensure default Admin ports are changed" in vs
}

test_2_4_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/global"}])
	vs := b.violations with input as inp
	"2.4.7: evidence missing — fortigate_config.system.global not collected" in vs
	not "2.4.7: Ensure default Admin ports are changed" in vs
}

test_2_4_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.8")
}

test_2_4_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/local_in_policy/0/virtual_patch", "value": "disable"}])
	vs := b.violations with input as inp
	"2.4.8: Virtual patching on the local-in management interface" in vs
}

test_2_4_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/local_in_policy"}])
	vs := b.violations with input as inp
	"2.4.8: evidence missing — fortigate_config.firewall.local_in_policy not collected" in vs
	not "2.4.8: Virtual patching on the local-in management interface" in vs
}

test_2_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.1")
}

test_2_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ha/mode", "value": "standalone"}])
	vs := b.violations with input as inp
	"2.5.1: Ensure High Availability configuration is enabled" in vs
}

test_2_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/ha"}])
	vs := b.violations with input as inp
	"2.5.1: evidence missing — fortigate_config.system.ha not collected" in vs
	not "2.5.1: Ensure High Availability configuration is enabled" in vs
}

test_2_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.2")
}

test_2_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ha/monitor", "value": []}])
	vs := b.violations with input as inp
	"2.5.2: Ensure \"Monitor Interfaces\" for High Availability devices is enabled" in vs
}

test_2_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/ha"}])
	vs := b.violations with input as inp
	"2.5.2: evidence missing — fortigate_config.system.ha not collected" in vs
	not "2.5.2: Ensure \"Monitor Interfaces\" for High Availability devices is enabled" in vs
}

test_2_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.3")
}

test_2_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ha/ha_mgmt_status", "value": "disable"}])
	vs := b.violations with input as inp
	"2.5.3: Ensure HA Reserved Management Interface is configured" in vs
}

test_2_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/ha"}])
	vs := b.violations with input as inp
	"2.5.3: evidence missing — fortigate_config.system.ha not collected" in vs
	not "2.5.3: Ensure HA Reserved Management Interface is configured" in vs
}

test_2_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.4")
}

test_2_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/ha/group_id", "value": 0}])
	vs := b.violations with input as inp
	"2.5.4: Ensure High Availability Group-ID is configured" in vs
}

test_2_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/ha"}])
	vs := b.violations with input as inp
	"2.5.4: evidence missing — fortigate_config.system.ha not collected" in vs
	not "2.5.4: Ensure High Availability Group-ID is configured" in vs
}

test_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1")
}

test_3_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/fortigate_config/attest/unused_policies_reviewed", "value": false}])
	vs := b.violations with input as inp
	"3.1: Ensure that unused policies are reviewed regularly (manual review not attested)" in vs
}

test_3_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/attest/unused_policies_reviewed"}])
	vs := b.violations with input as inp
	"3.1: Ensure that unused policies are reviewed regularly (manual review not attested)" in vs
}

test_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2")
}

test_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy/0/service", "value": ["ALL"]}])
	vs := b.violations with input as inp
	"3.2: Ensure that policies do not use \"ALL\" as Service" in vs
}

test_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"3.2: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "3.2: Ensure that policies do not use \"ALL\" as Service" in vs
}

test_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3")
}

test_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy/1/internet_service_src_name", "value": ["Tor-Exit.Node"]}])
	vs := b.violations with input as inp
	"3.3: Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB" in vs
}

test_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"3.3: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "3.3: Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB" in vs
}

test_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.4")
}

test_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/firewall/policy/0/logtraffic", "value": "disable"}])
	vs := b.violations with input as inp
	"3.4: Ensure logging is enabled on all firewall policies" in vs
}

test_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"3.4: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "3.4: Ensure logging is enabled on all firewall policies" in vs
}

test_4_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.1")
}

test_4_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/ips/sensor/0/scan_botnet_connections", "value": "monitor"}])
	vs := b.violations with input as inp
	"4.1.1: Detect Botnet connections" in vs
}

test_4_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/interface/0/role"}])
	vs := b.violations with input as inp
	"4.1.1: evidence missing — fortigate_config.{ips.sensor,firewall.policy,system.interface WAN role} not collected" in vs
	not "4.1.1: Detect Botnet connections" in vs
}

test_4_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.2")
}

test_4_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy/0/ips_sensor"}])
	vs := b.violations with input as inp
	"4.1.2: Apply IPS Security Profile to Policies" in vs
}

test_4_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"4.1.2: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "4.1.2: Apply IPS Security Profile to Policies" in vs
}

test_4_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.1")
}

test_4_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/autoupdate/schedule/frequency", "value": "daily"}])
	vs := b.violations with input as inp
	"4.2.1: Ensure Antivirus Definition Push Updates are Configured" in vs
}

test_4_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/autoupdate/schedule"}])
	vs := b.violations with input as inp
	"4.2.1: evidence missing — fortigate_config.system.autoupdate.schedule not collected" in vs
	not "4.2.1: Ensure Antivirus Definition Push Updates are Configured" in vs
}

test_4_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.2")
}

test_4_2_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy/0/av_profile"}])
	vs := b.violations with input as inp
	"4.2.2: Apply Antivirus Security Profile to Policies" in vs
}

test_4_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"4.2.2: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "4.2.2: Apply Antivirus Security Profile to Policies" in vs
}

test_4_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.3")
}

test_4_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/antivirus/profile/0/http/outbreak_prevention", "value": "disabled"}])
	vs := b.violations with input as inp
	"4.2.3: Enable Outbreak Prevention Database" in vs
}

test_4_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/antivirus/profile"}])
	vs := b.violations with input as inp
	"4.2.3: evidence missing — fortigate_config.antivirus.profile not collected" in vs
	not "4.2.3: Enable Outbreak Prevention Database" in vs
}

test_4_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.4")
}

test_4_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/antivirus/settings/machine_learning_detection", "value": "monitor"}])
	vs := b.violations with input as inp
	"4.2.4: Enable AI /heuristic based malware detection" in vs
}

test_4_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/antivirus/settings"}])
	vs := b.violations with input as inp
	"4.2.4: evidence missing — fortigate_config.antivirus.settings not collected" in vs
	not "4.2.4: Enable AI /heuristic based malware detection" in vs
}

test_4_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.5")
}

test_4_2_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/antivirus/settings/grayware", "value": "disable"}])
	vs := b.violations with input as inp
	"4.2.5: Enable grayware detection on antivirus" in vs
}

test_4_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/antivirus/settings"}])
	vs := b.violations with input as inp
	"4.2.5: evidence missing — fortigate_config.antivirus.settings not collected" in vs
	not "4.2.5: Enable grayware detection on antivirus" in vs
}

test_4_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.6")
}

test_4_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/fortiguard/sandbox_inline_scan", "value": "disable"}])
	vs := b.violations with input as inp
	"4.2.6: Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled" in vs
}

test_4_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/fortiguard"}])
	vs := b.violations with input as inp
	"4.2.6: evidence missing — fortigate_config.{system.fortiguard,antivirus.profile} not collected" in vs
	not "4.2.6: Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled" in vs
}

test_4_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.7")
}

test_4_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/antivirus/profile/0/feature_set", "value": "flow"}])
	vs := b.violations with input as inp
	"4.2.7: Enable CDR for proxy mode on XLSB, OpenOffice, and RTF files" in vs
}

test_4_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/antivirus/profile"}])
	vs := b.violations with input as inp
	"4.2.7: evidence missing — fortigate_config.antivirus.profile not collected" in vs
	not "4.2.7: Enable CDR for proxy mode on XLSB, OpenOffice, and RTF files" in vs
}

test_4_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3.1")
}

test_4_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/dnsfilter/profile/0/block_botnet", "value": "disable"}])
	vs := b.violations with input as inp
	"4.3.1: Enable Botnet C&C Domain Blocking DNS Filter" in vs
}

test_4_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/dnsfilter/profile"}])
	vs := b.violations with input as inp
	"4.3.1: evidence missing — fortigate_config.dnsfilter.profile not collected" in vs
	not "4.3.1: Enable Botnet C&C Domain Blocking DNS Filter" in vs
}

test_4_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3.2")
}

test_4_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/dnsfilter/profile/0/log_all_domain", "value": "disable"}])
	vs := b.violations with input as inp
	"4.3.2: Ensure DNS Filter logs all DNS queries and responses" in vs
}

test_4_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/dnsfilter/profile"}])
	vs := b.violations with input as inp
	"4.3.2: evidence missing — fortigate_config.dnsfilter.profile not collected" in vs
	not "4.3.2: Ensure DNS Filter logs all DNS queries and responses" in vs
}

test_4_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3.3")
}

test_4_3_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy/0/dnsfilter_profile"}])
	vs := b.violations with input as inp
	"4.3.3: Apply DNS Filter Security Profile to Policies" in vs
}

test_4_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/interface/0/role"}])
	vs := b.violations with input as inp
	"4.3.3: evidence missing — fortigate_config.{firewall.policy,system.interface WAN role} not collected" in vs
	not "4.3.3: Apply DNS Filter Security Profile to Policies" in vs
}

test_4_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.4.1")
}

test_4_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/webfilter/profile/0/ftgd_wf/filters/0/action", "value": "monitor"}])
	vs := b.violations with input as inp
	"4.4.1: Create a Web Filtering Profile" in vs
}

test_4_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/webfilter/profile"}])
	vs := b.violations with input as inp
	"4.4.1: evidence missing — fortigate_config.webfilter.profile not collected" in vs
	not "4.4.1: Create a Web Filtering Profile" in vs
}

test_4_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.5.1")
}

test_4_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/application/list/0/entries/0/action", "value": "monitor"}])
	vs := b.violations with input as inp
	"4.5.1: Block high risk categories on Application Control" in vs
}

test_4_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/application/list"}])
	vs := b.violations with input as inp
	"4.5.1: evidence missing — fortigate_config.application.list not collected" in vs
	not "4.5.1: Block high risk categories on Application Control" in vs
}

test_4_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.5.2")
}

test_4_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/application/list/0/enforce_default_app_port", "value": "disable"}])
	vs := b.violations with input as inp
	"4.5.2: Block applications running on non-default ports" in vs
}

test_4_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/application/list"}])
	vs := b.violations with input as inp
	"4.5.2: evidence missing — fortigate_config.application.list not collected" in vs
	not "4.5.2: Block applications running on non-default ports" in vs
}

test_4_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.5.3")
}

test_4_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/application/list/0/entries/1/action", "value": "pass"}])
	vs := b.violations with input as inp
	"4.5.3: Ensure all Application Control related traffic is logged" in vs
}

test_4_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/application/list"}])
	vs := b.violations with input as inp
	"4.5.3: evidence missing — fortigate_config.application.list not collected" in vs
	not "4.5.3: Ensure all Application Control related traffic is logged" in vs
}

test_4_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.5.4")
}

test_4_5_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy/0/application_list"}])
	vs := b.violations with input as inp
	"4.5.4: Apply Application Control Security Profile to Policies" in vs
}

test_4_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/firewall/policy"}])
	vs := b.violations with input as inp
	"4.5.4: evidence missing — fortigate_config.firewall.policy not collected" in vs
	not "4.5.4: Apply Application Control Security Profile to Policies" in vs
}

test_5_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.1")
}

test_5_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/automation_stitch/0/status", "value": "disable"}])
	vs := b.violations with input as inp
	"5.1.1: Enable Compromised Host Quarantine" in vs
}

test_5_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/automation_stitch"}])
	vs := b.violations with input as inp
	"5.1.1: evidence missing — fortigate_config.system.automation_stitch not collected" in vs
	not "5.1.1: Enable Compromised Host Quarantine" in vs
}

test_5_2_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.1.1")
}

test_5_2_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/system/csf/status", "value": "disable"}])
	vs := b.violations with input as inp
	"5.2.1.1: Ensure Security Fabric is Configured" in vs
}

test_5_2_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/system/csf"}])
	vs := b.violations with input as inp
	"5.2.1.1: evidence missing — fortigate_config.system.csf not collected" in vs
	not "5.2.1.1: Ensure Security Fabric is Configured" in vs
}

test_6_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.1.1")
}

test_6_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/vpn/ssl/settings/servercert", "value": "Fortinet_Factory"}])
	vs := b.violations with input as inp
	"6.1.1: Apply a Trusted Signed Certificate for VPN Portal" in vs
}

test_6_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/vpn/ssl/settings"}])
	vs := b.violations with input as inp
	"6.1.1: evidence missing — fortigate_config.vpn.ssl.settings not collected" in vs
	not "6.1.1: Apply a Trusted Signed Certificate for VPN Portal" in vs
}

test_6_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.1.2")
}

test_6_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/vpn/ssl/settings/ssl_min_proto_ver", "value": "tls1-1"}])
	vs := b.violations with input as inp
	"6.1.2: Enable Limited TLS Versions for SSL VPN" in vs
}

test_6_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/vpn/ssl/settings"}])
	vs := b.violations with input as inp
	"6.1.2: evidence missing — fortigate_config.vpn.ssl.settings not collected" in vs
	not "6.1.2: Enable Limited TLS Versions for SSL VPN" in vs
}

test_7_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.1.1")
}

test_7_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/log/eventfilter/vpn", "value": "disable"}])
	vs := b.violations with input as inp
	"7.1.1: Enable Event Logging" in vs
}

test_7_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/log/eventfilter"}])
	vs := b.violations with input as inp
	"7.1.1: evidence missing — fortigate_config.log.eventfilter not collected" in vs
	not "7.1.1: Enable Event Logging" in vs
}

test_7_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.2.1")
}

test_7_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/log/syslogd/setting/status", "value": "disable"}])
	vs := b.violations with input as inp
	"7.2.1: Centralized Logging and Reporting" in vs
}

test_7_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/log/syslogd/setting"}])
	vs := b.violations with input as inp
	"7.2.1: evidence missing — fortigate_config.log.syslogd.setting not collected" in vs
	not "7.2.1: Centralized Logging and Reporting" in vs
}

test_7_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3.1")
}

test_7_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/log/fortianalyzer/setting/enc_algorithm", "value": "low"}])
	vs := b.violations with input as inp
	"7.3.1: Encrypt Log Transmission to FortiAnalyzer / FortiManager" in vs
}

test_7_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/log/fortianalyzer/setting"}])
	vs := b.violations with input as inp
	"7.3.1: evidence missing — fortigate_config.log.fortianalyzer.setting not collected" in vs
	not "7.3.1: Encrypt Log Transmission to FortiAnalyzer / FortiManager" in vs
}

test_7_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3.2")
}

test_7_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/log/syslogd/setting/enc_algorithm", "value": "disable"}])
	vs := b.violations with input as inp
	"7.3.2: Encrypt Log Transmission to Syslog" in vs
}

test_7_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/log/syslogd/setting"}])
	vs := b.violations with input as inp
	"7.3.2: evidence missing — fortigate_config.log.syslogd.setting not collected" in vs
	not "7.3.2: Encrypt Log Transmission to Syslog" in vs
}

test_7_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3.3")
}

test_7_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/fortigate_config/log/syslogd/setting/reliable", "value": "disable"}])
	vs := b.violations with input as inp
	"7.3.3: Encrypt Log Transmission to Syslog" in vs
}

test_7_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/fortigate_config/log/syslogd/setting"}])
	vs := b.violations with input as inp
	"7.3.3: evidence missing — fortigate_config.log.syslogd.setting not collected" in vs
	not "7.3.3: Encrypt Log Transmission to Syslog" in vs
}
