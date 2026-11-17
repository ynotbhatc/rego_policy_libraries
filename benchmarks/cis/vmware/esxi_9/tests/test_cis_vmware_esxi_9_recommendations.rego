package cis_vmware_esxi_9_test

import rego.v1

import data.cis_vmware_esxi_9 as b

# Generated per-recommendation tests for CIS VMware ESXi 9.0 Benchmark v1.0.0 (tools/cis_generators/gen_esxi.py): every recommendation
# has a pass test (green input) and a fail test; configuration checks also have an evidence-missing test;
# attestations fail when false or absent.

green := {"esxi": {
	"advanced_settings": {
		"Net.BMCNetworkEnable": 0,
		"UserVars.SuppressHyperthreadWarning": 0,
		"Mem.ShareForceSalting": 2,
		"Mem.MemEagerZero": 1,
		"Config.HostAgent.plugins.solo.enableMob": "false",
		"UserVars.DcuiTimeOut": 600,
		"UserVars.ESXiShellInteractiveTimeOut": 300,
		"UserVars.ESXiShellTimeOut": 3600,
		"UserVars.SuppressShellWarning": 0,
		"Security.PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,disabled,15",
		"Security.AccountLockFailures": 5,
		"Security.AccountUnlockTime": 900,
		"Security.PasswordHistory": 5,
		"Config.HostAgent.vmacore.soap.sessionTimeout": 30,
		"UserVars.HostClientSessionTimeout": 900,
		"Syslog.global.logHost": "udp://10.0.0.30:514",
		"Net.DVFilterBindIpAddress": "",
		"Net.BlockGuestBPDU": 1,
	},
	"secure_boot": {"enabled": true},
	"encryption": {
		"mode": "TPM",
		"require_secure_boot": true,
	},
	"software": {"acceptance_level": "PartnerSupported"},
	"kernel_settings": {
		"execInstalledOnly": "TRUE",
		"disableHwrng": "FALSE",
	},
	"services": {
		"TSM-SSH": {
			"running": false,
			"policy": "off",
		},
		"TSM": {
			"running": false,
			"policy": "off",
		},
		"slpd": {
			"running": false,
			"policy": "off",
		},
		"ntpd": {
			"running": true,
			"policy": "on",
		},
	},
	"ntp": {"servers": [
		"10.0.0.123",
		"10.0.1.123",
	]},
	"wbem": {"enabled": false},
	"snmp": {"enabled": false},
	"lockdown_mode": "strict",
	"passwd": {
		"dcui": {"shell": "/sbin/nologin"},
		"vpxuser": {"shell": "/sbin/nologin"},
	},
	"syslog": {
		"log_level": "info",
		"log_filtering_enabled": false,
		"check_ssl_certs": true,
		"strict_x509_compliance": true,
	},
	"audit_records": {
		"storage_active": true,
		"remote_host_enabled": true,
	},
	"firewall": {
		"enabled": true,
		"default_action": "DROP",
		"rulesets": [
			{
				"name": "sshServer",
				"enabled": false,
				"allowed_ip_all": true,
			},
			{
				"name": "ntpClient",
				"enabled": true,
				"allowed_ip_all": false,
			},
		],
	},
	"vswitches": [{
		"name": "vSwitch0",
		"security": {
			"promiscuous_mode": false,
			"mac_changes": false,
			"forged_transmits": false,
		},
		"portgroups": [
			{
				"name": "VM Network",
				"vlan_id": 20,
				"security": {"forged_transmits": false},
			},
			{
				"name": "Mgmt",
				"vlan_id": 30,
			},
		],
	}],
	"datastores": [
		{"name": "ds-a"},
		{"name": "ds-b"},
	],
	"iscsi_adapters": [{
		"device": "vmhba64",
		"chap_type": "Required",
		"mutual_chap_enabled": true,
	}],
	"sshd_config": {
		"gatewayports": "no",
		"hostbasedauthentication": "no",
		"clientalivecountmax": 3,
		"clientaliveinterval": 200,
		"banner": "/etc/issue",
		"ignorerhosts": "yes",
		"allowstreamlocalforwarding": "no",
		"allowtcpforwarding": "no",
		"permittunnel": "no",
		"permituserenvironment": "no",
	},
	"vms": [
		{
			"name": "vm-a",
			"config": {
				"efi_secure_boot_enabled": true,
				"migrate_encryption": "required",
				"ft_encryption_mode": "ftEncryptionRequired",
				"version": "vmx-21",
			},
			"advanced_settings": {
				"mks.enable3d": "FALSE",
				"tools.guest.desktop.autolock": "TRUE",
				"RemoteDisplay.maxConnections": "1",
				"pciPassthru0.present": "FALSE",
				"isolation.device.edit.disable": "TRUE",
				"isolation.device.connectable.disable": "TRUE",
				"usb.present": "FALSE",
				"isolation.tools.dnd.disable": "TRUE",
				"isolation.tools.copy.disable": "TRUE",
				"isolation.tools.paste.disable": "TRUE",
				"isolation.tools.diskShrink.disable": "TRUE",
				"isolation.tools.diskWiper.disable": "TRUE",
				"tools.guestlib.enableHostInfo": "FALSE",
				"logging": "TRUE",
				"log.keepOld": "10",
				"log.rotateSize": "1024000",
			},
			"device_types": [],
			"tools_config": {
				"globalconf.enabled": "false",
				"containerinfo.poll-interval": "0",
				"appinfo.disabled": "true",
				"gueststoreupgrade.policy": "off",
				"servicediscovery.disabled": "true",
				"logging.log": "true",
				"guestoperations.disabled": "true",
			},
		},
		{
			"name": "vm-b",
			"config": {
				"efi_secure_boot_enabled": true,
				"migrate_encryption": "required",
				"ft_encryption_mode": "ftEncryptionRequired",
				"version": "vmx-21",
			},
			"advanced_settings": {
				"mks.enable3d": "FALSE",
				"tools.guest.desktop.autolock": "TRUE",
				"RemoteDisplay.maxConnections": "1",
				"pciPassthru0.present": "FALSE",
				"isolation.device.edit.disable": "TRUE",
				"isolation.device.connectable.disable": "TRUE",
				"usb.present": "FALSE",
				"isolation.tools.dnd.disable": "TRUE",
				"isolation.tools.copy.disable": "TRUE",
				"isolation.tools.paste.disable": "TRUE",
				"isolation.tools.diskShrink.disable": "TRUE",
				"isolation.tools.diskWiper.disable": "TRUE",
				"tools.guestlib.enableHostInfo": "FALSE",
				"logging": "TRUE",
				"log.keepOld": "10",
				"log.rotateSize": "1024000",
			},
			"device_types": [],
			"tools_config": {
				"globalconf.enabled": "false",
				"containerinfo.poll-interval": "0",
				"appinfo.disabled": "true",
				"gueststoreupgrade.policy": "off",
				"servicediscovery.disabled": "true",
				"logging.log": "true",
				"guestoperations.disabled": "true",
			},
		},
	],
	"attest": {
		"hardware_firmware_inventoried": true,
		"intel_txt_enabled_where_supported": true,
		"tpm_2_0_configured": true,
		"bmc_hardened": true,
		"bmc_time_synchronized": true,
		"bmc_remote_logging": true,
		"bmc_authentication_secure": true,
		"amd_sev_es_enabled_where_supported": true,
		"intel_sgx_enabled_where_supported": true,
		"unused_ports_secured": true,
		"esxi_release_in_general_support": true,
		"esxi_patches_current": true,
		"password_max_days_approved": true,
		"dcui_access_list_accurate": true,
		"lockdown_exception_users_accurate": true,
		"dcui_host_client_banner_approved": true,
		"ssh_banner_file_approved": true,
		"tls_highest_version_only": true,
		"system_log_location_persistent": true,
		"log_detail_sufficient": true,
		"audit_record_location_persistent": true,
		"audit_storage_seven_days": true,
		"virtual_hardware_mgmt_interfaces_absent": true,
		"management_traffic_isolated": true,
		"cim_access_limited": true,
		"storage_traffic_isolated": true,
		"iscsi_chap_secrets_unique": true,
		"snmp_access_limited": true,
		"sshd_ciphers_fips": true,
		"sshd_crypto_modules_fips": true,
		"unneeded_ahci_controllers_removed": true,
		"tools_setinfo_size_limit_approved": true,
		"tools_version_supported": true,
		"tools_updates_current": true,
		"tools_upgrade_policy_approved": true,
		"tools_recustomize_blocked": true,
		"tools_auto_add_features_limited": true,
		"tools_auto_remove_features_limited": true,
		"tools_msi_transforms_limited": true,
		"tools_logs_to_system_logger": true,
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
	s.passing_controls == 134
	s.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 134
	count([id | some id, r in b.recommendations; r.level == 2]) == 18
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 38
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == 40
}

test_empty_input_fails_every_recommendation if {
	r := b.compliance_report with input as {}
	r.total_controls == 134
	r.failed_controls == 134
	r.compliant == false
}

test_level_1_profile_scopes_the_report if {
	inp := json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": 1}}])
	r := b.compliance_report with input as inp
	r.total_controls == 116
	r.failed_controls == 0
	e := b.compliance_report with input as {"cis_profile": {"level": 1}}
	e.total_controls == 116
	e.failed_controls == 116
}

test_level_2_only_recommendation_skipped_at_level_1 if {
	inp := json.patch(green, [
		{"op": "add", "path": "/cis_profile", "value": {"level": 1}},
		{"op": "add", "path": "/esxi/lockdown_mode", "value": "normal"},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "3.21")
}

test_password_quality_needs_every_class_disabled if {
	inp := json.patch(green, [{
		"op": "add", "path": "/esxi/advanced_settings/Security.PasswordQualityControl",
		"value": "retry=3 min=disabled,disabled,12,disabled,15",
	}])
	vs := b.violations with input as inp
	_has_id(vs, "3.11")
}

test_zero_timeout_is_disabled_not_compliant if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.DcuiTimeOut", "value": "0"}])
	vs := b.violations with input as inp
	_has_id(vs, "3.7")
}

test_absent_slp_service_is_compliant if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/services/slpd"}])
	vs := b.violations with input as inp
	not _has_id(vs, "3.4")
}

test_port_group_override_accepting_promiscuous_fails if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/portgroups/1/security", "value": {"promiscuous_mode": true}}])
	vs := b.violations with input as inp
	_has_id(vs, "5.8")
}

test_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1")
}

test_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/hardware_firmware_inventoried", "value": false}])
	vs := b.violations with input as inp
	"1.1: firmware on the system and its devices must be inventoried against a supported baseline (manual review not attested)" in vs
}

test_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/hardware_firmware_inventoried"}])
	vs := b.violations with input as inp
	"1.1: firmware on the system and its devices must be inventoried against a supported baseline (manual review not attested)" in vs
}

test_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2")
}

test_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/secure_boot/enabled", "value": false}])
	vs := b.violations with input as inp
	"1.2: UEFI Secure Boot must be on in the host firmware" in vs
}

test_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/secure_boot"}])
	vs := b.violations with input as inp
	"1.2: evidence missing — esxi.secure_boot.enabled not collected" in vs
	not "1.2: UEFI Secure Boot must be on in the host firmware" in vs
}

test_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3")
}

test_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/intel_txt_enabled_where_supported", "value": false}])
	vs := b.violations with input as inp
	"1.3: Intel TXT must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/intel_txt_enabled_where_supported"}])
	vs := b.violations with input as inp
	"1.3: Intel TXT must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4")
}

test_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tpm_2_0_configured", "value": false}])
	vs := b.violations with input as inp
	"1.4: a TPM 2.0 must be present and configured (manual review not attested)" in vs
}

test_1_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tpm_2_0_configured"}])
	vs := b.violations with input as inp
	"1.4: a TPM 2.0 must be present and configured (manual review not attested)" in vs
}

test_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.5")
}

test_1_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/bmc_hardened", "value": false}])
	vs := b.violations with input as inp
	"1.5: the baseboard management controller must be hardened (manual review not attested)" in vs
}

test_1_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/bmc_hardened"}])
	vs := b.violations with input as inp
	"1.5: the baseboard management controller must be hardened (manual review not attested)" in vs
}

test_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.6")
}

test_1_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/bmc_time_synchronized", "value": false}])
	vs := b.violations with input as inp
	"1.6: the management controller clock must be synchronized (manual review not attested)" in vs
}

test_1_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/bmc_time_synchronized"}])
	vs := b.violations with input as inp
	"1.6: the management controller clock must be synchronized (manual review not attested)" in vs
}

test_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.7")
}

test_1_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/bmc_remote_logging", "value": false}])
	vs := b.violations with input as inp
	"1.7: the management controller must forward its events to a remote collector (manual review not attested)" in vs
}

test_1_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/bmc_remote_logging"}])
	vs := b.violations with input as inp
	"1.7: the management controller must forward its events to a remote collector (manual review not attested)" in vs
}

test_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.8")
}

test_1_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/bmc_authentication_secure", "value": false}])
	vs := b.violations with input as inp
	"1.8: management controller logins must be individual, strong and locked down (manual review not attested)" in vs
}

test_1_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/bmc_authentication_secure"}])
	vs := b.violations with input as inp
	"1.8: management controller logins must be individual, strong and locked down (manual review not attested)" in vs
}

test_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.9")
}

test_1_9_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/amd_sev_es_enabled_where_supported", "value": false}])
	vs := b.violations with input as inp
	"1.9: AMD SEV-ES must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_9_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/amd_sev_es_enabled_where_supported"}])
	vs := b.violations with input as inp
	"1.9: AMD SEV-ES must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.10")
}

test_1_10_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/intel_sgx_enabled_where_supported", "value": false}])
	vs := b.violations with input as inp
	"1.10: Intel SGX must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_10_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/intel_sgx_enabled_where_supported"}])
	vs := b.violations with input as inp
	"1.10: Intel SGX must be on where the CPU supports it (manual review not attested)" in vs
}

test_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.11")
}

test_1_11_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/unused_ports_secured", "value": false}])
	vs := b.violations with input as inp
	"1.11: unused external hardware ports must be secured (manual review not attested)" in vs
}

test_1_11_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/unused_ports_secured"}])
	vs := b.violations with input as inp
	"1.11: unused external hardware ports must be secured (manual review not attested)" in vs
}

test_1_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.12")
}

test_1_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Net.BMCNetworkEnable", "value": 1}])
	vs := b.violations with input as inp
	"1.12: Net.BMCNetworkEnable must be 0 so the controller has no internal network path" in vs
}

test_1_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Net.BMCNetworkEnable"}])
	vs := b.violations with input as inp
	"1.12: evidence missing — esxi.advanced_settings.Net.BMCNetworkEnable not collected" in vs
	not "1.12: Net.BMCNetworkEnable must be 0 so the controller has no internal network path" in vs
}

test_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1")
}

test_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/esxi_release_in_general_support", "value": false}])
	vs := b.violations with input as inp
	"2.1: the ESXi release must still be in general support (manual review not attested)" in vs
}

test_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/esxi_release_in_general_support"}])
	vs := b.violations with input as inp
	"2.1: the ESXi release must still be in general support (manual review not attested)" in vs
}

test_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2")
}

test_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/esxi_patches_current", "value": false}])
	vs := b.violations with input as inp
	"2.2: all available patches must be installed (manual review not attested)" in vs
}

test_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/esxi_patches_current"}])
	vs := b.violations with input as inp
	"2.2: all available patches must be installed (manual review not attested)" in vs
}

test_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3")
}

test_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/encryption/require_secure_boot", "value": false}])
	vs := b.violations with input as inp
	"2.3: the host must refuse to run with Secure Boot enforcement off" in vs
}

test_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/encryption"}])
	vs := b.violations with input as inp
	"2.3: evidence missing — esxi.encryption.require_secure_boot not collected" in vs
	not "2.3: the host must refuse to run with Secure Boot enforcement off" in vs
}

test_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4")
}

test_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/software/acceptance_level", "value": "CommunitySupported"}])
	vs := b.violations with input as inp
	"2.4: the image profile acceptance level must be PartnerSupported or stricter" in vs
}

test_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/software"}])
	vs := b.violations with input as inp
	"2.4: evidence missing — esxi.software.acceptance_level not collected" in vs
	not "2.4: the image profile acceptance level must be PartnerSupported or stricter" in vs
}

test_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5")
}

test_2_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/kernel_settings/execInstalledOnly", "value": "FALSE"}])
	vs := b.violations with input as inp
	"2.5: the host must run only binaries from installed signed VIBs" in vs
}

test_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/kernel_settings"}])
	vs := b.violations with input as inp
	"2.5: evidence missing — esxi.kernel_settings.execInstalledOnly not collected" in vs
	not "2.5: the host must run only binaries from installed signed VIBs" in vs
}

test_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.6")
}

test_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/services/ntpd/running", "value": false}])
	vs := b.violations with input as inp
	"2.6: NTP must run on the host with at least one server configured" in vs
}

test_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/ntp"}])
	vs := b.violations with input as inp
	"2.6: evidence missing — esxi.{services.ntpd,ntp.servers} not collected" in vs
	not "2.6: NTP must run on the host with at least one server configured" in vs
}

test_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.7")
}

test_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/services/ntpd/policy", "value": "off"}])
	vs := b.violations with input as inp
	"2.7: a time service must be enabled, configured and running" in vs
}

test_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/services"}])
	vs := b.violations with input as inp
	"2.7: evidence missing — esxi.{services.ntpd,ntp.servers} not collected" in vs
	not "2.7: a time service must be enabled, configured and running" in vs
}

test_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.8")
}

test_2_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/encryption/mode", "value": "NONE"}])
	vs := b.violations with input as inp
	"2.8: configuration encryption must be anchored in the TPM" in vs
}

test_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/encryption"}])
	vs := b.violations with input as inp
	"2.8: evidence missing — esxi.encryption.mode not collected" in vs
	not "2.8: configuration encryption must be anchored in the TPM" in vs
}

test_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.9")
}

test_2_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.SuppressHyperthreadWarning", "value": 1}])
	vs := b.violations with input as inp
	"2.9: UserVars.SuppressHyperthreadWarning must be 0" in vs
}

test_2_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.SuppressHyperthreadWarning"}])
	vs := b.violations with input as inp
	"2.9: evidence missing — esxi.advanced_settings.UserVars.SuppressHyperthreadWarning not collected" in vs
	not "2.9: UserVars.SuppressHyperthreadWarning must be 0" in vs
}

test_2_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.10")
}

test_2_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Mem.ShareForceSalting", "value": 1}])
	vs := b.violations with input as inp
	"2.10: Mem.ShareForceSalting must be 2 to stop inter-VM page sharing" in vs
}

test_2_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Mem.ShareForceSalting"}])
	vs := b.violations with input as inp
	"2.10: evidence missing — esxi.advanced_settings.Mem.ShareForceSalting not collected" in vs
	not "2.10: Mem.ShareForceSalting must be 2 to stop inter-VM page sharing" in vs
}

test_2_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.11")
}

test_2_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/kernel_settings/disableHwrng", "value": "TRUE"}])
	vs := b.violations with input as inp
	"2.11: the disableHwrng kernel option must not be TRUE" in vs
}

test_2_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/kernel_settings"}])
	vs := b.violations with input as inp
	"2.11: evidence missing — esxi.kernel_settings not collected" in vs
	not "2.11: the disableHwrng kernel option must not be TRUE" in vs
}

test_2_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.12")
}

test_2_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Mem.MemEagerZero", "value": 0}])
	vs := b.violations with input as inp
	"2.12: Mem.MemEagerZero must be 1 so freed memory is zeroed" in vs
}

test_2_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Mem.MemEagerZero"}])
	vs := b.violations with input as inp
	"2.12: evidence missing — esxi.advanced_settings.Mem.MemEagerZero not collected" in vs
	not "2.12: Mem.MemEagerZero must be 1 so freed memory is zeroed" in vs
}

test_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1")
}

test_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/services/TSM-SSH/running", "value": true}])
	vs := b.violations with input as inp
	"3.1: the SSH service must be stopped and set to start manually" in vs
}

test_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/services"}])
	vs := b.violations with input as inp
	"3.1: evidence missing — esxi.services.TSM-SSH not collected" in vs
	not "3.1: the SSH service must be stopped and set to start manually" in vs
}

test_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2")
}

test_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/services/TSM/running", "value": true}])
	vs := b.violations with input as inp
	"3.2: the ESXi shell service must be stopped and set to start manually" in vs
}

test_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/services"}])
	vs := b.violations with input as inp
	"3.2: evidence missing — esxi.services.TSM not collected" in vs
	not "3.2: the ESXi shell service must be stopped and set to start manually" in vs
}

test_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3")
}

test_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Config.HostAgent.plugins.solo.enableMob", "value": "true"}])
	vs := b.violations with input as inp
	"3.3: Config.HostAgent.plugins.solo.enableMob must be false" in vs
}

test_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Config.HostAgent.plugins.solo.enableMob"}])
	vs := b.violations with input as inp
	"3.3: evidence missing — esxi.advanced_settings.Config.HostAgent.plugins.solo.enableMob not collected" in vs
	not "3.3: Config.HostAgent.plugins.solo.enableMob must be false" in vs
}

test_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.4")
}

test_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/services/slpd/running", "value": true}])
	vs := b.violations with input as inp
	"3.4: the SLP service must not be running" in vs
}

test_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/services"}])
	vs := b.violations with input as inp
	"3.4: evidence missing — esxi.services not collected" in vs
	not "3.4: the SLP service must not be running" in vs
}

test_3_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.5")
}

test_3_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/wbem/enabled", "value": true}])
	vs := b.violations with input as inp
	"3.5: CIM/WBEM must be off" in vs
}

test_3_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/wbem"}])
	vs := b.violations with input as inp
	"3.5: evidence missing — esxi.wbem.enabled not collected" in vs
	not "3.5: CIM/WBEM must be off" in vs
}

test_3_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.6")
}

test_3_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/snmp/enabled", "value": true}])
	vs := b.violations with input as inp
	"3.6: SNMP must be off unless needed" in vs
}

test_3_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/snmp"}])
	vs := b.violations with input as inp
	"3.6: evidence missing — esxi.snmp.enabled not collected" in vs
	not "3.6: SNMP must be off unless needed" in vs
}

test_3_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.7")
}

test_3_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.DcuiTimeOut", "value": 0}])
	vs := b.violations with input as inp
	"3.7: UserVars.DcuiTimeOut must be 1 to 600 seconds" in vs
}

test_3_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.DcuiTimeOut"}])
	vs := b.violations with input as inp
	"3.7: evidence missing — esxi.advanced_settings.UserVars.DcuiTimeOut not collected" in vs
	not "3.7: UserVars.DcuiTimeOut must be 1 to 600 seconds" in vs
}

test_3_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.8")
}

test_3_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.ESXiShellInteractiveTimeOut", "value": 0}])
	vs := b.violations with input as inp
	"3.8: UserVars.ESXiShellInteractiveTimeOut must be 1 to 300 seconds" in vs
}

test_3_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.ESXiShellInteractiveTimeOut"}])
	vs := b.violations with input as inp
	"3.8: evidence missing — esxi.advanced_settings.UserVars.ESXiShellInteractiveTimeOut not collected" in vs
	not "3.8: UserVars.ESXiShellInteractiveTimeOut must be 1 to 300 seconds" in vs
}

test_3_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.9")
}

test_3_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.ESXiShellTimeOut", "value": 7200}])
	vs := b.violations with input as inp
	"3.9: UserVars.ESXiShellTimeOut must be 1 to 3600 seconds" in vs
}

test_3_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.ESXiShellTimeOut"}])
	vs := b.violations with input as inp
	"3.9: evidence missing — esxi.advanced_settings.UserVars.ESXiShellTimeOut not collected" in vs
	not "3.9: UserVars.ESXiShellTimeOut must be 1 to 3600 seconds" in vs
}

test_3_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.10")
}

test_3_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.SuppressShellWarning", "value": 1}])
	vs := b.violations with input as inp
	"3.10: UserVars.SuppressShellWarning must be 0" in vs
}

test_3_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.SuppressShellWarning"}])
	vs := b.violations with input as inp
	"3.10: evidence missing — esxi.advanced_settings.UserVars.SuppressShellWarning not collected" in vs
	not "3.10: UserVars.SuppressShellWarning must be 0" in vs
}

test_3_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.11")
}

test_3_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Security.PasswordQualityControl", "value": "retry=3 min=disabled,disabled,disabled,disabled,8"}])
	vs := b.violations with input as inp
	"3.11: Security.PasswordQualityControl must demand 15 or more characters from four classes" in vs
}

test_3_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Security.PasswordQualityControl"}])
	vs := b.violations with input as inp
	"3.11: evidence missing — esxi.advanced_settings.Security.PasswordQualityControl not collected" in vs
	not "3.11: Security.PasswordQualityControl must demand 15 or more characters from four classes" in vs
}

test_3_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.12")
}

test_3_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Security.AccountLockFailures", "value": 10}])
	vs := b.violations with input as inp
	"3.12: Security.AccountLockFailures must be 5" in vs
}

test_3_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Security.AccountLockFailures"}])
	vs := b.violations with input as inp
	"3.12: evidence missing — esxi.advanced_settings.Security.AccountLockFailures not collected" in vs
	not "3.12: Security.AccountLockFailures must be 5" in vs
}

test_3_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.13")
}

test_3_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Security.AccountUnlockTime", "value": 60}])
	vs := b.violations with input as inp
	"3.13: Security.AccountUnlockTime must be 900" in vs
}

test_3_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Security.AccountUnlockTime"}])
	vs := b.violations with input as inp
	"3.13: evidence missing — esxi.advanced_settings.Security.AccountUnlockTime not collected" in vs
	not "3.13: Security.AccountUnlockTime must be 900" in vs
}

test_3_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.14")
}

test_3_14_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Security.PasswordHistory", "value": 1}])
	vs := b.violations with input as inp
	"3.14: Security.PasswordHistory must be 5" in vs
}

test_3_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Security.PasswordHistory"}])
	vs := b.violations with input as inp
	"3.14: evidence missing — esxi.advanced_settings.Security.PasswordHistory not collected" in vs
	not "3.14: Security.PasswordHistory must be 5" in vs
}

test_3_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.15")
}

test_3_15_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/password_max_days_approved", "value": false}])
	vs := b.violations with input as inp
	"3.15: Security.PasswordMaxDays must match the approved rotation policy (manual review not attested)" in vs
}

test_3_15_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/password_max_days_approved"}])
	vs := b.violations with input as inp
	"3.15: Security.PasswordMaxDays must match the approved rotation policy (manual review not attested)" in vs
}

test_3_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.16")
}

test_3_16_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Config.HostAgent.vmacore.soap.sessionTimeout", "value": 0}])
	vs := b.violations with input as inp
	"3.16: the API session timeout must be a finite approved value" in vs
}

test_3_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Config.HostAgent.vmacore.soap.sessionTimeout"}])
	vs := b.violations with input as inp
	"3.16: evidence missing — esxi.advanced_settings.Config.HostAgent.vmacore.soap.sessionTimeout not collected" in vs
	not "3.16: the API session timeout must be a finite approved value" in vs
}

test_3_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.17")
}

test_3_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/UserVars.HostClientSessionTimeout", "value": 0}])
	vs := b.violations with input as inp
	"3.17: UserVars.HostClientSessionTimeout must be a finite positive value" in vs
}

test_3_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/UserVars.HostClientSessionTimeout"}])
	vs := b.violations with input as inp
	"3.17: evidence missing — esxi.advanced_settings.UserVars.HostClientSessionTimeout not collected" in vs
	not "3.17: UserVars.HostClientSessionTimeout must be a finite positive value" in vs
}

test_3_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.18")
}

test_3_18_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/dcui_access_list_accurate", "value": false}])
	vs := b.violations with input as inp
	"3.18: DCUI.Access must list only the approved override users (manual review not attested)" in vs
}

test_3_18_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/dcui_access_list_accurate"}])
	vs := b.violations with input as inp
	"3.18: DCUI.Access must list only the approved override users (manual review not attested)" in vs
}

test_3_19_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.19")
}

test_3_19_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/lockdown_exception_users_accurate", "value": false}])
	vs := b.violations with input as inp
	"3.19: the lockdown Exception Users list must be reviewed and accurate (manual review not attested)" in vs
}

test_3_19_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/lockdown_exception_users_accurate"}])
	vs := b.violations with input as inp
	"3.19: the lockdown Exception Users list must be reviewed and accurate (manual review not attested)" in vs
}

test_3_20_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.20")
}

test_3_20_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/lockdown_mode", "value": "disabled"}])
	vs := b.violations with input as inp
	"3.20: lockdown mode must be normal or strict" in vs
}

test_3_20_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/lockdown_mode"}])
	vs := b.violations with input as inp
	"3.20: evidence missing — esxi.lockdown_mode not collected" in vs
	not "3.20: lockdown mode must be normal or strict" in vs
}

test_3_21_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.21")
}

test_3_21_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/lockdown_mode", "value": "normal"}])
	vs := b.violations with input as inp
	"3.21: lockdown mode must be strict" in vs
}

test_3_21_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/lockdown_mode"}])
	vs := b.violations with input as inp
	"3.21: evidence missing — esxi.lockdown_mode not collected" in vs
	not "3.21: lockdown mode must be strict" in vs
}

test_3_22_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.22")
}

test_3_22_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/passwd/dcui/shell", "value": "/bin/sh"}])
	vs := b.violations with input as inp
	"3.22: the dcui account must have a non-interactive shell" in vs
}

test_3_22_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/passwd"}])
	vs := b.violations with input as inp
	"3.22: evidence missing — esxi.passwd.dcui.shell not collected" in vs
	not "3.22: the dcui account must have a non-interactive shell" in vs
}

test_3_23_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.23")
}

test_3_23_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/passwd/vpxuser/shell", "value": "/bin/sh"}])
	vs := b.violations with input as inp
	"3.23: the vpxuser account must have a non-interactive shell" in vs
}

test_3_23_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/passwd"}])
	vs := b.violations with input as inp
	"3.23: evidence missing — esxi.passwd.vpxuser.shell not collected" in vs
	not "3.23: the vpxuser account must have a non-interactive shell" in vs
}

test_3_24_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.24")
}

test_3_24_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/dcui_host_client_banner_approved", "value": false}])
	vs := b.violations with input as inp
	"3.24: the DCUI and Host Client welcome banner must carry the approved text (manual review not attested)" in vs
}

test_3_24_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/dcui_host_client_banner_approved"}])
	vs := b.violations with input as inp
	"3.24: the DCUI and Host Client welcome banner must carry the approved text (manual review not attested)" in vs
}

test_3_25_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.25")
}

test_3_25_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/ssh_banner_file_approved", "value": false}])
	vs := b.violations with input as inp
	"3.25: the SSH banner file must carry the approved text (manual review not attested)" in vs
}

test_3_25_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/ssh_banner_file_approved"}])
	vs := b.violations with input as inp
	"3.25: the SSH banner file must carry the approved text (manual review not attested)" in vs
}

test_3_26_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.26")
}

test_3_26_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tls_highest_version_only", "value": false}])
	vs := b.violations with input as inp
	"3.26: legacy TLS versions must be off and the highest supported version on (manual review not attested)" in vs
}

test_3_26_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tls_highest_version_only"}])
	vs := b.violations with input as inp
	"3.26: legacy TLS versions must be off and the highest supported version on (manual review not attested)" in vs
}

test_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1")
}

test_4_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/system_log_location_persistent", "value": false}])
	vs := b.violations with input as inp
	"4.1: system logs must be written to a persistent location (manual review not attested)" in vs
}

test_4_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/system_log_location_persistent"}])
	vs := b.violations with input as inp
	"4.1: system logs must be written to a persistent location (manual review not attested)" in vs
}

test_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2")
}

test_4_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Syslog.global.logHost", "value": ""}])
	vs := b.violations with input as inp
	"4.2: Syslog.global.logHost must name a remote collector" in vs
}

test_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Syslog.global.logHost"}])
	vs := b.violations with input as inp
	"4.2: evidence missing — esxi.advanced_settings.Syslog.global.logHost not collected" in vs
	not "4.2: Syslog.global.logHost must name a remote collector" in vs
}

test_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3")
}

test_4_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/log_detail_sufficient", "value": false}])
	vs := b.violations with input as inp
	"4.3: logging detail and local log files must be reviewed as sufficient (manual review not attested)" in vs
}

test_4_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/log_detail_sufficient"}])
	vs := b.violations with input as inp
	"4.3: logging detail and local log files must be reviewed as sufficient (manual review not attested)" in vs
}

test_4_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.4")
}

test_4_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/syslog/log_level", "value": "warning"}])
	vs := b.violations with input as inp
	"4.4: the syslog log level must be info" in vs
}

test_4_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/syslog"}])
	vs := b.violations with input as inp
	"4.4: evidence missing — esxi.syslog.log_level not collected" in vs
	not "4.4: the syslog log level must be info" in vs
}

test_4_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.5")
}

test_4_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/syslog/log_filtering_enabled", "value": true}])
	vs := b.violations with input as inp
	"4.5: syslog log filtering must be off" in vs
}

test_4_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/syslog"}])
	vs := b.violations with input as inp
	"4.5: evidence missing — esxi.syslog.log_filtering_enabled not collected" in vs
	not "4.5: syslog log filtering must be off" in vs
}

test_4_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.6")
}

test_4_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/audit_records/storage_active", "value": false}])
	vs := b.violations with input as inp
	"4.6: audit record storage must be active" in vs
}

test_4_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/audit_records"}])
	vs := b.violations with input as inp
	"4.6: evidence missing — esxi.audit_records.storage_active not collected" in vs
	not "4.6: audit record storage must be active" in vs
}

test_4_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.7")
}

test_4_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/audit_record_location_persistent", "value": false}])
	vs := b.violations with input as inp
	"4.7: audit records must be stored in a persistent location (manual review not attested)" in vs
}

test_4_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/audit_record_location_persistent"}])
	vs := b.violations with input as inp
	"4.7: audit records must be stored in a persistent location (manual review not attested)" in vs
}

test_4_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.8")
}

test_4_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/audit_storage_seven_days", "value": false}])
	vs := b.violations with input as inp
	"4.8: local audit storage must hold at least seven days (manual review not attested)" in vs
}

test_4_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/audit_storage_seven_days"}])
	vs := b.violations with input as inp
	"4.8: local audit storage must hold at least seven days (manual review not attested)" in vs
}

test_4_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.9")
}

test_4_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/audit_records/remote_host_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.9: audit records must be sent to a remote collector" in vs
}

test_4_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/audit_records"}])
	vs := b.violations with input as inp
	"4.9: evidence missing — esxi.{advanced_settings.Syslog.global.logHost,audit_records.remote_host_enabled} not collected" in vs
	not "4.9: audit records must be sent to a remote collector" in vs
}

test_4_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.10")
}

test_4_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/syslog/check_ssl_certs", "value": false}])
	vs := b.violations with input as inp
	"4.10: remote syslog over TLS must check the endpoint certificate" in vs
}

test_4_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/syslog"}])
	vs := b.violations with input as inp
	"4.10: evidence missing — esxi.syslog.check_ssl_certs not collected" in vs
	not "4.10: remote syslog over TLS must check the endpoint certificate" in vs
}

test_4_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.11")
}

test_4_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/syslog/strict_x509_compliance", "value": false}])
	vs := b.violations with input as inp
	"4.11: remote syslog over TLS must use strict x509 checks" in vs
}

test_4_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/syslog"}])
	vs := b.violations with input as inp
	"4.11: evidence missing — esxi.syslog.strict_x509_compliance not collected" in vs
	not "4.11: remote syslog over TLS must use strict x509 checks" in vs
}

test_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1")
}

test_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/firewall/rulesets/1/allowed_ip_all", "value": true}])
	vs := b.violations with input as inp
	"5.1: an enabled firewall ruleset must not allow all IP addresses" in vs
}

test_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/firewall"}])
	vs := b.violations with input as inp
	"5.1: evidence missing — esxi.firewall.rulesets not collected" in vs
	not "5.1: an enabled firewall ruleset must not allow all IP addresses" in vs
}

test_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2")
}

test_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/firewall/default_action", "value": "PASS"}])
	vs := b.violations with input as inp
	"5.2: the host firewall must be on and drop by default" in vs
}

test_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/firewall"}])
	vs := b.violations with input as inp
	"5.2: evidence missing — esxi.firewall.{enabled,default_action} not collected" in vs
	not "5.2: the host firewall must be on and drop by default" in vs
}

test_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3")
}

test_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Net.DVFilterBindIpAddress", "value": "10.0.0.5"}])
	vs := b.violations with input as inp
	"5.3: Net.DVFilterBindIpAddress must be empty" in vs
}

test_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Net.DVFilterBindIpAddress"}])
	vs := b.violations with input as inp
	"5.3: evidence missing — esxi.advanced_settings.Net.DVFilterBindIpAddress not collected" in vs
	not "5.3: Net.DVFilterBindIpAddress must be empty" in vs
}

test_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.4")
}

test_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/advanced_settings/Net.BlockGuestBPDU", "value": 0}])
	vs := b.violations with input as inp
	"5.4: Net.BlockGuestBPDU must be 1" in vs
}

test_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/advanced_settings/Net.BlockGuestBPDU"}])
	vs := b.violations with input as inp
	"5.4: evidence missing — esxi.advanced_settings.Net.BlockGuestBPDU not collected" in vs
	not "5.4: Net.BlockGuestBPDU must be 1" in vs
}

test_5_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.5")
}

test_5_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/virtual_hardware_mgmt_interfaces_absent", "value": false}])
	vs := b.violations with input as inp
	"5.5: VMkernel interfaces for virtual hardware management must be absent (manual review not attested)" in vs
}

test_5_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/virtual_hardware_mgmt_interfaces_absent"}])
	vs := b.violations with input as inp
	"5.5: VMkernel interfaces for virtual hardware management must be absent (manual review not attested)" in vs
}

test_5_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6")
}

test_5_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/security/forged_transmits", "value": true}])
	vs := b.violations with input as inp
	"5.6: standard switches and port groups must reject forged transmits" in vs
}

test_5_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vswitches"}])
	vs := b.violations with input as inp
	"5.6: evidence missing — esxi.vswitches[].security not collected" in vs
	not "5.6: standard switches and port groups must reject forged transmits" in vs
}

test_5_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.7")
}

test_5_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/security/mac_changes", "value": true}])
	vs := b.violations with input as inp
	"5.7: standard switches and port groups must reject MAC address changes" in vs
}

test_5_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vswitches"}])
	vs := b.violations with input as inp
	"5.7: evidence missing — esxi.vswitches[].security not collected" in vs
	not "5.7: standard switches and port groups must reject MAC address changes" in vs
}

test_5_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.8")
}

test_5_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/security/promiscuous_mode", "value": true}])
	vs := b.violations with input as inp
	"5.8: standard switches and port groups must reject promiscuous mode" in vs
}

test_5_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vswitches"}])
	vs := b.violations with input as inp
	"5.8: evidence missing — esxi.vswitches[].security not collected" in vs
	not "5.8: standard switches and port groups must reject promiscuous mode" in vs
}

test_5_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.9")
}

test_5_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/portgroups/0/vlan_id", "value": 1}])
	vs := b.violations with input as inp
	"5.9: a standard port group must not use the native VLAN" in vs
}

test_5_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vswitches"}])
	vs := b.violations with input as inp
	"5.9: evidence missing — esxi.vswitches[].portgroups[].vlan_id not collected" in vs
	not "5.9: a standard port group must not use the native VLAN" in vs
}

test_5_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.10")
}

test_5_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vswitches/0/portgroups/0/vlan_id", "value": 4095}])
	vs := b.violations with input as inp
	"5.10: a standard port group must not use VLAN 4095" in vs
}

test_5_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vswitches"}])
	vs := b.violations with input as inp
	"5.10: evidence missing — esxi.vswitches[].portgroups[].vlan_id not collected" in vs
	not "5.10: a standard port group must not use VLAN 4095" in vs
}

test_5_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.11")
}

test_5_11_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/management_traffic_isolated", "value": false}])
	vs := b.violations with input as inp
	"5.11: management traffic must stay on dedicated VMkernel interfaces and VLANs (manual review not attested)" in vs
}

test_5_11_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/management_traffic_isolated"}])
	vs := b.violations with input as inp
	"5.11: management traffic must stay on dedicated VMkernel interfaces and VLANs (manual review not attested)" in vs
}

test_6_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.1.1")
}

test_6_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/cim_access_limited", "value": false}])
	vs := b.violations with input as inp
	"6.1.1: CIM access, if used, must go through a least-privilege account (manual review not attested)" in vs
}

test_6_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/cim_access_limited"}])
	vs := b.violations with input as inp
	"6.1.1: CIM access, if used, must go through a least-privilege account (manual review not attested)" in vs
}

test_6_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.2.1")
}

test_6_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/storage_traffic_isolated", "value": false}])
	vs := b.violations with input as inp
	"6.2.1: storage traffic must be isolated from other networks (manual review not attested)" in vs
}

test_6_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/storage_traffic_isolated"}])
	vs := b.violations with input as inp
	"6.2.1: storage traffic must be isolated from other networks (manual review not attested)" in vs
}

test_6_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.2.2")
}

test_6_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/datastores/1/name", "value": "ds-a"}])
	vs := b.violations with input as inp
	"6.2.2: datastore names must be unique" in vs
}

test_6_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/datastores"}])
	vs := b.violations with input as inp
	"6.2.2: evidence missing — esxi.datastores[].name not collected" in vs
	not "6.2.2: datastore names must be unique" in vs
}

test_6_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.3.1")
}

test_6_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/iscsi_adapters/0/mutual_chap_enabled", "value": false}])
	vs := b.violations with input as inp
	"6.3.1: iSCSI adapters must use mutual CHAP" in vs
}

test_6_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/iscsi_adapters"}])
	vs := b.violations with input as inp
	"6.3.1: evidence missing — esxi.iscsi_adapters not collected" in vs
	not "6.3.1: iSCSI adapters must use mutual CHAP" in vs
}

test_6_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.3.2")
}

test_6_3_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/iscsi_chap_secrets_unique", "value": false}])
	vs := b.violations with input as inp
	"6.3.2: iSCSI CHAP secrets must be unique per adapter (manual review not attested)" in vs
}

test_6_3_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/iscsi_chap_secrets_unique"}])
	vs := b.violations with input as inp
	"6.3.2: iSCSI CHAP secrets must be unique per adapter (manual review not attested)" in vs
}

test_6_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.4.1")
}

test_6_4_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/snmp_access_limited", "value": false}])
	vs := b.violations with input as inp
	"6.4.1: SNMP, if used, must restrict who can poll (manual review not attested)" in vs
}

test_6_4_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/snmp_access_limited"}])
	vs := b.violations with input as inp
	"6.4.1: SNMP, if used, must restrict who can poll (manual review not attested)" in vs
}

test_6_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.1")
}

test_6_5_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/sshd_ciphers_fips", "value": false}])
	vs := b.violations with input as inp
	"6.5.1: sshd ciphers must be limited to approved FIPS-validated ones (manual review not attested)" in vs
}

test_6_5_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/sshd_ciphers_fips"}])
	vs := b.violations with input as inp
	"6.5.1: sshd ciphers must be limited to approved FIPS-validated ones (manual review not attested)" in vs
}

test_6_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.2")
}

test_6_5_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/sshd_crypto_modules_fips", "value": false}])
	vs := b.violations with input as inp
	"6.5.2: sshd must run on the platform FIPS-validated crypto modules (manual review not attested)" in vs
}

test_6_5_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/sshd_crypto_modules_fips"}])
	vs := b.violations with input as inp
	"6.5.2: sshd must run on the platform FIPS-validated crypto modules (manual review not attested)" in vs
}

test_6_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.3")
}

test_6_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/gatewayports", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.3: sshd GatewayPorts must be no" in vs
}

test_6_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.3: evidence missing — esxi.sshd_config.gatewayports not collected" in vs
	not "6.5.3: sshd GatewayPorts must be no" in vs
}

test_6_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.4")
}

test_6_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/hostbasedauthentication", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.4: sshd HostbasedAuthentication must be no" in vs
}

test_6_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.4: evidence missing — esxi.sshd_config.hostbasedauthentication not collected" in vs
	not "6.5.4: sshd HostbasedAuthentication must be no" in vs
}

test_6_5_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.5")
}

test_6_5_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/clientalivecountmax", "value": 0}])
	vs := b.violations with input as inp
	"6.5.5: sshd ClientAliveCountMax must be a positive value" in vs
}

test_6_5_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.5: evidence missing — esxi.sshd_config.clientalivecountmax not collected" in vs
	not "6.5.5: sshd ClientAliveCountMax must be a positive value" in vs
}

test_6_5_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.6")
}

test_6_5_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/clientaliveinterval", "value": 0}])
	vs := b.violations with input as inp
	"6.5.6: sshd ClientAliveInterval must be a positive value" in vs
}

test_6_5_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.6: evidence missing — esxi.sshd_config.clientaliveinterval not collected" in vs
	not "6.5.6: sshd ClientAliveInterval must be a positive value" in vs
}

test_6_5_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.7")
}

test_6_5_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/banner", "value": "none"}])
	vs := b.violations with input as inp
	"6.5.7: sshd must show a banner before login" in vs
}

test_6_5_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.7: evidence missing — esxi.sshd_config.banner not collected" in vs
	not "6.5.7: sshd must show a banner before login" in vs
}

test_6_5_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.8")
}

test_6_5_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/ignorerhosts", "value": "no"}])
	vs := b.violations with input as inp
	"6.5.8: sshd IgnoreRhosts must be yes" in vs
}

test_6_5_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.8: evidence missing — esxi.sshd_config.ignorerhosts not collected" in vs
	not "6.5.8: sshd IgnoreRhosts must be yes" in vs
}

test_6_5_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.9")
}

test_6_5_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/allowstreamlocalforwarding", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.9: sshd AllowStreamLocalForwarding must be no" in vs
}

test_6_5_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.9: evidence missing — esxi.sshd_config.allowstreamlocalforwarding not collected" in vs
	not "6.5.9: sshd AllowStreamLocalForwarding must be no" in vs
}

test_6_5_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.10")
}

test_6_5_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/allowtcpforwarding", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.10: sshd AllowTcpForwarding must be no" in vs
}

test_6_5_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.10: evidence missing — esxi.sshd_config.allowtcpforwarding not collected" in vs
	not "6.5.10: sshd AllowTcpForwarding must be no" in vs
}

test_6_5_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.11")
}

test_6_5_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/permittunnel", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.11: sshd PermitTunnel must be no" in vs
}

test_6_5_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.11: evidence missing — esxi.sshd_config.permittunnel not collected" in vs
	not "6.5.11: sshd PermitTunnel must be no" in vs
}

test_6_5_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5.12")
}

test_6_5_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/sshd_config/permituserenvironment", "value": "yes"}])
	vs := b.violations with input as inp
	"6.5.12: sshd PermitUserEnvironment must be no" in vs
}

test_6_5_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/sshd_config"}])
	vs := b.violations with input as inp
	"6.5.12: evidence missing — esxi.sshd_config.permituserenvironment not collected" in vs
	not "6.5.12: sshd PermitUserEnvironment must be no" in vs
}

test_7_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.1")
}

test_7_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/config/efi_secure_boot_enabled", "value": false}])
	vs := b.violations with input as inp
	"7.1: every VM must boot with EFI Secure Boot" in vs
}

test_7_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.1: evidence missing — esxi.vms[].config.efi_secure_boot_enabled not collected" in vs
	not "7.1: every VM must boot with EFI Secure Boot" in vs
}

test_7_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.2")
}

test_7_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/config/migrate_encryption", "value": "opportunistic"}])
	vs := b.violations with input as inp
	"7.2: every VM must require encrypted vMotion" in vs
}

test_7_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.2: evidence missing — esxi.vms[].config.migrate_encryption not collected" in vs
	not "7.2: every VM must require encrypted vMotion" in vs
}

test_7_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3")
}

test_7_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/config/ft_encryption_mode", "value": "ftEncryptionOpportunistic"}])
	vs := b.violations with input as inp
	"7.3: every VM must require encrypted Fault Tolerance traffic" in vs
}

test_7_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.3: evidence missing — esxi.vms[].config.ft_encryption_mode not collected" in vs
	not "7.3: every VM must require encrypted Fault Tolerance traffic" in vs
}

test_7_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.4")
}

test_7_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/mks.enable3d", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.4: mks.enable3d must not be on for VMs" in vs
}

test_7_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.4: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.4: mks.enable3d must not be on for VMs" in vs
}

test_7_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.5")
}

test_7_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/tools.guest.desktop.autolock", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.5: tools.guest.desktop.autolock must be TRUE" in vs
}

test_7_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.5: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.5: tools.guest.desktop.autolock must be TRUE" in vs
}

test_7_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.6")
}

test_7_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/RemoteDisplay.maxConnections", "value": "4"}])
	vs := b.violations with input as inp
	"7.6: RemoteDisplay.maxConnections must be 1" in vs
}

test_7_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.6: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.6: RemoteDisplay.maxConnections must be 1" in vs
}

test_7_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.7")
}

test_7_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/pciPassthru0.present", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.7: a VM must not have a pciPassthru device present" in vs
}

test_7_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.7: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.7: a VM must not have a pciPassthru device present" in vs
}

test_7_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.8")
}

test_7_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.device.edit.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.8: isolation.device.edit.disable must be TRUE" in vs
}

test_7_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.8: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.8: isolation.device.edit.disable must be TRUE" in vs
}

test_7_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.9")
}

test_7_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.device.connectable.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.9: isolation.device.connectable.disable must be TRUE" in vs
}

test_7_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.9: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.9: isolation.device.connectable.disable must be TRUE" in vs
}

test_7_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.10")
}

test_7_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/device_types", "value": ["sound"]}])
	vs := b.violations with input as inp
	"7.10: VMs must have no sound device" in vs
}

test_7_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.10: evidence missing — esxi.vms[].device_types not collected" in vs
	not "7.10: VMs must have no sound device" in vs
}

test_7_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.11")
}

test_7_11_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/unneeded_ahci_controllers_removed", "value": false}])
	vs := b.violations with input as inp
	"7.11: VMs must have no AHCI controller that backs nothing needed (manual review not attested)" in vs
}

test_7_11_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/unneeded_ahci_controllers_removed"}])
	vs := b.violations with input as inp
	"7.11: VMs must have no AHCI controller that backs nothing needed (manual review not attested)" in vs
}

test_7_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.12")
}

test_7_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/usb.present", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.12: VMs must have no USB or XHCI controller" in vs
}

test_7_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.12: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.12: VMs must have no USB or XHCI controller" in vs
}

test_7_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.13")
}

test_7_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/serial0.present", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.13: VMs must have no serial port" in vs
}

test_7_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.13: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.13: VMs must have no serial port" in vs
}

test_7_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.14")
}

test_7_14_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/parallel0.present", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.14: VMs must have no parallel port" in vs
}

test_7_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.14: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.14: VMs must have no parallel port" in vs
}

test_7_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.15")
}

test_7_15_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/device_types", "value": ["cdrom"]}])
	vs := b.violations with input as inp
	"7.15: VMs must have no CD/DVD drive" in vs
}

test_7_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.15: evidence missing — esxi.vms[].device_types not collected" in vs
	not "7.15: VMs must have no CD/DVD drive" in vs
}

test_7_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.16")
}

test_7_16_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/floppy0.present", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.16: VMs must have no floppy drive" in vs
}

test_7_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.16: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.16: VMs must have no floppy drive" in vs
}

test_7_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.17")
}

test_7_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.tools.dnd.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.17: isolation.tools.dnd.disable must be TRUE or absent" in vs
}

test_7_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.17: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.17: isolation.tools.dnd.disable must be TRUE or absent" in vs
}

test_7_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.18")
}

test_7_18_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.tools.copy.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.18: isolation.tools.copy.disable must be TRUE or absent" in vs
}

test_7_18_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.18: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.18: isolation.tools.copy.disable must be TRUE or absent" in vs
}

test_7_19_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.19")
}

test_7_19_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.tools.paste.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.19: isolation.tools.paste.disable must be TRUE or absent" in vs
}

test_7_19_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.19: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.19: isolation.tools.paste.disable must be TRUE or absent" in vs
}

test_7_20_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.20")
}

test_7_20_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/ethernet0.filter1.name", "value": "dvfilter-example"}])
	vs := b.violations with input as inp
	"7.20: VMs must not be bound to a dvfilter" in vs
}

test_7_20_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.20: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.20: VMs must not be bound to a dvfilter" in vs
}

test_7_21_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.21")
}

test_7_21_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.tools.diskShrink.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.21: isolation.tools.diskShrink.disable must be TRUE" in vs
}

test_7_21_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.21: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.21: isolation.tools.diskShrink.disable must be TRUE" in vs
}

test_7_22_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.22")
}

test_7_22_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/isolation.tools.diskWiper.disable", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.22: isolation.tools.diskWiper.disable must be TRUE" in vs
}

test_7_22_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.22: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.22: isolation.tools.diskWiper.disable must be TRUE" in vs
}

test_7_23_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.23")
}

test_7_23_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/0/advanced_settings/sched.mem.pshare.salt", "value": "shared"}, {"op": "add", "path": "/esxi/vms/1/advanced_settings/sched.mem.pshare.salt", "value": "shared"}])
	vs := b.violations with input as inp
	"7.23: two VMs must not share a sched.mem.pshare.salt value" in vs
}

test_7_23_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.23: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.23: two VMs must not share a sched.mem.pshare.salt value" in vs
}

test_7_24_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.24")
}

test_7_24_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/tools.guestlib.enableHostInfo", "value": "TRUE"}])
	vs := b.violations with input as inp
	"7.24: tools.guestlib.enableHostInfo must be FALSE" in vs
}

test_7_24_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.24: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.24: tools.guestlib.enableHostInfo must be FALSE" in vs
}

test_7_25_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.25")
}

test_7_25_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/logging", "value": "FALSE"}])
	vs := b.violations with input as inp
	"7.25: VM logging must be TRUE or left at its default" in vs
}

test_7_25_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.25: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.25: VM logging must be TRUE or left at its default" in vs
}

test_7_26_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.26")
}

test_7_26_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/log.keepOld", "value": "3"}])
	vs := b.violations with input as inp
	"7.26: log.keepOld must be 10" in vs
}

test_7_26_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.26: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.26: log.keepOld must be 10" in vs
}

test_7_27_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.27")
}

test_7_27_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/advanced_settings/log.rotateSize", "value": "0"}])
	vs := b.violations with input as inp
	"7.27: log.rotateSize must be 1024000" in vs
}

test_7_27_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.27: evidence missing — esxi.vms[].advanced_settings not collected" in vs
	not "7.27: log.rotateSize must be 1024000" in vs
}

test_7_28_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.28")
}

test_7_28_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_setinfo_size_limit_approved", "value": false}])
	vs := b.violations with input as inp
	"7.28: tools.setInfo.sizeLimit must be a finite approved value (manual review not attested)" in vs
}

test_7_28_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_setinfo_size_limit_approved"}])
	vs := b.violations with input as inp
	"7.28: tools.setInfo.sizeLimit must be a finite approved value (manual review not attested)" in vs
}

test_7_29_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.29")
}

test_7_29_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/config/version", "value": "vmx-13"}])
	vs := b.violations with input as inp
	"7.29: VM hardware version must be 19 or newer" in vs
}

test_7_29_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"7.29: evidence missing — esxi.vms[].config.version not collected" in vs
	not "7.29: VM hardware version must be 19 or newer" in vs
}

test_8_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.1")
}

test_8_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_version_supported", "value": false}])
	vs := b.violations with input as inp
	"8.1: VMware Tools must be a release still in general support (manual review not attested)" in vs
}

test_8_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_version_supported"}])
	vs := b.violations with input as inp
	"8.1: VMware Tools must be a release still in general support (manual review not attested)" in vs
}

test_8_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.2")
}

test_8_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_updates_current", "value": false}])
	vs := b.violations with input as inp
	"8.2: VMware Tools must carry all security updates (manual review not attested)" in vs
}

test_8_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_updates_current"}])
	vs := b.violations with input as inp
	"8.2: VMware Tools must carry all security updates (manual review not attested)" in vs
}

test_8_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.3")
}

test_8_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_upgrade_policy_approved", "value": false}])
	vs := b.violations with input as inp
	"8.3: the Tools upgrade policy must match the approved change model (manual review not attested)" in vs
}

test_8_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_upgrade_policy_approved"}])
	vs := b.violations with input as inp
	"8.3: the Tools upgrade policy must match the approved change model (manual review not attested)" in vs
}

test_8_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.4")
}

test_8_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_recustomize_blocked", "value": false}])
	vs := b.violations with input as inp
	"8.4: deployed VMs must not be re-customizable through Tools (manual review not attested)" in vs
}

test_8_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_recustomize_blocked"}])
	vs := b.violations with input as inp
	"8.4: deployed VMs must not be re-customizable through Tools (manual review not attested)" in vs
}

test_8_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.5")
}

test_8_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_auto_add_features_limited", "value": false}])
	vs := b.violations with input as inp
	"8.5: Tools must not add features automatically (manual review not attested)" in vs
}

test_8_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_auto_add_features_limited"}])
	vs := b.violations with input as inp
	"8.5: Tools must not add features automatically (manual review not attested)" in vs
}

test_8_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.6")
}

test_8_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_auto_remove_features_limited", "value": false}])
	vs := b.violations with input as inp
	"8.6: Tools must not remove features automatically (manual review not attested)" in vs
}

test_8_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_auto_remove_features_limited"}])
	vs := b.violations with input as inp
	"8.6: Tools must not remove features automatically (manual review not attested)" in vs
}

test_8_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.7")
}

test_8_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/globalconf.enabled", "value": "true"}])
	vs := b.violations with input as inp
	"8.7: Tools globalconf must be off" in vs
}

test_8_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.7: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.7: Tools globalconf must be off" in vs
}

test_8_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.8")
}

test_8_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/containerinfo.poll-interval", "value": "30"}])
	vs := b.violations with input as inp
	"8.8: Tools containerinfo poll-interval must be 0" in vs
}

test_8_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.8: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.8: Tools containerinfo poll-interval must be 0" in vs
}

test_8_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.9")
}

test_8_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/appinfo.disabled", "value": "false"}])
	vs := b.violations with input as inp
	"8.9: Tools appinfo must be disabled" in vs
}

test_8_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.9: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.9: Tools appinfo must be disabled" in vs
}

test_8_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.10")
}

test_8_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/gueststoreupgrade.policy", "value": "on"}])
	vs := b.violations with input as inp
	"8.10: Tools gueststoreupgrade policy must be off" in vs
}

test_8_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.10: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.10: Tools gueststoreupgrade policy must be off" in vs
}

test_8_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.11")
}

test_8_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/servicediscovery.disabled", "value": "false"}])
	vs := b.violations with input as inp
	"8.11: Tools servicediscovery must be disabled" in vs
}

test_8_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.11: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.11: Tools servicediscovery must be disabled" in vs
}

test_8_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.12")
}

test_8_12_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_msi_transforms_limited", "value": false}])
	vs := b.violations with input as inp
	"8.12: Tools must not allow MSI transforms on upgrade (manual review not attested)" in vs
}

test_8_12_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_msi_transforms_limited"}])
	vs := b.violations with input as inp
	"8.12: Tools must not allow MSI transforms on upgrade (manual review not attested)" in vs
}

test_8_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.13")
}

test_8_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/logging.log", "value": "false"}])
	vs := b.violations with input as inp
	"8.13: Tools logging must be on" in vs
}

test_8_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.13: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.13: Tools logging must be on" in vs
}

test_8_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.14")
}

test_8_14_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/esxi/attest/tools_logs_to_system_logger", "value": false}])
	vs := b.violations with input as inp
	"8.14: Tools logs must go to the guest system logger (manual review not attested)" in vs
}

test_8_14_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/attest/tools_logs_to_system_logger"}])
	vs := b.violations with input as inp
	"8.14: Tools logs must go to the guest system logger (manual review not attested)" in vs
}

test_8_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.15")
}

test_8_15_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/esxi/vms/1/tools_config/guestoperations.disabled", "value": "false"}])
	vs := b.violations with input as inp
	"8.15: Tools guestoperations must be disabled" in vs
}

test_8_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/esxi/vms"}])
	vs := b.violations with input as inp
	"8.15: evidence missing — esxi.vms[].tools_config not collected" in vs
	not "8.15: Tools guestoperations must be disabled" in vs
}
