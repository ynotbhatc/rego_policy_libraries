# METADATA
# title: "CIS VMware ESXi 8.0 Benchmark v1.4.0"
# custom:
#   class: security
#   framework: cis_vmware
#   source: cis
#   domains: [virtualization, vmware]
#   coverage:
#     checks: 142
#     cited: 142
#     expected: 134
#     found: 142
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_vmware_esxi

# CIS VMware ESXi 8.0 Benchmark v1.4.0
# Generated from the CIS workbook by tools/cis_generators/gen_esxi.py (one logic table for ESXi 8.0 and 9.0).
# 134 recommendations (38 Automated, 96 Manual; 116 Level 1, 18 Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent => 2. total_controls counts the
# recommendations in the selected profile.
# Facts missing => "<id>: evidence missing — <field> not collected". Manual recommendations whose audit names an
# exact value are checked like Automated ones: 1.2, 1.12, 2.3, 2.5, 2.7, 2.8, 2.9, 2.11, 2.12, 3.4, 3.5, 3.6, 3.10, 3.11, 3.14, 3.16, 3.17, 3.22, 3.23, 4.4, 4.5, 4.6, 4.9, 4.10, 4.11, 5.1, 5.2, 5.3, 5.4, 6.2.2, 6.5.3, 6.5.4, 6.5.5, 6.5.6, 6.5.7, 6.5.8, 6.5.9, 6.5.10, 6.5.11, 6.5.12, 7.1, 7.2, 7.3, 7.5, 7.10, 7.20, 7.23, 7.25, 7.29, 8.7, 8.8, 8.9, 8.10, 8.11, 8.13, 8.15.
# Attestation booleans under input.esxi.attest (false or absent => violation): 1.1, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 2.1, 2.2, 3.15, 3.18, 3.19, 3.24, 3.25, 3.26, 4.1, 4.3, 4.7, 4.8, 5.5, 5.11, 6.1.1, 6.2.1, 6.3.2, 6.4.1, 6.5.1, 6.5.2, 7.11, 7.28, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.12, 8.14.
#
# Input contract (input.esxi, one host; every name is what the audit procedure reads):
#   advanced_settings{<name>: value}  Get-AdvancedSetting on the host (the STIG ESXi module reads the same map)
#   lockdown_mode                      "disabled" | "normal" | "strict" (lockdownNormal etc. accepted)
#   services{<key>: {running, policy}} Get-VMHostService: TSM-SSH, TSM, slpd, ntpd; policy "on"|"off"|"automatic"
#   wbem.enabled, snmp.enabled         esxcli system wbem get / snmp get
#   software.acceptance_level          esxcli software acceptance get
#   kernel_settings{<option>: value}   esxcli system settings kernel list (execInstalledOnly, disableHwrng)
#   secure_boot.enabled                secureBoot.py -s ("Enabled" => true)
#   encryption{mode, require_secure_boot} esxcli system settings encryption get
#   ntp.servers[]                      esxcli system ntp config get
#   passwd.<dcui|vpxuser>.shell        login shell from the passwd entry
#   syslog{log_level, log_filtering_enabled, check_ssl_certs, strict_x509_compliance}  esxcli system syslog config get
#   audit_records{storage_active, remote_host_enabled}  esxcli system auditrecords get
#   firewall{enabled, default_action, rulesets[]{name, enabled, allowed_ip_all}}
#   vswitches[]{name, security{promiscuous_mode, mac_changes, forged_transmits}, portgroups[]{name, vlan_id,
#                security{...optional overrides}}}; native_vlan_id (optional, default 1)
#   datastores[]{name}, iscsi_adapters[]{device, chap_type, mutual_chap_enabled}
#   sshd_config{<directive>: value}    effective sshd settings, directive names lower-case
#   vms[]{config{efi_secure_boot_enabled, migrate_encryption, ft_encryption_mode, version}, advanced_settings{},
#          device_types[], tools_config{"<section>.<key>": value}}
#   attest.*                           attestation booleans for the judgement recommendations
# A setting that a VM does not carry is absent from advanced_settings; the "TRUE or absent" and "FALSE or absent"
# checks accept that, the others read it as not configured.

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {
	input.esxi
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		hardware_violations,
		software_and_boot_violations,
		access_and_shell_violations,
		logging_violations,
		host_network_violations,
		host_services_violations,
		virtual_machines_violations,
		vmware_tools_violations,
	]
	some a in arrays
	some v in a
]

# 1 Hardware
hardware_violations := sort([m | some m in _v_hardware])

# 2 Software and boot
software_and_boot_violations := sort([m | some m in _v_software_and_boot])

# 3 Access and shell
access_and_shell_violations := sort([m | some m in _v_access_and_shell])

# 4 Logging
logging_violations := sort([m | some m in _v_logging])

# 5 Host networking
host_network_violations := sort([m | some m in _v_host_network])

# 6 Host services
host_services_violations := sort([m | some m in _v_host_services])

# 7 Virtual machines
virtual_machines_violations := sort([m | some m in _v_virtual_machines])

# 8 VMware Tools
vmware_tools_violations := sort([m | some m in _v_vmware_tools])

# ── helpers ──────────────────────────────────────────────────────────────────
# profile selection: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent or other => 2, the stricter
default _level := 2

_level := 1 if input.cis_profile.level == 1

_applies(id) if recommendations[id].level <= _level

_nonempty(v) if {
	is_string(v)
	trim_space(v) != ""
}

# comparable text of a setting: "TRUE", true and " true " all read as "true"
_str(v) := lower(trim_space(sprintf("%v", [v])))

_istrue(v) if _str(v) == "true"

_isfalse(v) if _str(v) == "false"

# advanced settings come back as strings or numbers depending on the collector
_num(v) := v if is_number(v)

_num(v) := to_number(trim_space(v)) if {
	is_string(v)
	regex.match(`^\s*-?[0-9]+(\.[0-9]+)?\s*$`, v)
}

# ── host facts ──
_adv(k) := v if {
	v := input.esxi.advanced_settings[k]
	v != null
}

_has_adv(k) if input.esxi.advanced_settings[k] != null

_lockdown := trim_prefix(_str(input.esxi.lockdown_mode), "lockdown")

# Security.PasswordQualityControl: "min=N0,N1,N2,N3,N4" with the first four disabled and N4 >= 15
_pwq_ok if {
	m := regex.find_all_string_submatch_n(`(?:^|\s)min=([^\s]+)`, _adv("Security.PasswordQualityControl"), 1)
	parts := split(m[0][1], ",")
	count(parts) == 5
	every i in [0, 1, 2, 3] {
		lower(parts[i]) == "disabled"
	}
	regex.match(`^[0-9]+$`, parts[4])
	to_number(parts[4]) >= 15
}

# sshd effective settings (directive names lower-case); never a text search of the file
_has_sshd(k) if input.esxi.sshd_config[k] != null

_sshd(k) := _str(input.esxi.sshd_config[k]) if input.esxi.sshd_config[k] != null

# an enabled ruleset that does not name its allowed addresses is open to every address
_ruleset_open(r) if {
	r.enabled == true
	not r.allowed_ip_all == false
}

# VLAN the operator treats as native (default 1)
_native_vlan := object.get(input.esxi, "native_vlan_id", 1)

# ── VM facts ──
_vm_adv_ev if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms {
		is_object(vm.advanced_settings)
	}
}

_vhas(vm, k) if vm.advanced_settings[k] != null

_vtrue(vm, k) if _istrue(vm.advanced_settings[k])

_vfalse(vm, k) if _isfalse(vm.advanced_settings[k])

_vtrue_or_absent(vm, k) if not _vhas(vm, k)

_vtrue_or_absent(vm, k) if _vtrue(vm, k)

_vfalse_or_absent(vm, k) if not _vhas(vm, k)

_vfalse_or_absent(vm, k) if _vfalse(vm, k)

# a setting whose name matches the pattern with any value other than false
_vkey_bad(vm, re) if {
	some k, v in vm.advanced_settings
	regex.match(re, k)
	not _isfalse(v)
}

_vkey_any(vm, re) if {
	some k, _ in vm.advanced_settings
	regex.match(re, k)
}

# virtual hardware version as a number ("vmx-21" => 21)
_hw(vm) := to_number(trim_prefix(vm.config.version, "vmx-")) if regex.match(`^vmx-[0-9]+$`, vm.config.version)

# 1.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_1 := false

r_1_1 if {
	input.esxi.attest.hardware_firmware_inventoried == true
}

_v_hardware contains "1.1: firmware on the system and its devices must be inventoried against a supported baseline (manual review not attested)" if {
	_applies("1.1")
	not r_1_1
}

# 1.2 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_2 := false

r_1_2 if {
	input.esxi.secure_boot.enabled == true
}

default e_1_2 := false

e_1_2 if {
	is_boolean(input.esxi.secure_boot.enabled)
}

_v_hardware contains "1.2: evidence missing — esxi.secure_boot.enabled not collected" if {
	_applies("1.2")
	not e_1_2
}

_v_hardware contains "1.2: UEFI Secure Boot must be on in the host firmware" if {
	_applies("1.2")
	e_1_2
	not r_1_2
}

# 1.3 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_3 := false

r_1_3 if {
	input.esxi.attest.intel_txt_enabled_where_supported == true
}

_v_hardware contains "1.3: Intel TXT must be on where the CPU supports it (manual review not attested)" if {
	_applies("1.3")
	not r_1_3
}

# 1.4 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_4 := false

r_1_4 if {
	input.esxi.attest.tpm_2_0_configured == true
}

_v_hardware contains "1.4: a TPM 2.0 must be present and configured (manual review not attested)" if {
	_applies("1.4")
	not r_1_4
}

# 1.5 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_5 := false

r_1_5 if {
	input.esxi.attest.bmc_hardened == true
}

_v_hardware contains "1.5: the baseboard management controller must be hardened (manual review not attested)" if {
	_applies("1.5")
	not r_1_5
}

# 1.6 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_6 := false

r_1_6 if {
	input.esxi.attest.bmc_time_synchronized == true
}

_v_hardware contains "1.6: the management controller clock must be synchronized (manual review not attested)" if {
	_applies("1.6")
	not r_1_6
}

# 1.7 (Manual, Level 1 (L1) - Corporate_Enter)
default r_1_7 := false

r_1_7 if {
	input.esxi.attest.bmc_remote_logging == true
}

_v_hardware contains "1.7: the management controller must forward its events to a remote collector (manual review not attested)" if {
	_applies("1.7")
	not r_1_7
}

# 1.8 (Manual, Level 2 (L2) - High Security_S)
default r_1_8 := false

r_1_8 if {
	input.esxi.attest.bmc_authentication_secure == true
}

_v_hardware contains "1.8: management controller logins must be individual, strong and locked down (manual review not attested)" if {
	_applies("1.8")
	not r_1_8
}

# 1.9 (Manual, Level 2 (L2) - High Security_S)
default r_1_9 := false

r_1_9 if {
	input.esxi.attest.amd_sev_es_enabled_where_supported == true
}

_v_hardware contains "1.9: AMD SEV-ES must be on where the CPU supports it (manual review not attested)" if {
	_applies("1.9")
	not r_1_9
}

# 1.10 (Manual, Level 2 (L2) - High Security_S)
default r_1_10 := false

r_1_10 if {
	input.esxi.attest.intel_sgx_enabled_where_supported == true
}

_v_hardware contains "1.10: Intel SGX must be on where the CPU supports it (manual review not attested)" if {
	_applies("1.10")
	not r_1_10
}

# 1.11 (Manual, Level 2 (L2) - High Security_S)
default r_1_11 := false

r_1_11 if {
	input.esxi.attest.unused_ports_secured == true
}

_v_hardware contains "1.11: unused external hardware ports must be secured (manual review not attested)" if {
	_applies("1.11")
	not r_1_11
}

# 1.12 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_12 := false

r_1_12 if {
	v := _adv("Net.BMCNetworkEnable")
	n := _num(v)
	n == 0
}

default e_1_12 := false

e_1_12 if {
	_has_adv("Net.BMCNetworkEnable")
}

_v_hardware contains "1.12: evidence missing — esxi.advanced_settings.Net.BMCNetworkEnable not collected" if {
	_applies("1.12")
	not e_1_12
}

_v_hardware contains "1.12: Net.BMCNetworkEnable must be 0 so the controller has no internal network path" if {
	_applies("1.12")
	e_1_12
	not r_1_12
}

# 2.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_2_1 := false

r_2_1 if {
	input.esxi.attest.esxi_release_in_general_support == true
}

_v_software_and_boot contains "2.1: the ESXi release must still be in general support (manual review not attested)" if {
	_applies("2.1")
	not r_2_1
}

# 2.2 (Manual, Level 1 (L1) - Corporate_Enter)
default r_2_2 := false

r_2_2 if {
	input.esxi.attest.esxi_patches_current == true
}

_v_software_and_boot contains "2.2: all available patches must be installed (manual review not attested)" if {
	_applies("2.2")
	not r_2_2
}

# 2.3 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3 := false

r_2_3 if {
	input.esxi.encryption.require_secure_boot == true
}

default e_2_3 := false

e_2_3 if {
	is_boolean(input.esxi.encryption.require_secure_boot)
}

_v_software_and_boot contains "2.3: evidence missing — esxi.encryption.require_secure_boot not collected" if {
	_applies("2.3")
	not e_2_3
}

_v_software_and_boot contains "2.3: the host must refuse to run with Secure Boot enforcement off" if {
	_applies("2.3")
	e_2_3
	not r_2_3
}

# 2.4 (Automated, Level 1 (L1) - Corporate_Enter)
default r_2_4 := false

r_2_4 if {
	lower(input.esxi.software.acceptance_level) in {"vmwarecertified", "vmwareaccepted", "partnersupported"}
}

default e_2_4 := false

e_2_4 if {
	is_string(input.esxi.software.acceptance_level)
}

_v_software_and_boot contains "2.4: evidence missing — esxi.software.acceptance_level not collected" if {
	_applies("2.4")
	not e_2_4
}

_v_software_and_boot contains "2.4: the image profile acceptance level must be PartnerSupported or stricter" if {
	_applies("2.4")
	e_2_4
	not r_2_4
}

# 2.5 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_5 := false

r_2_5 if {
	_istrue(input.esxi.kernel_settings.execInstalledOnly)
}

default e_2_5 := false

e_2_5 if {
	is_object(input.esxi.kernel_settings)
	input.esxi.kernel_settings.execInstalledOnly != null
}

_v_software_and_boot contains "2.5: evidence missing — esxi.kernel_settings.execInstalledOnly not collected" if {
	_applies("2.5")
	not e_2_5
}

_v_software_and_boot contains "2.5: the host must run only binaries from installed signed VIBs" if {
	_applies("2.5")
	e_2_5
	not r_2_5
}

# 2.6 (Automated, Level 1 (L1) - Corporate_Enter)
default r_2_6 := false

r_2_6 if {
	input.esxi.services.ntpd.running == true
	lower(input.esxi.services.ntpd.policy) in {"on", "automatic"}
	count(input.esxi.ntp.servers) > 0
}

default e_2_6 := false

e_2_6 if {
	is_object(input.esxi.services.ntpd)
	is_array(input.esxi.ntp.servers)
}

_v_software_and_boot contains "2.6: evidence missing — esxi.{services.ntpd,ntp.servers} not collected" if {
	_applies("2.6")
	not e_2_6
}

_v_software_and_boot contains "2.6: NTP must run on the host with at least one server configured" if {
	_applies("2.6")
	e_2_6
	not r_2_6
}

# 2.7 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_7 := false

r_2_7 if {
	input.esxi.services.ntpd.running == true
	lower(input.esxi.services.ntpd.policy) in {"on", "automatic"}
	count(input.esxi.ntp.servers) > 0
}

default e_2_7 := false

e_2_7 if {
	is_object(input.esxi.services.ntpd)
	is_array(input.esxi.ntp.servers)
}

_v_software_and_boot contains "2.7: evidence missing — esxi.{services.ntpd,ntp.servers} not collected" if {
	_applies("2.7")
	not e_2_7
}

_v_software_and_boot contains "2.7: a time service must be enabled, configured and running" if {
	_applies("2.7")
	e_2_7
	not r_2_7
}

# 2.8 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_8 := false

r_2_8 if {
	lower(input.esxi.encryption.mode) == "tpm"
}

default e_2_8 := false

e_2_8 if {
	is_string(input.esxi.encryption.mode)
}

_v_software_and_boot contains "2.8: evidence missing — esxi.encryption.mode not collected" if {
	_applies("2.8")
	not e_2_8
}

_v_software_and_boot contains "2.8: configuration encryption must be anchored in the TPM" if {
	_applies("2.8")
	e_2_8
	not r_2_8
}

# 2.9 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_9 := false

r_2_9 if {
	v := _adv("UserVars.SuppressHyperthreadWarning")
	n := _num(v)
	n == 0
}

default e_2_9 := false

e_2_9 if {
	_has_adv("UserVars.SuppressHyperthreadWarning")
}

_v_software_and_boot contains "2.9: evidence missing — esxi.advanced_settings.UserVars.SuppressHyperthreadWarning not collected" if {
	_applies("2.9")
	not e_2_9
}

_v_software_and_boot contains "2.9: UserVars.SuppressHyperthreadWarning must be 0" if {
	_applies("2.9")
	e_2_9
	not r_2_9
}

# 2.10 (Automated, Level 1 (L1) - Corporate_Enter)
default r_2_10 := false

r_2_10 if {
	v := _adv("Mem.ShareForceSalting")
	n := _num(v)
	n == 2
}

default e_2_10 := false

e_2_10 if {
	_has_adv("Mem.ShareForceSalting")
}

_v_software_and_boot contains "2.10: evidence missing — esxi.advanced_settings.Mem.ShareForceSalting not collected" if {
	_applies("2.10")
	not e_2_10
}

_v_software_and_boot contains "2.10: Mem.ShareForceSalting must be 2 to stop inter-VM page sharing" if {
	_applies("2.10")
	e_2_10
	not r_2_10
}

# 2.11 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_11 := false

r_2_11 if {
	not _istrue(input.esxi.kernel_settings.disableHwrng)
}

default e_2_11 := false

e_2_11 if {
	is_object(input.esxi.kernel_settings)
}

_v_software_and_boot contains "2.11: evidence missing — esxi.kernel_settings not collected" if {
	_applies("2.11")
	not e_2_11
}

_v_software_and_boot contains "2.11: the disableHwrng kernel option must not be TRUE" if {
	_applies("2.11")
	e_2_11
	not r_2_11
}

# 2.12 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_12 := false

r_2_12 if {
	v := _adv("Mem.MemEagerZero")
	n := _num(v)
	n == 1
}

default e_2_12 := false

e_2_12 if {
	_has_adv("Mem.MemEagerZero")
}

_v_software_and_boot contains "2.12: evidence missing — esxi.advanced_settings.Mem.MemEagerZero not collected" if {
	_applies("2.12")
	not e_2_12
}

_v_software_and_boot contains "2.12: Mem.MemEagerZero must be 1 so freed memory is zeroed" if {
	_applies("2.12")
	e_2_12
	not r_2_12
}

# 3.1 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_1 := false

r_3_1 if {
	input.esxi.services["TSM-SSH"].running == false
	lower(input.esxi.services["TSM-SSH"].policy) == "off"
}

default e_3_1 := false

e_3_1 if {
	is_object(input.esxi.services["TSM-SSH"])
}

_v_access_and_shell contains "3.1: evidence missing — esxi.services.TSM-SSH not collected" if {
	_applies("3.1")
	not e_3_1
}

_v_access_and_shell contains "3.1: the SSH service must be stopped and set to start manually" if {
	_applies("3.1")
	e_3_1
	not r_3_1
}

# 3.2 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_2 := false

r_3_2 if {
	input.esxi.services.TSM.running == false
	lower(input.esxi.services.TSM.policy) == "off"
}

default e_3_2 := false

e_3_2 if {
	is_object(input.esxi.services.TSM)
}

_v_access_and_shell contains "3.2: evidence missing — esxi.services.TSM not collected" if {
	_applies("3.2")
	not e_3_2
}

_v_access_and_shell contains "3.2: the ESXi shell service must be stopped and set to start manually" if {
	_applies("3.2")
	e_3_2
	not r_3_2
}

# 3.3 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_3 := false

r_3_3 if {
	v := _adv("Config.HostAgent.plugins.solo.enableMob")
	_isfalse(v)
}

default e_3_3 := false

e_3_3 if {
	_has_adv("Config.HostAgent.plugins.solo.enableMob")
}

_v_access_and_shell contains "3.3: evidence missing — esxi.advanced_settings.Config.HostAgent.plugins.solo.enableMob not collected" if {
	_applies("3.3")
	not e_3_3
}

_v_access_and_shell contains "3.3: Config.HostAgent.plugins.solo.enableMob must be false" if {
	_applies("3.3")
	e_3_3
	not r_3_3
}

# 3.4 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_4 := false

r_3_4 if {
	not input.esxi.services.slpd
}

r_3_4 if {
	input.esxi.services.slpd.running == false
}

default e_3_4 := false

e_3_4 if {
	is_object(input.esxi.services)
}

_v_access_and_shell contains "3.4: evidence missing — esxi.services not collected" if {
	_applies("3.4")
	not e_3_4
}

_v_access_and_shell contains "3.4: the SLP service must not be running" if {
	_applies("3.4")
	e_3_4
	not r_3_4
}

# 3.5 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_5 := false

r_3_5 if {
	input.esxi.wbem.enabled == false
}

default e_3_5 := false

e_3_5 if {
	is_boolean(input.esxi.wbem.enabled)
}

_v_access_and_shell contains "3.5: evidence missing — esxi.wbem.enabled not collected" if {
	_applies("3.5")
	not e_3_5
}

_v_access_and_shell contains "3.5: CIM/WBEM must be off" if {
	_applies("3.5")
	e_3_5
	not r_3_5
}

# 3.6 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_6 := false

r_3_6 if {
	input.esxi.snmp.enabled == false
}

default e_3_6 := false

e_3_6 if {
	is_boolean(input.esxi.snmp.enabled)
}

_v_access_and_shell contains "3.6: evidence missing — esxi.snmp.enabled not collected" if {
	_applies("3.6")
	not e_3_6
}

_v_access_and_shell contains "3.6: SNMP must be off unless needed" if {
	_applies("3.6")
	e_3_6
	not r_3_6
}

# 3.7 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_7 := false

r_3_7 if {
	v := _adv("UserVars.DcuiTimeOut")
	n := _num(v)
	n > 0
	n <= 600
}

default e_3_7 := false

e_3_7 if {
	_has_adv("UserVars.DcuiTimeOut")
}

_v_access_and_shell contains "3.7: evidence missing — esxi.advanced_settings.UserVars.DcuiTimeOut not collected" if {
	_applies("3.7")
	not e_3_7
}

_v_access_and_shell contains "3.7: UserVars.DcuiTimeOut must be 1 to 600 seconds" if {
	_applies("3.7")
	e_3_7
	not r_3_7
}

# 3.8 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_8 := false

r_3_8 if {
	v := _adv("UserVars.ESXiShellInteractiveTimeOut")
	n := _num(v)
	n > 0
	n <= 300
}

default e_3_8 := false

e_3_8 if {
	_has_adv("UserVars.ESXiShellInteractiveTimeOut")
}

_v_access_and_shell contains "3.8: evidence missing — esxi.advanced_settings.UserVars.ESXiShellInteractiveTimeOut not collected" if {
	_applies("3.8")
	not e_3_8
}

_v_access_and_shell contains "3.8: UserVars.ESXiShellInteractiveTimeOut must be 1 to 300 seconds" if {
	_applies("3.8")
	e_3_8
	not r_3_8
}

# 3.9 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_9 := false

r_3_9 if {
	v := _adv("UserVars.ESXiShellTimeOut")
	n := _num(v)
	n > 0
	n <= 3600
}

default e_3_9 := false

e_3_9 if {
	_has_adv("UserVars.ESXiShellTimeOut")
}

_v_access_and_shell contains "3.9: evidence missing — esxi.advanced_settings.UserVars.ESXiShellTimeOut not collected" if {
	_applies("3.9")
	not e_3_9
}

_v_access_and_shell contains "3.9: UserVars.ESXiShellTimeOut must be 1 to 3600 seconds" if {
	_applies("3.9")
	e_3_9
	not r_3_9
}

# 3.10 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_10 := false

r_3_10 if {
	v := _adv("UserVars.SuppressShellWarning")
	n := _num(v)
	n == 0
}

default e_3_10 := false

e_3_10 if {
	_has_adv("UserVars.SuppressShellWarning")
}

_v_access_and_shell contains "3.10: evidence missing — esxi.advanced_settings.UserVars.SuppressShellWarning not collected" if {
	_applies("3.10")
	not e_3_10
}

_v_access_and_shell contains "3.10: UserVars.SuppressShellWarning must be 0" if {
	_applies("3.10")
	e_3_10
	not r_3_10
}

# 3.11 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_11 := false

r_3_11 if {
	_pwq_ok
}

default e_3_11 := false

e_3_11 if {
	is_string(_adv("Security.PasswordQualityControl"))
}

_v_access_and_shell contains "3.11: evidence missing — esxi.advanced_settings.Security.PasswordQualityControl not collected" if {
	_applies("3.11")
	not e_3_11
}

_v_access_and_shell contains "3.11: Security.PasswordQualityControl must demand 15 or more characters from four classes" if {
	_applies("3.11")
	e_3_11
	not r_3_11
}

# 3.12 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_12 := false

r_3_12 if {
	v := _adv("Security.AccountLockFailures")
	n := _num(v)
	n == 5
}

default e_3_12 := false

e_3_12 if {
	_has_adv("Security.AccountLockFailures")
}

_v_access_and_shell contains "3.12: evidence missing — esxi.advanced_settings.Security.AccountLockFailures not collected" if {
	_applies("3.12")
	not e_3_12
}

_v_access_and_shell contains "3.12: Security.AccountLockFailures must be 5" if {
	_applies("3.12")
	e_3_12
	not r_3_12
}

# 3.13 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_13 := false

r_3_13 if {
	v := _adv("Security.AccountUnlockTime")
	n := _num(v)
	n == 900
}

default e_3_13 := false

e_3_13 if {
	_has_adv("Security.AccountUnlockTime")
}

_v_access_and_shell contains "3.13: evidence missing — esxi.advanced_settings.Security.AccountUnlockTime not collected" if {
	_applies("3.13")
	not e_3_13
}

_v_access_and_shell contains "3.13: Security.AccountUnlockTime must be 900" if {
	_applies("3.13")
	e_3_13
	not r_3_13
}

# 3.14 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_14 := false

r_3_14 if {
	v := _adv("Security.PasswordHistory")
	n := _num(v)
	n == 5
}

default e_3_14 := false

e_3_14 if {
	_has_adv("Security.PasswordHistory")
}

_v_access_and_shell contains "3.14: evidence missing — esxi.advanced_settings.Security.PasswordHistory not collected" if {
	_applies("3.14")
	not e_3_14
}

_v_access_and_shell contains "3.14: Security.PasswordHistory must be 5" if {
	_applies("3.14")
	e_3_14
	not r_3_14
}

# 3.15 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_15 := false

r_3_15 if {
	input.esxi.attest.password_max_days_approved == true
}

_v_access_and_shell contains "3.15: Security.PasswordMaxDays must match the approved rotation policy (manual review not attested)" if {
	_applies("3.15")
	not r_3_15
}

# 3.16 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_16 := false

r_3_16 if {
	v := _adv("Config.HostAgent.vmacore.soap.sessionTimeout")
	n := _num(v)
	n > 0
}

default e_3_16 := false

e_3_16 if {
	_has_adv("Config.HostAgent.vmacore.soap.sessionTimeout")
}

_v_access_and_shell contains "3.16: evidence missing — esxi.advanced_settings.Config.HostAgent.vmacore.soap.sessionTimeout not collected" if {
	_applies("3.16")
	not e_3_16
}

_v_access_and_shell contains "3.16: the API session timeout must be a finite approved value" if {
	_applies("3.16")
	e_3_16
	not r_3_16
}

# 3.17 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_17 := false

r_3_17 if {
	v := _adv("UserVars.HostClientSessionTimeout")
	n := _num(v)
	n > 0
}

default e_3_17 := false

e_3_17 if {
	_has_adv("UserVars.HostClientSessionTimeout")
}

_v_access_and_shell contains "3.17: evidence missing — esxi.advanced_settings.UserVars.HostClientSessionTimeout not collected" if {
	_applies("3.17")
	not e_3_17
}

_v_access_and_shell contains "3.17: UserVars.HostClientSessionTimeout must be a finite positive value" if {
	_applies("3.17")
	e_3_17
	not r_3_17
}

# 3.18 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_18 := false

r_3_18 if {
	input.esxi.attest.dcui_access_list_accurate == true
}

_v_access_and_shell contains "3.18: DCUI.Access must list only the approved override users (manual review not attested)" if {
	_applies("3.18")
	not r_3_18
}

# 3.19 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_19 := false

r_3_19 if {
	input.esxi.attest.lockdown_exception_users_accurate == true
}

_v_access_and_shell contains "3.19: the lockdown Exception Users list must be reviewed and accurate (manual review not attested)" if {
	_applies("3.19")
	not r_3_19
}

# 3.20 (Automated, Level 1 (L1) - Corporate_Enter)
default r_3_20 := false

r_3_20 if {
	_lockdown in {"normal", "strict"}
}

default e_3_20 := false

e_3_20 if {
	is_string(input.esxi.lockdown_mode)
}

_v_access_and_shell contains "3.20: evidence missing — esxi.lockdown_mode not collected" if {
	_applies("3.20")
	not e_3_20
}

_v_access_and_shell contains "3.20: lockdown mode must be normal or strict" if {
	_applies("3.20")
	e_3_20
	not r_3_20
}

# 3.21 (Automated, Level 2 (L2) - High Security_S)
default r_3_21 := false

r_3_21 if {
	_lockdown == "strict"
}

default e_3_21 := false

e_3_21 if {
	is_string(input.esxi.lockdown_mode)
}

_v_access_and_shell contains "3.21: evidence missing — esxi.lockdown_mode not collected" if {
	_applies("3.21")
	not e_3_21
}

_v_access_and_shell contains "3.21: lockdown mode must be strict" if {
	_applies("3.21")
	e_3_21
	not r_3_21
}

# 3.22 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_22 := false

r_3_22 if {
	lower(input.esxi.passwd.dcui.shell) in {"/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin"}
}

default e_3_22 := false

e_3_22 if {
	is_string(input.esxi.passwd.dcui.shell)
}

_v_access_and_shell contains "3.22: evidence missing — esxi.passwd.dcui.shell not collected" if {
	_applies("3.22")
	not e_3_22
}

_v_access_and_shell contains "3.22: the dcui account must have a non-interactive shell" if {
	_applies("3.22")
	e_3_22
	not r_3_22
}

# 3.23 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_23 := false

r_3_23 if {
	lower(input.esxi.passwd.vpxuser.shell) in {"/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin"}
}

default e_3_23 := false

e_3_23 if {
	is_string(input.esxi.passwd.vpxuser.shell)
}

_v_access_and_shell contains "3.23: evidence missing — esxi.passwd.vpxuser.shell not collected" if {
	_applies("3.23")
	not e_3_23
}

_v_access_and_shell contains "3.23: the vpxuser account must have a non-interactive shell" if {
	_applies("3.23")
	e_3_23
	not r_3_23
}

# 3.24 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_24 := false

r_3_24 if {
	input.esxi.attest.dcui_host_client_banner_approved == true
}

_v_access_and_shell contains "3.24: the DCUI and Host Client welcome banner must carry the approved text (manual review not attested)" if {
	_applies("3.24")
	not r_3_24
}

# 3.25 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_25 := false

r_3_25 if {
	input.esxi.attest.ssh_banner_file_approved == true
}

_v_access_and_shell contains "3.25: the SSH banner file must carry the approved text (manual review not attested)" if {
	_applies("3.25")
	not r_3_25
}

# 3.26 (Manual, Level 1 (L1) - Corporate_Enter)
default r_3_26 := false

r_3_26 if {
	input.esxi.attest.tls_highest_version_only == true
}

_v_access_and_shell contains "3.26: legacy TLS versions must be off and the highest supported version on (manual review not attested)" if {
	_applies("3.26")
	not r_3_26
}

# 4.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_4_1 := false

r_4_1 if {
	input.esxi.attest.system_log_location_persistent == true
}

_v_logging contains "4.1: system logs must be written to a persistent location (manual review not attested)" if {
	_applies("4.1")
	not r_4_1
}

# 4.2 (Automated, Level 1 (L1) - Corporate_Enter)
default r_4_2 := false

r_4_2 if {
	_nonempty(_adv("Syslog.global.logHost"))
}

default e_4_2 := false

e_4_2 if {
	_has_adv("Syslog.global.logHost")
}

_v_logging contains "4.2: evidence missing — esxi.advanced_settings.Syslog.global.logHost not collected" if {
	_applies("4.2")
	not e_4_2
}

_v_logging contains "4.2: Syslog.global.logHost must name a remote collector" if {
	_applies("4.2")
	e_4_2
	not r_4_2
}

# 4.3 (Manual, Level 1 (L1) - Corporate_Enter)
default r_4_3 := false

r_4_3 if {
	input.esxi.attest.log_detail_sufficient == true
}

_v_logging contains "4.3: logging detail and local log files must be reviewed as sufficient (manual review not attested)" if {
	_applies("4.3")
	not r_4_3
}

# 4.4 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_4 := false

r_4_4 if {
	lower(input.esxi.syslog.log_level) == "info"
}

default e_4_4 := false

e_4_4 if {
	is_string(input.esxi.syslog.log_level)
}

_v_logging contains "4.4: evidence missing — esxi.syslog.log_level not collected" if {
	_applies("4.4")
	not e_4_4
}

_v_logging contains "4.4: the syslog log level must be info" if {
	_applies("4.4")
	e_4_4
	not r_4_4
}

# 4.5 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_5 := false

r_4_5 if {
	input.esxi.syslog.log_filtering_enabled == false
}

default e_4_5 := false

e_4_5 if {
	is_boolean(input.esxi.syslog.log_filtering_enabled)
}

_v_logging contains "4.5: evidence missing — esxi.syslog.log_filtering_enabled not collected" if {
	_applies("4.5")
	not e_4_5
}

_v_logging contains "4.5: syslog log filtering must be off" if {
	_applies("4.5")
	e_4_5
	not r_4_5
}

# 4.6 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_6 := false

r_4_6 if {
	input.esxi.audit_records.storage_active == true
}

default e_4_6 := false

e_4_6 if {
	is_boolean(input.esxi.audit_records.storage_active)
}

_v_logging contains "4.6: evidence missing — esxi.audit_records.storage_active not collected" if {
	_applies("4.6")
	not e_4_6
}

_v_logging contains "4.6: audit record storage must be active" if {
	_applies("4.6")
	e_4_6
	not r_4_6
}

# 4.7 (Manual, Level 1 (L1) - Corporate_Enter)
default r_4_7 := false

r_4_7 if {
	input.esxi.attest.audit_record_location_persistent == true
}

_v_logging contains "4.7: audit records must be stored in a persistent location (manual review not attested)" if {
	_applies("4.7")
	not r_4_7
}

# 4.8 (Manual, Level 1 (L1) - Corporate_Enter)
default r_4_8 := false

r_4_8 if {
	input.esxi.attest.audit_storage_seven_days == true
}

_v_logging contains "4.8: local audit storage must hold at least seven days (manual review not attested)" if {
	_applies("4.8")
	not r_4_8
}

# 4.9 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_9 := false

r_4_9 if {
	_nonempty(_adv("Syslog.global.logHost"))
	input.esxi.audit_records.remote_host_enabled == true
}

default e_4_9 := false

e_4_9 if {
	_has_adv("Syslog.global.logHost")
	is_boolean(input.esxi.audit_records.remote_host_enabled)
}

_v_logging contains "4.9: evidence missing — esxi.{advanced_settings.Syslog.global.logHost,audit_records.remote_host_enabled} not collected" if {
	_applies("4.9")
	not e_4_9
}

_v_logging contains "4.9: audit records must be sent to a remote collector" if {
	_applies("4.9")
	e_4_9
	not r_4_9
}

# 4.10 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_10 := false

r_4_10 if {
	input.esxi.syslog.check_ssl_certs == true
}

default e_4_10 := false

e_4_10 if {
	is_boolean(input.esxi.syslog.check_ssl_certs)
}

_v_logging contains "4.10: evidence missing — esxi.syslog.check_ssl_certs not collected" if {
	_applies("4.10")
	not e_4_10
}

_v_logging contains "4.10: remote syslog over TLS must check the endpoint certificate" if {
	_applies("4.10")
	e_4_10
	not r_4_10
}

# 4.11 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_11 := false

r_4_11 if {
	input.esxi.syslog.strict_x509_compliance == true
}

default e_4_11 := false

e_4_11 if {
	is_boolean(input.esxi.syslog.strict_x509_compliance)
}

_v_logging contains "4.11: evidence missing — esxi.syslog.strict_x509_compliance not collected" if {
	_applies("4.11")
	not e_4_11
}

_v_logging contains "4.11: remote syslog over TLS must use strict x509 checks" if {
	_applies("4.11")
	e_4_11
	not r_4_11
}

# 5.1 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_1 := false

r_5_1 if {
	count([1 | some r in input.esxi.firewall.rulesets; _ruleset_open(r)]) == 0
}

default e_5_1 := false

e_5_1 if {
	is_array(input.esxi.firewall.rulesets)
}

_v_host_network contains "5.1: evidence missing — esxi.firewall.rulesets not collected" if {
	_applies("5.1")
	not e_5_1
}

_v_host_network contains "5.1: an enabled firewall ruleset must not allow all IP addresses" if {
	_applies("5.1")
	e_5_1
	not r_5_1
}

# 5.2 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_2 := false

r_5_2 if {
	input.esxi.firewall.enabled == true
	lower(input.esxi.firewall.default_action) == "drop"
}

default e_5_2 := false

e_5_2 if {
	is_boolean(input.esxi.firewall.enabled)
	is_string(input.esxi.firewall.default_action)
}

_v_host_network contains "5.2: evidence missing — esxi.firewall.{enabled,default_action} not collected" if {
	_applies("5.2")
	not e_5_2
}

_v_host_network contains "5.2: the host firewall must be on and drop by default" if {
	_applies("5.2")
	e_5_2
	not r_5_2
}

# 5.3 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_3 := false

r_5_3 if {
	v := _adv("Net.DVFilterBindIpAddress")
	v == ""
}

default e_5_3 := false

e_5_3 if {
	_has_adv("Net.DVFilterBindIpAddress")
}

_v_host_network contains "5.3: evidence missing — esxi.advanced_settings.Net.DVFilterBindIpAddress not collected" if {
	_applies("5.3")
	not e_5_3
}

_v_host_network contains "5.3: Net.DVFilterBindIpAddress must be empty" if {
	_applies("5.3")
	e_5_3
	not r_5_3
}

# 5.4 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_4 := false

r_5_4 if {
	v := _adv("Net.BlockGuestBPDU")
	n := _num(v)
	n == 1
}

default e_5_4 := false

e_5_4 if {
	_has_adv("Net.BlockGuestBPDU")
}

_v_host_network contains "5.4: evidence missing — esxi.advanced_settings.Net.BlockGuestBPDU not collected" if {
	_applies("5.4")
	not e_5_4
}

_v_host_network contains "5.4: Net.BlockGuestBPDU must be 1" if {
	_applies("5.4")
	e_5_4
	not r_5_4
}

# 5.5 (Manual, Level 2 (L2) - High Security_S)
default r_5_5 := false

r_5_5 if {
	input.esxi.attest.virtual_hardware_mgmt_interfaces_absent == true
}

_v_host_network contains "5.5: VMkernel interfaces for virtual hardware management must be absent (manual review not attested)" if {
	_applies("5.5")
	not r_5_5
}

# 5.6 (Automated, Level 1 (L1) - Corporate_Enter)
default r_5_6 := false

r_5_6 if {
	every sw in input.esxi.vswitches { sw.security.forged_transmits == false; count([1 | some pg in object.get(sw, "portgroups", []); pg.security.forged_transmits == true]) == 0}
}

default e_5_6 := false

e_5_6 if {
	is_array(input.esxi.vswitches)
	every sw in input.esxi.vswitches { is_boolean(sw.security.forged_transmits) }
}

_v_host_network contains "5.6: evidence missing — esxi.vswitches[].security not collected" if {
	_applies("5.6")
	not e_5_6
}

_v_host_network contains "5.6: standard switches and port groups must reject forged transmits" if {
	_applies("5.6")
	e_5_6
	not r_5_6
}

# 5.7 (Automated, Level 1 (L1) - Corporate_Enter)
default r_5_7 := false

r_5_7 if {
	every sw in input.esxi.vswitches { sw.security.mac_changes == false; count([1 | some pg in object.get(sw, "portgroups", []); pg.security.mac_changes == true]) == 0}
}

default e_5_7 := false

e_5_7 if {
	is_array(input.esxi.vswitches)
	every sw in input.esxi.vswitches { is_boolean(sw.security.mac_changes) }
}

_v_host_network contains "5.7: evidence missing — esxi.vswitches[].security not collected" if {
	_applies("5.7")
	not e_5_7
}

_v_host_network contains "5.7: standard switches and port groups must reject MAC address changes" if {
	_applies("5.7")
	e_5_7
	not r_5_7
}

# 5.8 (Automated, Level 1 (L1) - Corporate_Enter)
default r_5_8 := false

r_5_8 if {
	every sw in input.esxi.vswitches { sw.security.promiscuous_mode == false; count([1 | some pg in object.get(sw, "portgroups", []); pg.security.promiscuous_mode == true]) == 0}
}

default e_5_8 := false

e_5_8 if {
	is_array(input.esxi.vswitches)
	every sw in input.esxi.vswitches { is_boolean(sw.security.promiscuous_mode) }
}

_v_host_network contains "5.8: evidence missing — esxi.vswitches[].security not collected" if {
	_applies("5.8")
	not e_5_8
}

_v_host_network contains "5.8: standard switches and port groups must reject promiscuous mode" if {
	_applies("5.8")
	e_5_8
	not r_5_8
}

# 5.9 (Automated, Level 1 (L1) - Corporate_Enter)
default r_5_9 := false

r_5_9 if {
	count([1 | some sw in input.esxi.vswitches; some pg in sw.portgroups; pg.vlan_id == _native_vlan]) == 0
}

default e_5_9 := false

e_5_9 if {
	is_array(input.esxi.vswitches)
	every sw in input.esxi.vswitches { every pg in sw.portgroups { is_number(pg.vlan_id) } }
}

_v_host_network contains "5.9: evidence missing — esxi.vswitches[].portgroups[].vlan_id not collected" if {
	_applies("5.9")
	not e_5_9
}

_v_host_network contains "5.9: a standard port group must not use the native VLAN" if {
	_applies("5.9")
	e_5_9
	not r_5_9
}

# 5.10 (Automated, Level 1 (L1) - Corporate_Enter)
default r_5_10 := false

r_5_10 if {
	count([1 | some sw in input.esxi.vswitches; some pg in sw.portgroups; pg.vlan_id == 4095]) == 0
}

default e_5_10 := false

e_5_10 if {
	is_array(input.esxi.vswitches)
	every sw in input.esxi.vswitches { every pg in sw.portgroups { is_number(pg.vlan_id) } }
}

_v_host_network contains "5.10: evidence missing — esxi.vswitches[].portgroups[].vlan_id not collected" if {
	_applies("5.10")
	not e_5_10
}

_v_host_network contains "5.10: a standard port group must not use VLAN 4095" if {
	_applies("5.10")
	e_5_10
	not r_5_10
}

# 5.11 (Manual, Level 1 (L1) - Corporate_Enter)
default r_5_11 := false

r_5_11 if {
	input.esxi.attest.management_traffic_isolated == true
}

_v_host_network contains "5.11: management traffic must stay on dedicated VMkernel interfaces and VLANs (manual review not attested)" if {
	_applies("5.11")
	not r_5_11
}

# 6.1.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_1_1 := false

r_6_1_1 if {
	input.esxi.attest.cim_access_limited == true
}

_v_host_services contains "6.1.1: CIM access, if used, must go through a least-privilege account (manual review not attested)" if {
	_applies("6.1.1")
	not r_6_1_1
}

# 6.2.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_2_1 := false

r_6_2_1 if {
	input.esxi.attest.storage_traffic_isolated == true
}

_v_host_services contains "6.2.1: storage traffic must be isolated from other networks (manual review not attested)" if {
	_applies("6.2.1")
	not r_6_2_1
}

# 6.2.2 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_2_2 := false

r_6_2_2 if {
	count({d.name | some d in input.esxi.datastores}) == count(input.esxi.datastores)
}

default e_6_2_2 := false

e_6_2_2 if {
	is_array(input.esxi.datastores)
	every d in input.esxi.datastores { is_string(d.name) }
}

_v_host_services contains "6.2.2: evidence missing — esxi.datastores[].name not collected" if {
	_applies("6.2.2")
	not e_6_2_2
}

_v_host_services contains "6.2.2: datastore names must be unique" if {
	_applies("6.2.2")
	e_6_2_2
	not r_6_2_2
}

# 6.3.1 (Automated, Level 1 (L1) - Corporate_Enter)
default r_6_3_1 := false

r_6_3_1 if {
	every a in input.esxi.iscsi_adapters { a.mutual_chap_enabled == true; lower(a.chap_type) == "required"}
}

default e_6_3_1 := false

e_6_3_1 if {
	is_array(input.esxi.iscsi_adapters)
}

_v_host_services contains "6.3.1: evidence missing — esxi.iscsi_adapters not collected" if {
	_applies("6.3.1")
	not e_6_3_1
}

_v_host_services contains "6.3.1: iSCSI adapters must use mutual CHAP" if {
	_applies("6.3.1")
	e_6_3_1
	not r_6_3_1
}

# 6.3.2 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_3_2 := false

r_6_3_2 if {
	input.esxi.attest.iscsi_chap_secrets_unique == true
}

_v_host_services contains "6.3.2: iSCSI CHAP secrets must be unique per adapter (manual review not attested)" if {
	_applies("6.3.2")
	not r_6_3_2
}

# 6.4.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_4_1 := false

r_6_4_1 if {
	input.esxi.attest.snmp_access_limited == true
}

_v_host_services contains "6.4.1: SNMP, if used, must restrict who can poll (manual review not attested)" if {
	_applies("6.4.1")
	not r_6_4_1
}

# 6.5.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_5_1 := false

r_6_5_1 if {
	input.esxi.attest.sshd_ciphers_fips == true
}

_v_host_services contains "6.5.1: sshd ciphers must be limited to approved FIPS-validated ones (manual review not attested)" if {
	_applies("6.5.1")
	not r_6_5_1
}

# 6.5.2 (Manual, Level 1 (L1) - Corporate_Enter)
default r_6_5_2 := false

r_6_5_2 if {
	input.esxi.attest.sshd_crypto_modules_fips == true
}

_v_host_services contains "6.5.2: sshd must run on the platform FIPS-validated crypto modules (manual review not attested)" if {
	_applies("6.5.2")
	not r_6_5_2
}

# 6.5.3 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_3 := false

r_6_5_3 if {
	_sshd("gatewayports") == "no"
}

default e_6_5_3 := false

e_6_5_3 if {
	_has_sshd("gatewayports")
}

_v_host_services contains "6.5.3: evidence missing — esxi.sshd_config.gatewayports not collected" if {
	_applies("6.5.3")
	not e_6_5_3
}

_v_host_services contains "6.5.3: sshd GatewayPorts must be no" if {
	_applies("6.5.3")
	e_6_5_3
	not r_6_5_3
}

# 6.5.4 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_4 := false

r_6_5_4 if {
	_sshd("hostbasedauthentication") == "no"
}

default e_6_5_4 := false

e_6_5_4 if {
	_has_sshd("hostbasedauthentication")
}

_v_host_services contains "6.5.4: evidence missing — esxi.sshd_config.hostbasedauthentication not collected" if {
	_applies("6.5.4")
	not e_6_5_4
}

_v_host_services contains "6.5.4: sshd HostbasedAuthentication must be no" if {
	_applies("6.5.4")
	e_6_5_4
	not r_6_5_4
}

# 6.5.5 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_5 := false

r_6_5_5 if {
	input.esxi.sshd_config.clientalivecountmax != null
	_num(input.esxi.sshd_config.clientalivecountmax) > 0
}

default e_6_5_5 := false

e_6_5_5 if {
	_has_sshd("clientalivecountmax")
}

_v_host_services contains "6.5.5: evidence missing — esxi.sshd_config.clientalivecountmax not collected" if {
	_applies("6.5.5")
	not e_6_5_5
}

_v_host_services contains "6.5.5: sshd ClientAliveCountMax must be a positive value" if {
	_applies("6.5.5")
	e_6_5_5
	not r_6_5_5
}

# 6.5.6 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_6 := false

r_6_5_6 if {
	input.esxi.sshd_config.clientaliveinterval != null
	_num(input.esxi.sshd_config.clientaliveinterval) > 0
}

default e_6_5_6 := false

e_6_5_6 if {
	_has_sshd("clientaliveinterval")
}

_v_host_services contains "6.5.6: evidence missing — esxi.sshd_config.clientaliveinterval not collected" if {
	_applies("6.5.6")
	not e_6_5_6
}

_v_host_services contains "6.5.6: sshd ClientAliveInterval must be a positive value" if {
	_applies("6.5.6")
	e_6_5_6
	not r_6_5_6
}

# 6.5.7 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_7 := false

r_6_5_7 if {
	_sshd("banner") != "none"
	_sshd("banner") != ""
}

default e_6_5_7 := false

e_6_5_7 if {
	_has_sshd("banner")
}

_v_host_services contains "6.5.7: evidence missing — esxi.sshd_config.banner not collected" if {
	_applies("6.5.7")
	not e_6_5_7
}

_v_host_services contains "6.5.7: sshd must show a banner before login" if {
	_applies("6.5.7")
	e_6_5_7
	not r_6_5_7
}

# 6.5.8 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_8 := false

r_6_5_8 if {
	_sshd("ignorerhosts") == "yes"
}

default e_6_5_8 := false

e_6_5_8 if {
	_has_sshd("ignorerhosts")
}

_v_host_services contains "6.5.8: evidence missing — esxi.sshd_config.ignorerhosts not collected" if {
	_applies("6.5.8")
	not e_6_5_8
}

_v_host_services contains "6.5.8: sshd IgnoreRhosts must be yes" if {
	_applies("6.5.8")
	e_6_5_8
	not r_6_5_8
}

# 6.5.9 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_9 := false

r_6_5_9 if {
	_sshd("allowstreamlocalforwarding") == "no"
}

default e_6_5_9 := false

e_6_5_9 if {
	_has_sshd("allowstreamlocalforwarding")
}

_v_host_services contains "6.5.9: evidence missing — esxi.sshd_config.allowstreamlocalforwarding not collected" if {
	_applies("6.5.9")
	not e_6_5_9
}

_v_host_services contains "6.5.9: sshd AllowStreamLocalForwarding must be no" if {
	_applies("6.5.9")
	e_6_5_9
	not r_6_5_9
}

# 6.5.10 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_10 := false

r_6_5_10 if {
	_sshd("allowtcpforwarding") == "no"
}

default e_6_5_10 := false

e_6_5_10 if {
	_has_sshd("allowtcpforwarding")
}

_v_host_services contains "6.5.10: evidence missing — esxi.sshd_config.allowtcpforwarding not collected" if {
	_applies("6.5.10")
	not e_6_5_10
}

_v_host_services contains "6.5.10: sshd AllowTcpForwarding must be no" if {
	_applies("6.5.10")
	e_6_5_10
	not r_6_5_10
}

# 6.5.11 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_11 := false

r_6_5_11 if {
	_sshd("permittunnel") == "no"
}

default e_6_5_11 := false

e_6_5_11 if {
	_has_sshd("permittunnel")
}

_v_host_services contains "6.5.11: evidence missing — esxi.sshd_config.permittunnel not collected" if {
	_applies("6.5.11")
	not e_6_5_11
}

_v_host_services contains "6.5.11: sshd PermitTunnel must be no" if {
	_applies("6.5.11")
	e_6_5_11
	not r_6_5_11
}

# 6.5.12 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_5_12 := false

r_6_5_12 if {
	_sshd("permituserenvironment") == "no"
}

default e_6_5_12 := false

e_6_5_12 if {
	_has_sshd("permituserenvironment")
}

_v_host_services contains "6.5.12: evidence missing — esxi.sshd_config.permituserenvironment not collected" if {
	_applies("6.5.12")
	not e_6_5_12
}

_v_host_services contains "6.5.12: sshd PermitUserEnvironment must be no" if {
	_applies("6.5.12")
	e_6_5_12
	not r_6_5_12
}

# 7.1 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_1 := false

r_7_1 if {
	every vm in input.esxi.vms { vm.config.efi_secure_boot_enabled == true }
}

default e_7_1 := false

e_7_1 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_boolean(vm.config.efi_secure_boot_enabled) }
}

_v_virtual_machines contains "7.1: evidence missing — esxi.vms[].config.efi_secure_boot_enabled not collected" if {
	_applies("7.1")
	not e_7_1
}

_v_virtual_machines contains "7.1: every VM must boot with EFI Secure Boot" if {
	_applies("7.1")
	e_7_1
	not r_7_1
}

# 7.2 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_2 := false

r_7_2 if {
	every vm in input.esxi.vms { lower(vm.config.migrate_encryption) == "required" }
}

default e_7_2 := false

e_7_2 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_string(vm.config.migrate_encryption) }
}

_v_virtual_machines contains "7.2: evidence missing — esxi.vms[].config.migrate_encryption not collected" if {
	_applies("7.2")
	not e_7_2
}

_v_virtual_machines contains "7.2: every VM must require encrypted vMotion" if {
	_applies("7.2")
	e_7_2
	not r_7_2
}

# 7.3 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_3 := false

r_7_3 if {
	every vm in input.esxi.vms { lower(vm.config.ft_encryption_mode) == "ftencryptionrequired" }
}

default e_7_3 := false

e_7_3 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_string(vm.config.ft_encryption_mode) }
}

_v_virtual_machines contains "7.3: evidence missing — esxi.vms[].config.ft_encryption_mode not collected" if {
	_applies("7.3")
	not e_7_3
}

_v_virtual_machines contains "7.3: every VM must require encrypted Fault Tolerance traffic" if {
	_applies("7.3")
	e_7_3
	not r_7_3
}

# 7.4 (Automated, Level 2 (L2) - High Security_S)
default r_7_4 := false

r_7_4 if {
	every vm in input.esxi.vms { _vfalse_or_absent(vm, "mks.enable3d") }
}

default e_7_4 := false

e_7_4 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.4: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.4")
	not e_7_4
}

_v_virtual_machines contains "7.4: mks.enable3d must not be on for VMs" if {
	_applies("7.4")
	e_7_4
	not r_7_4
}

# 7.5 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_5 := false

r_7_5 if {
	every vm in input.esxi.vms { _vtrue(vm, "tools.guest.desktop.autolock") }
}

default e_7_5 := false

e_7_5 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.5: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.5")
	not e_7_5
}

_v_virtual_machines contains "7.5: tools.guest.desktop.autolock must be TRUE" if {
	_applies("7.5")
	e_7_5
	not r_7_5
}

# 7.6 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_6 := false

r_7_6 if {
	every vm in input.esxi.vms { _num(vm.advanced_settings["RemoteDisplay.maxConnections"]) == 1 }
}

default e_7_6 := false

e_7_6 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.6: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.6")
	not e_7_6
}

_v_virtual_machines contains "7.6: RemoteDisplay.maxConnections must be 1" if {
	_applies("7.6")
	e_7_6
	not r_7_6
}

# 7.7 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_7 := false

r_7_7 if {
	every vm in input.esxi.vms { not _vkey_bad(vm, "(?i)^pcipassthru[0-9]*\\.present$") }
}

default e_7_7 := false

e_7_7 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.7: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.7")
	not e_7_7
}

_v_virtual_machines contains "7.7: a VM must not have a pciPassthru device present" if {
	_applies("7.7")
	e_7_7
	not r_7_7
}

# 7.8 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_8 := false

r_7_8 if {
	every vm in input.esxi.vms { _vtrue(vm, "isolation.device.edit.disable") }
}

default e_7_8 := false

e_7_8 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.8: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.8")
	not e_7_8
}

_v_virtual_machines contains "7.8: isolation.device.edit.disable must be TRUE" if {
	_applies("7.8")
	e_7_8
	not r_7_8
}

# 7.9 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_9 := false

r_7_9 if {
	every vm in input.esxi.vms { _vtrue(vm, "isolation.device.connectable.disable") }
}

default e_7_9 := false

e_7_9 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.9: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.9")
	not e_7_9
}

_v_virtual_machines contains "7.9: isolation.device.connectable.disable must be TRUE" if {
	_applies("7.9")
	e_7_9
	not r_7_9
}

# 7.10 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_10 := false

r_7_10 if {
	every vm in input.esxi.vms { not "sound" in {lower(t) | some t in vm.device_types} }
}

default e_7_10 := false

e_7_10 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_array(vm.device_types) }
}

_v_virtual_machines contains "7.10: evidence missing — esxi.vms[].device_types not collected" if {
	_applies("7.10")
	not e_7_10
}

_v_virtual_machines contains "7.10: VMs must have no sound device" if {
	_applies("7.10")
	e_7_10
	not r_7_10
}

# 7.11 (Manual, Level 1 (L1) - Corporate_Enter)
default r_7_11 := false

r_7_11 if {
	input.esxi.attest.unneeded_ahci_controllers_removed == true
}

_v_virtual_machines contains "7.11: VMs must have no AHCI controller that backs nothing needed (manual review not attested)" if {
	_applies("7.11")
	not r_7_11
}

# 7.12 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_12 := false

r_7_12 if {
	every vm in input.esxi.vms { not _vkey_bad(vm, "(?i)^(usb|usb_xhci)\\.present$") }
}

default e_7_12 := false

e_7_12 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.12: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.12")
	not e_7_12
}

_v_virtual_machines contains "7.12: VMs must have no USB or XHCI controller" if {
	_applies("7.12")
	e_7_12
	not r_7_12
}

# 7.13 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_13 := false

r_7_13 if {
	every vm in input.esxi.vms { not _vkey_bad(vm, "(?i)^serial[0-9]+\\.present$") }
}

default e_7_13 := false

e_7_13 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.13: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.13")
	not e_7_13
}

_v_virtual_machines contains "7.13: VMs must have no serial port" if {
	_applies("7.13")
	e_7_13
	not r_7_13
}

# 7.14 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_14 := false

r_7_14 if {
	every vm in input.esxi.vms { not _vkey_bad(vm, "(?i)^parallel[0-9]+\\.present$") }
}

default e_7_14 := false

e_7_14 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.14: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.14")
	not e_7_14
}

_v_virtual_machines contains "7.14: VMs must have no parallel port" if {
	_applies("7.14")
	e_7_14
	not r_7_14
}

# 7.15 (Automated, Level 2 (L2) - High Security_S)
default r_7_15 := false

r_7_15 if {
	every vm in input.esxi.vms { not "cdrom" in {lower(t) | some t in vm.device_types} }
}

default e_7_15 := false

e_7_15 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_array(vm.device_types) }
}

_v_virtual_machines contains "7.15: evidence missing — esxi.vms[].device_types not collected" if {
	_applies("7.15")
	not e_7_15
}

_v_virtual_machines contains "7.15: VMs must have no CD/DVD drive" if {
	_applies("7.15")
	e_7_15
	not r_7_15
}

# 7.16 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_16 := false

r_7_16 if {
	every vm in input.esxi.vms { not _vkey_bad(vm, "(?i)^floppy[0-9]+\\.present$") }
}

default e_7_16 := false

e_7_16 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.16: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.16")
	not e_7_16
}

_v_virtual_machines contains "7.16: VMs must have no floppy drive" if {
	_applies("7.16")
	e_7_16
	not r_7_16
}

# 7.17 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_17 := false

r_7_17 if {
	every vm in input.esxi.vms { _vtrue_or_absent(vm, "isolation.tools.dnd.disable") }
}

default e_7_17 := false

e_7_17 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.17: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.17")
	not e_7_17
}

_v_virtual_machines contains "7.17: isolation.tools.dnd.disable must be TRUE or absent" if {
	_applies("7.17")
	e_7_17
	not r_7_17
}

# 7.18 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_18 := false

r_7_18 if {
	every vm in input.esxi.vms { _vtrue_or_absent(vm, "isolation.tools.copy.disable") }
}

default e_7_18 := false

e_7_18 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.18: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.18")
	not e_7_18
}

_v_virtual_machines contains "7.18: isolation.tools.copy.disable must be TRUE or absent" if {
	_applies("7.18")
	e_7_18
	not r_7_18
}

# 7.19 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_19 := false

r_7_19 if {
	every vm in input.esxi.vms { _vtrue_or_absent(vm, "isolation.tools.paste.disable") }
}

default e_7_19 := false

e_7_19 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.19: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.19")
	not e_7_19
}

_v_virtual_machines contains "7.19: isolation.tools.paste.disable must be TRUE or absent" if {
	_applies("7.19")
	e_7_19
	not r_7_19
}

# 7.20 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_20 := false

r_7_20 if {
	every vm in input.esxi.vms { not _vkey_any(vm, "(?i)^ethernet[0-9]+\\.filter[0-9]+\\.name$") }
}

default e_7_20 := false

e_7_20 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.20: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.20")
	not e_7_20
}

_v_virtual_machines contains "7.20: VMs must not be bound to a dvfilter" if {
	_applies("7.20")
	e_7_20
	not r_7_20
}

# 7.21 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_21 := false

r_7_21 if {
	every vm in input.esxi.vms { _vtrue(vm, "isolation.tools.diskShrink.disable") }
}

default e_7_21 := false

e_7_21 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.21: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.21")
	not e_7_21
}

_v_virtual_machines contains "7.21: isolation.tools.diskShrink.disable must be TRUE" if {
	_applies("7.21")
	e_7_21
	not r_7_21
}

# 7.22 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_22 := false

r_7_22 if {
	every vm in input.esxi.vms { _vtrue(vm, "isolation.tools.diskWiper.disable") }
}

default e_7_22 := false

e_7_22 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.22: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.22")
	not e_7_22
}

_v_virtual_machines contains "7.22: isolation.tools.diskWiper.disable must be TRUE" if {
	_applies("7.22")
	e_7_22
	not r_7_22
}

# 7.23 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_23 := false

r_7_23 if {
	salts := [s | some vm in input.esxi.vms; s := vm.advanced_settings["sched.mem.pshare.salt"]]
	count(salts) == count({s | some s in salts})
}

default e_7_23 := false

e_7_23 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.23: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.23")
	not e_7_23
}

_v_virtual_machines contains "7.23: two VMs must not share a sched.mem.pshare.salt value" if {
	_applies("7.23")
	e_7_23
	not r_7_23
}

# 7.24 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_24 := false

r_7_24 if {
	every vm in input.esxi.vms { _vfalse(vm, "tools.guestlib.enableHostInfo") }
}

default e_7_24 := false

e_7_24 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.24: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.24")
	not e_7_24
}

_v_virtual_machines contains "7.24: tools.guestlib.enableHostInfo must be FALSE" if {
	_applies("7.24")
	e_7_24
	not r_7_24
}

# 7.25 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_25 := false

r_7_25 if {
	every vm in input.esxi.vms { _vtrue_or_absent(vm, "logging") }
}

default e_7_25 := false

e_7_25 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.25: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.25")
	not e_7_25
}

_v_virtual_machines contains "7.25: VM logging must be TRUE or left at its default" if {
	_applies("7.25")
	e_7_25
	not r_7_25
}

# 7.26 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_26 := false

r_7_26 if {
	every vm in input.esxi.vms { _num(vm.advanced_settings["log.keepOld"]) == 10 }
}

default e_7_26 := false

e_7_26 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.26: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.26")
	not e_7_26
}

_v_virtual_machines contains "7.26: log.keepOld must be 10" if {
	_applies("7.26")
	e_7_26
	not r_7_26
}

# 7.27 (Automated, Level 1 (L1) - Corporate_Enter)
default r_7_27 := false

r_7_27 if {
	every vm in input.esxi.vms { _num(vm.advanced_settings["log.rotateSize"]) == 1024000 }
}

default e_7_27 := false

e_7_27 if {
	_vm_adv_ev
}

_v_virtual_machines contains "7.27: evidence missing — esxi.vms[].advanced_settings not collected" if {
	_applies("7.27")
	not e_7_27
}

_v_virtual_machines contains "7.27: log.rotateSize must be 1024000" if {
	_applies("7.27")
	e_7_27
	not r_7_27
}

# 7.28 (Manual, Level 1 (L1) - Corporate_Enter)
default r_7_28 := false

r_7_28 if {
	input.esxi.attest.tools_setinfo_size_limit_approved == true
}

_v_virtual_machines contains "7.28: tools.setInfo.sizeLimit must be a finite approved value (manual review not attested)" if {
	_applies("7.28")
	not r_7_28
}

# 7.29 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_29 := false

r_7_29 if {
	every vm in input.esxi.vms { _hw(vm) >= 19 }
}

default e_7_29 := false

e_7_29 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { is_number(_hw(vm)) }
}

_v_virtual_machines contains "7.29: evidence missing — esxi.vms[].config.version not collected" if {
	_applies("7.29")
	not e_7_29
}

_v_virtual_machines contains "7.29: VM hardware version must be 19 or newer" if {
	_applies("7.29")
	e_7_29
	not r_7_29
}

# 8.1 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_1 := false

r_8_1 if {
	input.esxi.attest.tools_version_supported == true
}

_v_vmware_tools contains "8.1: VMware Tools must be a release still in general support (manual review not attested)" if {
	_applies("8.1")
	not r_8_1
}

# 8.2 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_2 := false

r_8_2 if {
	input.esxi.attest.tools_updates_current == true
}

_v_vmware_tools contains "8.2: VMware Tools must carry all security updates (manual review not attested)" if {
	_applies("8.2")
	not r_8_2
}

# 8.3 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_3 := false

r_8_3 if {
	input.esxi.attest.tools_upgrade_policy_approved == true
}

_v_vmware_tools contains "8.3: the Tools upgrade policy must match the approved change model (manual review not attested)" if {
	_applies("8.3")
	not r_8_3
}

# 8.4 (Manual, Level 2 (L2) - High Security_S)
default r_8_4 := false

r_8_4 if {
	input.esxi.attest.tools_recustomize_blocked == true
}

_v_vmware_tools contains "8.4: deployed VMs must not be re-customizable through Tools (manual review not attested)" if {
	_applies("8.4")
	not r_8_4
}

# 8.5 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_5 := false

r_8_5 if {
	input.esxi.attest.tools_auto_add_features_limited == true
}

_v_vmware_tools contains "8.5: Tools must not add features automatically (manual review not attested)" if {
	_applies("8.5")
	not r_8_5
}

# 8.6 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_6 := false

r_8_6 if {
	input.esxi.attest.tools_auto_remove_features_limited == true
}

_v_vmware_tools contains "8.6: Tools must not remove features automatically (manual review not attested)" if {
	_applies("8.6")
	not r_8_6
}

# 8.7 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_7 := false

r_8_7 if {
	every vm in input.esxi.vms { _isfalse(vm.tools_config["globalconf.enabled"]) }
}

default e_8_7 := false

e_8_7 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["globalconf.enabled"] != null }
}

_v_vmware_tools contains "8.7: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.7")
	not e_8_7
}

_v_vmware_tools contains "8.7: Tools globalconf must be off" if {
	_applies("8.7")
	e_8_7
	not r_8_7
}

# 8.8 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_8 := false

r_8_8 if {
	every vm in input.esxi.vms { _num(vm.tools_config["containerinfo.poll-interval"]) == 0 }
}

default e_8_8 := false

e_8_8 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["containerinfo.poll-interval"] != null }
}

_v_vmware_tools contains "8.8: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.8")
	not e_8_8
}

_v_vmware_tools contains "8.8: Tools containerinfo poll-interval must be 0" if {
	_applies("8.8")
	e_8_8
	not r_8_8
}

# 8.9 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_9 := false

r_8_9 if {
	every vm in input.esxi.vms { _istrue(vm.tools_config["appinfo.disabled"]) }
}

default e_8_9 := false

e_8_9 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["appinfo.disabled"] != null }
}

_v_vmware_tools contains "8.9: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.9")
	not e_8_9
}

_v_vmware_tools contains "8.9: Tools appinfo must be disabled" if {
	_applies("8.9")
	e_8_9
	not r_8_9
}

# 8.10 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_10 := false

r_8_10 if {
	every vm in input.esxi.vms { _str(vm.tools_config["gueststoreupgrade.policy"]) == "off" }
}

default e_8_10 := false

e_8_10 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["gueststoreupgrade.policy"] != null }
}

_v_vmware_tools contains "8.10: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.10")
	not e_8_10
}

_v_vmware_tools contains "8.10: Tools gueststoreupgrade policy must be off" if {
	_applies("8.10")
	e_8_10
	not r_8_10
}

# 8.11 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_11 := false

r_8_11 if {
	every vm in input.esxi.vms { _istrue(vm.tools_config["servicediscovery.disabled"]) }
}

default e_8_11 := false

e_8_11 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["servicediscovery.disabled"] != null }
}

_v_vmware_tools contains "8.11: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.11")
	not e_8_11
}

_v_vmware_tools contains "8.11: Tools servicediscovery must be disabled" if {
	_applies("8.11")
	e_8_11
	not r_8_11
}

# 8.12 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_12 := false

r_8_12 if {
	input.esxi.attest.tools_msi_transforms_limited == true
}

_v_vmware_tools contains "8.12: Tools must not allow MSI transforms on upgrade (manual review not attested)" if {
	_applies("8.12")
	not r_8_12
}

# 8.13 (Manual, Level 1 (L1) - Corporate_Enter) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_13 := false

r_8_13 if {
	every vm in input.esxi.vms { _istrue(vm.tools_config["logging.log"]) }
}

default e_8_13 := false

e_8_13 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["logging.log"] != null }
}

_v_vmware_tools contains "8.13: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.13")
	not e_8_13
}

_v_vmware_tools contains "8.13: Tools logging must be on" if {
	_applies("8.13")
	e_8_13
	not r_8_13
}

# 8.14 (Manual, Level 1 (L1) - Corporate_Enter)
default r_8_14 := false

r_8_14 if {
	input.esxi.attest.tools_logs_to_system_logger == true
}

_v_vmware_tools contains "8.14: Tools logs must go to the guest system logger (manual review not attested)" if {
	_applies("8.14")
	not r_8_14
}

# 8.15 (Manual, Level 2 (L2) - High Security_S) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_8_15 := false

r_8_15 if {
	every vm in input.esxi.vms { _istrue(vm.tools_config["guestoperations.disabled"]) }
}

default e_8_15 := false

e_8_15 if {
	is_array(input.esxi.vms)
	every vm in input.esxi.vms { vm.tools_config["guestoperations.disabled"] != null }
}

_v_vmware_tools contains "8.15: evidence missing — esxi.vms[].tools_config not collected" if {
	_applies("8.15")
	not e_8_15
}

_v_vmware_tools contains "8.15: Tools guestoperations must be disabled" if {
	_applies("8.15")
	e_8_15
	not r_8_15
}

# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.
recommendations := {
	"1.1": {
		"title": "firmware on the system and its devices must be inventoried against a supported baseline",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.2": {
		"title": "UEFI Secure Boot must be on in the host firmware",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "hardware",
	},
	"1.3": {
		"title": "Intel TXT must be on where the CPU supports it",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.4": {
		"title": "a TPM 2.0 must be present and configured",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.5": {
		"title": "the baseboard management controller must be hardened",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.6": {
		"title": "the management controller clock must be synchronized",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.7": {
		"title": "the management controller must forward its events to a remote collector",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.8": {
		"title": "management controller logins must be individual, strong and locked down",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.9": {
		"title": "AMD SEV-ES must be on where the CPU supports it",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.10": {
		"title": "Intel SGX must be on where the CPU supports it",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.11": {
		"title": "unused external hardware ports must be secured",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "hardware",
	},
	"1.12": {
		"title": "Net.BMCNetworkEnable must be 0 so the controller has no internal network path",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "hardware",
	},
	"2.1": {
		"title": "the ESXi release must still be in general support",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "software_and_boot",
	},
	"2.2": {
		"title": "all available patches must be installed",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "software_and_boot",
	},
	"2.3": {
		"title": "the host must refuse to run with Secure Boot enforcement off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.4": {
		"title": "the image profile acceptance level must be PartnerSupported or stricter",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.5": {
		"title": "the host must run only binaries from installed signed VIBs",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.6": {
		"title": "NTP must run on the host with at least one server configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.7": {
		"title": "a time service must be enabled, configured and running",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.8": {
		"title": "configuration encryption must be anchored in the TPM",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.9": {
		"title": "UserVars.SuppressHyperthreadWarning must be 0",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.10": {
		"title": "Mem.ShareForceSalting must be 2 to stop inter-VM page sharing",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.11": {
		"title": "the disableHwrng kernel option must not be TRUE",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"2.12": {
		"title": "Mem.MemEagerZero must be 1 so freed memory is zeroed",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "software_and_boot",
	},
	"3.1": {
		"title": "the SSH service must be stopped and set to start manually",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.2": {
		"title": "the ESXi shell service must be stopped and set to start manually",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.3": {
		"title": "Config.HostAgent.plugins.solo.enableMob must be false",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.4": {
		"title": "the SLP service must not be running",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.5": {
		"title": "CIM/WBEM must be off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.6": {
		"title": "SNMP must be off unless needed",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.7": {
		"title": "UserVars.DcuiTimeOut must be 1 to 600 seconds",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.8": {
		"title": "UserVars.ESXiShellInteractiveTimeOut must be 1 to 300 seconds",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.9": {
		"title": "UserVars.ESXiShellTimeOut must be 1 to 3600 seconds",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.10": {
		"title": "UserVars.SuppressShellWarning must be 0",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.11": {
		"title": "Security.PasswordQualityControl must demand 15 or more characters from four classes",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.12": {
		"title": "Security.AccountLockFailures must be 5",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.13": {
		"title": "Security.AccountUnlockTime must be 900",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.14": {
		"title": "Security.PasswordHistory must be 5",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.15": {
		"title": "Security.PasswordMaxDays must match the approved rotation policy",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"3.16": {
		"title": "the API session timeout must be a finite approved value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.17": {
		"title": "UserVars.HostClientSessionTimeout must be a finite positive value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.18": {
		"title": "DCUI.Access must list only the approved override users",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"3.19": {
		"title": "the lockdown Exception Users list must be reviewed and accurate",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"3.20": {
		"title": "lockdown mode must be normal or strict",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.21": {
		"title": "lockdown mode must be strict",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.22": {
		"title": "the dcui account must have a non-interactive shell",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.23": {
		"title": "the vpxuser account must have a non-interactive shell",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "access_and_shell",
	},
	"3.24": {
		"title": "the DCUI and Host Client welcome banner must carry the approved text",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"3.25": {
		"title": "the SSH banner file must carry the approved text",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"3.26": {
		"title": "legacy TLS versions must be off and the highest supported version on",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "access_and_shell",
	},
	"4.1": {
		"title": "system logs must be written to a persistent location",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "logging",
	},
	"4.2": {
		"title": "Syslog.global.logHost must name a remote collector",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.3": {
		"title": "logging detail and local log files must be reviewed as sufficient",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "logging",
	},
	"4.4": {
		"title": "the syslog log level must be info",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.5": {
		"title": "syslog log filtering must be off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.6": {
		"title": "audit record storage must be active",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.7": {
		"title": "audit records must be stored in a persistent location",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "logging",
	},
	"4.8": {
		"title": "local audit storage must hold at least seven days",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "logging",
	},
	"4.9": {
		"title": "audit records must be sent to a remote collector",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.10": {
		"title": "remote syslog over TLS must check the endpoint certificate",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"4.11": {
		"title": "remote syslog over TLS must use strict x509 checks",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "logging",
	},
	"5.1": {
		"title": "an enabled firewall ruleset must not allow all IP addresses",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.2": {
		"title": "the host firewall must be on and drop by default",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.3": {
		"title": "Net.DVFilterBindIpAddress must be empty",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.4": {
		"title": "Net.BlockGuestBPDU must be 1",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.5": {
		"title": "VMkernel interfaces for virtual hardware management must be absent",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "host_network",
	},
	"5.6": {
		"title": "standard switches and port groups must reject forged transmits",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.7": {
		"title": "standard switches and port groups must reject MAC address changes",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.8": {
		"title": "standard switches and port groups must reject promiscuous mode",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.9": {
		"title": "a standard port group must not use the native VLAN",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.10": {
		"title": "a standard port group must not use VLAN 4095",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_network",
	},
	"5.11": {
		"title": "management traffic must stay on dedicated VMkernel interfaces and VLANs",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_network",
	},
	"6.1.1": {
		"title": "CIM access, if used, must go through a least-privilege account",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.2.1": {
		"title": "storage traffic must be isolated from other networks",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.2.2": {
		"title": "datastore names must be unique",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.3.1": {
		"title": "iSCSI adapters must use mutual CHAP",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.3.2": {
		"title": "iSCSI CHAP secrets must be unique per adapter",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.4.1": {
		"title": "SNMP, if used, must restrict who can poll",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.5.1": {
		"title": "sshd ciphers must be limited to approved FIPS-validated ones",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.5.2": {
		"title": "sshd must run on the platform FIPS-validated crypto modules",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "host_services",
	},
	"6.5.3": {
		"title": "sshd GatewayPorts must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.4": {
		"title": "sshd HostbasedAuthentication must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.5": {
		"title": "sshd ClientAliveCountMax must be a positive value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.6": {
		"title": "sshd ClientAliveInterval must be a positive value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.7": {
		"title": "sshd must show a banner before login",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.8": {
		"title": "sshd IgnoreRhosts must be yes",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.9": {
		"title": "sshd AllowStreamLocalForwarding must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.10": {
		"title": "sshd AllowTcpForwarding must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.11": {
		"title": "sshd PermitTunnel must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"6.5.12": {
		"title": "sshd PermitUserEnvironment must be no",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "host_services",
	},
	"7.1": {
		"title": "every VM must boot with EFI Secure Boot",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.2": {
		"title": "every VM must require encrypted vMotion",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.3": {
		"title": "every VM must require encrypted Fault Tolerance traffic",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.4": {
		"title": "mks.enable3d must not be on for VMs",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.5": {
		"title": "tools.guest.desktop.autolock must be TRUE",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.6": {
		"title": "RemoteDisplay.maxConnections must be 1",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.7": {
		"title": "a VM must not have a pciPassthru device present",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.8": {
		"title": "isolation.device.edit.disable must be TRUE",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.9": {
		"title": "isolation.device.connectable.disable must be TRUE",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.10": {
		"title": "VMs must have no sound device",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.11": {
		"title": "VMs must have no AHCI controller that backs nothing needed",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "virtual_machines",
	},
	"7.12": {
		"title": "VMs must have no USB or XHCI controller",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.13": {
		"title": "VMs must have no serial port",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.14": {
		"title": "VMs must have no parallel port",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.15": {
		"title": "VMs must have no CD/DVD drive",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.16": {
		"title": "VMs must have no floppy drive",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.17": {
		"title": "isolation.tools.dnd.disable must be TRUE or absent",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.18": {
		"title": "isolation.tools.copy.disable must be TRUE or absent",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.19": {
		"title": "isolation.tools.paste.disable must be TRUE or absent",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.20": {
		"title": "VMs must not be bound to a dvfilter",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.21": {
		"title": "isolation.tools.diskShrink.disable must be TRUE",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.22": {
		"title": "isolation.tools.diskWiper.disable must be TRUE",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.23": {
		"title": "two VMs must not share a sched.mem.pshare.salt value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.24": {
		"title": "tools.guestlib.enableHostInfo must be FALSE",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.25": {
		"title": "VM logging must be TRUE or left at its default",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.26": {
		"title": "log.keepOld must be 10",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.27": {
		"title": "log.rotateSize must be 1024000",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"7.28": {
		"title": "tools.setInfo.sizeLimit must be a finite approved value",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "virtual_machines",
	},
	"7.29": {
		"title": "VM hardware version must be 19 or newer",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "virtual_machines",
	},
	"8.1": {
		"title": "VMware Tools must be a release still in general support",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.2": {
		"title": "VMware Tools must carry all security updates",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.3": {
		"title": "the Tools upgrade policy must match the approved change model",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.4": {
		"title": "deployed VMs must not be re-customizable through Tools",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.5": {
		"title": "Tools must not add features automatically",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.6": {
		"title": "Tools must not remove features automatically",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.7": {
		"title": "Tools globalconf must be off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.8": {
		"title": "Tools containerinfo poll-interval must be 0",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.9": {
		"title": "Tools appinfo must be disabled",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.10": {
		"title": "Tools gueststoreupgrade policy must be off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.11": {
		"title": "Tools servicediscovery must be disabled",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.12": {
		"title": "Tools must not allow MSI transforms on upgrade",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.13": {
		"title": "Tools logging must be on",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "configuration",
		"section": "vmware_tools",
	},
	"8.14": {
		"title": "Tools logs must go to the guest system logger",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1 (L1) - Corporate_Enter"],
		"check": "attestation",
		"section": "vmware_tools",
	},
	"8.15": {
		"title": "Tools guestoperations must be disabled",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2 (L2) - High Security_S"],
		"check": "configuration",
		"section": "vmware_tools",
	},
}

# recommendations in the selected profile
in_scope := {id | some id, _ in recommendations; _applies(id)}

_failed_ids := {id | some v in violations; id := split(v, ":")[0]; id in in_scope}

# Compliance summary for reporting (counts are recommendations; a recommendation fails once however many messages it emits)
compliance_summary := {
	"total_controls": count(in_scope),
	"passing_controls": count(in_scope) - count(_failed_ids),
	"failing_controls": count(_failed_ids),
	"compliance_percentage": ((count(in_scope) - count(_failed_ids)) * 100) / count(in_scope),
	"sections": {
		"hardware": {
			"total": count({id | some id, r in recommendations; r.section == "hardware"; _applies(id)}),
			"violations": count(hardware_violations),
		},
		"software_and_boot": {
			"total": count({id | some id, r in recommendations; r.section == "software_and_boot"; _applies(id)}),
			"violations": count(software_and_boot_violations),
		},
		"access_and_shell": {
			"total": count({id | some id, r in recommendations; r.section == "access_and_shell"; _applies(id)}),
			"violations": count(access_and_shell_violations),
		},
		"logging": {
			"total": count({id | some id, r in recommendations; r.section == "logging"; _applies(id)}),
			"violations": count(logging_violations),
		},
		"host_network": {
			"total": count({id | some id, r in recommendations; r.section == "host_network"; _applies(id)}),
			"violations": count(host_network_violations),
		},
		"host_services": {
			"total": count({id | some id, r in recommendations; r.section == "host_services"; _applies(id)}),
			"violations": count(host_services_violations),
		},
		"virtual_machines": {
			"total": count({id | some id, r in recommendations; r.section == "virtual_machines"; _applies(id)}),
			"violations": count(virtual_machines_violations),
		},
		"vmware_tools": {
			"total": count({id | some id, r in recommendations; r.section == "vmware_tools"; _applies(id)}),
			"violations": count(vmware_tools_violations),
		},
	},
}

compliance_report := {
	"benchmark": "CIS VMware ESXi 8.0 Benchmark v1.4.0",
	"level": _level,
	"total_controls": count(in_scope),
	"standard_total": 134,
	"standard_total_source": "CIS VMware ESXi 8.0 Benchmark v1.4.0, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
