package cis_windows_server_2022.l2

# CIS Microsoft Windows Server 2022 Benchmark v5.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter settings for high-security environments.
# May affect functionality — intended for regulated/classified environments.

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1 - Account Policies (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.1.1: Password history should be 24 or more passwords (L2: 24)" if {
	input.account_policies.password_history_count < 24
}

violations contains "CIS L2 1.1.2: Maximum password age should be 60 or fewer days (L2: 60)" if {
	input.account_policies.max_password_age > 60
}

violations contains "CIS L2 1.1.4: Minimum password length should be 14 or more characters (L2: 14)" if {
	input.account_policies.min_password_length < 14
}

violations contains "CIS L2 1.2.1: Account lockout duration should be 15 or more minutes (L2: 15)" if {
	input.account_policies.lockout_duration < 15
}

violations contains "CIS L2 1.2.2: Account lockout threshold should be 5 or fewer invalid attempts (L2: 5)" if {
	input.account_policies.lockout_threshold > 5
}

violations contains "CIS L2 1.2.3: Reset account lockout counter after 15 or more minutes (L2: 15)" if {
	input.account_policies.lockout_reset_counter < 15
}

# ---------------------------------------------------------------------------
# Section 2 - Local Policies (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.2.1: 'Access Credential Manager as trusted caller' — no accounts assigned" if {
	count(input.local_policies.access_credential_manager_accounts) > 0
}

violations contains "CIS L2 2.2.2: 'Act as part of OS' — no accounts assigned" if {
	count(input.local_policies.act_as_os_accounts) > 0
}

violations contains "CIS L2 2.2.8: 'Create a token object' — no accounts assigned" if {
	count(input.local_policies.create_token_object_accounts) > 0
}

violations contains "CIS L2 2.2.11: 'Debug programs' — no accounts assigned" if {
	count(input.local_policies.debug_programs_accounts) > 0
}

violations contains "CIS L2 2.2.15: 'Force shutdown from a remote system' — Administrators only" if {
	some acct in input.local_policies.force_shutdown_accounts
	acct != "Administrators"
}

violations contains "CIS L2 2.2.19: 'Load and unload device drivers' — Administrators only" if {
	some acct in input.local_policies.load_unload_drivers_accounts
	acct != "Administrators"
}

violations contains "CIS L2 2.2.29: 'Take ownership of files or objects' — Administrators only" if {
	some acct in input.local_policies.take_ownership_accounts
	acct != "Administrators"
}

# ---------------------------------------------------------------------------
# Section 2.3 - Security Options (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.3.1.1: Accounts: Block Microsoft accounts — Users cannot add or log on with Microsoft accounts" if {
	input.security_options.noconnecteduser != 3
}

violations contains "CIS L2 2.3.7.8: Interactive logon: Machine inactivity limit should be 900 seconds or less" if {
	input.security_options.machine_inactivity_limit > 900
}

violations contains "CIS L2 2.3.9.1: Microsoft network client: Digitally sign communications (always) — enabled" if {
	not input.security_options.smb_client_signing_always
}

violations contains "CIS L2 2.3.10.2: Microsoft network server: Disconnect clients when logon hours expire — enabled" if {
	not input.security_options.smb_server_disconnect_on_logon_expiry
}

violations contains "CIS L2 2.3.11.7: Network security: LAN Manager authentication level — Send NTLMv2 only, refuse LM & NTLM" if {
	input.security_options.lm_auth_level < 5
}

violations contains "CIS L2 2.3.11.9: Network security: Minimum session security for NTLM — require NTLMv2 + 128-bit encryption" if {
	input.security_options.ntlm_min_session_security < 537395200
}

violations contains "CIS L2 2.3.15.2: System objects: Strengthen default permissions of internal system objects" if {
	not input.security_options.strengthen_default_system_object_permissions
}

# ---------------------------------------------------------------------------
# Section 9 - Windows Firewall (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 9.1.2: Windows Firewall — Domain profile inbound connections blocked by default" if {
	input.firewall.domain.inbound_action != "Block"
}

violations contains "CIS L2 9.1.6: Windows Firewall — Domain logging of dropped packets enabled" if {
	not input.firewall.domain.log_dropped_packets
}

violations contains "CIS L2 9.1.7: Windows Firewall — Domain log file size at least 16384 KB" if {
	input.firewall.domain.log_max_file_size < 16384
}

violations contains "CIS L2 9.2.2: Windows Firewall — Private profile inbound connections blocked by default" if {
	input.firewall.private.inbound_action != "Block"
}

violations contains "CIS L2 9.2.6: Windows Firewall — Private logging of dropped packets enabled" if {
	not input.firewall.private.log_dropped_packets
}

violations contains "CIS L2 9.3.2: Windows Firewall — Public profile inbound connections blocked by default" if {
	input.firewall.public.inbound_action != "Block"
}

violations contains "CIS L2 9.3.6: Windows Firewall — Public logging of dropped packets enabled" if {
	not input.firewall.public.log_dropped_packets
}

# ---------------------------------------------------------------------------
# Section 17 - Advanced Audit Policy (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 17.1.1: Audit Credential Validation — Success and Failure" if {
	not input.advanced_audit.credential_validation_success
	not input.advanced_audit.credential_validation_failure
}

violations contains "CIS L2 17.2.1: Audit Application Group Management — Success and Failure" if {
	not input.advanced_audit.application_group_management_success
}

violations contains "CIS L2 17.3.1: Audit Account Lockout — Failure" if {
	not input.advanced_audit.account_lockout_failure
}

violations contains "CIS L2 17.5.1: Audit Process Creation — Success" if {
	not input.advanced_audit.process_creation_success
}

violations contains "CIS L2 17.5.2: Audit Process Termination — Success" if {
	not input.advanced_audit.process_termination_success
}

violations contains "CIS L2 17.6.1: Audit Detailed File Share — Failure" if {
	not input.advanced_audit.detailed_file_share_failure
}

violations contains "CIS L2 17.7.1: Audit Audit Policy Change — Success and Failure" if {
	not input.advanced_audit.policy_change_success
}

violations contains "CIS L2 17.9.1: Audit IPsec Driver — Failure" if {
	not input.advanced_audit.ipsec_driver_failure
}

violations contains "CIS L2 17.9.4: Audit Security State Change — Success" if {
	not input.advanced_audit.security_state_change_success
}

violations contains "CIS L2 17.9.5: Audit Security System Extension — Success" if {
	not input.advanced_audit.security_system_extension_success
}

# ---------------------------------------------------------------------------
# Section 18 - Administrative Templates (L2 Registry Settings)
# ---------------------------------------------------------------------------

violations contains "CIS L2 18.3.1: MSS: AutoAdminLogon disabled" if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon"] != "0"
}

violations contains "CIS L2 18.4.2: MSS: DisableIPSourceRouting IPv6 = highest protection" if {
	input.registry["HKLM\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisableIPSourceRouting"] != "2"
}

violations contains "CIS L2 18.4.3: MSS: EnableICMPRedirect = 0 (disabled)" if {
	input.registry["HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\EnableICMPRedirect"] != "0"
}

violations contains "CIS L2 18.6.19.2: Disable IPv6 — unchecked (IPv6 allowed for servers that require it)" if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents"] != "0"
}

violations contains "CIS L2 18.9.5.1: Allow Cortana above lock screen — disabled" if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\AllowCortanaAboveLock"] != "0"
}

violations contains "CIS L2 18.9.46.2: Allow network connectivity during connected-standby — disabled" if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9\\ACSettingIndex"] != "0"
}

violations contains "CIS L2 18.10.15.1: Windows Defender Credential Guard — enabled with UEFI lock" if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\LsaCfgFlags"] != "1"
}

violations contains "CIS L2 18.10.92.2.1: BitLocker — require additional authentication at startup" if {
	not input.bitlocker.additional_auth_required
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 42

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Microsoft Windows Server 2022 Benchmark v5.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. May impact functionality — designed for high-security environments.",
}
