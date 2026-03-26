package cis_windows_server_2022.security_options

# CIS Windows Server 2022 Benchmark v3.0.0 - Section 2.3: Security Options

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in account_violations], [v | some v in network_violations]),
	array.concat([v | some v in interactive_logon_violations], [v | some v in uac_violations]),
)

# =============================================================================
# Accounts
# =============================================================================

# CIS 2.3.1.1: Accounts: Administrator account status = Disabled
account_violations contains msg if {
	input.security_options.administrator_account_enabled
	msg := "CIS 2.3.1.1: Built-in Administrator account should be disabled (or renamed)"
}

# CIS 2.3.1.2: Accounts: Block Microsoft accounts = Users can't add or log on with Microsoft accounts
account_violations contains msg if {
	input.security_options.microsoft_accounts_allowed
	msg := "CIS 2.3.1.2: Microsoft accounts should be blocked ('Users can't add or log on with Microsoft accounts')"
}

# CIS 2.3.1.3: Accounts: Guest account status = Disabled
account_violations contains msg if {
	input.security_options.guest_account_enabled
	msg := "CIS 2.3.1.3: Guest account should be disabled"
}

# CIS 2.3.1.4: Accounts: Limit local account use of blank passwords = Enabled
account_violations contains msg if {
	not input.security_options.limit_blank_password_use
	msg := "CIS 2.3.1.4: 'Limit local account use of blank passwords to console logon only' is not enabled"
}

# CIS 2.3.1.5: Rename Administrator account
account_violations contains msg if {
	lower(input.security_options.administrator_account_name) == "administrator"
	msg := "CIS 2.3.1.5: Built-in Administrator account should be renamed from default name"
}

# CIS 2.3.1.6: Rename Guest account
account_violations contains msg if {
	lower(input.security_options.guest_account_name) == "guest"
	msg := "CIS 2.3.1.6: Built-in Guest account should be renamed from default name"
}

# =============================================================================
# Interactive Logon
# =============================================================================

# CIS 2.3.7.1: Interactive logon: Do not require CTRL+ALT+DEL = Disabled
interactive_logon_violations contains msg if {
	input.security_options.no_ctrl_alt_del_required
	msg := "CIS 2.3.7.1: 'Do not require CTRL+ALT+DEL' should be disabled (CTRL+ALT+DEL should be required)"
}

# CIS 2.3.7.2: Interactive logon: Don't display last signed-in = Enabled
interactive_logon_violations contains msg if {
	not input.security_options.dont_display_last_username
	msg := "CIS 2.3.7.2: 'Don't display last signed-in' is not enabled"
}

# CIS 2.3.7.4: Interactive logon: Machine inactivity limit <= 900 seconds
interactive_logon_violations contains msg if {
	input.security_options.machine_inactivity_limit > 900
	msg := sprintf("CIS 2.3.7.4: Machine inactivity limit is %d seconds, should be 900 or less", [input.security_options.machine_inactivity_limit])
}

interactive_logon_violations contains msg if {
	input.security_options.machine_inactivity_limit == 0
	msg := "CIS 2.3.7.4: Machine inactivity limit is 0 (disabled), should be 900 or less"
}

# CIS 2.3.7.7: Interactive logon: Prompt user to change password before expiration >= 5 days
interactive_logon_violations contains msg if {
	input.security_options.password_expiry_warning_days < 5
	msg := sprintf("CIS 2.3.7.7: Password expiry warning is %d days, should be 5 or more", [input.security_options.password_expiry_warning_days])
}

# =============================================================================
# Network Security
# =============================================================================

# CIS 2.3.11.1: Network security: Allow Local System to use computer identity for NTLM = Enabled
network_violations contains msg if {
	not input.security_options.allow_local_system_null_session
	msg := "CIS 2.3.11.1: 'Allow Local System to use computer identity for NTLM' is not enabled"
}

# CIS 2.3.11.5: Network security: LAN Manager authentication level = NTLMv2 only
network_violations contains msg if {
	input.security_options.lan_manager_auth_level < 5
	msg := sprintf("CIS 2.3.11.5: LAN Manager authentication level is %d, should be 5 (NTLMv2 only, refuse LM and NTLM)", [input.security_options.lan_manager_auth_level])
}

# CIS 2.3.11.6: Network security: LDAP client signing requirements = Negotiate or Require
network_violations contains msg if {
	input.security_options.ldap_client_signing < 1
	msg := "CIS 2.3.11.6: LDAP client signing should be set to Negotiate signing or Require signing"
}

# CIS 2.3.11.7: Network security: Minimum session security for NTLM SSP = Require NTLMv2 + 128-bit
network_violations contains msg if {
	input.security_options.ntlm_min_session_security_client < 537395200
	msg := "CIS 2.3.11.7: NTLM SSP minimum session security for NTLM-based clients should require NTLMv2 and 128-bit encryption"
}

network_violations contains msg if {
	input.security_options.ntlm_min_session_security_server < 537395200
	msg := "CIS 2.3.11.8: NTLM SSP minimum session security for NTLM-based servers should require NTLMv2 and 128-bit encryption"
}

# CIS 2.3.15.1: System objects: Require case insensitivity for non-Windows subsystems = Enabled
network_violations contains msg if {
	not input.security_options.case_insensitive_subsystems
	msg := "CIS 2.3.15.1: 'Require case insensitivity for non-Windows subsystems' is not enabled"
}

# =============================================================================
# UAC Settings
# =============================================================================

# CIS 2.3.17.1: UAC: Admin Approval Mode for Built-in Administrator = Enabled
uac_violations contains msg if {
	not input.security_options.uac_admin_approval_mode
	msg := "CIS 2.3.17.1: UAC Admin Approval Mode for Built-in Administrator is not enabled"
}

# CIS 2.3.17.2: UAC: Behavior for elevation prompt for admins = Prompt for consent on secure desktop
uac_violations contains msg if {
	input.security_options.uac_admin_elevation_behavior < 2
	msg := sprintf("CIS 2.3.17.2: UAC admin elevation behavior is %d, should be 2 (prompt for consent on secure desktop)", [input.security_options.uac_admin_elevation_behavior])
}

# CIS 2.3.17.3: UAC: Behavior for elevation prompt for standard users = Automatically deny elevation
uac_violations contains msg if {
	input.security_options.uac_standard_elevation_behavior != 0
	msg := "CIS 2.3.17.3: UAC standard user elevation should be set to automatically deny"
}

# CIS 2.3.17.4: UAC: Detect application installations and prompt for elevation = Enabled
uac_violations contains msg if {
	not input.security_options.uac_detect_installations
	msg := "CIS 2.3.17.4: UAC 'Detect application installations and prompt for elevation' is not enabled"
}

# CIS 2.3.17.8: UAC: Run all administrators in Admin Approval Mode = Enabled
uac_violations contains msg if {
	not input.security_options.uac_run_admins_in_approval_mode
	msg := "CIS 2.3.17.8: UAC 'Run all administrators in Admin Approval Mode' is not enabled"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"account_violations": count(account_violations),
	"network_violations": count(network_violations),
	"interactive_logon_violations": count(interactive_logon_violations),
	"uac_violations": count(uac_violations),
	"controls_checked": 22,
	"section": "2.3 Security Options",
	"benchmark": "CIS Windows Server 2022 v3.0.0",
}
