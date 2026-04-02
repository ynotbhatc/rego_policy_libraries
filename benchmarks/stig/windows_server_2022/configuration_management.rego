package stig.windows_server_2022.configuration_management

# DISA STIG for Windows Server 2022 - Configuration Management Module
# STIG Version: V2R2 | Released: October 2024
# Covers: OS settings, account policies, system settings, banners

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# WN22-00-000005 | V-254238 | CAT I - Domain-joined: Trusted Platform Module must be used
default tpm_enabled := false
tpm_enabled if { input.security_config.tpm_enabled == true }
tpm_enabled if { input.security_config.tpm_version >= "2.0" }

status_wn22_000005 := "Not_a_Finding" if { tpm_enabled } else := "Open"
finding_wn22_000005 := {
	"vuln_id": "V-254238",
	"stig_id": "WN22-00-000005",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must have a Trusted Platform Module (TPM) enabled and ready for use",
	"status": status_wn22_000005,
	"fix_text": "Enable TPM in BIOS/UEFI settings and ensure BitLocker is configured to use TPM",
}

# WN22-00-000010 | V-254239 | CAT I - BitLocker must be enabled for OS drive
default bitlocker_enabled := false
bitlocker_enabled if { input.security_config.bitlocker_os_drive == true }

status_wn22_000010 := "Not_a_Finding" if { bitlocker_enabled } else := "Open"
finding_wn22_000010 := {
	"vuln_id": "V-254239",
	"stig_id": "WN22-00-000010",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must employ BitLocker-based disk encryption on the OS drive",
	"status": status_wn22_000010,
	"fix_text": "Enable BitLocker on OS drive: manage-bde -on C:",
}

# WN22-00-000015 | V-254240 | CAT I - Administrator account must be renamed
default admin_renamed := false
admin_renamed if { input.local_accounts.Administrator.name != "Administrator" }
admin_renamed if { input.security_policy.RenameAdministratorAccount != "" }

status_wn22_000015 := "Not_a_Finding" if { admin_renamed } else := "Open"
finding_wn22_000015 := {
	"vuln_id": "V-254240",
	"stig_id": "WN22-00-000015",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 built-in Administrator account must be renamed",
	"status": status_wn22_000015,
	"fix_text": "Rename the built-in Administrator account via Local Security Policy",
}

# WN22-00-000020 | V-254241 | CAT I - Guest account must be disabled
default guest_disabled := false
guest_disabled if { input.local_accounts.Guest.enabled == false }
guest_disabled if { input.security_policy.GuestAccount.enabled == false }

status_wn22_000020 := "Not_a_Finding" if { guest_disabled } else := "Open"
finding_wn22_000020 := {
	"vuln_id": "V-254241",
	"stig_id": "WN22-00-000020",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 built-in Guest account must be disabled",
	"status": status_wn22_000020,
	"fix_text": "Disable Guest account: net user Guest /active:no",
}

# WN22-00-000025 | V-254242 | CAT I - Reversible password encryption must be disabled
default no_reversible_passwords := false
no_reversible_passwords if { input.security_policy.ClearTextPassword == 0 }
no_reversible_passwords if { input.security_policy.ClearTextPassword == false }

status_wn22_000025 := "Not_a_Finding" if { no_reversible_passwords } else := "Open"
finding_wn22_000025 := {
	"vuln_id": "V-254242",
	"stig_id": "WN22-00-000025",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must not store passwords using reversible encryption",
	"status": status_wn22_000025,
	"fix_text": "Set 'Store passwords using reversible encryption' to Disabled in security policy",
}

# WN22-AC-000070 | V-254253 | CAT I - Account lockout must be 3 or less
default account_lockout := false
account_lockout if {
	input.security_policy.LockoutBadCount <= 3
	input.security_policy.LockoutBadCount > 0
}

status_wn22_ac_000070 := "Not_a_Finding" if { account_lockout } else := "Open"
finding_wn22_ac_000070 := {
	"vuln_id": "V-254253",
	"stig_id": "WN22-AC-000070",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must have the number of allowed bad logon attempts set to 3 or fewer",
	"status": status_wn22_ac_000070,
	"fix_text": "Set Account lockout threshold to 3 or fewer in security policy",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# WN22-00-000030 | V-254243 | CAT II - DoD warning banner must be configured
default warning_banner := false
warning_banner if { contains(input.security_policy.LegalNoticeText, "U.S. Government") }
warning_banner if { contains(input.security_policy.LegalNoticeText, "authorized users") }

status_wn22_000030 := "Not_a_Finding" if { warning_banner } else := "Open"
finding_wn22_000030 := {
	"vuln_id": "V-254243",
	"stig_id": "WN22-00-000030",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must display the Standard Mandatory DoD Notice and Consent Banner before logon",
	"status": status_wn22_000030,
	"fix_text": "Configure the Legal Notice text in Local Security Policy",
}

# WN22-00-000035 | V-254244 | CAT II - Legal notice caption must be set
default warning_banner_caption := false
warning_banner_caption if { input.security_policy.LegalNoticeCaption != "" }

status_wn22_000035 := "Not_a_Finding" if { warning_banner_caption } else := "Open"
finding_wn22_000035 := {
	"vuln_id": "V-254244",
	"stig_id": "WN22-00-000035",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have a logon banner title configured",
	"status": status_wn22_000035,
	"fix_text": "Set the Legal Notice Caption in Local Security Policy",
}

# WN22-00-000040 | V-254245 | CAT II - Credential Guard must be enabled
default credential_guard := false
credential_guard if { input.security_config.credential_guard_enabled == true }

status_wn22_000040 := "Not_a_Finding" if { credential_guard } else := "Open"
finding_wn22_000040 := {
	"vuln_id": "V-254245",
	"stig_id": "WN22-00-000040",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Credential Guard must be running",
	"status": status_wn22_000040,
	"fix_text": "Enable Credential Guard via Group Policy or Device Guard",
}

# WN22-AC-000020 | V-254248 | CAT II - Password minimum length must be 14+
default password_min_length := false
password_min_length if { input.security_policy.MinimumPasswordLength >= 14 }

status_wn22_ac_000020 := "Not_a_Finding" if { password_min_length } else := "Open"
finding_wn22_ac_000020 := {
	"vuln_id": "V-254248",
	"stig_id": "WN22-AC-000020",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 passwords must have a minimum of 14 characters",
	"status": status_wn22_ac_000020,
	"fix_text": "Set Minimum Password Length to 14 in security policy",
}

# WN22-AC-000030 | V-254249 | CAT II - Password complexity must be enabled
default password_complexity := false
password_complexity if { input.security_policy.PasswordComplexity == 1 }
password_complexity if { input.security_policy.PasswordComplexity == true }

status_wn22_ac_000030 := "Not_a_Finding" if { password_complexity } else := "Open"
finding_wn22_ac_000030 := {
	"vuln_id": "V-254249",
	"stig_id": "WN22-AC-000030",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have the password complexity requirement enabled",
	"status": status_wn22_ac_000030,
	"fix_text": "Enable 'Password must meet complexity requirements' in security policy",
}

# WN22-AC-000040 | V-254250 | CAT II - Password max age must be 60 days
default password_max_age := false
password_max_age if {
	input.security_policy.MaximumPasswordAge <= 60
	input.security_policy.MaximumPasswordAge > 0
}

status_wn22_ac_000040 := "Not_a_Finding" if { password_max_age } else := "Open"
finding_wn22_ac_000040 := {
	"vuln_id": "V-254250",
	"stig_id": "WN22-AC-000040",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 maximum password age must be 60 days or less",
	"status": status_wn22_ac_000040,
	"fix_text": "Set Maximum Password Age to 60 in security policy",
}

# WN22-AC-000050 | V-254251 | CAT II - Password min age must be 1 day
default password_min_age := false
password_min_age if { input.security_policy.MinimumPasswordAge >= 1 }

status_wn22_ac_000050 := "Not_a_Finding" if { password_min_age } else := "Open"
finding_wn22_ac_000050 := {
	"vuln_id": "V-254251",
	"stig_id": "WN22-AC-000050",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 minimum password age must be 1 day",
	"status": status_wn22_ac_000050,
	"fix_text": "Set Minimum Password Age to 1 in security policy",
}

# WN22-AC-000060 | V-254252 | CAT II - Password history must be 24
default password_history := false
password_history if { input.security_policy.PasswordHistorySize >= 24 }

status_wn22_ac_000060 := "Not_a_Finding" if { password_history } else := "Open"
finding_wn22_ac_000060 := {
	"vuln_id": "V-254252",
	"stig_id": "WN22-AC-000060",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have the password history set to 24",
	"status": status_wn22_ac_000060,
	"fix_text": "Set Enforce Password History to 24 in security policy",
}

# WN22-AC-000080 | V-254254 | CAT II - Account lockout reset time must be 15 minutes
default lockout_reset := false
lockout_reset if { input.security_policy.ResetLockoutCount >= 15 }

status_wn22_ac_000080 := "Not_a_Finding" if { lockout_reset } else := "Open"
finding_wn22_ac_000080 := {
	"vuln_id": "V-254254",
	"stig_id": "WN22-AC-000080",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must reset the account lockout counter at 15 minutes",
	"status": status_wn22_ac_000080,
	"fix_text": "Set Reset account lockout counter after to 15 minutes",
}

# WN22-AC-000090 | V-254255 | CAT II - Lockout duration must be 15 minutes
default lockout_duration := false
lockout_duration if { input.security_policy.LockoutDuration >= 15 }
lockout_duration if { input.security_policy.LockoutDuration == 0 }  # 0 = forever

status_wn22_ac_000090 := "Not_a_Finding" if { lockout_duration } else := "Open"
finding_wn22_ac_000090 := {
	"vuln_id": "V-254255",
	"stig_id": "WN22-AC-000090",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 account lockout duration must be 15 minutes or greater",
	"status": status_wn22_ac_000090,
	"fix_text": "Set Account lockout duration to 15 minutes",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_wn22_000005,
	finding_wn22_000010,
	finding_wn22_000015,
	finding_wn22_000020,
	finding_wn22_000025,
	finding_wn22_ac_000070,
]

cat_ii_findings := [
	finding_wn22_000030,
	finding_wn22_000035,
	finding_wn22_000040,
	finding_wn22_ac_000020,
	finding_wn22_ac_000030,
	finding_wn22_ac_000040,
	finding_wn22_ac_000050,
	finding_wn22_ac_000060,
	finding_wn22_ac_000080,
	finding_wn22_ac_000090,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "configuration_management",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
