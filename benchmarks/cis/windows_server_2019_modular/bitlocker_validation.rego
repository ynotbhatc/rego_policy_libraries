package cis_windows_server_2019.bitlocker

# CIS Windows Server 2019 Benchmark v3.0.0 - Section 18.10.9: BitLocker Drive Encryption

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in os_drive_violations], [v | some v in fixed_drive_violations]),
	[v | some v in removable_drive_violations],
)

# =============================================================================
# CIS 18.10.9.1: BitLocker - OS Drive
# =============================================================================

# CIS 18.10.9.1.1: Require additional authentication at startup = Enabled
os_drive_violations contains msg if {
	not input.bitlocker.require_additional_auth_at_startup
	msg := "CIS 18.10.9.1.1: BitLocker 'Require additional authentication at startup' is not enabled"
}

# CIS 18.10.9.1.1: Allow BitLocker without compatible TPM = Disabled
os_drive_violations contains msg if {
	input.bitlocker.allow_without_tpm
	msg := "CIS 18.10.9.1.1: BitLocker 'Allow BitLocker without a compatible TPM' should be disabled"
}

# CIS 18.10.9.1.2: TPM startup PIN = Required
os_drive_violations contains msg if {
	input.bitlocker.tpm_startup_pin != "RequireStartupPIN"
	not input.bitlocker.tpm_startup_pin == "RequireStartupPINAndKey"
	msg := sprintf("CIS 18.10.9.1.2: BitLocker TPM startup PIN is '%s', should require startup PIN", [input.bitlocker.tpm_startup_pin])
}

# CIS 18.10.9.1.3: Configure minimum PIN length >= 6
os_drive_violations contains msg if {
	input.bitlocker.minimum_pin_length < 6
	msg := sprintf("CIS 18.10.9.1.3: BitLocker minimum PIN length is %d, should be 6 or more", [input.bitlocker.minimum_pin_length])
}

# OS drive encryption status
os_drive_violations contains msg if {
	not input.bitlocker.os_drive_encrypted
	msg := "CIS 18.10.9: BitLocker OS drive is not encrypted"
}

os_drive_violations contains msg if {
	input.bitlocker.os_drive_encrypted
	input.bitlocker.os_encryption_method != "XtsAes256"
	input.bitlocker.os_encryption_method != "XtsAes128"
	msg := sprintf("CIS 18.10.9: BitLocker OS drive encryption method is '%s', should be XTS-AES 128 or 256", [input.bitlocker.os_encryption_method])
}

# CIS 18.10.9.1.4: Recovery options - save to AD DS
os_drive_violations contains msg if {
	not input.bitlocker.os_recovery_to_ad
	msg := "CIS 18.10.9.1.4: BitLocker OS drive recovery information should be backed up to Active Directory"
}

# =============================================================================
# CIS 18.10.9.2: BitLocker - Fixed Data Drives
# =============================================================================

# CIS 18.10.9.2.1: Deny write access without BitLocker = Enabled (if required by policy)
fixed_drive_violations contains msg if {
	input.require_bitlocker_on_fixed_drives
	not input.bitlocker.deny_fixed_write_without_encryption
	msg := "CIS 18.10.9.2.1: Deny write access to fixed drives not protected by BitLocker should be enabled"
}

# Fixed drive encryption status
fixed_drive_violations contains msg if {
	input.require_bitlocker_on_fixed_drives
	some drive in input.bitlocker.fixed_drives
	not drive.encrypted
	msg := sprintf("CIS 18.10.9.2: Fixed drive '%s' is not BitLocker encrypted", [drive.drive_letter])
}

# CIS 18.10.9.2.2: Fixed drive encryption method
fixed_drive_violations contains msg if {
	some drive in input.bitlocker.fixed_drives
	drive.encrypted
	drive.encryption_method != "XtsAes256"
	drive.encryption_method != "XtsAes128"
	msg := sprintf("CIS 18.10.9.2: Fixed drive '%s' encryption method is '%s', should be XTS-AES", [drive.drive_letter, drive.encryption_method])
}

# =============================================================================
# CIS 18.10.9.3: BitLocker - Removable Data Drives
# =============================================================================

# CIS 18.10.9.3.1: Deny write access to removable drives without BitLocker = Enabled
removable_drive_violations contains msg if {
	not input.bitlocker.deny_removable_write_without_encryption
	msg := "CIS 18.10.9.3.1: Deny write access to removable drives not protected by BitLocker should be enabled"
}

# CIS 18.10.9.3.2: Deny write access to removable drives configured in another org = Enabled
removable_drive_violations contains msg if {
	not input.bitlocker.deny_cross_org_removable_drives
	msg := "CIS 18.10.9.3.2: Deny write access to removable drives configured in another organization should be enabled"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"os_drive_violations": count(os_drive_violations),
	"fixed_drive_violations": count(fixed_drive_violations),
	"removable_drive_violations": count(removable_drive_violations),
	"encryption_status": {
		"os_drive_encrypted": input.bitlocker.os_drive_encrypted,
		"tpm_available": input.bitlocker.tpm_available,
		"tpm_version": input.bitlocker.tpm_version,
	},
	"controls_checked": 13,
	"section": "18.10.9 BitLocker Drive Encryption",
	"benchmark": "CIS Windows Server 2019 v3.0.0",
}
