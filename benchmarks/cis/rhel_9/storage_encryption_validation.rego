package cis_rhel9.storage_encryption

import rego.v1

# Storage Encryption and FIPS Validation
# Standards: DISA STIG RHEL 9 (RHEL-09-231xxx, RHEL-09-672xxx)
#            NIST SP 800-53 SC-28 (Protection of Information at Rest)
#            NIST SP 800-53 SC-13 (Cryptographic Protection)
# Use case: Batch compliance assessment + EDA real-time drift detection
#           on /etc/crypttab, /etc/fstab, and LUKS volume changes.
#
# Expected input.storage_encryption keys:
#   fips_enabled              bool   — /proc/sys/crypto/fips_enabled == 1
#   fips_mode_required        bool   — true for FISMA/FIPS environments
#   crypto_policy             string — update-crypto-policies --show (DEFAULT/FUTURE/FIPS/LEGACY)
#   luks_volumes              array  — [{device, version, cipher, active_key_slots}]
#   unencrypted_data_partitions array — ["/dev/sdX", ...] data partitions without LUKS
#   crypttab_entries          array  — [{name, device, options: [string]}]
#   crypttab_missing_devices  array  — [{name, device}] entries whose devices don't exist
#   fstab_entries             array  — [{device, mountpoint, encrypted: bool}]
#   fstab_unencrypted_data_mounts array — [{device, mountpoint}]
#   data_encryption_required  bool   — enforce encryption on sensitive mountpoints
#   swap_present              bool   — swapon --show has output
#   swap_encrypted            bool   — swap is on a LUKS device or encrypted zram

default compliant := false

# ── Helpers ───────────────────────────────────────────────────────────────────

sensitive_mountpoint(mp) if {
	sensitive := {"/var", "/var/log", "/var/log/audit", "/home", "/tmp"}
	sensitive[mp]
}

weak_luks_cipher(cipher) if {
	weak := {"des-", "3des-", "rc4", "blowfish", "twofish", "serpent"}
	some w in weak
	contains(lower(cipher), w)
}

fips_compliant_policy(policy) if {
	fips_ok := {"FIPS", "FUTURE", "FIPS:OSPP"}
	fips_ok[policy]
}

# ── FIPS Mode ─────────────────────────────────────────────────────────────────

# STIG RHEL-09-672010: FIPS mode must be enabled when required
violations contains msg if {
	input.storage_encryption.fips_mode_required
	not input.storage_encryption.fips_enabled
	msg := "STIG RHEL-09-672010: FIPS 140-2/140-3 mode is not enabled (/proc/sys/crypto/fips_enabled != 1)"
}

# STIG RHEL-09-672020: Crypto policy must align with FIPS when FIPS is required
violations contains msg if {
	input.storage_encryption.fips_mode_required
	not fips_compliant_policy(input.storage_encryption.crypto_policy)
	msg := sprintf(
		"STIG RHEL-09-672020: Crypto policy '%v' does not meet FIPS requirements — use FIPS or FUTURE",
		[input.storage_encryption.crypto_policy],
	)
}

# NIST SC-13: LEGACY crypto policy allows weak algorithms (MD5, RC4, DES)
violations contains msg if {
	input.storage_encryption.crypto_policy == "LEGACY"
	msg := "NIST SC-13: System crypto policy is LEGACY — permits MD5, RC4, DES. Upgrade to DEFAULT or FUTURE."
}

# ── LUKS Disk Encryption ──────────────────────────────────────────────────────

# STIG RHEL-09-231010: Data partitions must be encrypted with LUKS
violations contains msg if {
	some partition in input.storage_encryption.unencrypted_data_partitions
	msg := sprintf("STIG RHEL-09-231010: Data partition %v is not LUKS-encrypted", [partition])
}

# LUKS v1 is deprecated — LUKS v2 required for FIPS 140-3
violations contains msg if {
	some volume in input.storage_encryption.luks_volumes
	volume.version == "1"
	msg := sprintf(
		"NIST SC-28: LUKS volume %v uses LUKS v1 (deprecated) — upgrade to LUKS v2 for FIPS 140-3 compliance",
		[volume.device],
	)
}

# Weak encryption cipher on LUKS volume
violations contains msg if {
	some volume in input.storage_encryption.luks_volumes
	weak_luks_cipher(volume.cipher)
	msg := sprintf(
		"NIST SC-13: LUKS volume %v uses weak cipher '%v' — use aes-xts-plain64 with SHA-256 or stronger",
		[volume.device, volume.cipher],
	)
}

# Excessive key slots — possible unauthorized key injection
violations contains msg if {
	some volume in input.storage_encryption.luks_volumes
	count(volume.active_key_slots) > 2
	msg := sprintf(
		"NIST SC-28: LUKS volume %v has %v active key slots — review for unauthorized keys (expected ≤ 2)",
		[volume.device, count(volume.active_key_slots)],
	)
}

# ── /etc/crypttab ─────────────────────────────────────────────────────────────

# crypttab entry references a device that doesn't exist
violations contains msg if {
	some entry in input.storage_encryption.crypttab_missing_devices
	msg := sprintf(
		"STIG RHEL-09-231020: /etc/crypttab entry '%v' references missing device %v",
		[entry.name, entry.device],
	)
}

# crypttab plain mode = no encryption
violations contains msg if {
	some entry in input.storage_encryption.crypttab_entries
	"plain" in entry.options
	msg := sprintf(
		"NIST SC-28: /etc/crypttab entry '%v' uses 'plain' mode (unencrypted dm device) — use LUKS",
		[entry.name],
	)
}

# ── /etc/fstab Encryption Consistency ────────────────────────────────────────

# Data mount in fstab with no LUKS backing
violations contains msg if {
	some mount in input.storage_encryption.fstab_unencrypted_data_mounts
	msg := sprintf(
		"STIG RHEL-09-231030: fstab mount %v at %v holds data but is not backed by a LUKS device",
		[mount.device, mount.mountpoint],
	)
}

# Sensitive mountpoints on unencrypted partitions (when data encryption is required)
violations contains msg if {
	input.storage_encryption.data_encryption_required
	some mount in input.storage_encryption.fstab_entries
	sensitive_mountpoint(mount.mountpoint)
	not mount.encrypted
	msg := sprintf(
		"NIST SC-28: Sensitive mountpoint %v is on an unencrypted partition",
		[mount.mountpoint],
	)
}

# ── Swap Encryption ───────────────────────────────────────────────────────────

# STIG RHEL-09-231040: Swap must be encrypted to protect in-memory data at rest
violations contains msg if {
	input.storage_encryption.swap_present
	not input.storage_encryption.swap_encrypted
	msg := "STIG RHEL-09-231040: Swap is not encrypted — sensitive in-memory data may persist at rest"
}

# ── Compliance ────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "storage_encryption",
	"standards": ["STIG RHEL-09-231xxx", "STIG RHEL-09-672xxx", "NIST SP 800-53 SC-28", "NIST SP 800-53 SC-13"],
	"violations": violations,
	"compliant": compliant,
	"fips_enabled": object.get(input.storage_encryption, "fips_enabled", false),
	"crypto_policy": object.get(input.storage_encryption, "crypto_policy", "unknown"),
	"luks_volume_count": count(object.get(input.storage_encryption, "luks_volumes", [])),
}
