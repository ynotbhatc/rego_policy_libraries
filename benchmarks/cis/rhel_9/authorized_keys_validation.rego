package cis_rhel9.authorized_keys

import rego.v1

# SSH Authorized Keys Validation
# Standards: CIS RHEL 9 v2.0.0 Section 5.2 (SSH Server Configuration)
#            DISA STIG RHEL-09-255xxx (SSH Access Controls)
#            NIST SP 800-53 IA-3  (Device Identification and Authentication)
#            NIST SP 800-53 SC-13 (Cryptographic Protection)
# Use case: EDA real-time drift detection — inotifywait on /root/.ssh and
#           /home/*/.ssh triggers this policy when authorized_keys changes.
#           Also used in batch assessment for SSH key hygiene audits.
#
# Expected input.authorized_keys keys:
#   files                      array  — per-user authorized_keys files:
#     path                     string — absolute path to authorized_keys file
#     user                     string — username who owns this file
#     expected_owner           string — user the file should be owned by
#     owner                    string — actual current owner
#     mode                     string — file permissions as decimal string ("644", "0644")
#     keys                     array  — parsed keys in this file:
#       type                   string — "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", etc.
#       bits                   number — key size in bits (RSA/EC only)
#       fingerprint            string — SHA-256 fingerprint (ssh-keygen -lf format)
#       comment                string — key comment/identifier
#       age_minutes            number — minutes since key was added (from file mtime or audit log)
#   ssh_dirs                   array  — [{path, mode}] .ssh directories
#   approved_fingerprints      array  — authorized fingerprints (empty = no baseline enforcement)
#   recent_key_threshold_minutes number — alert threshold for newly-added keys (default 60)

default compliant := false

# ── Helpers ───────────────────────────────────────────────────────────────────

# Permission write digits: 2=w--, 3=wx-, 6=rw-, 7=rwx
write_digit(d) if {
	write_digits := {2, 3, 6, 7}
	write_digits[d]
}

group_or_world_writable(mode) if {
	n := to_number(mode)
	world_digit := n % 10
	write_digit(world_digit)
}

group_or_world_writable(mode) if {
	n := to_number(mode)
	group_digit := floor(n / 10) % 10
	write_digit(group_digit)
}

deprecated_key_type(t) if {
	deprecated := {"ssh-dss", "ssh-dsa", "ecdsa-sha2-nistp192"}
	deprecated[t]
}

approved_fingerprint(fp) if {
	some approved in input.authorized_keys.approved_fingerprints
	approved == fp
}

# ── File and Directory Permissions ───────────────────────────────────────────

# STIG RHEL-09-255045: authorized_keys must not be group or world writable
violations contains msg if {
	some entry in input.authorized_keys.files
	group_or_world_writable(entry.mode)
	msg := sprintf(
		"STIG RHEL-09-255045: %v has permissions %v — group/world writable allows unauthorized key injection",
		[entry.path, entry.mode],
	)
}

# authorized_keys must be owned by the corresponding user
violations contains msg if {
	some entry in input.authorized_keys.files
	entry.owner != entry.expected_owner
	msg := sprintf(
		"STIG RHEL-09-255050: %v owned by '%v', expected '%v' — ownership mismatch allows key substitution",
		[entry.path, entry.owner, entry.expected_owner],
	)
}

# .ssh directory must be 700 (only owner can access)
violations contains msg if {
	some dir in input.authorized_keys.ssh_dirs
	dir.mode != "0700"
	dir.mode != "700"
	msg := sprintf(
		"CIS 5.2: .ssh directory %v has mode %v — must be 700 (owner read/write/execute only)",
		[dir.path, dir.mode],
	)
}

# ── Key Type and Strength ─────────────────────────────────────────────────────

# DSA and ECDSA P-192 are cryptographically broken or below NIST minimums
violations contains msg if {
	some entry in input.authorized_keys.files
	some key in entry.keys
	deprecated_key_type(key.type)
	msg := sprintf(
		"NIST SC-13: %v contains deprecated key type '%v' (user: %v) — replace with ed25519 or RSA-4096",
		[entry.path, key.type, entry.user],
	)
}

# RSA keys below 2048 bits do not meet NIST SP 800-131A minimum
violations contains msg if {
	some entry in input.authorized_keys.files
	some key in entry.keys
	key.type == "ssh-rsa"
	key.bits < 2048
	msg := sprintf(
		"NIST SC-13: RSA key in %v is %v bits (user: %v) — NIST SP 800-131A minimum is 2048 bits",
		[entry.path, key.bits, entry.user],
	)
}

# ── Key Attribution ───────────────────────────────────────────────────────────

# Keys with no comment cannot be attributed during an incident or audit
violations contains msg if {
	some entry in input.authorized_keys.files
	some key in entry.keys
	trim_space(key.comment) == ""
	msg := sprintf(
		"NIST IA-3: Key %v in %v has no comment — key ownership cannot be determined during audit (user: %v)",
		[key.fingerprint, entry.path, entry.user],
	)
}

# ── Unauthorized and Root Keys ────────────────────────────────────────────────

# Key not in approved fingerprint baseline (enforced only when baseline is populated)
violations contains msg if {
	count(input.authorized_keys.approved_fingerprints) > 0
	some entry in input.authorized_keys.files
	some key in entry.keys
	not approved_fingerprint(key.fingerprint)
	msg := sprintf(
		"STIG RHEL-09-255060: Key %v in %v (user: %v) is not in the approved fingerprint list",
		[key.fingerprint, entry.path, entry.user],
	)
}

# Direct root SSH key login is not recommended (CIS 5.2 / principle of least privilege)
violations contains msg if {
	some entry in input.authorized_keys.files
	entry.user == "root"
	count(entry.keys) > 0
	msg := sprintf(
		"CIS 5.2: root authorized_keys at %v has %v key(s) — disable direct root SSH key authentication",
		[entry.path, count(entry.keys)],
	)
}

# ── Freshly-Added Key Detection (primary EDA trigger) ────────────────────────

# Key added recently and not in the approved list — active injection scenario
violations contains msg if {
	threshold := object.get(input.authorized_keys, "recent_key_threshold_minutes", 60)
	count(input.authorized_keys.approved_fingerprints) > 0
	some entry in input.authorized_keys.files
	some key in entry.keys
	key.age_minutes < threshold
	not approved_fingerprint(key.fingerprint)
	msg := sprintf(
		"NIST IA-3: Key %v added to %v within last %v minutes and is not in the approved list (user: %v) — INVESTIGATE IMMEDIATELY",
		[key.fingerprint, entry.path, threshold, entry.user],
	)
}

# ── Compliance ────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "authorized_keys",
	"standards": ["CIS RHEL 9 5.2", "STIG RHEL-09-255xxx", "NIST SP 800-53 IA-3", "NIST SP 800-53 SC-13"],
	"violations": violations,
	"compliant": compliant,
	"files_checked": count(object.get(input.authorized_keys, "files", [])),
	"total_keys": count([k | some e in input.authorized_keys.files; some k in e.keys]),
	"unapproved_keys": count([k |
		count(input.authorized_keys.approved_fingerprints) > 0
		some e in input.authorized_keys.files
		some k in e.keys
		not approved_fingerprint(k.fingerprint)
	]),
}
