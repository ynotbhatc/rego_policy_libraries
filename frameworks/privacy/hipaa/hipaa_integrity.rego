# METADATA
# title: "HIPAA Security Rule — 45 CFR 164.312(c)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 22
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package hipaa.integrity

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(c)
# Technical Safeguard: Integrity
#
# Implement policies and procedures to protect ePHI from improper alteration
# or destruction.
#
# Standard:    164.312(c)(1) - Integrity (a standard; its one implementation specification is (c)(2))
# Addressable: 164.312(c)(2) - Mechanism to authenticate ePHI
#
# Input shape:
#   input.phi_systems[]         - systems storing ePHI
#   input.integrity.policies_and_procedures_implemented - 164.312(c)(1) evidence
#
# Backup, restore testing, offsite copies, disposal and media re-use are decided by the Security Rule rows
# 164.308(a)(7)(ii)(A) and 164.310(d)(2)(i)-(ii) (hipaa.security_rule), not by 164.312(c); this module reports
# its former checks of them, and its library frequencies, as `advisories` only.
#   input.integrity             - integrity control configuration
#   input.transmission          - data in transit controls
#   input.backup                - backup and recovery configuration
# =============================================================================

_addressable_ids := {"164.312(c)(2)"}

# Addressable specifications (45 CFR 164.306(d)(3)): implemented, or documented as not reasonable and
# appropriate together with an equivalent alternative measure (or documentation that none is reasonable
# and appropriate), read from input.hipaa.addressable_decisions["<cfr id>"] =
#   {"not_reasonable_and_appropriate_documented": true,
#    "equivalent_alternative_implemented": true  OR  "no_reasonable_alternative_documented": true}
# A finding cited to an addressable paragraph with that decision evidenced is not a violation (listed in
# addressed_by_alternative); with neither path evidenced the finding stands (fail closed).
_decision(id) := d if {
	d := object.get(input, ["hipaa", "addressable_decisions", id], null)
	is_object(d)
}

_alternative_documented(id) if {
	id in _addressable_ids
	d := _decision(id)
	d.not_reasonable_and_appropriate_documented == true
	_alternative_or_none(d)
}

_alternative_or_none(d) if d.equivalent_alternative_implemented == true

_alternative_or_none(d) if d.no_reasonable_alternative_documented == true

_cited(msg) := trim_space(split(trim_prefix(msg, "HIPAA "), ":")[0])

_kept(msg) if not _alternative_documented(_cited(msg))

addressed_by_alternative contains id if {
	some id in _addressable_ids
	_alternative_documented(id)
}

# ---------------------------------------------------------------------------
# 164.312(c)(1) — Integrity Controls (Required)
# Protect ePHI from improper alteration or destruction
# ---------------------------------------------------------------------------

# 164.312(c)(1): policies and procedures protecting ePHI from improper alteration or destruction.
violation_data_integrity contains msg if {
	not input.integrity.policies_and_procedures_implemented == true
	msg := "HIPAA 164.312(c)(1): evidence missing — policies and procedures to protect ePHI from improper alteration or destruction are not evidenced (integrity.policies_and_procedures_implemented not true)."
}

advisories contains msg if {
	some phi_system in input.phi_systems
	phi_system.integrity_checking_enabled
	is_number(phi_system.integrity_check_frequency_hours)
	phi_system.integrity_check_frequency_hours > 24
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): System '%v' integrity checks run every %v hours. Daily or more frequent checks are required for ePHI.",
		[phi_system.name, phi_system.integrity_check_frequency_hours],
	)
}

advisories contains msg if {
	some phi_system in input.phi_systems
	phi_system.integrity_checking_enabled
	not is_number(object.get(phi_system, "integrity_check_frequency_hours", null))
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): evidence missing — integrity_check_frequency_hours not collected for system '%v'.",
		[object.get(phi_system, "name", "unknown")],
	)
}

advisories contains msg if {
	not input.integrity.change_management_process
	msg := "Advisory (library practice, not a 45 CFR requirement): No change management process for ePHI systems. Changes must be controlled to prevent unauthorized alteration."
}

advisories contains msg if {
	not input.integrity.write_protection_on_archived_phi
	msg := "Advisory (library practice, not a 45 CFR requirement): Archived ePHI is not write-protected. Historical records must be protected from modification."
}

# ---------------------------------------------------------------------------
# 164.312(c)(2) — Mechanism to Authenticate ePHI (Addressable)
# Implement electronic mechanisms to corroborate ePHI has not been altered
# ---------------------------------------------------------------------------

# 164.312(c)(2): an electronic mechanism corroborating that ePHI has not been altered or destroyed: integrity
# checking on the system, or checksums/hashes. Which algorithm, how often and signatures are advisories.
violation_phi_authentication contains msg if {
	some phi_system in input.phi_systems
	not phi_system.integrity_checking_enabled == true
	not input.integrity.checksum_or_hash_enabled == true
	msg := sprintf(
		"HIPAA 164.312(c)(2): System '%v' has no electronic mechanism (integrity checking or checksums/hashes) to corroborate that ePHI has not been altered or destroyed.",
		[object.get(phi_system, "name", "unknown")],
	)
}

advisories contains msg if {
	input.integrity.checksum_or_hash_enabled
	input.integrity.hash_algorithm in {"MD5", "SHA1"}
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Hash algorithm '%v' is cryptographically weak. Use SHA-256 or stronger for ePHI integrity verification.",
		[input.integrity.hash_algorithm],
	)
}

advisories contains msg if {
	not input.integrity.digital_signatures_for_phi_export
	msg := "Advisory (library practice, not a 45 CFR requirement): ePHI exports do not use digital signatures. Signatures provide non-repudiation and integrity assurance."
}

# ---------------------------------------------------------------------------
# Backup and Recovery (supports integrity)
# ---------------------------------------------------------------------------

advisories contains msg if {
	not input.backup.regular_backups_enabled
	msg := "Advisory (library practice, not a 45 CFR requirement): Regular backups of ePHI are not configured. Backups are essential for recovery from corruption or destruction."
}

advisories contains msg if {
	input.backup.regular_backups_enabled
	is_number(input.backup.backup_frequency_hours)
	input.backup.backup_frequency_hours > 24
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): ePHI is backed up every %v hours. Daily backups are the recommended minimum.",
		[input.backup.backup_frequency_hours],
	)
}

advisories contains msg if {
	input.backup.regular_backups_enabled
	not is_number(object.get(input, ["backup", "backup_frequency_hours"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — backup.backup_frequency_hours not collected. Backup cadence cannot be verified."
}

advisories contains msg if {
	not input.backup.offsite_or_cloud_backup
	msg := "Advisory (library practice, not a 45 CFR requirement): ePHI backups are not stored offsite or in cloud. Backups must be protected from site-level disasters."
}

advisories contains msg if {
	not input.backup.restore_tested
	msg := "Advisory (library practice, not a 45 CFR requirement): ePHI backup restoration has not been tested. Backups must be verified to ensure recoverability."
}

advisories contains msg if {
	input.backup.restore_tested
	is_number(input.backup.restore_test_days)
	input.backup.restore_test_days > 90
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): ePHI backup restore test is %v days old. Test restoration at least quarterly.",
		[input.backup.restore_test_days],
	)
}

# ---------------------------------------------------------------------------
# Destruction of ePHI
# ---------------------------------------------------------------------------

advisories contains msg if {
	input.backup.restore_tested
	not is_number(object.get(input, ["backup", "restore_test_days"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — backup.restore_test_days not collected. Restore-test recency cannot be verified."
}

advisories contains msg if {
	not input.integrity.secure_deletion_policy
	msg := "Advisory (library practice, not a 45 CFR requirement): No secure deletion policy for ePHI. Media containing ePHI must be securely destroyed when no longer needed."
}

advisories contains msg if {
	input.integrity.media_reuse_without_sanitization
	msg := "Advisory (library practice, not a 45 CFR requirement): Media containing ePHI is being reused without sanitization. Media must be sanitized before reuse."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if some msg in violation_data_integrity

violations contains msg if {
	some msg in violation_phi_authentication
	_kept(msg)
}

_phi_authentication_ok if count(violation_phi_authentication) == 0

_phi_authentication_ok if _alternative_documented("164.312(c)(2)")

default _phi_authentication_ok := false

# Fail-closed: no ePHI systems in scope → cannot certify this safeguard
violations contains msg if {
	count(object.get(input, "phi_systems", [])) == 0
	msg := "HIPAA 164.312(c): no ePHI systems in scope (input.phi_systems is empty) — cannot certify Integrity. Declare the ePHI systems to be evaluated."
}

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "164.312(c)",
	"title": "Integrity",
	"required": true,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"advisories": advisories,
	"addressed_by_alternative": addressed_by_alternative,
	"controls": {
		"data_integrity": count(violation_data_integrity) == 0,
		"phi_authentication": _phi_authentication_ok,
	},
}
