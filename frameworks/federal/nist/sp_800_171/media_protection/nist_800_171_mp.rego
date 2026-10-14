# METADATA
# title: "NIST SP 800-171 Rev 3 - Media Protection (MP) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 18
#     cited: 7
#     expected: 8
#     found: 18
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.media_protection

import rego.v1

# NIST SP 800-171 Rev 3 - Media Protection (MP) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.08 Media Protection — Protecting Controlled Unclassified Information (CUI)

# 03.08.01 Media Storage (Rev 2 3.8.1): Protect (i.e., physically control and securely store) system media containing CUI,
#         both paper and digital
default media_physical_protection := false

media_physical_protection if {
	input.nist_800_171.media_protection.physical.paper_media_secured == true
	input.nist_800_171.media_protection.physical.digital_media_secured == true
	input.nist_800_171.media_protection.physical.access_controlled == true
}

# 03.08.02 Media Access (Rev 2 3.8.2): Limit access to CUI on system media to authorized users
default media_access_limited := false

media_access_limited if {
	input.nist_800_171.media_protection.access.authorized_users_only == true
	input.nist_800_171.media_protection.access.access_list_documented == true
	input.nist_800_171.media_protection.access.access_enforcement_implemented == true
}

# 03.08.03 Media Sanitization (Rev 2 3.8.3): Sanitize or destroy system media before disposal or reuse
default media_sanitization_disposal := false

media_sanitization_disposal if {
	input.nist_800_171.media_protection.sanitization.sanitized_before_disposal == true
	input.nist_800_171.media_protection.sanitization.sanitized_before_reuse == true
	input.nist_800_171.media_protection.sanitization.method_documented == true
	input.nist_800_171.media_protection.sanitization.verification_performed == true
}

# 03.08.04 Media Marking (Rev 2 3.8.4): Mark media with necessary CUI markings and distribution limitations
default media_marking := false

media_marking if {
	input.nist_800_171.media_protection.marking.cui_markings_applied == true
	input.nist_800_171.media_protection.marking.distribution_limitations_marked == true
	input.nist_800_171.media_protection.marking.marking_policy_documented == true
}

# 03.08.05 Media Transport (Rev 2 3.8.5): Control access to media containing CUI and maintain accountability for media
#         during transport
default media_transport_control := false

media_transport_control if {
	input.nist_800_171.media_protection.transport.access_controlled_during_transport == true
	input.nist_800_171.media_protection.transport.accountability_maintained == true
	input.nist_800_171.media_protection.transport.chain_of_custody_documented == true
}

# 03.13.08 (Rev 2 3.8.6, withdrawn in Rev 3: Incorporated into 03.13.08.): Implement cryptographic mechanisms to protect the confidentiality of CUI during
#         transport unless otherwise protected by alternative physical safeguards
default media_transport_encryption := false

media_transport_encryption if {
	input.nist_800_171.media_protection.transport_crypto.encryption_implemented == true
	input.nist_800_171.media_protection.transport_crypto.approved_algorithms == true
	input.nist_800_171.media_protection.transport_crypto.covers_all_cui_transport == true
}

# 03.08.07 Media Use (Rev 2 3.8.7): Control the use of removable media on system components
default removable_media_controlled := false

removable_media_controlled if {
	input.nist_800_171.media_protection.removable.usage_policy_defined == true
	input.nist_800_171.media_protection.removable.technical_controls_implemented == true
	input.nist_800_171.media_protection.removable.approval_required == true
}

# 03.08.07 (Rev 2 3.8.8, withdrawn in Rev 3: Incorporated into 03.08.07.): Prohibit the use of portable storage devices when such devices have no identifiable
#         owner
default portable_storage_owner_required := false

portable_storage_owner_required if {
	input.nist_800_171.media_protection.portable_storage.owner_identification_required == true
	input.nist_800_171.media_protection.portable_storage.unidentified_devices_prohibited == true
	input.nist_800_171.media_protection.portable_storage.enforcement_implemented == true
}

# 03.08.09 System Backup – Cryptographic Protection (Rev 2 3.8.9): Protect the confidentiality of backup CUI at storage locations
default backup_cui_protected := false

backup_cui_protected if {
	input.nist_800_171.media_protection.backup.backups_encrypted == true
	input.nist_800_171.media_protection.backup.storage_location_secured == true
	input.nist_800_171.media_protection.backup.access_restricted == true
}

# Violations set
violations contains msg if {
	not media_physical_protection
	msg := "NIST SP 800-171 03.08.01: System media containing CUI (paper and digital) must be physically controlled and securely stored"
}

violations contains msg if {
	not media_access_limited
	msg := "NIST SP 800-171 03.08.02: Access to CUI on system media must be limited to authorized users with a documented and enforced access list"
}

violations contains msg if {
	not media_sanitization_disposal
	msg := "NIST SP 800-171 03.08.03: System media must be sanitized using documented methods before disposal or reuse, with verification performed"
}

violations contains msg if {
	not media_marking
	msg := "NIST SP 800-171 03.08.04: Media must be marked with required CUI markings and distribution limitations per documented policy"
}

violations contains msg if {
	not media_transport_control
	msg := "NIST SP 800-171 03.08.05: Access to media containing CUI must be controlled during transport with chain-of-custody documentation"
}

violations contains msg if {
	not media_transport_encryption
	msg := "NIST SP 800-171 03.13.08 (Rev 2 3.8.6, withdrawn in Rev 3: Incorporated into 03.13.08.): Cryptographic mechanisms using approved algorithms must protect CUI confidentiality during transport"
}

violations contains msg if {
	not removable_media_controlled
	msg := "NIST SP 800-171 03.08.07: Use of removable media on system components must be controlled with defined policy and technical enforcement"
}

violations contains msg if {
	not portable_storage_owner_required
	msg := "NIST SP 800-171 03.08.07 (Rev 2 3.8.8, withdrawn in Rev 3: Incorporated into 03.08.07.): Portable storage devices without identifiable owners must be prohibited with technical enforcement"
}

violations contains msg if {
	not backup_cui_protected
	msg := "NIST SP 800-171 03.08.09: Backup CUI must be encrypted and stored in secured locations with restricted access"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.08 Media Protection",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 8,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.08.01_media_physical_protection": media_physical_protection,
		"03.08.02_media_access_limited": media_access_limited,
		"03.08.03_media_sanitization_disposal": media_sanitization_disposal,
		"03.08.04_media_marking": media_marking,
		"03.08.05_media_transport_control": media_transport_control,
		"03.13.08_media_transport_encryption": media_transport_encryption,
		"03.08.07_removable_media_controlled": removable_media_controlled,
		"03.08.07_portable_storage_owner_required": portable_storage_owner_required,
		"03.08.09_backup_cui_protected": backup_cui_protected,
	},
}
