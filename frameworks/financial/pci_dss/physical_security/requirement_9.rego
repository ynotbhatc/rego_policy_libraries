# PCI DSS v4.0.1 Requirement 9 - Restrict Physical Access to Cardholder Data

# METADATA
# title: "PCI DSS v4.0.1 Requirement 9 - Restrict Physical Access to Cardholder Data"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 12
#     cited: 5
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.physical_security.requirement_9

import rego.v1

# Numbers are compared only when they are numbers: OPA orders every string above every number, so a string
# such as "5" would otherwise satisfy `>= 12` (audit 2026-11-17 follow-up).
_num_ge(x, n) if {
	is_number(x)
	x >= n
}

# A frequency the entity defines in its targeted risk analysis (12.3.1): both the defined value and the
# actual value must be numbers, and the actual must not exceed the defined one.
_within_defined(actual, defined) if {
	is_number(actual)
	is_number(defined)
	defined > 0
	actual <= defined
}

# =================================================================
# 9.1 - Processes and mechanisms for restricting physical access
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
physical_security_policies_established if {
	input.pci.physical_security.policies.documented == true
	input.pci.physical_security.policies.approved == true
	input.pci.physical_security.policies.current == true
}

physical_security_roles_defined if {
	input.pci.physical_security.roles.defined == true
	input.pci.physical_security.responsibilities.assigned == true
}

# =================================================================
# 9.2 - Physical access controls manage entry into facilities and systems
# =================================================================

# Physical access controls for sensitive areas
physical_access_controls if {
	input.pci.physical_access.sensitive_areas.access_controls_implemented == true
	input.pci.physical_access.sensitive_areas.entry_logs.maintained == true
	_sensitive_area_monitoring
}

# 9.2.1.1: entry/exit of sensitive areas monitored with video cameras OR physical access control mechanisms
# (or both), collected data kept at least three months.
_sensitive_area_monitoring if {
	input.pci.physical_access.sensitive_areas.cameras.installed == true
	_num_ge(input.pci.physical_access.sensitive_areas.cameras.footage_retained_days, 90)
}

_sensitive_area_monitoring if {
	input.pci.physical_access.sensitive_areas.access_control_mechanisms.monitor_entry_exit == true
	_num_ge(input.pci.physical_access.sensitive_areas.access_control_mechanisms.data_retained_days, 90)
}

# Badge or other ID management
badge_system if {
	input.pci.badge_system.implemented == true
	input.pci.badge_system.unique_per_individual == true
	input.pci.badge_system.lost_badges.revoked_immediately == true
	input.pci.badge_system.terminated_employees.revoked_immediately == true
}

# Network jacks in public areas disabled
public_network_jacks_disabled if {
	input.pci.network_access.public_area_jacks.disabled == true
	input.pci.network_access.public_area_wireless.restricted == true
}

# =================================================================
# 9.3 - Physical access for personnel and visitors managed
# =================================================================

# Physical access authorization process
physical_access_authorization if {
	input.pci.physical_access.authorization.documented == true
	input.pci.physical_access.authorization.approval_required == true
	input.pci.physical_access.authorization.regularly_reviewed == true
	input.pci.physical_access.authorization.access_list.current == true
}

# Visitor management
visitor_management if {
	input.pci.visitors.identification.required == true
	input.pci.visitors.badge.temporary_issued == true
	input.pci.visitors.badge.visually_distinguishable == true
	input.pci.visitors.escort.required_in_sensitive_areas == true
	input.pci.visitors.log.maintained == true
	_num_ge(input.pci.visitors.log.retention_months, 3)
	input.pci.visitors.badge.surrendered_on_departure == true
}

# =================================================================
# 9.4 - Media with cardholder data is securely stored, accessed, distributed and destroyed
# =================================================================

# Physical media controls
physical_media_controls if {
	input.pci.media.inventory.maintained == true
	input.pci.media.storage.physically_secured == true
	input.pci.media.access.restricted_to_authorized == true
	input.pci.media.external_distribution.management_approval == true
	input.pci.media.external_distribution.logged == true
}

# Media sent outside facility secured
media_distribution_secured if {
	input.pci.media.distribution.tracking_implemented == true
	input.pci.media.distribution.secured_courier == true
	input.pci.media.distribution.management_approval_required == true
	input.pci.media.distribution.encrypted == true
}

# Media destruction
media_destruction if {
	input.pci.media.destruction.secure_process == true
	input.pci.media.destruction.certificates_obtained == true
	input.pci.media.destruction.cross_cut_shredding_or_equivalent == true
	input.pci.media.destruction.log.maintained == true
	input.pci.media.destruction.third_party.verified == true
}

# Hard disk destruction or cryptographic wiping
disk_destruction if {
	input.pci.disk.destruction.dod_or_nist_wipe == true
	input.pci.disk.destruction.cryptographic_erasure_acceptable == true
	input.pci.disk.destruction.physical_destruction.when_cryptographic_not_possible == true
	input.pci.disk.destruction.documented == true
}

# =================================================================
# 9.5 - Point-of-interaction devices protected from tampering and substitution
# =================================================================

poi_device_protection if {
	# Only required if POI devices are used
	input.pci.poi_devices.in_scope == false
} else if {
	input.pci.poi_devices.in_scope == true
	input.pci.poi_devices.inventory.maintained == true
	input.pci.poi_devices.inspection.periodic == true

	# 9.5.1.2.1: inspection frequency defined by the entity's targeted risk analysis
	_within_defined(input.pci.poi_devices.inspection.frequency_days, input.pci.poi_devices.inspection.tra_defined_frequency_days)
	input.pci.poi_devices.tampering.training_for_personnel == true
	input.pci.poi_devices.serial_numbers.verified == true
	input.pci.poi_devices.substitution.procedures_for_detecting == true
}

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default physical_security_policies_established := false

default physical_security_roles_defined := false

default physical_access_controls := false

default badge_system := false

default public_network_jacks_disabled := false

default physical_access_authorization := false

default visitor_management := false

default physical_media_controls := false

default media_distribution_secured := false

default media_destruction := false

default disk_destruction := false

default poi_device_protection := false

default pci_requirement_9_compliant := false

# =================================================================
# Scoring
# =================================================================

pci_requirement_9_compliant if {
	physical_security_policies_established
	physical_security_roles_defined
	physical_access_controls
	badge_system
	public_network_jacks_disabled
	physical_access_authorization
	visitor_management
	physical_media_controls
	media_distribution_secured
	media_destruction
	disk_destruction
	poi_device_protection
}

default pci_requirement_9_score := 0

default pci_requirement_9_findings := {}

pci_requirement_9_score := score if {
	controls := [
		physical_security_policies_established,
		physical_security_roles_defined,
		physical_access_controls,
		badge_system,
		public_network_jacks_disabled,
		physical_access_authorization,
		visitor_management,
		physical_media_controls,
		media_distribution_secured,
		media_destruction,
		disk_destruction,
		poi_device_protection,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_9_findings := {
	"requirement_9_1": {
		"policies_established": physical_security_policies_established,
		"roles_defined": physical_security_roles_defined,
	},
	"requirement_9_2": {
		"physical_access_controls": physical_access_controls,
		"badge_system": badge_system,
		"public_jacks_disabled": public_network_jacks_disabled,
	},
	"requirement_9_3": {
		"access_authorization": physical_access_authorization,
		"visitor_management": visitor_management,
	},
	"requirement_9_4": {
		"media_controls": physical_media_controls,
		"media_distribution": media_distribution_secured,
		"media_destruction": media_destruction,
		"disk_destruction": disk_destruction,
	},
	"requirement_9_5": {"poi_device_protection": poi_device_protection},
	"overall_score": pci_requirement_9_score,
	"overall_compliant": pci_requirement_9_compliant,
}

# BEGIN evidence_spec (generated by scripts/gen_pci_dss_evidence_spec.py; do not edit by hand)
# The facts each check that gates pci_requirement_9_compliant reads, for pci_dss.main: a failing check is
# "evidence missing" when no alternative holds a present, non-compliant fact and some fact is absent or of
# the wrong type. Term tests are described in the generator's docstring.
evidence_spec := {
	"physical_security_policies_established": {
		"passed": physical_security_policies_established,
		"alternatives": [
			[["pci.physical_security.policies.documented", "true"], ["pci.physical_security.policies.approved", "true"], ["pci.physical_security.policies.current", "true"]],
		],
	},
	"physical_security_roles_defined": {
		"passed": physical_security_roles_defined,
		"alternatives": [
			[["pci.physical_security.roles.defined", "true"], ["pci.physical_security.responsibilities.assigned", "true"]],
		],
	},
	"physical_access_controls": {
		"passed": physical_access_controls,
		"alternatives": [
			[["pci.physical_access.sensitive_areas.access_controls_implemented", "true"], ["pci.physical_access.sensitive_areas.entry_logs.maintained", "true"], ["pci.physical_access.sensitive_areas.cameras.installed", "true"], ["pci.physical_access.sensitive_areas.cameras.footage_retained_days", "ge", 90]],
			[["pci.physical_access.sensitive_areas.access_controls_implemented", "true"], ["pci.physical_access.sensitive_areas.entry_logs.maintained", "true"], ["pci.physical_access.sensitive_areas.access_control_mechanisms.monitor_entry_exit", "true"], ["pci.physical_access.sensitive_areas.access_control_mechanisms.data_retained_days", "ge", 90]],
		],
	},
	"badge_system": {
		"passed": badge_system,
		"alternatives": [
			[["pci.badge_system.implemented", "true"], ["pci.badge_system.unique_per_individual", "true"], ["pci.badge_system.lost_badges.revoked_immediately", "true"], ["pci.badge_system.terminated_employees.revoked_immediately", "true"]],
		],
	},
	"public_network_jacks_disabled": {
		"passed": public_network_jacks_disabled,
		"alternatives": [
			[["pci.network_access.public_area_jacks.disabled", "true"], ["pci.network_access.public_area_wireless.restricted", "true"]],
		],
	},
	"physical_access_authorization": {
		"passed": physical_access_authorization,
		"alternatives": [
			[["pci.physical_access.authorization.documented", "true"], ["pci.physical_access.authorization.approval_required", "true"], ["pci.physical_access.authorization.regularly_reviewed", "true"], ["pci.physical_access.authorization.access_list.current", "true"]],
		],
	},
	"visitor_management": {
		"passed": visitor_management,
		"alternatives": [
			[["pci.visitors.identification.required", "true"], ["pci.visitors.badge.temporary_issued", "true"], ["pci.visitors.badge.visually_distinguishable", "true"], ["pci.visitors.escort.required_in_sensitive_areas", "true"], ["pci.visitors.log.maintained", "true"], ["pci.visitors.log.retention_months", "ge", 3], ["pci.visitors.badge.surrendered_on_departure", "true"]],
		],
	},
	"physical_media_controls": {
		"passed": physical_media_controls,
		"alternatives": [
			[["pci.media.inventory.maintained", "true"], ["pci.media.storage.physically_secured", "true"], ["pci.media.access.restricted_to_authorized", "true"], ["pci.media.external_distribution.management_approval", "true"], ["pci.media.external_distribution.logged", "true"]],
		],
	},
	"media_distribution_secured": {
		"passed": media_distribution_secured,
		"alternatives": [
			[["pci.media.distribution.tracking_implemented", "true"], ["pci.media.distribution.secured_courier", "true"], ["pci.media.distribution.management_approval_required", "true"], ["pci.media.distribution.encrypted", "true"]],
		],
	},
	"media_destruction": {
		"passed": media_destruction,
		"alternatives": [
			[["pci.media.destruction.secure_process", "true"], ["pci.media.destruction.certificates_obtained", "true"], ["pci.media.destruction.cross_cut_shredding_or_equivalent", "true"], ["pci.media.destruction.log.maintained", "true"], ["pci.media.destruction.third_party.verified", "true"]],
		],
	},
	"disk_destruction": {
		"passed": disk_destruction,
		"alternatives": [
			[["pci.disk.destruction.dod_or_nist_wipe", "true"], ["pci.disk.destruction.cryptographic_erasure_acceptable", "true"], ["pci.disk.destruction.physical_destruction.when_cryptographic_not_possible", "true"], ["pci.disk.destruction.documented", "true"]],
		],
	},
	"poi_device_protection": {
		"passed": poi_device_protection,
		"alternatives": [
			[["pci.poi_devices.in_scope", "false"]],
			[["pci.poi_devices.in_scope", "true"], ["pci.poi_devices.inventory.maintained", "true"], ["pci.poi_devices.inspection.periodic", "true"], ["pci.poi_devices.inspection.frequency_days", "within", "pci.poi_devices.inspection.tra_defined_frequency_days"], ["pci.poi_devices.tampering.training_for_personnel", "true"], ["pci.poi_devices.serial_numbers.verified", "true"], ["pci.poi_devices.substitution.procedures_for_detecting", "true"]],
		],
	},
}

# END evidence_spec
