# PCI DSS v4.0 Requirement 9 - Restrict Physical Access to Cardholder Data

package pci_dss.physical_security.requirement_9

import rego.v1

# =================================================================
# 9.1 - Processes and mechanisms for restricting physical access
# =================================================================

physical_security_policies_established if {
	input.pci.physical_security.policies.documented == true
	input.pci.physical_security.policies.approved == true
	input.pci.physical_security.policies.current == true
	input.pci.physical_security.policies.reviewed_annually == true
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
	input.pci.physical_access.sensitive_areas.cameras.installed == true
	input.pci.physical_access.sensitive_areas.cameras.footage_retained_days >= 90
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
	input.pci.visitors.log.retention_months >= 3
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
	not input.pci.poi_devices.in_scope
} else if {
	input.pci.poi_devices.in_scope
	input.pci.poi_devices.inventory.maintained == true
	input.pci.poi_devices.inspection.periodic == true
	input.pci.poi_devices.inspection.frequency_days <= 180
	input.pci.poi_devices.tampering.training_for_personnel == true
	input.pci.poi_devices.serial_numbers.verified == true
	input.pci.poi_devices.substitution.procedures_for_detecting == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_9_compliant if {
	physical_security_policies_established
	physical_security_roles_defined
	physical_access_controls
	badge_system
	physical_access_authorization
	visitor_management
	physical_media_controls
	media_distribution_secured
	media_destruction
	disk_destruction
	poi_device_protection
}

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
	"requirement_9_5": {
		"poi_device_protection": poi_device_protection,
	},
	"overall_score": pci_requirement_9_score,
	"overall_compliant": pci_requirement_9_compliant,
}
