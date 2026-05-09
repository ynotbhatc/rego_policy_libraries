package nist.sp800_171.media_protection

import rego.v1

# NIST SP 800-171 Rev 3 - Media Protection (MP) Requirements
# Family: 3.8 — Protecting Controlled Unclassified Information (CUI)

# 3.8.1: Protect (i.e., physically control and securely store) system media containing CUI,
#         both paper and digital
default media_physical_protection := false

media_physical_protection if {
    input.nist_800_171.media_protection.physical.paper_media_secured == true
    input.nist_800_171.media_protection.physical.digital_media_secured == true
    input.nist_800_171.media_protection.physical.access_controlled == true
}

# 3.8.2: Limit access to CUI on system media to authorized users
default media_access_limited := false

media_access_limited if {
    input.nist_800_171.media_protection.access.authorized_users_only == true
    input.nist_800_171.media_protection.access.access_list_documented == true
    input.nist_800_171.media_protection.access.access_enforcement_implemented == true
}

# 3.8.3: Sanitize or destroy system media before disposal or reuse
default media_sanitization_disposal := false

media_sanitization_disposal if {
    input.nist_800_171.media_protection.sanitization.sanitized_before_disposal == true
    input.nist_800_171.media_protection.sanitization.sanitized_before_reuse == true
    input.nist_800_171.media_protection.sanitization.method_documented == true
    input.nist_800_171.media_protection.sanitization.verification_performed == true
}

# 3.8.4: Mark media with necessary CUI markings and distribution limitations
default media_marking := false

media_marking if {
    input.nist_800_171.media_protection.marking.cui_markings_applied == true
    input.nist_800_171.media_protection.marking.distribution_limitations_marked == true
    input.nist_800_171.media_protection.marking.marking_policy_documented == true
}

# 3.8.5: Control access to media containing CUI and maintain accountability for media
#         during transport
default media_transport_control := false

media_transport_control if {
    input.nist_800_171.media_protection.transport.access_controlled_during_transport == true
    input.nist_800_171.media_protection.transport.accountability_maintained == true
    input.nist_800_171.media_protection.transport.chain_of_custody_documented == true
}

# 3.8.6: Implement cryptographic mechanisms to protect the confidentiality of CUI during
#         transport unless otherwise protected by alternative physical safeguards
default media_transport_encryption := false

media_transport_encryption if {
    input.nist_800_171.media_protection.transport_crypto.encryption_implemented == true
    input.nist_800_171.media_protection.transport_crypto.approved_algorithms == true
    input.nist_800_171.media_protection.transport_crypto.covers_all_cui_transport == true
}

# 3.8.7: Control the use of removable media on system components
default removable_media_controlled := false

removable_media_controlled if {
    input.nist_800_171.media_protection.removable.usage_policy_defined == true
    input.nist_800_171.media_protection.removable.technical_controls_implemented == true
    input.nist_800_171.media_protection.removable.approval_required == true
}

# 3.8.8: Prohibit the use of portable storage devices when such devices have no identifiable
#         owner
default portable_storage_owner_required := false

portable_storage_owner_required if {
    input.nist_800_171.media_protection.portable_storage.owner_identification_required == true
    input.nist_800_171.media_protection.portable_storage.unidentified_devices_prohibited == true
    input.nist_800_171.media_protection.portable_storage.enforcement_implemented == true
}

# 3.8.9: Protect the confidentiality of backup CUI at storage locations
default backup_cui_protected := false

backup_cui_protected if {
    input.nist_800_171.media_protection.backup.backups_encrypted == true
    input.nist_800_171.media_protection.backup.storage_location_secured == true
    input.nist_800_171.media_protection.backup.access_restricted == true
}

# Violations set
violations contains msg if {
    not media_physical_protection
    msg := "NIST 800-171 3.8.1: System media containing CUI (paper and digital) must be physically controlled and securely stored"
}

violations contains msg if {
    not media_access_limited
    msg := "NIST 800-171 3.8.2: Access to CUI on system media must be limited to authorized users with a documented and enforced access list"
}

violations contains msg if {
    not media_sanitization_disposal
    msg := "NIST 800-171 3.8.3: System media must be sanitized using documented methods before disposal or reuse, with verification performed"
}

violations contains msg if {
    not media_marking
    msg := "NIST 800-171 3.8.4: Media must be marked with required CUI markings and distribution limitations per documented policy"
}

violations contains msg if {
    not media_transport_control
    msg := "NIST 800-171 3.8.5: Access to media containing CUI must be controlled during transport with chain-of-custody documentation"
}

violations contains msg if {
    not media_transport_encryption
    msg := "NIST 800-171 3.8.6: Cryptographic mechanisms using approved algorithms must protect CUI confidentiality during transport"
}

violations contains msg if {
    not removable_media_controlled
    msg := "NIST 800-171 3.8.7: Use of removable media on system components must be controlled with defined policy and technical enforcement"
}

violations contains msg if {
    not portable_storage_owner_required
    msg := "NIST 800-171 3.8.8: Portable storage devices without identifiable owners must be prohibited with technical enforcement"
}

violations contains msg if {
    not backup_cui_protected
    msg := "NIST 800-171 3.8.9: Backup CUI must be encrypted and stored in secured locations with restricted access"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.8 Media Protection",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 9,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.8.1_media_physical_protection": media_physical_protection,
        "3.8.2_media_access_limited": media_access_limited,
        "3.8.3_media_sanitization_disposal": media_sanitization_disposal,
        "3.8.4_media_marking": media_marking,
        "3.8.5_media_transport_control": media_transport_control,
        "3.8.6_media_transport_encryption": media_transport_encryption,
        "3.8.7_removable_media_controlled": removable_media_controlled,
        "3.8.8_portable_storage_owner_required": portable_storage_owner_required,
        "3.8.9_backup_cui_protected": backup_cui_protected,
    },
}
