package cmmc.media_protection

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.8: Media Protection
# NIST SP 800-171 Rev 2 — 9 Practices
# =============================================================================

# 3.8.1 — Protect system media containing CUI, both paper and digital. (L2)
default compliant_3_8_1 := false
compliant_3_8_1 if {
    input.media.digital_media_protected == true
    input.media.paper_media_protected == true
    input.media.media_access_controlled == true
}

violation_3_8_1 contains msg if {
    not input.media.digital_media_protected
    msg := "3.8.1: Digital media containing CUI is not protected"
}
violation_3_8_1 contains msg if {
    not input.media.paper_media_protected
    msg := "3.8.1: Paper media containing CUI is not protected"
}
violation_3_8_1 contains msg if {
    not input.media.media_access_controlled
    msg := "3.8.1: Access to CUI media is not controlled"
}

# 3.8.2 — Limit access to CUI on system media to authorized users. (L2)
default compliant_3_8_2 := false
compliant_3_8_2 if {
    input.media.media_access_restricted_to_authorized == true
    input.media.media_access_list_maintained == true
}

violation_3_8_2 contains msg if {
    not input.media.media_access_restricted_to_authorized
    msg := "3.8.2: CUI media access is not restricted to authorized users"
}
violation_3_8_2 contains msg if {
    not input.media.media_access_list_maintained
    msg := "3.8.2: No maintained list of users authorized to access CUI media"
}

# 3.8.3 — Sanitize or destroy system media before disposal or reuse. (L2)
default compliant_3_8_3 := false
compliant_3_8_3 if {
    input.media.sanitization_policy_exists == true
    input.media.nist_800_88_compliant == true
    input.media.sanitization_records_kept == true
}

violation_3_8_3 contains msg if {
    not input.media.sanitization_policy_exists
    msg := "3.8.3: No media sanitization policy before disposal or reuse"
}
violation_3_8_3 contains msg if {
    not input.media.nist_800_88_compliant
    msg := "3.8.3: Media sanitization does not comply with NIST SP 800-88 guidelines"
}
violation_3_8_3 contains msg if {
    not input.media.sanitization_records_kept
    msg := "3.8.3: Media sanitization/destruction records are not maintained"
}

# 3.8.4 — Mark media with necessary CUI markings and distribution
#          limitations. (L2)
default compliant_3_8_4 := false
compliant_3_8_4 if {
    input.media.cui_marking_policy == true
    input.media.media_labeled_with_classification == true
}

violation_3_8_4 contains msg if {
    not input.media.cui_marking_policy
    msg := "3.8.4: No policy for marking media with CUI designations"
}
violation_3_8_4 contains msg if {
    not input.media.media_labeled_with_classification
    msg := "3.8.4: CUI media is not labeled with appropriate markings and distribution limits"
}

# 3.8.5 — Control access to media containing CUI and maintain accountability
#          for media during transport. (L2)
default compliant_3_8_5 := false
compliant_3_8_5 if {
    input.media.transport_controls_implemented == true
    input.media.chain_of_custody_maintained == true
    input.media.encrypted_during_transport == true
}

violation_3_8_5 contains msg if {
    not input.media.transport_controls_implemented
    msg := "3.8.5: No controls for CUI media during transport"
}
violation_3_8_5 contains msg if {
    not input.media.chain_of_custody_maintained
    msg := "3.8.5: Chain of custody is not maintained for CUI media in transport"
}
violation_3_8_5 contains msg if {
    not input.media.encrypted_during_transport
    msg := "3.8.5: CUI media is not encrypted during transport"
}

# 3.8.6 — Implement cryptographic mechanisms to protect CUI during transport
#          unless otherwise protected by alternative physical safeguards. (L2)
default compliant_3_8_6 := false
compliant_3_8_6 if {
    input.media.encryption_at_rest == true
    input.media.fips_validated_encryption == true
}

violation_3_8_6 contains msg if {
    not input.media.encryption_at_rest
    msg := "3.8.6: CUI media is not encrypted at rest"
}
violation_3_8_6 contains msg if {
    not input.media.fips_validated_encryption
    msg := "3.8.6: Media encryption does not use FIPS-validated cryptographic modules"
}

# 3.8.7 — Control the use of removable media on system components. (L2)
default compliant_3_8_7 := false
compliant_3_8_7 if {
    input.media.removable_media_policy == true
    input.media.unauthorized_removable_media_blocked == true
}

violation_3_8_7 contains msg if {
    not input.media.removable_media_policy
    msg := "3.8.7: No policy controlling use of removable media on system components"
}
violation_3_8_7 contains msg if {
    not input.media.unauthorized_removable_media_blocked
    msg := "3.8.7: Unauthorized removable media is not blocked (USB, SD cards, etc.)"
}

# 3.8.8 — Prohibit the use of portable storage devices when such devices have
#          no identifiable owner. (L2)
default compliant_3_8_8 := false
compliant_3_8_8 if {
    input.media.unowned_portable_storage_prohibited == true
    input.media.device_registration_required == true
}

violation_3_8_8 contains msg if {
    not input.media.unowned_portable_storage_prohibited
    msg := "3.8.8: Portable storage devices without identifiable owners are not prohibited"
}
violation_3_8_8 contains msg if {
    not input.media.device_registration_required
    msg := "3.8.8: Portable storage devices are not required to be registered/identified"
}

# 3.8.9 — Protect the confidentiality of backup CUI at storage locations. (L2)
default compliant_3_8_9 := false
compliant_3_8_9 if {
    input.media.backup_cui_encrypted == true
    input.media.backup_storage_access_controlled == true
    input.media.backup_integrity_verified == true
}

violation_3_8_9 contains msg if {
    not input.media.backup_cui_encrypted
    msg := "3.8.9: Backup CUI is not encrypted at storage locations"
}
violation_3_8_9 contains msg if {
    not input.media.backup_storage_access_controlled
    msg := "3.8.9: Access to backup CUI storage locations is not controlled"
}
violation_3_8_9 contains msg if {
    not input.media.backup_integrity_verified
    msg := "3.8.9: Backup integrity is not verified to detect unauthorized modification"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations_1_4 := array.concat(
    array.concat(
        [v | some v in violation_3_8_1],
        [v | some v in violation_3_8_2]
    ),
    array.concat(
        [v | some v in violation_3_8_3],
        [v | some v in violation_3_8_4]
    )
)

all_violations_5_9 := array.concat(
    array.concat(
        [v | some v in violation_3_8_5],
        [v | some v in violation_3_8_6]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_3_8_7],
            [v | some v in violation_3_8_8]
        ),
        [v | some v in violation_3_8_9]
    )
)

all_violations := array.concat(all_violations_1_4, all_violations_5_9)

practices := [
    {"id": "3.8.1", "level": 2, "compliant": compliant_3_8_1},
    {"id": "3.8.2", "level": 2, "compliant": compliant_3_8_2},
    {"id": "3.8.3", "level": 2, "compliant": compliant_3_8_3},
    {"id": "3.8.4", "level": 2, "compliant": compliant_3_8_4},
    {"id": "3.8.5", "level": 2, "compliant": compliant_3_8_5},
    {"id": "3.8.6", "level": 2, "compliant": compliant_3_8_6},
    {"id": "3.8.7", "level": 2, "compliant": compliant_3_8_7},
    {"id": "3.8.8", "level": 2, "compliant": compliant_3_8_8},
    {"id": "3.8.9", "level": 2, "compliant": compliant_3_8_9},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Media Protection",
    "domain_id": "3.8",
    "total_practices": 9,
    "passing": passing_count,
    "failing": 9 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
