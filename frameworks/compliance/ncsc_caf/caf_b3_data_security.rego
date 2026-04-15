package ncsc_caf.b3_data_security

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective B — Protecting Against Cyber Attack
# Principle B3 — Data Security
#
# Contributing Outcomes covered (automatable subset):
#   B3.b — Data in Transit
#   B3.c — Stored Data
#   B3.d — Mobile Data
#
# Note: B3.a (Understanding Data) and B3.e (Media Sanitisation) are
# partially/non-automatable and handled in caf_objective_b_governance.rego
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# B3.b — Data in Transit
# IGPs: All data links encrypted, TLS 1.2+ minimum, no unencrypted protocols
#       in use (telnet/ftp/http), alternative paths for critical links,
#       certificates valid and current
# ---------------------------------------------------------------------------

default _b3b_all_links_encrypted := false
_b3b_all_links_encrypted if {
    input.data_in_transit.all_links_encrypted == true
}

default _b3b_tls_min_version_strong := false
_b3b_tls_min_version_strong if {
    tls_ver := input.data_in_transit.tls_min_version
    tls_ver in ["1.2", "1.3"]
}

default _b3b_tls_version_acceptable := false
_b3b_tls_version_acceptable if {
    tls_ver := input.data_in_transit.tls_min_version
    tls_ver in ["1.1", "1.2", "1.3"]
}

default _b3b_no_unencrypted_protocols := false
_b3b_no_unencrypted_protocols if {
    count(input.data_in_transit.unencrypted_protocols_in_use) == 0
}

default _b3b_cert_valid := false
_b3b_cert_valid if {
    input.data_in_transit.cert_validity_days_remaining > 30
}

default _b3b_fully_achieved := false
_b3b_fully_achieved if {
    _b3b_all_links_encrypted
    _b3b_tls_min_version_strong
    _b3b_no_unencrypted_protocols
    _b3b_cert_valid
}

default _b3b_partially_achieved := false
_b3b_partially_achieved if {
    _b3b_tls_version_acceptable
    _b3b_cert_valid
}

default co_b3b_achievement := "not_achieved"

co_b3b_achievement := "achieved" if { _b3b_fully_achieved }

co_b3b_achievement := "partially_achieved" if {
    not _b3b_fully_achieved
    _b3b_partially_achieved
}

co_b3b_details := {
    "all_links_encrypted": _b3b_all_links_encrypted,
    "tls_min_version": object.get(input, ["data_in_transit", "tls_min_version"], "unknown"),
    "tls_version_adequate": _b3b_tls_min_version_strong,
    "unencrypted_protocols_in_use": object.get(input, ["data_in_transit", "unencrypted_protocols_in_use"], []),
    "certificate_valid": _b3b_cert_valid,
    "cert_validity_days_remaining": object.get(input, ["data_in_transit", "cert_validity_days_remaining"], 0),
    "achievement": co_b3b_achievement,
}

# ---------------------------------------------------------------------------
# B3.c — Stored Data
# IGPs: Encryption at rest on all important data stores, cryptographic
#       protection with justified confidence, offline/segregated backups,
#       backup restore tested, backup integrity verified
# ---------------------------------------------------------------------------

default _b3c_encryption_at_rest := false
_b3c_encryption_at_rest if {
    input.stored_data.encryption_at_rest == true
}

default _b3c_backup_exists := false
_b3c_backup_exists if {
    input.stored_data.backup_exists == true
}

default _b3c_backup_recent := false
_b3c_backup_recent if {
    input.stored_data.backup_age_days <= 1
}

default _b3c_backup_acceptable_age := false
_b3c_backup_acceptable_age if {
    input.stored_data.backup_age_days <= 7
}

default _b3c_backup_segregated := false
_b3c_backup_segregated if {
    input.stored_data.backup_segregated == true
}

default _b3c_restore_tested := false
_b3c_restore_tested if {
    input.stored_data.restore_test_days <= 30
}

default _b3c_restore_tested_annually := false
_b3c_restore_tested_annually if {
    input.stored_data.restore_test_days <= 365
}

default _b3c_fully_achieved := false
_b3c_fully_achieved if {
    _b3c_encryption_at_rest
    _b3c_backup_exists
    _b3c_backup_recent
    _b3c_backup_segregated
    _b3c_restore_tested
}

default _b3c_partially_achieved := false
_b3c_partially_achieved if {
    _b3c_encryption_at_rest
    _b3c_backup_exists
    _b3c_backup_acceptable_age
}

default co_b3c_achievement := "not_achieved"

co_b3c_achievement := "achieved" if { _b3c_fully_achieved }

co_b3c_achievement := "partially_achieved" if {
    not _b3c_fully_achieved
    _b3c_partially_achieved
}

co_b3c_details := {
    "encryption_at_rest": _b3c_encryption_at_rest,
    "backup_exists": _b3c_backup_exists,
    "backup_age_days": object.get(input, ["stored_data", "backup_age_days"], 9999),
    "backup_segregated": _b3c_backup_segregated,
    "restore_test_days": object.get(input, ["stored_data", "restore_test_days"], 9999),
    "restore_tested_recently": _b3c_restore_tested,
    "achievement": co_b3c_achievement,
}

# ---------------------------------------------------------------------------
# B3.d — Mobile Data
# IGPs: All mobile devices under MDM, device encryption enforced,
#       remote wipe capability configured, data minimised on devices,
#       devices configured to platform security best practice
# ---------------------------------------------------------------------------

default _b3d_mdm_enrolled := false
_b3d_mdm_enrolled if {
    input.mobile_data.mdm_enrolled == true
}

default _b3d_device_encrypted := false
_b3d_device_encrypted if {
    input.mobile_data.device_encryption == true
}

default _b3d_remote_wipe := false
_b3d_remote_wipe if {
    input.mobile_data.remote_wipe_configured == true
}

default _b3d_data_minimised := false
_b3d_data_minimised if {
    input.mobile_data.data_minimised == true
}

default _b3d_fully_achieved := false
_b3d_fully_achieved if {
    _b3d_mdm_enrolled
    _b3d_device_encrypted
    _b3d_remote_wipe
    _b3d_data_minimised
}

default _b3d_partially_achieved := false
_b3d_partially_achieved if {
    _b3d_mdm_enrolled
    _b3d_device_encrypted
}

default co_b3d_achievement := "not_achieved"

co_b3d_achievement := "achieved" if { _b3d_fully_achieved }

co_b3d_achievement := "partially_achieved" if {
    not _b3d_fully_achieved
    _b3d_partially_achieved
}

co_b3d_details := {
    "mdm_enrolled": _b3d_mdm_enrolled,
    "device_encryption": _b3d_device_encrypted,
    "remote_wipe_configured": _b3d_remote_wipe,
    "data_minimised": _b3d_data_minimised,
    "achievement": co_b3d_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default b3_compliant := false

b3_compliant if {
    co_b3b_achievement == "achieved"
    co_b3c_achievement == "achieved"
    co_b3d_achievement == "achieved"
}

b3_achievement_counts := {
    "achieved": count([co | some co in [co_b3b_achievement, co_b3c_achievement, co_b3d_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_b3b_achievement, co_b3c_achievement, co_b3d_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_b3b_achievement, co_b3c_achievement, co_b3d_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "B3",
    "name": "Data Security",
    "compliant": b3_compliant,
    "achievement_counts": b3_achievement_counts,
    "contributing_outcomes": {
        "B3.b": co_b3b_details,
        "B3.c": co_b3c_details,
        "B3.d": co_b3d_details,
    },
}
