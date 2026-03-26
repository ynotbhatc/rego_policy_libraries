package ami.device.compliance

import rego.v1

# AMI 2.0 Device Compliance Policy
# Covers: firmware version/integrity, certificate expiry, key rotation,
#         communications encryption, mutual authentication, tamper detection
# OPA endpoint: /v1/data/ami/device/compliance

# Weak encryption algorithms prohibited on AMI devices
prohibited_algorithms := {"DES", "3DES", "RC4", "RC2", "MD5", "SHA1"}

# =============================================================================
# FIRMWARE COMPLIANCE HELPERS
# =============================================================================

firmware_meets_minimum(current_version, minimum_version) if {
    current_parts := split(current_version, ".")
    min_parts := split(minimum_version, ".")
    to_number(current_parts[0]) > to_number(min_parts[0])
}

firmware_meets_minimum(current_version, minimum_version) if {
    current_parts := split(current_version, ".")
    min_parts := split(minimum_version, ".")
    to_number(current_parts[0]) == to_number(min_parts[0])
    to_number(current_parts[1]) > to_number(min_parts[1])
}

firmware_meets_minimum(current_version, minimum_version) if {
    current_parts := split(current_version, ".")
    min_parts := split(minimum_version, ".")
    to_number(current_parts[0]) == to_number(min_parts[0])
    to_number(current_parts[1]) == to_number(min_parts[1])
    to_number(current_parts[2]) >= to_number(min_parts[2])
}

# =============================================================================
# TIME CONSTANTS
# =============================================================================

thirty_days_ns := 30 * 24 * 60 * 60 * 1000000000

ninety_days_ns := 90 * 24 * 60 * 60 * 1000000000

# =============================================================================
# PER-DEVICE COMPLIANCE CHECKS (return true = compliant)
# =============================================================================

firmware_current(device) if {
    firmware_meets_minimum(device.firmware.version, input.device_standards.minimum_firmware_version)
}

firmware_signed(device) if {
    device.firmware.signature_valid == true
    device.firmware.signature_algorithm in {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}
}

ota_updates_signed(device) if {
    device.firmware.ota_update_signing_required == true
    device.firmware.unsigned_updates_blocked == true
}

rollback_protection_enabled(device) if {
    device.firmware.rollback_protection == true
}

cert_not_expired(device) if {
    expiry_ns := time.parse_rfc3339_ns(device.certificate.expiry_date)
    expiry_ns > time.now_ns()
}

cert_not_expiring_soon(device) if {
    expiry_ns := time.parse_rfc3339_ns(device.certificate.expiry_date)
    (expiry_ns - time.now_ns()) > thirty_days_ns
}

cert_algorithm_strong(device) if {
    device.certificate.algorithm in {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}
}

key_rotation_current(device) if {
    last_rotation_ns := time.parse_rfc3339_ns(device.key_management.last_rotation_date)
    (time.now_ns() - last_rotation_ns) <= ninety_days_ns
}

keys_in_secure_storage(device) if {
    device.key_management.secure_storage in {"TPM", "secure_element", "HSM"}
}

strong_encryption_only(device) if {
    device_algorithms := {alg | alg := device.communications.encryption_algorithms[_]}
    count(device_algorithms & prohibited_algorithms) == 0
}

mutual_auth_enabled(device) if {
    device.communications.mutual_authentication == true
}

comms_encrypted(device) if {
    device.communications.encrypted == true
    device.communications.encryption_mode in {"AES-128-CCM", "AES-256-CCM", "AES-128-GCM", "AES-256-GCM"}
}

no_tamper_detected(device) if {
    device.security.tamper_status != "tamper_detected"
}

tamper_detection_operational(device) if {
    device.security.tamper_detection_enabled == true
    device.security.tamper_detection_status == "operational"
}

secure_boot_enabled(device) if {
    device.security.secure_boot == true
}

# =============================================================================
# PER-DEVICE VIOLATION LISTS (using comprehensions, not partial rules)
# =============================================================================

firmware_violation_msgs(device) := msgs if {
    msgs := array.concat(
        ([ sprintf("Device %v: Firmware %v is below minimum required version %v",
            [device.device_id, device.firmware.version, input.device_standards.minimum_firmware_version]) |
            not firmware_current(device)]),
        array.concat(
            ([ sprintf("Device %v: Firmware signature invalid or uses weak algorithm", [device.device_id]) |
                not firmware_signed(device)]),
            array.concat(
                ([ sprintf("Device %v: OTA firmware updates not enforced to be signed", [device.device_id]) |
                    not ota_updates_signed(device)]),
                ([ sprintf("Device %v: Firmware rollback protection not enabled", [device.device_id]) |
                    not rollback_protection_enabled(device)])
            )
        )
    )
}

cert_violation_msgs(device) := msgs if {
    expired_msgs := [ sprintf("Device %v: CRITICAL — Device certificate has expired", [device.device_id]) |
        not cert_not_expired(device)]
    expiring_msgs := [ sprintf("Device %v: WARNING — Device certificate expires within 30 days (%v)",
        [device.device_id, device.certificate.expiry_date]) |
        cert_not_expired(device)
        not cert_not_expiring_soon(device)]
    weak_algo_msgs := [ sprintf("Device %v: Certificate uses weak algorithm: %v",
        [device.device_id, device.certificate.algorithm]) |
        not cert_algorithm_strong(device)]
    msgs := array.concat(array.concat(expired_msgs, expiring_msgs), weak_algo_msgs)
}

key_violation_msgs(device) := msgs if {
    rotation_msgs := [ sprintf("Device %v: Key rotation overdue — last rotation: %v (>90 days ago)",
        [device.device_id, device.key_management.last_rotation_date]) |
        not key_rotation_current(device)]
    storage_msgs := [ sprintf("Device %v: Keys not stored in secure hardware (TPM/secure element/HSM)",
        [device.device_id]) |
        not keys_in_secure_storage(device)]
    msgs := array.concat(rotation_msgs, storage_msgs)
}

comms_violation_msgs(device) := msgs if {
    weak_cipher_msgs := [ sprintf("Device %v: Prohibited encryption algorithms in use",
        [device.device_id]) |
        not strong_encryption_only(device)]
    no_mutual_auth_msgs := [ sprintf("Device %v: Mutual authentication with head-end not enabled",
        [device.device_id]) |
        not mutual_auth_enabled(device)]
    not_encrypted_msgs := [ sprintf("Device %v: Communications not encrypted with approved AES mode",
        [device.device_id]) |
        not comms_encrypted(device)]
    msgs := array.concat(array.concat(weak_cipher_msgs, no_mutual_auth_msgs), not_encrypted_msgs)
}

tamper_violation_msgs(device) := msgs if {
    tamper_msgs := [ sprintf("Device %v: CRITICAL — Physical tamper detected! Immediate investigation required",
        [device.device_id]) |
        not no_tamper_detected(device)]
    detection_msgs := [ sprintf("Device %v: Tamper detection hardware not enabled or not operational",
        [device.device_id]) |
        not tamper_detection_operational(device)]
    boot_msgs := [ sprintf("Device %v: Secure boot not enabled", [device.device_id]) |
        not secure_boot_enabled(device)]
    msgs := array.concat(array.concat(tamper_msgs, detection_msgs), boot_msgs)
}

device_all_violations(device) := msgs if {
    fw_cm := array.concat(firmware_violation_msgs(device), cert_violation_msgs(device))
    kv_cv := array.concat(key_violation_msgs(device), comms_violation_msgs(device))
    first_half := array.concat(fw_cm, kv_cv)
    msgs := array.concat(first_half, tamper_violation_msgs(device))
}

# =============================================================================
# AGGREGATE VIOLATIONS ACROSS ALL DEVICES
# =============================================================================

device_violations[device.device_id] := device_all_violations(device) if {
    device := input.devices[_]
}

all_violations := [msg |
    device := input.devices[_]
    msg := device_all_violations(device)[_]
]

critical_violations := [msg |
    msg := all_violations[_]
    contains(msg, "CRITICAL")
]

# =============================================================================
# AGGREGATE COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
    count(all_violations) == 0
}

total_devices := count(input.devices)

compliant_devices := count([1 |
    device := input.devices[_]
    count(device_all_violations(device)) == 0
])

compliance_report := {
    "framework": "AMI 2.0 Device Compliance",
    "standards_applied": ["NIST IR 7628", "ANSI C12.22", "IEC 62351"],
    "total_devices": total_devices,
    "compliant_devices": compliant_devices,
    "non_compliant_devices": total_devices - compliant_devices,
    "total_violations": count(all_violations),
    "critical_violations": count(critical_violations),
    "compliant": compliant,
    "per_device_violations": device_violations,
    "all_violations": all_violations,
}
