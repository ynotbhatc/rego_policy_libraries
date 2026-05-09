package csa_ccm.endpoint_management

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.endpoint_management.uem_policy.policy_established
    msg := "UEM-01: Endpoint management policy not formally established for all device types accessing cloud services"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.uem_policy.byod_policy_defined
    msg := "UEM-01: BYOD (bring your own device) policy not defined — personal device access to corporate data must be governed"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.uem_policy.policy_reviewed_annually
    msg := "UEM-01: Endpoint management policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.uem_policy.all_device_types_in_scope
    msg := "UEM-01: All device types (laptops, mobile, tablets, IoT) not included in endpoint management policy scope"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.mdm_deployment.mdm_uem_solution_deployed
    msg := "UEM-02: MDM/UEM solution not deployed — endpoint management must be centralized for all managed devices"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.mdm_deployment.all_managed_devices_enrolled
    msg := "UEM-02: All managed devices not enrolled in MDM/UEM platform — unenrolled devices must be blocked from corporate resources"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.mdm_deployment.compliance_policies_enforced
    msg := "UEM-02: Device compliance policies not enforced via MDM/UEM — non-compliant devices must be blocked or quarantined"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.mdm_deployment.device_inventory_maintained
    msg := "UEM-02: Device inventory not maintained through MDM/UEM — all managed endpoints must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.device_encryption.encryption_enforced
    msg := "UEM-03: Device encryption not enforced on all managed endpoints — full-disk encryption must be enabled"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.device_encryption.encryption_compliance_monitored
    msg := "UEM-03: Endpoint encryption compliance not monitored — devices without encryption must be identified and remediated"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.device_encryption.mobile_device_encryption_enforced
    msg := "UEM-03: Mobile device encryption not enforced — smartphones and tablets accessing corporate data must encrypt storage"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.remote_wipe.remote_wipe_capability_enabled
    msg := "UEM-04: Remote wipe capability not enabled for managed devices — lost or stolen devices must be remotely wiped"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.remote_wipe.remote_wipe_procedure_defined
    msg := "UEM-04: Remote wipe procedure not defined — process for initiating wipe upon device loss or employee termination must be documented"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.remote_wipe.selective_wipe_for_byod
    msg := "UEM-04: Selective wipe capability not implemented for BYOD — corporate data must be removable without wiping personal data"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.byod.byod_policy_enforced
    msg := "UEM-05: BYOD policy not enforced — personal devices accessing corporate resources must meet minimum security requirements"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.byod.containerization_or_mam_implemented
    msg := "UEM-05: Containerization or mobile application management (MAM) not implemented to isolate corporate data on BYOD devices"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.byod.jailbroken_rooted_devices_blocked
    msg := "UEM-05: Jailbroken or rooted devices not blocked from accessing corporate applications and data"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.byod.minimum_os_version_enforced
    msg := "UEM-05: Minimum OS version not enforced for BYOD devices — outdated OS versions must be blocked"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.edr.edr_solution_deployed
    msg := "UEM-06: Endpoint detection and response (EDR) solution not deployed on managed endpoints"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.edr.edr_coverage_complete
    msg := "UEM-06: EDR coverage not complete — all managed servers and workstations must have EDR agent installed and reporting"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.edr.edr_alerts_monitored
    msg := "UEM-06: EDR alerts not actively monitored — threat detections must be reviewed and responded to within defined SLA"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.edr.automated_response_enabled
    msg := "UEM-06: EDR automated response not enabled — high-confidence threat detections should trigger automated containment"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.endpoint_patching.patch_management_implemented
    msg := "UEM-07: Endpoint patch management not implemented — all managed devices must receive security patches"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.endpoint_patching.critical_patches_applied_timely
    msg := "UEM-07: Critical endpoint patches not applied within defined SLA — critical OS and application patches must be deployed promptly"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.endpoint_patching.patch_compliance_monitored
    msg := "UEM-07: Endpoint patch compliance not monitored — unpatched devices must be identified and reported"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.endpoint_patching.patch_testing_before_deployment
    msg := "UEM-07: Patches not tested before broad deployment — pilot deployment must verify patch stability"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.removable_media.removable_media_policy_defined
    msg := "UEM-08: Removable media (USB, external drives) policy not defined — use must be governed and restricted"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.removable_media.unauthorized_media_blocked
    msg := "UEM-08: Unauthorized removable media not blocked — only approved and encrypted media must be permitted"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.removable_media.media_scanning_enforced
    msg := "UEM-08: Removable media not scanned for malware upon connection — automatic scanning must be enforced"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.screen_lock.screen_lock_enforced
    msg := "UEM-09: Screen lock not enforced on managed endpoints — automatic lock after defined idle period must be configured"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.screen_lock.screen_lock_timeout_appropriate
    msg := "UEM-09: Screen lock timeout not appropriate — maximum idle time before lock must not exceed 15 minutes"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.application_control.application_allowlisting_implemented
    msg := "UEM-10: Application allowlisting or application control not implemented — unauthorized applications must be prevented from executing"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.application_control.unauthorized_apps_blocked
    msg := "UEM-10: Unauthorized application execution not blocked — software installation without approval must be prevented"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.configuration_baseline.endpoint_hardening_standards_applied
    msg := "UEM-11: Endpoint hardening standards not applied — managed endpoints must be configured per security baseline (CIS Benchmark)"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.configuration_baseline.baseline_drift_detected
    msg := "UEM-11: Configuration drift from endpoint hardening baseline not detected — deviation from standard must trigger remediation"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.configuration_baseline.new_devices_hardened_before_deployment
    msg := "UEM-11: New endpoints not hardened before deployment — security configuration must be applied prior to production use"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.network_access_control.nac_implemented
    msg := "UEM-12: Network access control (NAC) not implemented — device compliance must be verified before granting network access"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.network_access_control.non_compliant_devices_quarantined
    msg := "UEM-12: Non-compliant devices not quarantined — devices failing compliance checks must be isolated from corporate networks"
}

violations contains msg if {
    not input.csa_ccm.endpoint_management.network_access_control.guest_network_segregated
    msg := "UEM-12: Guest and BYOD network not segregated from corporate network — untrusted devices must access only segregated network segments"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "UEM — Universal Endpoint Management",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
