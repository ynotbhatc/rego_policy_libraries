# METADATA
# title: "Csa Ccm Endpoint Management"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 39
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.endpoint_management

import rego.v1

default compliant := false

_base := ["csa_ccm", "endpoint_management"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("UEM-01: Endpoint management policy not formally established for all device types accessing cloud services", ["uem_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("UEM-01: BYOD (bring your own device) policy not defined — personal device access to corporate data must be governed", ["uem_policy", "byod_policy_defined"])
}

violations contains msg if {
	msg := _finding("UEM-01: Endpoint management policy not reviewed and updated at least annually", ["uem_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("UEM-01: All device types (laptops, mobile, tablets, IoT) not included in endpoint management policy scope", ["uem_policy", "all_device_types_in_scope"])
}

violations contains msg if {
	msg := _finding("UEM-02: MDM/UEM solution not deployed — endpoint management must be centralized for all managed devices", ["mdm_deployment", "mdm_uem_solution_deployed"])
}

violations contains msg if {
	msg := _finding("UEM-02: All managed devices not enrolled in MDM/UEM platform — unenrolled devices must be blocked from corporate resources", ["mdm_deployment", "all_managed_devices_enrolled"])
}

violations contains msg if {
	msg := _finding("UEM-02: Device compliance policies not enforced via MDM/UEM — non-compliant devices must be blocked or quarantined", ["mdm_deployment", "compliance_policies_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-02: Device inventory not maintained through MDM/UEM — all managed endpoints must be catalogued", ["mdm_deployment", "device_inventory_maintained"])
}

violations contains msg if {
	msg := _finding("UEM-03: Device encryption not enforced on all managed endpoints — full-disk encryption must be enabled", ["device_encryption", "encryption_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-03: Endpoint encryption compliance not monitored — devices without encryption must be identified and remediated", ["device_encryption", "encryption_compliance_monitored"])
}

violations contains msg if {
	msg := _finding("UEM-03: Mobile device encryption not enforced — smartphones and tablets accessing corporate data must encrypt storage", ["device_encryption", "mobile_device_encryption_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-04: Remote wipe capability not enabled for managed devices — lost or stolen devices must be remotely wiped", ["remote_wipe", "remote_wipe_capability_enabled"])
}

violations contains msg if {
	msg := _finding("UEM-04: Remote wipe procedure not defined — process for initiating wipe upon device loss or employee termination must be documented", ["remote_wipe", "remote_wipe_procedure_defined"])
}

violations contains msg if {
	msg := _finding("UEM-04: Selective wipe capability not implemented for BYOD — corporate data must be removable without wiping personal data", ["remote_wipe", "selective_wipe_for_byod"])
}

violations contains msg if {
	msg := _finding("UEM-05: BYOD policy not enforced — personal devices accessing corporate resources must meet minimum security requirements", ["byod", "byod_policy_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-05: Containerization or mobile application management (MAM) not implemented to isolate corporate data on BYOD devices", ["byod", "containerization_or_mam_implemented"])
}

violations contains msg if {
	msg := _finding("UEM-05: Jailbroken or rooted devices not blocked from accessing corporate applications and data", ["byod", "jailbroken_rooted_devices_blocked"])
}

violations contains msg if {
	msg := _finding("UEM-05: Minimum OS version not enforced for BYOD devices — outdated OS versions must be blocked", ["byod", "minimum_os_version_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-06: Endpoint detection and response (EDR) solution not deployed on managed endpoints", ["edr", "edr_solution_deployed"])
}

violations contains msg if {
	msg := _finding("UEM-06: EDR coverage not complete — all managed servers and workstations must have EDR agent installed and reporting", ["edr", "edr_coverage_complete"])
}

violations contains msg if {
	msg := _finding("UEM-06: EDR alerts not actively monitored — threat detections must be reviewed and responded to within defined SLA", ["edr", "edr_alerts_monitored"])
}

violations contains msg if {
	msg := _finding("UEM-06: EDR automated response not enabled — high-confidence threat detections should trigger automated containment", ["edr", "automated_response_enabled"])
}

violations contains msg if {
	msg := _finding("UEM-07: Endpoint patch management not implemented — all managed devices must receive security patches", ["endpoint_patching", "patch_management_implemented"])
}

violations contains msg if {
	msg := _finding("UEM-07: Critical endpoint patches not applied within defined SLA — critical OS and application patches must be deployed promptly", ["endpoint_patching", "critical_patches_applied_timely"])
}

violations contains msg if {
	msg := _finding("UEM-07: Endpoint patch compliance not monitored — unpatched devices must be identified and reported", ["endpoint_patching", "patch_compliance_monitored"])
}

violations contains msg if {
	msg := _finding("UEM-07: Patches not tested before broad deployment — pilot deployment must verify patch stability", ["endpoint_patching", "patch_testing_before_deployment"])
}

violations contains msg if {
	msg := _finding("UEM-08: Removable media (USB, external drives) policy not defined — use must be governed and restricted", ["removable_media", "removable_media_policy_defined"])
}

violations contains msg if {
	msg := _finding("UEM-08: Unauthorized removable media not blocked — only approved and encrypted media must be permitted", ["removable_media", "unauthorized_media_blocked"])
}

violations contains msg if {
	msg := _finding("UEM-08: Removable media not scanned for malware upon connection — automatic scanning must be enforced", ["removable_media", "media_scanning_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-09: Screen lock not enforced on managed endpoints — automatic lock after defined idle period must be configured", ["screen_lock", "screen_lock_enforced"])
}

violations contains msg if {
	msg := _finding("UEM-09: Screen lock timeout not appropriate — maximum idle time before lock must not exceed 15 minutes", ["screen_lock", "screen_lock_timeout_appropriate"])
}

violations contains msg if {
	msg := _finding("UEM-10: Application allowlisting or application control not implemented — unauthorized applications must be prevented from executing", ["application_control", "application_allowlisting_implemented"])
}

violations contains msg if {
	msg := _finding("UEM-10: Unauthorized application execution not blocked — software installation without approval must be prevented", ["application_control", "unauthorized_apps_blocked"])
}

violations contains msg if {
	msg := _finding("UEM-11: Endpoint hardening standards not applied — managed endpoints must be configured per security baseline (CIS Benchmark)", ["configuration_baseline", "endpoint_hardening_standards_applied"])
}

violations contains msg if {
	msg := _finding("UEM-11: Configuration drift from endpoint hardening baseline not detected — deviation from standard must trigger remediation", ["configuration_baseline", "baseline_drift_detected"])
}

violations contains msg if {
	msg := _finding("UEM-11: New endpoints not hardened before deployment — security configuration must be applied prior to production use", ["configuration_baseline", "new_devices_hardened_before_deployment"])
}

violations contains msg if {
	msg := _finding("UEM-12: Network access control (NAC) not implemented — device compliance must be verified before granting network access", ["network_access_control", "nac_implemented"])
}

violations contains msg if {
	msg := _finding("UEM-12: Non-compliant devices not quarantined — devices failing compliance checks must be isolated from corporate networks", ["network_access_control", "non_compliant_devices_quarantined"])
}

violations contains msg if {
	msg := _finding("UEM-12: Guest and BYOD network not segregated from corporate network — untrusted devices must access only segregated network segments", ["network_access_control", "guest_network_segregated"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["UEM-01", "UEM-02", "UEM-03", "UEM-04", "UEM-05", "UEM-06", "UEM-07", "UEM-08", "UEM-09", "UEM-10", "UEM-11", "UEM-12"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "UEM — Universal Endpoint Management",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 39,
	"violation_count": count(violations),
	"violations": violations,
}
