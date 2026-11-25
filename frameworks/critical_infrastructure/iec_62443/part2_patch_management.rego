# METADATA
# title: "IEC 62443-2-3 — Patch Management in the IACS Environment"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 15
#     cited: 1
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iec_62443.part2_3

import rego.v1

# =============================================================================
# IEC 62443-2-3 — Patch Management in the IACS Environment
#
# Purpose: Define requirements for managing security patches and updates for
# IACS components. OT patch management differs significantly from IT — patches
# must be tested in isolated environments before production deployment, and
# rollback capability is essential to prevent operational disruption.
#
# Key Requirement Areas:
#   - Patch identification and evaluation
#   - Patch testing and qualification
#   - Patch deployment and scheduling
#   - Compensating controls for unpatched systems
#   - Vendor coordination
#
# Input shape:
#   input.patch_management
#     .process_documented                      - bool
#     .max_patch_delay_days                    - int
#     .tested_before_deployment                - bool
#     .rollback_capability                     - bool
#     .patch_testing_environment               - bool
#     .vendor_notification_subscriptions       - bool
#     .compensating_controls_for_unpatched     - bool
#     .patch_inventory_tracked                 - bool
#     .emergency_patch_procedure               - bool
#     .change_management_integrated            - bool
#     .patch_deployment_schedule_documented    - bool
#   input.ics_systems[]
#     .name                                    - string
#     .os_version_current                      - bool
#     .firmware_version_current                - bool
#     .patch_status_documented                 - bool
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# Patch Identification and Evaluation
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.patch_management.process_documented == true
	finding := "IEC 62443-2-3: No patch management process documented for IACS. A formal process for identifying, evaluating, testing, and applying security patches is required."
	msg := concat("", [finding, _ev_input("patch_management.process_documented")])
}

violations contains msg if {
	not input.patch_management.vendor_notification_subscriptions == true
	finding := "IEC 62443-2-3: No vendor security notification subscriptions. Subscribe to ICS-CERT, vendor security advisories, and sector-specific vulnerability feeds to receive timely patch notifications."
	msg := concat("", [finding, _ev_input("patch_management.vendor_notification_subscriptions")])
}

violations contains msg if {
	not input.patch_management.patch_inventory_tracked == true
	finding := "IEC 62443-2-3: Patch status is not tracked for IACS components. Maintain a current patch inventory for all IACS hardware and software components."
	msg := concat("", [finding, _ev_input("patch_management.patch_inventory_tracked")])
}

violations contains msg if {
	some system in input.ics_systems
	not system.patch_status_documented == true
	finding := sprintf(
		"IEC 62443-2-3: Patch status for ICS system '%v' is not documented. Every IACS component must have a documented patch status, including exceptions and compensating controls for unpatched vulnerabilities.",
		[object.get(system, "name", "<unnamed>")],
	)
	msg := concat("", [finding, _ev_item(system, "patch_status_documented")])
}

# ---------------------------------------------------------------------------
# Patch Testing and Qualification
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.patch_management.tested_before_deployment == true
	finding := "IEC 62443-2-3: IACS patches are not tested before production deployment. Patches must be evaluated in an isolated test environment that mirrors the production IACS before deployment — untested patches can cause operational failures."
	msg := concat("", [finding, _ev_input("patch_management.tested_before_deployment")])
}

violations contains msg if {
	not input.patch_management.patch_testing_environment == true
	finding := "IEC 62443-2-3: No dedicated patch testing environment for IACS. A test environment replicating the production IACS is required for safe patch qualification."
	msg := concat("", [finding, _ev_input("patch_management.patch_testing_environment")])
}

# ---------------------------------------------------------------------------
# Patch Deployment and Scheduling
# ---------------------------------------------------------------------------

violations contains msg if {
	is_number(input.patch_management.max_patch_delay_days)
	input.patch_management.max_patch_delay_days > 90
	msg := sprintf(
		"IEC 62443-2-3: Critical IACS patches are delayed up to %v days. Critical security patches must be deployed within 90 days; within 30 days for actively exploited vulnerabilities.",
		[input.patch_management.max_patch_delay_days],
	)
}

violations contains "IEC 62443-2-3: evidence missing - input.patch_management.max_patch_delay_days is not a number" if {
	not is_number(object.get(input, ["patch_management", "max_patch_delay_days"], null))
}

violations contains msg if {
	not input.patch_management.patch_deployment_schedule_documented == true
	finding := "IEC 62443-2-3: No documented patch deployment schedule. A maintenance window schedule for IACS patches must be established that balances security and operational continuity."
	msg := concat("", [finding, _ev_input("patch_management.patch_deployment_schedule_documented")])
}

violations contains msg if {
	not input.patch_management.change_management_integrated == true
	finding := "IEC 62443-2-3: Patch management is not integrated with change management. All IACS patches must go through the formal change management process to maintain configuration control."
	msg := concat("", [finding, _ev_input("patch_management.change_management_integrated")])
}

violations contains msg if {
	not input.patch_management.emergency_patch_procedure == true
	finding := "IEC 62443-2-3: No emergency patch procedure defined. A documented emergency patch procedure for critical/zero-day vulnerabilities is required for timely response."
	msg := concat("", [finding, _ev_input("patch_management.emergency_patch_procedure")])
}

# ---------------------------------------------------------------------------
# Rollback and Recovery
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.patch_management.rollback_capability == true
	finding := "IEC 62443-2-3: No rollback capability for IACS patches. The ability to revert to a pre-patch state is required in case a patch causes operational issues."
	msg := concat("", [finding, _ev_input("patch_management.rollback_capability")])
}

# ---------------------------------------------------------------------------
# Compensating Controls
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.patch_management.compensating_controls_for_unpatched == true
	finding := "IEC 62443-2-3: No compensating controls defined for unpatched IACS vulnerabilities. When patching is not immediately feasible, compensating controls (network isolation, additional monitoring, vendor mitigations) must be documented and implemented."
	msg := concat("", [finding, _ev_input("patch_management.compensating_controls_for_unpatched")])
}

# System-level checks
violations contains msg if {
	some system in input.ics_systems
	not system.os_version_current == true
	finding := sprintf(
		"IEC 62443-2-3: ICS system '%v' is running an outdated OS version. Unsupported or unpatched operating systems represent unacceptable risk in an IACS environment.",
		[object.get(system, "name", "<unnamed>")],
	)
	msg := concat("", [finding, _ev_item(system, "os_version_current")])
}

violations contains msg if {
	some system in input.ics_systems
	not system.firmware_version_current == true
	finding := sprintf(
		"IEC 62443-2-3: ICS system '%v' firmware is not current. Outdated firmware may contain unmitigated vulnerabilities — apply vendor-recommended firmware updates following the patch testing process.",
		[object.get(system, "name", "<unnamed>")],
	)
	msg := concat("", [finding, _ev_item(system, "firmware_version_current")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if count(violations) == 0

compliance_report := {
	"part": "IEC 62443-2-3",
	"title": "Patch Management in the IACS Environment",
	"standard": "IEC 62443-2-3",
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
