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
    not input.patch_management.process_documented
    msg := "IEC 62443-2-3: No patch management process documented for IACS. A formal process for identifying, evaluating, testing, and applying security patches is required."
}

violations contains msg if {
    not input.patch_management.vendor_notification_subscriptions
    msg := "IEC 62443-2-3: No vendor security notification subscriptions. Subscribe to ICS-CERT, vendor security advisories, and sector-specific vulnerability feeds to receive timely patch notifications."
}

violations contains msg if {
    not input.patch_management.patch_inventory_tracked
    msg := "IEC 62443-2-3: Patch status is not tracked for IACS components. Maintain a current patch inventory for all IACS hardware and software components."
}

violations contains msg if {
    some system in input.ics_systems
    not system.patch_status_documented
    msg := sprintf(
        "IEC 62443-2-3: Patch status for ICS system '%v' is not documented. Every IACS component must have a documented patch status, including exceptions and compensating controls for unpatched vulnerabilities.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# Patch Testing and Qualification
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.patch_management.tested_before_deployment
    msg := "IEC 62443-2-3: IACS patches are not tested before production deployment. Patches must be evaluated in an isolated test environment that mirrors the production IACS before deployment — untested patches can cause operational failures."
}

violations contains msg if {
    not input.patch_management.patch_testing_environment
    msg := "IEC 62443-2-3: No dedicated patch testing environment for IACS. A test environment replicating the production IACS is required for safe patch qualification."
}

# ---------------------------------------------------------------------------
# Patch Deployment and Scheduling
# ---------------------------------------------------------------------------

violations contains msg if {
    input.patch_management.max_patch_delay_days > 90
    msg := sprintf(
        "IEC 62443-2-3: Critical IACS patches are delayed up to %v days. Critical security patches must be deployed within 90 days; within 30 days for actively exploited vulnerabilities.",
        [input.patch_management.max_patch_delay_days]
    )
}

violations contains msg if {
    not input.patch_management.patch_deployment_schedule_documented
    msg := "IEC 62443-2-3: No documented patch deployment schedule. A maintenance window schedule for IACS patches must be established that balances security and operational continuity."
}

violations contains msg if {
    not input.patch_management.change_management_integrated
    msg := "IEC 62443-2-3: Patch management is not integrated with change management. All IACS patches must go through the formal change management process to maintain configuration control."
}

violations contains msg if {
    not input.patch_management.emergency_patch_procedure
    msg := "IEC 62443-2-3: No emergency patch procedure defined. A documented emergency patch procedure for critical/zero-day vulnerabilities is required for timely response."
}

# ---------------------------------------------------------------------------
# Rollback and Recovery
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.patch_management.rollback_capability
    msg := "IEC 62443-2-3: No rollback capability for IACS patches. The ability to revert to a pre-patch state is required in case a patch causes operational issues."
}

# ---------------------------------------------------------------------------
# Compensating Controls
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.patch_management.compensating_controls_for_unpatched
    msg := "IEC 62443-2-3: No compensating controls defined for unpatched IACS vulnerabilities. When patching is not immediately feasible, compensating controls (network isolation, additional monitoring, vendor mitigations) must be documented and implemented."
}

# System-level checks
violations contains msg if {
    some system in input.ics_systems
    not system.os_version_current
    msg := sprintf(
        "IEC 62443-2-3: ICS system '%v' is running an outdated OS version. Unsupported or unpatched operating systems represent unacceptable risk in an IACS environment.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.firmware_version_current == false
    msg := sprintf(
        "IEC 62443-2-3: ICS system '%v' firmware is not current. Outdated firmware may contain unmitigated vulnerabilities — apply vendor-recommended firmware updates following the patch testing process.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

compliance_report := {
    "part":       "IEC 62443-2-3",
    "title":      "Patch Management in the IACS Environment",
    "standard":   "IEC 62443-2-3",
    "compliant":  compliant,
    "violations": violations,
}
