package iec_62443.fr7

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 7 — Resource Availability (RA)
#
# Purpose: Ensure the availability of the IACS under all circumstances,
# including the resilience of the IACS against denial-of-service attacks
# and support for required capacity and performance.
#
# Security Requirements (SRs):
#   SR 7.1 — Denial of service protection
#   SR 7.2 — Resource management
#   SR 7.3 — Control system backup
#   SR 7.4 — Control system recovery and reconstitution
#   SR 7.5 — Emergency power
#   SR 7.6 — Network and security configuration settings
#   SR 7.7 — Least functionality
#   SR 7.8 — Control system component inventory
#
# Input shape:
#   input.target_sl                              - int (1–4)
#   input.ics_systems[]
#     .name                                      - string
#     .high_availability_configured              - bool
#     .criticality                               - string ("high"/"medium"/"low")
#     .unnecessary_services_disabled             - bool
#     .os_version_current                        - bool
#     .inventory_documented                      - bool
#     .backup_configured                         - bool
#     .resource_monitoring_enabled               - bool
#     .rate_limiting_enabled                     - bool
#     .emergency_power_backup                    - bool
#     .recovery_time_objective_hours             - int
#   input.monitoring
#     .dos_protection                            - bool
#   input.patch_management
#     .process_documented                        - bool
#     .tested_before_deployment                  - bool
#     .rollback_capability                       - bool
#   input.backups
#     .backup_frequency_days                     - int
#     .offsite_storage                           - bool
#     .restoration_tested                        - bool
#     .encryption_at_rest                        - bool
#     .backup_rto_hours                          - int
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 7.1 — Denial of service protection
# Protect the IACS against DoS attacks.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.dos_protection
    msg := "IEC 62443 SR 7.1 (RA): No DoS protection for IACS network. Industrial control systems must be protected against denial-of-service attacks that could disrupt critical operations."
}

violations contains msg if {
    some system in input.ics_systems
    not system.rate_limiting_enabled
    msg := sprintf(
        "IEC 62443 SR 7.1 (RA): ICS system '%v' has no rate limiting. Rate limiting on communication interfaces prevents resource exhaustion from DoS attacks.",
        [system.name]
    )
}

# SR 7.1 RE 1 (SL 2+): DoS protection with traffic management
violations contains msg if {
    input.target_sl >= 2
    not input.network.dos_traffic_management
    msg := sprintf(
        "IEC 62443 SR 7.1 RE 1 SL%v (RA): No active DoS traffic management implemented. Intrusion prevention, traffic shaping, or equivalent controls are required at Security Level 2+.",
        [input.target_sl]
    )
}

# SR 7.1 RE 2 (SL 3+): Redundant network paths
violations contains msg if {
    input.target_sl >= 3
    not input.network.redundant_paths
    msg := sprintf(
        "IEC 62443 SR 7.1 RE 2 SL%v (RA): No redundant network paths for critical IACS communications. Network redundancy is required at Security Level 3+ to maintain availability under partial failure.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 7.2 — Resource management
# Manage IACS resources to prevent resource exhaustion.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.resource_monitoring_enabled
    msg := sprintf(
        "IEC 62443 SR 7.2 (RA): ICS system '%v' does not monitor resource usage. CPU, memory, disk, and network resource utilization must be monitored with alerts for degraded capacity.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.resource_limits_configured
    msg := sprintf(
        "IEC 62443 SR 7.2 RE 1 SL%v (RA): ICS system '%v' has no resource limits configured. Resource quotas must be enforced to prevent a single process or user from exhausting system resources.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 7.3 — Control system backup
# Maintain backups of the IACS configuration and data.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.backup_configured
    msg := sprintf(
        "IEC 62443 SR 7.3 (RA): ICS system '%v' has no backup configured. Regular backups of IACS configuration, logic, and data are required for recovery.",
        [system.name]
    )
}

violations contains msg if {
    input.backups.backup_frequency_days > 7
    msg := sprintf(
        "IEC 62443 SR 7.3 (RA): IACS backups are performed every %v days. Backups must be performed at least weekly; daily backups are recommended for critical systems.",
        [input.backups.backup_frequency_days]
    )
}

violations contains msg if {
    not input.backups.offsite_storage
    msg := "IEC 62443 SR 7.3 (RA): IACS backups are not stored offsite. Offsite or geographically separated backup storage is required to survive a site-level disaster."
}

violations contains msg if {
    not input.backups.restoration_tested
    msg := "IEC 62443 SR 7.3 (RA): IACS backup restoration has not been tested. Backups must be periodically tested for recoverability — an untested backup is not a reliable backup."
}

violations contains msg if {
    input.target_sl >= 2
    not input.backups.encryption_at_rest
    msg := sprintf(
        "IEC 62443 SR 7.3 RE 1 SL%v (RA): IACS backups are not encrypted at rest. Backup media containing IACS configuration and data must be encrypted at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 7.4 — Control system recovery and reconstitution
# Recover the IACS to a known secure state after an incident.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.recovery_procedure_documented
    msg := sprintf(
        "IEC 62443 SR 7.4 (RA): ICS system '%v' has no documented recovery procedure. A step-by-step recovery procedure enabling restoration to a known secure state is required.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.recovery_time_objective_hours > 24
    system.criticality == "high"
    msg := sprintf(
        "IEC 62443 SR 7.4 (RA): High-criticality ICS system '%v' has an RTO of %v hours. Critical IACS systems must achieve recovery within 24 hours; 4 hours or less is recommended.",
        [system.name, system.recovery_time_objective_hours]
    )
}

violations contains msg if {
    not input.patch_management.rollback_capability
    msg := "IEC 62443 SR 7.4 (RA): No rollback capability for IACS updates/patches. The ability to revert to a previous known-good state is required for all IACS changes."
}

# SR 7.4 RE 1 (SL 2+): Tested recovery plan
violations contains msg if {
    input.target_sl >= 2
    not input.security_management.recovery_plan_tested
    msg := sprintf(
        "IEC 62443 SR 7.4 RE 1 SL%v (RA): IACS recovery plan has not been tested. At Security Level 2+, recovery procedures must be exercised at least annually.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 7.5 — Emergency power
# Maintain IACS availability during power disruptions.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.criticality == "high"
    not system.emergency_power_backup
    msg := sprintf(
        "IEC 62443 SR 7.5 (RA): High-criticality ICS system '%v' has no emergency power backup (UPS/generator). Uninterrupted power is required for critical industrial control systems.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.emergency_power_backup
    msg := sprintf(
        "IEC 62443 SR 7.5 SL%v (RA): ICS system '%v' has no emergency power backup. Emergency power capability is required at Security Level 2+ for all IACS components.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.emergency_power_backup
    not system.emergency_power_tested
    msg := sprintf(
        "IEC 62443 SR 7.5 (RA): ICS system '%v' emergency power backup has not been tested. UPS/generator systems must be tested at least semi-annually to verify runtime and automatic switchover.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 7.6 — Network and security configuration settings
# Maintain security configurations to ensure continued protection.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.configuration_baseline_documented
    msg := sprintf(
        "IEC 62443 SR 7.6 (RA): ICS system '%v' has no documented configuration baseline. A hardened baseline configuration must be documented and enforced.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    not input.security_management.configuration_change_management
    msg := sprintf(
        "IEC 62443 SR 7.6 RE 1 SL%v (RA): No configuration change management process. All changes to IACS network and security configurations must go through a formal change control process.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 7.7 — Least functionality
# Configure IACS to provide only essential functionality.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.unnecessary_services_disabled
    msg := sprintf(
        "IEC 62443 SR 7.7 (RA): ICS system '%v' has unnecessary services enabled. Disable all services, protocols, and ports not required for IACS operation to reduce the attack surface.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.os_hardened
    msg := sprintf(
        "IEC 62443 SR 7.7 (RA): ICS system '%v' OS has not been hardened. Remove unnecessary OS components, disable unused features, and apply a hardening standard (CIS benchmark or equivalent).",
        [system.name]
    )
}

# SR 7.7 RE 1 (SL 2+): Periodic review of enabled functionality
violations contains msg if {
    input.target_sl >= 2
    not input.security_management.functionality_review_schedule
    msg := sprintf(
        "IEC 62443 SR 7.7 RE 1 SL%v (RA): No periodic review of IACS enabled functionality. Enabled services, protocols, and functions must be reviewed at least annually at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 7.8 — Control system component inventory
# Maintain a current inventory of all IACS components.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.inventory_documented
    msg := sprintf(
        "IEC 62443 SR 7.8 (RA): ICS system '%v' is not documented in the IACS component inventory. Every IACS component must be inventoried with hardware, software, firmware versions, and network information.",
        [system.name]
    )
}

violations contains msg if {
    not input.network.network_inventory_documented
    msg := "IEC 62443 SR 7.8 (RA): Network inventory is not documented. A complete, up-to-date asset inventory of all IACS network components is required."
}

violations contains msg if {
    input.target_sl >= 2
    not input.security_management.inventory_auto_discovery
    msg := sprintf(
        "IEC 62443 SR 7.8 RE 1 SL%v (RA): No automated asset discovery for IACS. Automated inventory discovery or network scanning tools are required at Security Level 2+ to detect unauthorized devices.",
        [input.target_sl]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.inventory_documented
    not system.os_version_current
    msg := sprintf(
        "IEC 62443 SR 7.8 (RA): ICS system '%v' is running an outdated OS version. Inventory data must be current and unsupported OS versions must be remediated or documented as accepted risk.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr7_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 7.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.2")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.3")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.4")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.5")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.6")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.7")]) == 0,
        count([v | some v in violations; contains(v, "SR 7.8")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 7",
    "title":                    "Resource Availability (RA)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                8,
    "passing_srs":              fr7_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
