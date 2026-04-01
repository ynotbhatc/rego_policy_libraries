package cmmc.configuration_management

import rego.v1

# =============================================================================
# CMMC 2.0 — Configuration Management Domain (CM)
# Practices CM.L2-3.4.1 through CM.L2-3.4.9
#
# Input shape:
#   input.systems[]             - managed systems
#   input.configuration         - configuration management program
#   input.software              - software inventory and management
#   input.cmmc_level            - target maturity level
# =============================================================================

# CM.L2-3.4.1 — Establish baseline configurations
violation_cm_1 contains msg if {
    input.cmmc_level >= 2
    some system in input.systems
    not system.baseline_configuration_documented
    msg := sprintf(
        "CMMC CM.L2-3.4.1: System '%v' has no documented baseline configuration. Baselines must be established for all CUI systems.",
        [system.name]
    )
}

# CM.L2-3.4.2 — Establish and enforce security configuration settings
violation_cm_2 contains msg if {
    input.cmmc_level >= 2
    some system in input.systems
    not system.security_configuration_enforced
    msg := sprintf(
        "CMMC CM.L2-3.4.2: System '%v' does not enforce security configuration settings. STIGs or CIS Benchmarks must be applied.",
        [system.name]
    )
}

# CM.L2-3.4.3 — Track, review, approve/disapprove changes to systems
violation_cm_3 contains msg if {
    input.cmmc_level >= 2
    not input.configuration.change_control_process
    msg := "CMMC CM.L2-3.4.3: No change control process. All changes to CUI systems must go through an approval process."
}

violation_cm_3 contains msg if {
    input.cmmc_level >= 2
    not input.configuration.changes_reviewed_before_implementation
    msg := "CMMC CM.L2-3.4.3: Changes are not reviewed before implementation. Security impact analysis is required for all changes."
}

# CM.L2-3.4.4 — Analyze impact of changes prior to implementation
violation_cm_4 contains msg if {
    input.cmmc_level >= 2
    not input.configuration.security_impact_analysis
    msg := "CMMC CM.L2-3.4.4: No security impact analysis process. Changes must be analyzed for security impact before implementation."
}

# CM.L2-3.4.5 — Define, document, approve, and enforce access restrictions for change
violation_cm_5 contains msg if {
    input.cmmc_level >= 2
    not input.configuration.change_access_restricted
    msg := "CMMC CM.L2-3.4.5: Change access is not restricted. Only authorized personnel should be able to make changes to CUI systems."
}

# CM.L2-3.4.6 — Employ principle of least functionality
violation_cm_6 contains msg if {
    input.cmmc_level >= 2
    some system in input.systems
    count(system.unnecessary_services) > 0
    msg := sprintf(
        "CMMC CM.L2-3.4.6: System '%v' has unnecessary services running: %v. Disable all non-essential services.",
        [system.name, system.unnecessary_services]
    )
}

# CM.L2-3.4.7 — Restrict, disable, or prevent the use of nonessential programs
violation_cm_7 contains msg if {
    input.cmmc_level >= 2
    not input.software.application_whitelist_enabled
    msg := "CMMC CM.L2-3.4.7: Application whitelisting is not enabled. Only authorized software should be permitted to execute."
}

violation_cm_7 contains msg if {
    input.cmmc_level >= 2
    some system in input.systems
    count(system.unauthorized_software) > 0
    msg := sprintf(
        "CMMC CM.L2-3.4.7: Unauthorized software detected on '%v': %v. Remove or authorize these programs.",
        [system.name, system.unauthorized_software]
    )
}

# CM.L2-3.4.8 — Apply deny-by-exception policy for software usage
violation_cm_8 contains msg if {
    input.cmmc_level >= 2
    not input.software.deny_by_default
    msg := "CMMC CM.L2-3.4.8: Software policy is allow-by-default. Implement deny-by-exception (whitelist approach) for software execution."
}

# CM.L2-3.4.9 — Control and monitor user-installed software
violation_cm_9 contains msg if {
    input.cmmc_level >= 2
    not input.software.user_install_controlled
    msg := "CMMC CM.L2-3.4.9: User-installed software is not controlled. Users must be prevented from installing unauthorized software."
}

violations contains msg if { some msg in violation_cm_1 }
violations contains msg if { some msg in violation_cm_2 }
violations contains msg if { some msg in violation_cm_3 }
violations contains msg if { some msg in violation_cm_4 }
violations contains msg if { some msg in violation_cm_5 }
violations contains msg if { some msg in violation_cm_6 }
violations contains msg if { some msg in violation_cm_7 }
violations contains msg if { some msg in violation_cm_8 }
violations contains msg if { some msg in violation_cm_9 }

compliant if { count(violations) == 0 }

compliance_report := {
    "domain":          "Configuration Management (CM)",
    "cmmc_level":      input.cmmc_level,
    "compliant":       compliant,
    "violation_count": count(violations),
    "violations":      violations,
    "passing":         9 - count(violations),
}
