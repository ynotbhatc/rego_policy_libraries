package nist.sp800_53.configuration_management

import rego.v1

# NIST SP 800-53 Rev 5 — Configuration Management (CM) Family
# Baseline configurations, change control, and configuration monitoring.

default compliant := false

violation contains msg if {
    not input.cm_controls.policy.documented
    msg := "NIST CM-1: Configuration management policy not documented"
}

violation contains msg if {
    not input.cm_controls.baseline_config.maintained
    msg := "NIST CM-2: Baseline configuration not established or maintained for the system"
}

violation contains msg if {
    not input.cm_controls.change_control.process_exists
    msg := "NIST CM-3: Configuration change control process not in place"
}

violation contains msg if {
    not input.cm_controls.security_impact_analysis.performed
    msg := "NIST CM-4: Security impact analysis not performed before changes are deployed"
}

violation contains msg if {
    not input.cm_controls.access_restrictions_for_change.enforced
    msg := "NIST CM-5: Access restrictions for change are not enforced"
}

violation contains msg if {
    not input.cm_controls.configuration_settings.documented
    msg := "NIST CM-6: Mandatory configuration settings not documented or applied"
}

violation contains msg if {
    not input.cm_controls.least_functionality.enforced
    msg := "NIST CM-7: Least functionality (disable unused services/ports) not enforced"
}

violation contains msg if {
    not input.cm_controls.system_component_inventory.maintained
    msg := "NIST CM-8: System component inventory not maintained or accurate"
}

violation contains msg if {
    not input.cm_controls.config_management_plan.documented
    msg := "NIST CM-9: Configuration management plan not documented"
}

violation contains msg if {
    not input.cm_controls.software_usage_restrictions.enforced
    msg := "NIST CM-10: Software usage restrictions (licensing/copy controls) not enforced"
}

violation contains msg if {
    not input.cm_controls.user_installed_software.restricted
    msg := "NIST CM-11: User-installed software is not restricted by policy"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "CM",
    "name":   "Configuration Management",
    "controls_evaluated": 11,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
