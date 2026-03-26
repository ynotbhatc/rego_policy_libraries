package ami.nist_ir7628.config_management

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.CM - Configuration Management
# Scope: AMI devices, head-end systems, network infrastructure

# SG.CM-2: Baseline Configuration
# A documented baseline configuration must exist for all AMI components
baseline_config_exists if {
    input.config_management.baseline.documented == true
    input.config_management.baseline.version_controlled == true
    count(input.config_management.baseline.components_covered) > 0
}

# SG.CM-2: Baseline must be current (reviewed within 1 year)
baseline_config_current if {
    last_review_ns := time.parse_rfc3339_ns(input.config_management.baseline.last_review_date)
    age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
}

# SG.CM-3: Configuration Change Control
# All changes to AMI systems must follow a formal change control process
change_control_implemented if {
    input.config_management.change_control.formal_process == true
    input.config_management.change_control.approval_required == true
    input.config_management.change_control.testing_required == true
    input.config_management.change_control.rollback_capability == true
}

# SG.CM-6: Configuration Settings
# Devices must be hardened — unnecessary services, ports, and protocols disabled
device_hardening_applied if {
    input.config_management.hardening.unnecessary_services_disabled == true
    input.config_management.hardening.default_passwords_changed == true
    input.config_management.hardening.unnecessary_ports_closed == true
    input.config_management.hardening.secure_protocols_only == true
}

# SG.CM-7: Least Functionality
# AMI devices must operate with minimum required software and services
least_functionality_enforced if {
    input.config_management.least_functionality.application_whitelisting == true
    input.config_management.least_functionality.unnecessary_software_removed == true
    input.config_management.least_functionality.firmware_locked == true
}

# SG.CM-8: Information System Component Inventory
# A current inventory of all AMI devices and components must be maintained
component_inventory_current if {
    count(input.config_management.inventory.components) > 0
    last_update_ns := time.parse_rfc3339_ns(input.config_management.inventory.last_updated)
    age_days := (time.now_ns() - last_update_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 30
}

# Violations

violations contains msg if {
    not baseline_config_exists
    msg := "SG.CM-2: Baseline configuration not documented or not version-controlled"
}

violations contains msg if {
    baseline_config_exists
    not baseline_config_current
    msg := "SG.CM-2: Baseline configuration has not been reviewed within the past 365 days"
}

violations contains msg if {
    not change_control_implemented
    msg := "SG.CM-3: Formal change control process with approval and rollback not implemented"
}

violations contains msg if {
    not device_hardening_applied
    msg := "SG.CM-6: AMI device hardening incomplete — default passwords, unnecessary services, or ports not addressed"
}

violations contains msg if {
    not least_functionality_enforced
    msg := "SG.CM-7: Least functionality not enforced — application whitelisting or unnecessary software removal missing"
}

violations contains msg if {
    not component_inventory_current
    msg := "SG.CM-8: AMI component inventory is missing or not updated within the past 30 days"
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.CM",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.CM-2", "SG.CM-3", "SG.CM-6", "SG.CM-7", "SG.CM-8"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
