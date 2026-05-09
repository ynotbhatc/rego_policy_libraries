package nist.sp800_171.maintenance

import rego.v1

# NIST SP 800-171 Rev 3 - Maintenance (MA) Requirements
# Family: 3.7 — Protecting Controlled Unclassified Information (CUI)

# 3.7.1: Perform maintenance on organizational systems
default maintenance_performed := false

maintenance_performed if {
    input.nist_800_171.maintenance.maintenance_schedule.schedule_documented == true
    input.nist_800_171.maintenance.maintenance_schedule.performed_regularly == true
    input.nist_800_171.maintenance.maintenance_schedule.records_maintained == true
}

# 3.7.2: Provide controls on the tools, techniques, mechanisms, and personnel that perform
#         maintenance on organizational systems
default maintenance_controls := false

maintenance_controls if {
    input.nist_800_171.maintenance.controls.approved_tools == true
    input.nist_800_171.maintenance.controls.approved_techniques == true
    input.nist_800_171.maintenance.controls.authorized_personnel_only == true
    input.nist_800_171.maintenance.controls.controls_documented == true
}

# 3.7.3: Ensure equipment removed for off-site maintenance is sanitized of any CUI
default equipment_sanitization := false

equipment_sanitization if {
    input.nist_800_171.maintenance.sanitization.removed_equipment_sanitized == true
    input.nist_800_171.maintenance.sanitization.sanitization_verified == true
    input.nist_800_171.maintenance.sanitization.process_documented == true
}

# 3.7.4: Check media containing diagnostic programs for malicious code before use
default diagnostic_media_checked := false

diagnostic_media_checked if {
    input.nist_800_171.maintenance.diagnostic_media.scanned_before_use == true
    input.nist_800_171.maintenance.diagnostic_media.approved_scanning_tool == true
    input.nist_800_171.maintenance.diagnostic_media.results_documented == true
}

# 3.7.5: Require MFA to establish nonlocal (remote) maintenance sessions via external
#         networks and terminate such connections when nonlocal maintenance is complete
default remote_maintenance_mfa := false

remote_maintenance_mfa if {
    input.nist_800_171.maintenance.remote_maintenance.mfa_required == true
    input.nist_800_171.maintenance.remote_maintenance.session_terminated_after == true
    input.nist_800_171.maintenance.remote_maintenance.connections_monitored == true
}

# 3.7.6: Supervise maintenance activities of maintenance personnel without required
#         access authorization
default maintenance_supervision := false

maintenance_supervision if {
    input.nist_800_171.maintenance.supervision.unauthorized_personnel_supervised == true
    input.nist_800_171.maintenance.supervision.supervisor_has_required_access == true
    input.nist_800_171.maintenance.supervision.supervision_documented == true
}

# Violations set
violations contains msg if {
    not maintenance_performed
    msg := "NIST 800-171 3.7.1: System maintenance must be performed on a documented schedule with records maintained"
}

violations contains msg if {
    not maintenance_controls
    msg := "NIST 800-171 3.7.2: Controls must be established for maintenance tools, techniques, mechanisms, and authorized personnel"
}

violations contains msg if {
    not equipment_sanitization
    msg := "NIST 800-171 3.7.3: Equipment removed for off-site maintenance must be sanitized of CUI and sanitization must be verified"
}

violations contains msg if {
    not diagnostic_media_checked
    msg := "NIST 800-171 3.7.4: Media containing diagnostic programs must be scanned for malicious code before use in maintenance"
}

violations contains msg if {
    not remote_maintenance_mfa
    msg := "NIST 800-171 3.7.5: MFA must be required for remote maintenance sessions and connections must be terminated when complete"
}

violations contains msg if {
    not maintenance_supervision
    msg := "NIST 800-171 3.7.6: Maintenance personnel without required access authorization must be supervised by authorized individuals"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.7 Maintenance",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 6,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.7.1_maintenance_performed": maintenance_performed,
        "3.7.2_maintenance_controls": maintenance_controls,
        "3.7.3_equipment_sanitization": equipment_sanitization,
        "3.7.4_diagnostic_media_checked": diagnostic_media_checked,
        "3.7.5_remote_maintenance_mfa": remote_maintenance_mfa,
        "3.7.6_maintenance_supervision": maintenance_supervision,
    },
}
