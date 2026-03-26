package ami.nist_ir7628.incident_response

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.IR - Incident Response
# Scope: AMI security events, meter tamper alerts, grid anomalies

# SG.IR-1: Incident Response Policy and Procedures
# A documented, approved IR plan specific to AMI/smart grid events must exist
ir_policy_documented if {
    input.incident_response.policy.documented == true
    input.incident_response.policy.approved == true
    input.incident_response.policy.ami_specific_procedures == true
}

ir_policy_current if {
    last_review_ns := time.parse_rfc3339_ns(input.incident_response.policy.last_review_date)
    age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
}

# SG.IR-2: Incident Response Training
# Staff must be trained on IR procedures including AMI-specific scenarios
ir_training_current if {
    last_training_ns := time.parse_rfc3339_ns(input.incident_response.training.last_date)
    age_days := (time.now_ns() - last_training_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
    input.incident_response.training.ami_scenarios_covered == true
}

# SG.IR-3: Incident Response Testing
# IR procedures must be tested at least annually via tabletop or simulation
ir_testing_current if {
    last_test_ns := time.parse_rfc3339_ns(input.incident_response.testing.last_test_date)
    age_days := (time.now_ns() - last_test_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
    input.incident_response.testing.type in {"tabletop", "simulation", "full_exercise"}
}

# SG.IR-4: Incident Handling
# An automated detection capability must be in place for AMI security events
automated_detection_enabled if {
    input.incident_response.detection.automated_alerting == true
    input.incident_response.detection.tamper_detection_integrated == true
    input.incident_response.detection.anomaly_detection_enabled == true
}

# SG.IR-6: Incident Reporting
# Security incidents must be reported within defined timeframes
# and reported to relevant authorities (E-ISAC, ICS-CERT as applicable)
incident_reporting_configured if {
    input.incident_response.reporting.internal_escalation_path_defined == true
    input.incident_response.reporting.external_reporting_contacts_current == true
    input.incident_response.reporting.reporting_timeframe_hours <= 24
}

# SG.IR-8: Incident Response Plan
# The IR plan must address AMI-specific scenarios including mass meter compromise
ami_scenarios_covered if {
    required_scenarios := {
        "mass_meter_compromise",
        "head_end_breach",
        "rf_network_jamming",
        "firmware_tampering",
        "data_exfiltration",
    }
    covered := {s | s := input.incident_response.plan.scenarios_covered[_]}
    every scenario in required_scenarios {
        scenario in covered
    }
}

# Violations

violations contains msg if {
    not ir_policy_documented
    msg := "SG.IR-1: Incident response policy with AMI-specific procedures not documented or approved"
}

violations contains msg if {
    ir_policy_documented
    not ir_policy_current
    msg := "SG.IR-1: Incident response policy has not been reviewed within the past 365 days"
}

violations contains msg if {
    not ir_training_current
    msg := "SG.IR-2: Incident response training (including AMI scenarios) not completed within 365 days"
}

violations contains msg if {
    not ir_testing_current
    msg := "SG.IR-3: Incident response procedures not tested (tabletop or simulation) within the past 365 days"
}

violations contains msg if {
    not automated_detection_enabled
    msg := "SG.IR-4: Automated AMI incident detection (tamper alerts, anomaly detection) not enabled"
}

violations contains msg if {
    not incident_reporting_configured
    msg := "SG.IR-6: Incident reporting chain or external contacts not current; reporting timeframe must be <= 24 hours"
}

violations contains msg if {
    not ami_scenarios_covered
    missing := {
        "mass_meter_compromise",
        "head_end_breach",
        "rf_network_jamming",
        "firmware_tampering",
        "data_exfiltration",
    } - {s | s := input.incident_response.plan.scenarios_covered[_]}
    msg := sprintf("SG.IR-8: AMI-specific IR scenarios not covered in plan: %v", [missing])
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.IR",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.IR-1", "SG.IR-2", "SG.IR-3", "SG.IR-4", "SG.IR-6", "SG.IR-8"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
