package ami.nist_ir7628.complete

import rego.v1

import data.ami.nist_ir7628.access_control
import data.ami.nist_ir7628.audit
import data.ami.nist_ir7628.identification_auth
import data.ami.nist_ir7628.system_comms
import data.ami.nist_ir7628.config_management
import data.ami.nist_ir7628.incident_response

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Master Orchestrator — aggregates all control family assessments
# OPA endpoint: /v1/data/ami/nist_ir7628/complete

# Aggregate violations from all control families using nested concat
# (Rego v1: array.concat takes exactly 2 arrays)
violations_ac_au := array.concat(
    [v | v := access_control.violations[_]],
    [v | v := audit.violations[_]]
)

violations_ia_sc := array.concat(
    [v | v := identification_auth.violations[_]],
    [v | v := system_comms.violations[_]]
)

violations_cm_ir := array.concat(
    [v | v := config_management.violations[_]],
    [v | v := incident_response.violations[_]]
)

violations_first_half := array.concat(violations_ac_au, violations_ia_sc)

all_violations := array.concat(violations_first_half, violations_cm_ir)

# Overall compliance
default compliant := false

compliant if {
    count(all_violations) == 0
}

# Compliance score (percentage of control families passing)
control_families_total := 6

control_families_passing := count([1 |
    families := [
        access_control.compliant,
        audit.compliant,
        identification_auth.compliant,
        system_comms.compliant,
        config_management.compliant,
        incident_response.compliant,
    ]
    families[_] == true
])

compliance_score := (control_families_passing * 100) / control_families_total

# Compliance level
compliance_level := "compliant" if {
    compliance_score == 100
}

compliance_level := "mostly_compliant" if {
    compliance_score >= 80
    compliance_score < 100
}

compliance_level := "partially_compliant" if {
    compliance_score >= 50
    compliance_score < 80
}

compliance_level := "non_compliant" if {
    compliance_score < 50
}

# Full assessment report
compliance_assessment := {
    "framework": "NIST IR 7628 Rev 1",
    "framework_name": "Guidelines for Smart Grid Cybersecurity",
    "scope": "AMI 2.0 - Advanced Metering Infrastructure",
    "compliance_level": compliance_level,
    "compliance_score": compliance_score,
    "total_violations": count(all_violations),
    "all_violations": all_violations,
    "control_families": {
        "SG.AC": access_control.compliance_report,
        "SG.AU": audit.compliance_report,
        "SG.IA": identification_auth.compliance_report,
        "SG.SC": system_comms.compliance_report,
        "SG.CM": config_management.compliance_report,
        "SG.IR": incident_response.compliance_report,
    },
}
