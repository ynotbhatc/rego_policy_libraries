package nist.sp800_53.incident_response

import rego.v1

# NIST SP 800-53 Rev 5 — Incident Response (IR) Family
# Detect, analyze, contain, eradicate, and recover from incidents.

default compliant := false

violation contains msg if {
    not input.ir_controls.policy.documented
    msg := "NIST IR-1: Incident response policy and procedures not documented"
}

violation contains msg if {
    not input.ir_controls.training.completed_within_year
    msg := "NIST IR-2: Incident response training not completed within the last year"
}

violation contains msg if {
    not input.ir_controls.testing.exercised_within_year
    msg := "NIST IR-3: Incident response plan not tested/exercised within the last year"
}

violation contains msg if {
    not input.ir_controls.handling.process_defined
    msg := "NIST IR-4: Incident handling process (preparation/detection/analysis/containment/eradication/recovery) not defined"
}

violation contains msg if {
    not input.ir_controls.monitoring.continuous
    msg := "NIST IR-5: Continuous incident monitoring not in place"
}

violation contains msg if {
    not input.ir_controls.reporting.timely
    msg := "NIST IR-6: Incident reporting to internal/external parties not timely"
}

violation contains msg if {
    not input.ir_controls.assistance.available
    msg := "NIST IR-7: Incident response assistance/coordination resources not available"
}

violation contains msg if {
    not input.ir_controls.plan.documented
    msg := "NIST IR-8: Documented incident response plan does not exist"
}

violation contains msg if {
    not input.ir_controls.information_spillage.process_defined
    msg := "NIST IR-9: Information spillage response process not defined"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "IR",
    "name":   "Incident Response",
    "controls_evaluated": 9,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
