package nist.sp800_171.awareness_training

import rego.v1

# NIST SP 800-171 Rev 3 - Awareness and Training (AT) Requirements
# Family: 3.2 — Protecting Controlled Unclassified Information (CUI)

# 3.2.1: Ensure personnel are aware of security risks associated with their activities and
#         organizational systems, and ensure personnel are trained to carry out assigned
#         information security responsibilities
default security_awareness_program := false

security_awareness_program if {
    input.nist_800_171.awareness_training.awareness.program_established == true
    input.nist_800_171.awareness_training.awareness.all_personnel_covered == true
    input.nist_800_171.awareness_training.awareness.risk_topics_included == true
    input.nist_800_171.awareness_training.awareness.periodic_refreshes == true
}

# 3.2.2: Ensure personnel are trained to carry out assigned information security responsibilities
default role_based_training := false

role_based_training if {
    input.nist_800_171.awareness_training.role_training.role_specific_content == true
    input.nist_800_171.awareness_training.role_training.completion_tracked == true
    input.nist_800_171.awareness_training.role_training.before_access_granted == true
}

# 3.2.3: Provide security awareness training on recognizing and reporting threats including
#         phishing, social engineering, and insider threats
default threat_recognition_training := false

threat_recognition_training if {
    input.nist_800_171.awareness_training.threat_training.phishing_covered == true
    input.nist_800_171.awareness_training.threat_training.social_engineering_covered == true
    input.nist_800_171.awareness_training.threat_training.insider_threat_covered == true
    input.nist_800_171.awareness_training.threat_training.reporting_procedures_covered == true
}

# Violations set
violations contains msg if {
    not security_awareness_program
    msg := "NIST 800-171 3.2.1: A security awareness program covering CUI-related risks must be established for all personnel"
}

violations contains msg if {
    not role_based_training
    msg := "NIST 800-171 3.2.2: Role-based security training must be provided before granting access and tracked to completion"
}

violations contains msg if {
    not threat_recognition_training
    msg := "NIST 800-171 3.2.3: Security awareness training must cover phishing, social engineering, insider threats, and reporting procedures"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.2 Awareness and Training",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 3,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.2.1_security_awareness_program": security_awareness_program,
        "3.2.2_role_based_training": role_based_training,
        "3.2.3_threat_recognition_training": threat_recognition_training,
    },
}
