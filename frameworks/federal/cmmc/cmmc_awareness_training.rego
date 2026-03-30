package cmmc.awareness_training

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.2: Awareness & Training
# NIST SP 800-171 Rev 2 — 3 Practices
# =============================================================================

# ---------------------------------------------------------------------------
# 3.2.1 — Ensure that managers, systems administrators, and users of
#          organizational systems are made aware of the security risks
#          associated with their activities. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_1 := false
compliant_3_2_1 if {
    input.training.security_awareness_program == true
    input.training.all_users_trained == true
    input.training.training_frequency_days <= 365
}

violation_3_2_1 contains msg if {
    not input.training.security_awareness_program
    msg := "3.2.1: No organizational security awareness program established"
}
violation_3_2_1 contains msg if {
    not input.training.all_users_trained
    msg := "3.2.1: Not all users have completed security awareness training"
}
violation_3_2_1 contains msg if {
    input.training.training_frequency_days > 365
    msg := sprintf("3.2.1: Security awareness training interval (%v days) exceeds annual requirement", [input.training.training_frequency_days])
}

# ---------------------------------------------------------------------------
# 3.2.2 — Ensure that personnel are trained to carry out their assigned
#          information security responsibilities. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_2 := false
compliant_3_2_2 if {
    input.training.role_based_training == true
    input.training.privileged_user_training == true
    input.training.training_records_maintained == true
}

violation_3_2_2 contains msg if {
    not input.training.role_based_training
    msg := "3.2.2: Role-based security training is not implemented"
}
violation_3_2_2 contains msg if {
    not input.training.privileged_user_training
    msg := "3.2.2: Privileged users have not received specialized security training"
}
violation_3_2_2 contains msg if {
    not input.training.training_records_maintained
    msg := "3.2.2: Training completion records are not maintained"
}

# ---------------------------------------------------------------------------
# 3.2.3 — Provide security awareness training on recognizing and reporting
#          potential threats, such as social engineering and phishing. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_3 := false
compliant_3_2_3 if {
    input.training.phishing_awareness_training == true
    input.training.social_engineering_training == true
    input.training.insider_threat_training == true
}

violation_3_2_3 contains msg if {
    not input.training.phishing_awareness_training
    msg := "3.2.3: Phishing awareness training is not included in security program"
}
violation_3_2_3 contains msg if {
    not input.training.social_engineering_training
    msg := "3.2.3: Social engineering recognition training is not provided"
}
violation_3_2_3 contains msg if {
    not input.training.insider_threat_training
    msg := "3.2.3: Insider threat awareness training is not provided"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

all_violations := array.concat(
    [v | some v in violation_3_2_1],
    array.concat(
        [v | some v in violation_3_2_2],
        [v | some v in violation_3_2_3]
    )
)

practices := [
    {"id": "3.2.1", "level": 2, "compliant": compliant_3_2_1},
    {"id": "3.2.2", "level": 2, "compliant": compliant_3_2_2},
    {"id": "3.2.3", "level": 2, "compliant": compliant_3_2_3},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Awareness & Training",
    "domain_id": "3.2",
    "total_practices": 3,
    "passing": passing_count,
    "failing": 3 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
