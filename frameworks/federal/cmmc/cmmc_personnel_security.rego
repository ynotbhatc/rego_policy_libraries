package cmmc.personnel_security

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.9: Personnel Security
# NIST SP 800-171 Rev 2 — 2 Practices
# =============================================================================

# 3.9.1 — Screen individuals prior to authorizing access to organizational
#          systems containing CUI. (L2)
default compliant_3_9_1 := false
compliant_3_9_1 if {
    input.personnel.pre_employment_screening == true
    input.personnel.background_check_required == true
    input.personnel.screening_records_maintained == true
}

violation_3_9_1 contains msg if {
    not input.personnel.pre_employment_screening
    msg := "3.9.1: Pre-employment screening is not performed before granting CUI access"
}
violation_3_9_1 contains msg if {
    not input.personnel.background_check_required
    msg := "3.9.1: Background checks are not required for personnel accessing CUI systems"
}
violation_3_9_1 contains msg if {
    not input.personnel.screening_records_maintained
    msg := "3.9.1: Personnel screening records are not maintained"
}

# 3.9.2 — Ensure that CUI is protected during and after personnel actions
#          such as terminations and transfers. (L2)
default compliant_3_9_2 := false
compliant_3_9_2 if {
    input.personnel.termination_procedure_exists == true
    input.personnel.access_revoked_on_termination == true
    input.personnel.equipment_returned_on_termination == true
    input.personnel.transfer_access_reviewed == true
}

violation_3_9_2 contains msg if {
    not input.personnel.termination_procedure_exists
    msg := "3.9.2: No documented procedure for revoking CUI access upon termination"
}
violation_3_9_2 contains msg if {
    not input.personnel.access_revoked_on_termination
    msg := "3.9.2: CUI system access is not revoked immediately upon personnel termination"
}
violation_3_9_2 contains msg if {
    not input.personnel.equipment_returned_on_termination
    msg := "3.9.2: Equipment and credentials are not retrieved upon personnel termination"
}
violation_3_9_2 contains msg if {
    not input.personnel.transfer_access_reviewed
    msg := "3.9.2: CUI access privileges are not reviewed when personnel transfer roles"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    [v | some v in violation_3_9_1],
    [v | some v in violation_3_9_2]
)

practices := [
    {"id": "3.9.1", "level": 2, "compliant": compliant_3_9_1},
    {"id": "3.9.2", "level": 2, "compliant": compliant_3_9_2},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Personnel Security",
    "domain_id": "3.9",
    "total_practices": 2,
    "passing": passing_count,
    "failing": 2 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
