package nist.sp800_171.personnel_security

import rego.v1

# NIST SP 800-171 Rev 3 - Personnel Security (PS) Requirements
# Family: 3.9 — Protecting Controlled Unclassified Information (CUI)

# 3.9.1: Screen individuals prior to authorizing access to organizational systems containing CUI
default personnel_screening := false

personnel_screening if {
    input.nist_800_171.personnel_security.screening.background_checks_performed == true
    input.nist_800_171.personnel_security.screening.criteria_documented == true
    input.nist_800_171.personnel_security.screening.rescreening_policy == true
}

# 3.9.2: Ensure CUI is protected during and after personnel actions such as terminations and transfers
default personnel_actions_protection := false

personnel_actions_protection if {
    input.nist_800_171.personnel_security.personnel_actions.termination_procedures == true
    input.nist_800_171.personnel_security.personnel_actions.transfer_procedures == true
    input.nist_800_171.personnel_security.personnel_actions.access_revocation_timely == true
    input.nist_800_171.personnel_security.personnel_actions.property_return_required == true
}

# Violations set
violations contains msg if {
    not personnel_screening
    msg := "NIST 800-171 3.9.1: Personnel screening must be performed prior to authorizing access to systems containing CUI"
}

violations contains msg if {
    not personnel_actions_protection
    msg := "NIST 800-171 3.9.2: CUI must be protected during and after personnel actions (terminations, transfers) with timely access revocation"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.9 Personnel Security",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 2,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.9.1_personnel_screening": personnel_screening,
        "3.9.2_personnel_actions_protection": personnel_actions_protection,
    },
}
