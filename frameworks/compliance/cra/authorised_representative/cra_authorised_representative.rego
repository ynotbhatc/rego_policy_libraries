package cra.authorised_representative

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 18
# Authorised representative obligations.
#
# Non-EU manufacturers placing products on the EU market must appoint an
# authorised representative established in the Union. The mandate must be
# in writing. The authorised representative performs specific tasks on
# behalf of the manufacturer (Art.18(3)).

default compliant := false

# Art.18(1) — Mandate must be in writing
violation contains msg if {
    input.authorised_representative.required == true
    not input.authorised_representative.written_mandate_in_place
    msg := "CRA Art.18(1): Written mandate from the manufacturer to the authorised representative not in place"
}

# Art.18(1) — Non-EU manufacturer must appoint an EU rep
violation contains msg if {
    input.authorised_representative.manufacturer_outside_eu == true
    not input.authorised_representative.appointed
    msg := "CRA Art.18(1): Non-EU manufacturer has not appointed an authorised representative established in the Union"
}

# Art.18(2) — Mandate must enable the rep to perform the tasks in 18(3)
violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.mandate_enables_required_tasks
    msg := "CRA Art.18(2): Authorised representative's mandate does not enable performance of all tasks required by Art.18(3)"
}

# Art.18(3)(a) — Keep Declaration of Conformity + technical documentation
violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.tasks.keeps_declaration_of_conformity
    msg := "CRA Art.18(3)(a): Authorised representative does not retain the Declaration of Conformity"
}

violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.tasks.keeps_technical_documentation
    msg := "CRA Art.18(3)(a): Authorised representative does not retain a copy of the technical documentation"
}

violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.tasks.retention_10_years
    msg := "CRA Art.18(3)(a): Authorised representative's retention period for documentation is below the 10-year requirement"
}

# Art.18(3)(b) — Provide info/documentation to authorities on reasoned request
violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.tasks.provide_info_on_request
    msg := "CRA Art.18(3)(b): Authorised representative does not commit to providing information on reasoned request from authorities"
}

# Art.18(3)(c) — Cooperate with authorities on actions to eliminate cyber risks
violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.tasks.cooperate_on_cyber_risk_action
    msg := "CRA Art.18(3)(c): Authorised representative does not commit to cooperating with authorities on eliminating cybersecurity risks"
}

# Art.18(3)(d) — Terminate mandate if manufacturer acts contrary to CRA
violation contains msg if {
    input.authorised_representative.appointed == true
    input.authorised_representative.manufacturer_breaching_cra == true
    not input.authorised_representative.tasks.notified_competent_authority
    msg := "CRA Art.18(3)(d): Authorised representative aware of manufacturer breach of CRA but has not informed competent authorities"
}

violation contains msg if {
    input.authorised_representative.appointed == true
    input.authorised_representative.manufacturer_breaching_cra == true
    not input.authorised_representative.tasks.mandate_termination_considered
    msg := "CRA Art.18(3)(d): Authorised representative aware of manufacturer's persistent breach but has not considered mandate termination"
}

# Art.18(4) — Cannot delegate manufacturer's core obligations (essential reqs, conformity assessment)
violation contains msg if {
    input.authorised_representative.appointed == true
    input.authorised_representative.tasks.essential_requirements_delegated == true
    msg := "CRA Art.18(4): Manufacturer's obligation to ensure essential requirements compliance has been delegated to the authorised representative — this delegation is not permitted"
}

violation contains msg if {
    input.authorised_representative.appointed == true
    input.authorised_representative.tasks.conformity_assessment_delegated == true
    msg := "CRA Art.18(4): Manufacturer's obligation to perform conformity assessment has been delegated to the authorised representative — this delegation is not permitted"
}

# Art.18(5) — Contact details of the rep included in user information
violation contains msg if {
    input.authorised_representative.appointed == true
    not input.authorised_representative.contact_in_user_info
    msg := "CRA Art.18(5): Authorised representative contact details not included in product user information / accompanying documentation"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 18",
    "name":   "Authorised representative obligations",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
