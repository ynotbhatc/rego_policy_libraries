package cra.declaration_of_conformity

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex IV
# Content of the EU Declaration of Conformity.
#
# This module checks the CONTENT of the declaration, distinct from
# cra.conformity_assessment which only checks that the declaration
# was prepared and signed. Annex IV enumerates the required elements;
# omitting any of them invalidates the declaration even if it exists.

default compliant := false

# Annex IV (1) — Product model identifier
violation contains msg if {
    not input.declaration_of_conformity.product_identification.model_id
    msg := "CRA Annex IV.1: Declaration of Conformity does not state the product model / type identifier"
}

violation contains msg if {
    not input.declaration_of_conformity.product_identification.serial_or_batch
    msg := "CRA Annex IV.1: Declaration of Conformity does not state the serial/batch identifier"
}

# Annex IV (2) — Manufacturer details
violation contains msg if {
    not input.declaration_of_conformity.manufacturer.name
    msg := "CRA Annex IV.2: Declaration of Conformity does not state the manufacturer name"
}

violation contains msg if {
    not input.declaration_of_conformity.manufacturer.postal_address
    msg := "CRA Annex IV.2: Declaration of Conformity does not state the manufacturer postal address"
}

# Annex IV (3) — Authorised representative details (where applicable)
violation contains msg if {
    input.declaration_of_conformity.authorised_representative.required == true
    not input.declaration_of_conformity.authorised_representative.name
    msg := "CRA Annex IV.3: Authorised representative is required but the declaration does not state their name"
}

violation contains msg if {
    input.declaration_of_conformity.authorised_representative.required == true
    not input.declaration_of_conformity.authorised_representative.postal_address
    msg := "CRA Annex IV.3: Authorised representative is required but the declaration does not state their postal address"
}

# Annex IV (4) — Statement of sole responsibility
violation contains msg if {
    not input.declaration_of_conformity.statement_of_sole_responsibility
    msg := "CRA Annex IV.4: Declaration of Conformity does not include the statement 'This declaration of conformity is issued under the sole responsibility of the manufacturer'"
}

# Annex IV (5) — Object of the declaration (description sufficient for product traceability)
violation contains msg if {
    not input.declaration_of_conformity.object_description.sufficient_for_traceability
    msg := "CRA Annex IV.5: Object of the declaration (product description) not sufficient for product traceability — must include name, type, additional info"
}

# Annex IV (6) — Statement of conformity with CRA
violation contains msg if {
    not input.declaration_of_conformity.conformity_statement.references_cra
    msg := "CRA Annex IV.6: Declaration does not explicitly state conformity with Regulation (EU) 2024/2847"
}

# Annex IV (7) — Reference to harmonised standards / common specifications used
violation contains msg if {
    not input.declaration_of_conformity.standards.harmonised_standards_referenced
    msg := "CRA Annex IV.7: Declaration does not reference the harmonised standards or common specifications applied to demonstrate conformity"
}

violation contains msg if {
    input.declaration_of_conformity.standards.harmonised_standards_referenced == true
    not input.declaration_of_conformity.standards.standard_dates_versions_included
    msg := "CRA Annex IV.7: Declaration references harmonised standards but does not include their dates/versions"
}

# Annex IV (8) — Notified body involvement (where applicable)
violation contains msg if {
    input.declaration_of_conformity.notified_body.involved == true
    not input.declaration_of_conformity.notified_body.name
    msg := "CRA Annex IV.8: Notified body involvement is declared but the notified body name is missing"
}

violation contains msg if {
    input.declaration_of_conformity.notified_body.involved == true
    not input.declaration_of_conformity.notified_body.id_number
    msg := "CRA Annex IV.8: Notified body involvement is declared but the notified body identification number is missing"
}

violation contains msg if {
    input.declaration_of_conformity.notified_body.involved == true
    not input.declaration_of_conformity.notified_body.certificate_reference
    msg := "CRA Annex IV.8: Notified body involvement is declared but the issued certificate reference is missing"
}

# Annex IV (9) — Additional information
violation contains msg if {
    not input.declaration_of_conformity.additional_info.support_period_stated
    msg := "CRA Annex IV.9: Declaration of Conformity does not state the declared support period"
}

# Annex IV (10) — Signature
violation contains msg if {
    not input.declaration_of_conformity.signature.signed_for_manufacturer
    msg := "CRA Annex IV.10: Declaration of Conformity has not been signed for and on behalf of the manufacturer"
}

violation contains msg if {
    not input.declaration_of_conformity.signature.signatory_name
    msg := "CRA Annex IV.10: Declaration of Conformity signature does not include the signatory's name"
}

violation contains msg if {
    not input.declaration_of_conformity.signature.signatory_function
    msg := "CRA Annex IV.10: Declaration of Conformity signature does not include the signatory's function"
}

violation contains msg if {
    not input.declaration_of_conformity.signature.place_and_date
    msg := "CRA Annex IV.10: Declaration of Conformity does not include the place and date of issue"
}

# Languages — Annex IV preamble (translated into Member State languages where product is sold)
violation contains msg if {
    not input.declaration_of_conformity.languages.translated_for_member_states
    msg := "CRA Annex IV (preamble): Declaration not translated into the official languages of the Member States where the product is placed on the market"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Annex IV",
    "name":   "Content of EU Declaration of Conformity",
    "controls_evaluated": 20,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
