package cfr_part_11.main

import rego.v1

# FDA 21 CFR Part 11 — Electronic Records; Electronic Signatures
# Published: 1997 (foundational rule), FDA Guidance: 2003
# Enforced by: U.S. Food and Drug Administration (FDA)
#
# Applies to:
#   - Pharmaceutical manufacturers
#   - Biotech and medical device companies
#   - Clinical research organizations (CROs)
#   - Any FDA-regulated industry using electronic records and e-signatures
#     in place of paper records required under FDA regulations (Predicate Rules)
#
# Key sections:
#   11.10  — Controls for closed systems
#   11.30  — Controls for open systems
#   11.50  — Signature manifestations
#   11.70  — Signature/record linking
#   11.100 — General requirements for electronic signatures
#   11.200 — Electronic signature components and controls
#   11.300 — Controls for identification codes/passwords
#
# OPA endpoint: POST http://<host>:8182/v1/data/cfr_part_11/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── §11.10 — Controls for Closed Systems ──────────────────────────────────────

# §11.10(a) — Validation
violations contains msg if {
    not input.system_validation.validated
    msg := "21 CFR 11.10(a): System not validated to ensure accuracy, reliability, consistent intended performance, and ability to discern invalid/altered records"
}

violations contains msg if {
    not input.system_validation.iq_oq_pq.documented
    msg := "21 CFR 11.10(a): Installation Qualification (IQ), Operational Qualification (OQ), Performance Qualification (PQ) not documented"
}

violations contains msg if {
    not input.system_validation.revalidation.on_change
    msg := "21 CFR 11.10(a): System not revalidated after significant changes affecting electronic records or signatures"
}

# §11.10(b) — Ability to generate accurate copies of records
violations contains msg if {
    not input.records.human_readable.capable
    msg := "21 CFR 11.10(b): System cannot produce accurate and complete copies of records in human readable form"
}

violations contains msg if {
    not input.records.electronic_copy.capable
    msg := "21 CFR 11.10(b): System cannot produce accurate electronic copies of records for authorized agency inspection"
}

# §11.10(c) — Protection of records
violations contains msg if {
    not input.records.retention.protected_during_retention_period
    msg := "21 CFR 11.10(c): Electronic records not protected to enable their accurate and ready retrieval throughout record retention period"
}

violations contains msg if {
    not input.records.backup.regular_and_tested
    msg := "21 CFR 11.10(c): Electronic records not regularly backed up with tested restoration procedures"
}

# §11.10(d) — System access limited to authorized individuals
violations contains msg if {
    not input.access_control.authorized_users.only
    msg := "21 CFR 11.10(d): System access not limited to authorized individuals"
}

violations contains msg if {
    not input.access_control.unique_user_ids.enforced
    msg := "21 CFR 11.10(d): Unique user IDs not enforced — shared accounts not acceptable for 21 CFR Part 11"
}

# §11.10(e) — Secure, computer-generated, time-stamped audit trails
violations contains msg if {
    not input.audit_trail.computer_generated
    msg := "21 CFR 11.10(e): Audit trails not computer-generated (no manual audit trail entries permitted)"
}

violations contains msg if {
    not input.audit_trail.timestamps.accurate
    msg := "21 CFR 11.10(e): Audit trail timestamps not accurate and synchronized to authoritative time source"
}

violations contains msg if {
    not input.audit_trail.captures_record_changes
    msg := "21 CFR 11.10(e): Audit trail does not record date/time, operator ID, and nature of record changes"
}

violations contains msg if {
    not input.audit_trail.protected_from_modification
    msg := "21 CFR 11.10(e): Audit trail records not protected against modification or deletion by users"
}

violations contains msg if {
    not input.audit_trail.retention.at_least_as_long_as_record
    msg := "21 CFR 11.10(e): Audit trail not retained for at least as long as the records it covers, and available for agency review"
}

# §11.10(f) — Operational system checks
violations contains msg if {
    not input.operational_checks.sequence_enforcement
    msg := "21 CFR 11.10(f): System checks not in place to enforce permitted sequencing of steps and events where required"
}

# §11.10(g) — Authority checks
violations contains msg if {
    not input.authority_checks.enabled
    msg := "21 CFR 11.10(g): System does not check authority to sign, access system, or perform operations at time of attempted action"
}

# §11.10(h) — Device checks
violations contains msg if {
    not input.device_checks.input_validation
    msg := "21 CFR 11.10(h): Device checks not used to determine validity of source of data input or operational instruction"
}

# §11.10(i) — Personnel qualification
violations contains msg if {
    not input.personnel.training.system_specific
    msg := "21 CFR 11.10(i): Personnel not trained and qualified on the use of the electronic records/signatures system"
}

violations contains msg if {
    not input.personnel.training.records.maintained
    msg := "21 CFR 11.10(i): Training records for electronic records system use not maintained"
}

# §11.10(j) — Written policies holding individuals accountable
violations contains msg if {
    not input.policies.individual_accountability.documented
    msg := "21 CFR 11.10(j): Written policies holding individuals accountable for actions initiated under their electronic signatures not established"
}

# §11.10(k) — Controls over systems documentation
violations contains msg if {
    not input.documentation.distribution.controlled
    msg := "21 CFR 11.10(k)(1): Controls not established for distribution of, access to, and use of system documentation"
}

violations contains msg if {
    not input.documentation.revision.controlled
    msg := "21 CFR 11.10(k)(2): Revision and change control procedures not established for system documentation"
}

# ── §11.30 — Controls for Open Systems ────────────────────────────────────────

violations contains msg if {
    not input.open_systems.encryption.records_in_transit
    msg := "21 CFR 11.30: Electronic records transmitted over open networks not encrypted to ensure authenticity and integrity"
}

violations contains msg if {
    not input.open_systems.digital_signatures.where_appropriate
    msg := "21 CFR 11.30: Digital signatures or equivalent controls not used to ensure record authenticity on open systems"
}

# ── §11.50 — Signature Manifestations ─────────────────────────────────────────

violations contains msg if {
    not input.electronic_signatures.manifestation.printed_name
    msg := "21 CFR 11.50(a)(1): Electronic signature does not include the printed name of the signer"
}

violations contains msg if {
    not input.electronic_signatures.manifestation.date_time
    msg := "21 CFR 11.50(a)(2): Electronic signature does not include the date and time of signing"
}

violations contains msg if {
    not input.electronic_signatures.manifestation.meaning
    msg := "21 CFR 11.50(a)(3): Electronic signature does not indicate the meaning of the signature (review, approval, responsibility)"
}

violations contains msg if {
    not input.electronic_signatures.manifestation.human_readable
    msg := "21 CFR 11.50(b): Electronic signature manifestation not included in human readable form of signed records"
}

# ── §11.70 — Signature/Record Linking ─────────────────────────────────────────

violations contains msg if {
    not input.electronic_signatures.record_linking.cryptographically_bound
    msg := "21 CFR 11.70: Electronic signatures not cryptographically or procedurally linked to their respective records"
}

violations contains msg if {
    not input.electronic_signatures.record_linking.tamper_evident
    msg := "21 CFR 11.70: Signed records not tamper-evident — signature cannot be copied/transferred to falsify records"
}

# ── §11.100 — General Requirements for Electronic Signatures ──────────────────

violations contains msg if {
    not input.electronic_signatures.uniqueness.guaranteed
    msg := "21 CFR 11.100(a): Electronic signatures not proven unique to one individual and not reused or reassigned"
}

violations contains msg if {
    not input.electronic_signatures.identity_verification.before_assignment
    msg := "21 CFR 11.100(b): Identity not verified before electronic signature privileges assigned"
}

violations contains msg if {
    not input.electronic_signatures.fda_certification.filed
    msg := "21 CFR 11.100(c): Certification to FDA that electronic signatures are intended to be equivalent to handwritten signatures not filed"
}

# ── §11.200 — Electronic Signature Components and Controls ────────────────────

violations contains msg if {
    not input.electronic_signatures.non_biometric.two_distinct_components
    msg := "21 CFR 11.200(a)(1): Non-biometric electronic signatures do not use at least two distinct identification components (e.g., ID code + password)"
}

violations contains msg if {
    not input.electronic_signatures.non_biometric.single_session_reauth
    msg := "21 CFR 11.200(a)(2): Executing multiple signings in one session does not require all components at first signing and at least one component thereafter"
}

violations contains msg if {
    not input.electronic_signatures.non_biometric.different_session_full_auth
    msg := "21 CFR 11.200(a)(3): Executing signatures not during a single continuous session requires use of all signature components"
}

violations contains msg if {
    not input.electronic_signatures.biometric.designed_exclusively_for_individual
    msg := "21 CFR 11.200(b): Biometric electronic signatures not designed to ensure they cannot be used by anyone other than the genuine owner"
}

# ── §11.300 — Controls for Identification Codes/Passwords ─────────────────────

violations contains msg if {
    not input.identification_codes.uniqueness.maintained
    msg := "21 CFR 11.300(a): Identification code/password combinations not maintained to ensure uniqueness"
}

violations contains msg if {
    not input.identification_codes.periodic_revision
    msg := "21 CFR 11.300(b): Identification codes or passwords not periodically checked, recalled, or revised"
}

violations contains msg if {
    not input.identification_codes.unauthorized_use.detection
    msg := "21 CFR 11.300(c): Controls not in place to detect unauthorized use of passwords or identification codes"
}

violations contains msg if {
    not input.identification_codes.loss_management.procedures
    msg := "21 CFR 11.300(d): Device loss management procedures not established (for token/card-based systems)"
}

violations contains msg if {
    not input.identification_codes.transaction_safeguards
    msg := "21 CFR 11.300(e): Transaction safeguards not used to prevent unauthorized use of passwords"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":       "FDA 21 CFR Part 11",
    "title":           "Electronic Records; Electronic Signatures",
    "regulation":      "21 Code of Federal Regulations Part 11",
    "entity_name":     input.entity_name,
    "entity_type":     input.entity_type,
    "system_name":     input.system_name,
    "assessed_at":     input.assessment_date,
    "compliant":       compliant,
    "total_controls":  43,
    "violations":      violations,
    "violation_count": count(violations),
    "section_summary": {
        "s11_10_closed_systems":    [v | some v in violations; contains(v, "11.10")],
        "s11_30_open_systems":      [v | some v in violations; contains(v, "11.30")],
        "s11_50_manifestations":    [v | some v in violations; contains(v, "11.50")],
        "s11_70_record_linking":    [v | some v in violations; contains(v, "11.70")],
        "s11_100_general_esig":     [v | some v in violations; contains(v, "11.100")],
        "s11_200_esig_components":  [v | some v in violations; contains(v, "11.200")],
        "s11_300_id_codes":         [v | some v in violations; contains(v, "11.300")],
    },
}
