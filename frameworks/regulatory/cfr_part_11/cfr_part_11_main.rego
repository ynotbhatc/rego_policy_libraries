# METADATA
# title: "FDA 21 CFR Part 11 — Electronic Records; Electronic Signatures"
# custom:
#   class: compliance
#   framework: cfr_part_11
#   source: fda
#   domains: [life-sciences, us-federal]
#   coverage:
#     checks: 50
#     cited: 34
#     expected: 50
#     found: 50
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cfr_part_11.main

import rego.v1

# FDA 21 CFR Part 11: Electronic Records; Electronic Signatures
# Source: https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11 (text checked 2026-11-23 against the
# eCFR version of 2026-01-01). Final rule 62 FR 13464, Mar. 20, 1997; §11.100 amended at 88 FR 13018, Mar. 2, 2023.
# Enforced by: U.S. Food and Drug Administration (FDA)
#
# Applies to electronic records and electronic signatures used in place of paper records and handwritten
# signatures required by FDA regulations (the predicate rules): pharmaceutical, biotech and medical device
# manufacturers, clinical research organizations, and other FDA-regulated firms.
#
# What is checked: 50 checks, one violation each.
#   11.10  Controls for closed systems            (a) to (k)(2), 22 checks
#   11.30  Controls for open systems              2 checks + 1 scope declaration
#   11.50  Signature manifestations               (a)(1) to (b), 4 checks
#   11.70  Signature/record linking               2 checks
#   11.100 General requirements                   (a) to (c), 3 checks
#   11.200 Signature components and controls      (a)(1), (a)(1)(i), (a)(1)(ii), (a)(2), (a)(3), (b), 6 checks
#                                                 + 2 scope declarations
#   11.300 Controls for identification codes      (a) to (e), 6 checks ((d) has two) + 2 scope declarations
# Four of the §11.10 checks are marked "(supporting check)": they test a means to the paragraph's stated outcome that
# the paragraph itself does not name (revalidation, backups, unique user IDs, training records).
#
# Not implemented: §11.100(c)(1) (certification signed with a handwritten signature) and §11.100(c)(2) (additional
# certification or testimony on agency request); §11.1 to §11.3 (scope, implementation, definitions) carry no check.
#
# Evidence: every fact must be the boolean true. A missing, null, false or non-boolean value (the string "true"
# included) is a violation.
#
# Scope declarations: §11.30, §11.200(a), §11.200(b) and §11.300 each apply to a kind of system or signature. The
# five in_use facts say which kinds are present and must be booleans; a missing or non-boolean in_use is itself a
# violation ("evidence missing or invalid") and the section's controls apply. A section is not applicable only when
# its in_use fact is the boolean false (see the sections below).
#
# Advisories (non-scoring): IQ/OQ/PQ qualification records are one accepted form of validation evidence for
# §11.10(a). The terms do not appear in 21 CFR Part 11, so their absence is reported in `advisories`, not `violations`.
#
# OPA endpoint: POST http://<host>:8182/v1/data/cfr_part_11/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

# Defaults: without these, an empty input makes compliance_report undefined
# and the OPA endpoint returns null.
default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

default system_name := "unknown"

system_name := input.system_name

default assessed_at := "unknown"

assessed_at := input.assessment_date

# ── §11.10 Controls for closed systems ──────────────────────────────────────────

# §11.10(a): "Validation of systems to ensure accuracy, reliability, consistent intended performance, and the
# ability to discern invalid or altered records."

violations contains msg if {
	not input.system_validation.validated == true
	msg := "21 CFR 11.10(a): System not validated to ensure accuracy, reliability, consistent intended performance, and the ability to discern invalid or altered records"
}

# Supporting check (the library's reading of "consistent intended performance"; revalidation is not named in the text).

violations contains msg if {
	not input.system_validation.revalidation.on_change == true
	msg := "21 CFR 11.10(a): Validation not repeated after changes that affect electronic records or signatures, so consistent intended performance is not shown (supporting check)"
}

# §11.10(b): accurate and complete copies in both human readable and electronic form for the agency

violations contains msg if {
	not input.records.human_readable.capable == true
	msg := "21 CFR 11.10(b): System cannot generate accurate and complete copies of records in human readable form suitable for inspection, review, and copying by the agency"
}

violations contains msg if {
	not input.records.electronic_copy.capable == true
	msg := "21 CFR 11.10(b): System cannot generate accurate and complete copies of records in electronic form suitable for inspection, review, and copying by the agency"
}

# §11.10(c): protection of records for accurate and ready retrieval throughout the retention period

violations contains msg if {
	not input.records.retention.protected_during_retention_period == true
	msg := "21 CFR 11.10(c): Records not protected to enable their accurate and ready retrieval throughout the records retention period"
}

# Supporting check (backups are a means to ready retrieval; the paragraph does not name them).

violations contains msg if {
	not input.records.backup.regular_and_tested == true
	msg := "21 CFR 11.10(c): Records not regularly backed up with tested restoration, so ready retrieval throughout the retention period is not shown (supporting check)"
}

# §11.10(d): limiting system access to authorized individuals

violations contains msg if {
	not input.access_control.authorized_users.only == true
	msg := "21 CFR 11.10(d): System access not limited to authorized individuals"
}

# Supporting check (shared accounts defeat the limit; uniqueness itself is required by §11.100(a) and §11.300(a)).

violations contains msg if {
	not input.access_control.unique_user_ids.enforced == true
	msg := "21 CFR 11.10(d): Unique user IDs not enforced, so access cannot be shown to be limited to authorized individuals (supporting check)"
}

# §11.10(e): secure, computer-generated, time-stamped audit trails

violations contains msg if {
	not input.audit_trail.computer_generated == true
	msg := "21 CFR 11.10(e): Audit trails are not computer-generated"
}

violations contains msg if {
	not input.audit_trail.timestamps.accurate == true
	msg := "21 CFR 11.10(e): Audit trail entries are not accurately time-stamped"
}

violations contains msg if {
	not input.audit_trail.captures_record_changes == true
	msg := "21 CFR 11.10(e): Audit trail does not independently record the date and time of operator entries and actions that create, modify, or delete electronic records"
}

violations contains msg if {
	not input.audit_trail.protected_from_modification == true
	msg := "21 CFR 11.10(e): Audit trail is not secure: users can modify or delete its entries"
}

violations contains msg if {
	not input.audit_trail.previous_entries_not_obscured == true
	msg := "21 CFR 11.10(e): Record changes obscure previously recorded information"
}

violations contains msg if {
	not input.audit_trail.retention.at_least_as_long_as_record == true
	msg := "21 CFR 11.10(e): Audit trail documentation not retained at least as long as the subject electronic records, or not available for agency review and copying"
}

# §11.10(f): operational system checks

violations contains msg if {
	not input.operational_checks.sequence_enforcement == true
	msg := "21 CFR 11.10(f): Operational system checks not used to enforce permitted sequencing of steps and events, as appropriate"
}

# §11.10(g): authority checks

violations contains msg if {
	not input.authority_checks.enabled == true
	msg := "21 CFR 11.10(g): Authority checks not used to ensure that only authorized individuals can use the system, sign a record, access devices, alter a record, or perform the operation at hand"
}

# §11.10(h): device checks

violations contains msg if {
	not input.device_checks.input_validation == true
	msg := "21 CFR 11.10(h): Device (e.g., terminal) checks not used to determine, as appropriate, the validity of the source of data input or operational instruction"
}

# §11.10(i): education, training, and experience of the people who develop, maintain, or use the system

violations contains msg if {
	not input.personnel.training.system_specific == true
	msg := "21 CFR 11.10(i): No determination that persons who develop, maintain, or use the system have the education, training, and experience to perform their assigned tasks"
}

# Supporting check (records are the evidence of the determination; the paragraph does not name them).

violations contains msg if {
	not input.personnel.training.records.maintained == true
	msg := "21 CFR 11.10(i): Training records that evidence the education, training, and experience determination are not maintained (supporting check)"
}

# §11.10(j): written accountability policies

violations contains msg if {
	not input.policies.individual_accountability.documented == true
	msg := "21 CFR 11.10(j): Written policies that hold individuals accountable and responsible for actions initiated under their electronic signatures are not established and adhered to"
}

# §11.10(k): controls over systems documentation

violations contains msg if {
	not input.documentation.distribution.controlled == true
	msg := "21 CFR 11.10(k)(1): No adequate controls over the distribution of, access to, and use of documentation for system operation and maintenance"
}

violations contains msg if {
	not input.documentation.revision.controlled == true
	msg := "21 CFR 11.10(k)(2): No revision and change control procedures that maintain an audit trail of time-sequenced development and modification of systems documentation"
}

# ── §11.30 Controls for open systems ────────────────────────────────────────────

# Applies to "persons who use open systems". Not applicable only when input.open_systems.in_use is the boolean false.
# The §11.10 controls above apply to open systems too ("shall include those identified in § 11.10, as appropriate").

violations contains msg if {
	not _declared_open_systems
	msg := "21 CFR 11.30: evidence missing or invalid: open_systems.in_use must be the boolean true or false (open system: 11.3(b)(9)); the open-system controls apply until it is false"
}

violations contains msg if {
	not _open_systems_na
	not input.open_systems.encryption.records_in_transit == true
	msg := "21 CFR 11.30: Open system does not use additional measures such as document encryption to ensure record authenticity, integrity, and confidentiality from creation to receipt"
}

violations contains msg if {
	not _open_systems_na
	not input.open_systems.digital_signatures.where_appropriate == true
	msg := "21 CFR 11.30: Open system does not use appropriate digital signature standards (or an equivalent measure) to ensure record authenticity and integrity"
}

# ── §11.50 Signature manifestations ─────────────────────────────────────────────

violations contains msg if {
	not input.electronic_signatures.manifestation.printed_name == true
	msg := "21 CFR 11.50(a)(1): Signed electronic records do not contain the printed name of the signer"
}

violations contains msg if {
	not input.electronic_signatures.manifestation.date_time == true
	msg := "21 CFR 11.50(a)(2): Signed electronic records do not contain the date and time when the signature was executed"
}

violations contains msg if {
	not input.electronic_signatures.manifestation.meaning == true
	msg := "21 CFR 11.50(a)(3): Signed electronic records do not contain the meaning (such as review, approval, responsibility, or authorship) associated with the signature"
}

violations contains msg if {
	not input.electronic_signatures.manifestation.human_readable == true
	msg := "21 CFR 11.50(b): Signer name, date and time, and meaning are not included in every human readable form of the electronic record (display or printout)"
}

# ── §11.70 Signature/record linking ─────────────────────────────────────────────

violations contains msg if {
	not input.electronic_signatures.record_linking.cryptographically_bound == true
	msg := "21 CFR 11.70: Signatures are not linked to their respective electronic records"
}

violations contains msg if {
	not input.electronic_signatures.record_linking.tamper_evident == true
	msg := "21 CFR 11.70: Signatures can be excised, copied, or otherwise transferred to falsify an electronic record by ordinary means"
}

# ── §11.100 General requirements for electronic signatures ──────────────────────

violations contains msg if {
	not input.electronic_signatures.uniqueness.guaranteed == true
	msg := "21 CFR 11.100(a): Electronic signatures are not unique to one individual, or are reused by or reassigned to someone else"
}

violations contains msg if {
	not input.electronic_signatures.identity_verification.before_assignment == true
	msg := "21 CFR 11.100(b): Identity of the individual not verified before the electronic signature is established, assigned, certified, or otherwise sanctioned"
}

violations contains msg if {
	not input.electronic_signatures.fda_certification.filed == true
	msg := "21 CFR 11.100(c): No certification to the agency that the electronic signatures are intended to be the legally binding equivalent of traditional handwritten signatures"
}

# ── §11.200 Electronic signature components and controls ────────────────────────

# §11.200(a) covers signatures "not based upon biometrics"; §11.200(b) covers signatures "based upon biometrics".
# (b) is not applicable only when biometric.in_use is the boolean false. (a) is not applicable only when
# non_biometric.in_use is the boolean false AND biometric.in_use is true, so declaring neither kind exempts nothing.

violations contains msg if {
	not _declared_electronic_signatures_non_biometric
	msg := "21 CFR 11.200(a): evidence missing or invalid: electronic_signatures.non_biometric.in_use must be true or false; the 11.200(a) controls apply until it is false and biometric.in_use is true"
}

violations contains msg if {
	not _non_biometric_na
	not input.electronic_signatures.non_biometric.two_distinct_components == true
	msg := "21 CFR 11.200(a)(1): Non-biometric electronic signatures do not employ at least two distinct identification components such as an identification code and password"
}

violations contains msg if {
	not _non_biometric_na
	not input.electronic_signatures.non_biometric.single_session_reauth == true
	msg := "21 CFR 11.200(a)(1)(i): In a series of signings in one continuous period of controlled access, the first does not use all components or a later one uses none executable only by the signer"
}

violations contains msg if {
	not _non_biometric_na
	not input.electronic_signatures.non_biometric.different_session_full_auth == true
	msg := "21 CFR 11.200(a)(1)(ii): Signings not performed during one continuous period of controlled system access are not each executed using all of the electronic signature components"
}

violations contains msg if {
	not _non_biometric_na
	not input.electronic_signatures.non_biometric.genuine_owner_only == true
	msg := "21 CFR 11.200(a)(2): Non-biometric electronic signatures are not shown to be used only by their genuine owners"
}

violations contains msg if {
	not _non_biometric_na
	not input.electronic_signatures.non_biometric.misuse_requires_collaboration == true
	msg := "21 CFR 11.200(a)(3): Non-biometric electronic signatures are not administered so that use by anyone other than the genuine owner requires collaboration of two or more individuals"
}

violations contains msg if {
	not _declared_electronic_signatures_biometric
	msg := "21 CFR 11.200(b): evidence missing or invalid: electronic_signatures.biometric.in_use must be true or false (biometrics: 11.3(b)(3)); the control applies until it is false"
}

violations contains msg if {
	not _biometric_na
	not input.electronic_signatures.biometric.designed_exclusively_for_individual == true
	msg := "21 CFR 11.200(b): Biometric electronic signatures are not designed to ensure that they cannot be used by anyone other than their genuine owners"
}

# ── §11.300 Controls for identification codes/passwords ─────────────────────────

# Applies to "electronic signatures based upon use of identification codes in combination with passwords". Not
# applicable only when identification_codes.in_use is the boolean false. (c) and (e) concern tokens, cards and other
# devices that bear or generate code or password information: also not applicable when devices.in_use is false.

violations contains msg if {
	not _declared_identification_codes
	msg := "21 CFR 11.300: evidence missing or invalid: identification_codes.in_use must be true or false (signatures based on identification codes with passwords); the controls apply until it is false"
}

violations contains msg if {
	not _id_codes_na
	not _declared_identification_codes_devices
	msg := "21 CFR 11.300: evidence missing or invalid: identification_codes.devices.in_use must be true or false (tokens, cards, other code or password devices); (c) and (e) apply until it is false"
}

violations contains msg if {
	not _id_codes_na
	not input.identification_codes.uniqueness.maintained == true
	msg := "21 CFR 11.300(a): Uniqueness of each combined identification code and password is not maintained"
}

violations contains msg if {
	not _id_codes_na
	not input.identification_codes.periodic_revision == true
	msg := "21 CFR 11.300(b): Identification code and password issuances are not periodically checked, recalled, or revised (e.g., password aging)"
}

violations contains msg if {
	not _id_devices_na
	not input.identification_codes.loss_management.procedures == true
	msg := "21 CFR 11.300(c): No loss management procedures to electronically deauthorize lost, stolen, missing, or potentially compromised tokens, cards, and other devices and to issue replacements"
}

violations contains msg if {
	not _id_codes_na
	not input.identification_codes.transaction_safeguards == true
	msg := "21 CFR 11.300(d): Transaction safeguards not used to prevent unauthorized use of passwords and/or identification codes"
}

violations contains msg if {
	not _id_codes_na
	not input.identification_codes.unauthorized_use.detection == true
	msg := "21 CFR 11.300(d): Attempts at unauthorized use of passwords or identification codes are not detected and reported in an immediate and urgent manner to the system security unit"
}

violations contains msg if {
	not _id_devices_na
	not input.identification_codes.device_testing.initial_and_periodic == true
	msg := "21 CFR 11.300(e): No initial and periodic testing of devices, such as tokens or cards, that bear or generate identification code or password information"
}

# ── Applicability (explicit, typed) ──────────────────────────────────────────

_open_systems_na if input.open_systems.in_use == false

_biometric_na if input.electronic_signatures.biometric.in_use == false

_non_biometric_na if {
	input.electronic_signatures.non_biometric.in_use == false
	input.electronic_signatures.biometric.in_use == true
}

_id_codes_na if input.identification_codes.in_use == false

_id_devices_na if _id_codes_na

_id_devices_na if input.identification_codes.devices.in_use == false

# A scope declaration counts only as a boolean. (Written as helper rules: `not is_boolean(input.x)` is not true when
# input.x is missing, so the negation has to be over a rule.)
_declared_open_systems if is_boolean(input.open_systems.in_use)

_declared_electronic_signatures_non_biometric if is_boolean(input.electronic_signatures.non_biometric.in_use)

_declared_electronic_signatures_biometric if is_boolean(input.electronic_signatures.biometric.in_use)

_declared_identification_codes if is_boolean(input.identification_codes.in_use)

_declared_identification_codes_devices if is_boolean(input.identification_codes.devices.in_use)

# ── Advisories (non-scoring) ─────────────────────────────────────────────────

# Installation, operational and performance qualification (IQ/OQ/PQ) is common industry practice for showing that a
# system is validated. It is not regulation text: §11.10(a) requires validation and does not say how to show it.
advisories contains msg if {
	not input.system_validation.iq_oq_pq.documented == true
	msg := "Advisory (not a 21 CFR Part 11 requirement): IQ/OQ/PQ qualification records are not documented. They are one accepted form of evidence for the validation that 21 CFR 11.10(a) requires."
}

# ── Compliance Report ────────────────────────────────────────────────────────

not_applicable contains "21 CFR 11.30 (open systems): input.open_systems.in_use is false" if _open_systems_na

not_applicable contains "21 CFR 11.200(a) (non-biometric signatures): non_biometric.in_use is false and biometric.in_use is true" if _non_biometric_na

not_applicable contains "21 CFR 11.200(b) (biometric signatures): input.electronic_signatures.biometric.in_use is false" if _biometric_na

not_applicable contains "21 CFR 11.300 (identification codes/passwords): input.identification_codes.in_use is false" if _id_codes_na

not_applicable contains "21 CFR 11.300(c) and (e) (tokens, cards and other devices): input.identification_codes.devices.in_use is false" if {
	_id_devices_na
	not _id_codes_na
}

compliance_report := {
	"framework": "FDA 21 CFR Part 11",
	"title": "Electronic Records; Electronic Signatures",
	"regulation": "21 Code of Federal Regulations Part 11",
	"entity_name": entity_name,
	"entity_type": entity_type,
	"system_name": system_name,
	"assessed_at": assessed_at,
	"compliant": compliant,
	"total_controls": 50,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": count(violations),
	"not_applicable": not_applicable,
	"advisories": advisories,
	"section_summary": {
		"s11_10_closed_systems": [v | some v in violations; startswith(v, "21 CFR 11.10(")],
		"s11_30_open_systems": [v | some v in violations; startswith(v, "21 CFR 11.30:")],
		"s11_50_manifestations": [v | some v in violations; startswith(v, "21 CFR 11.50(")],
		"s11_70_record_linking": [v | some v in violations; startswith(v, "21 CFR 11.70:")],
		"s11_100_general_esig": [v | some v in violations; startswith(v, "21 CFR 11.100(")],
		"s11_200_esig_components": [v | some v in violations; startswith(v, "21 CFR 11.200(")],
		"s11_300_id_codes": [v | some v in violations; startswith(v, "21 CFR 11.300")],
	},
}
