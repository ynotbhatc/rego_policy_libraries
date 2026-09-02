package itar.main

import rego.v1

# ITAR — International Traffic in Arms Regulations, 22 CFR Parts 120-130
# (U.S. Department of State, Directorate of Defense Trade Controls)
#
# HONEST SCOPE: most of ITAR is licensing and legal process — export
# authorizations, TAA/MLA agreements, empowered-official decisions —
# which no technical assessment can attest. This module covers the
# ASSESSABLE slice: safeguarding of export-controlled technical data
# on information systems, the §120.54 encryption carve-out for
# transfers/storage, access restriction to U.S. persons, registration
# and recordkeeping hygiene, and the compliance-program basics DDTC
# consent agreements consistently require.
#
# For CUI-grade technical control depth on the systems holding ITAR
# technical data, pair this with NIST SP 800-171
# (frameworks/federal/nist/sp_800_171/) — the DFARS/CMMC control set
# is the appropriate hardening baseline for the same systems.
#
# Input contract: entity-level attestation + data-handling facts.
# See tests for the expected shape.

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Registration & Jurisdiction ──────────────────────────────────────────────

violations contains msg if {
	not input.registration.ddtc_current
	msg := "ITAR 22 CFR 122.1: DDTC registration not current for manufacturer/exporter of defense articles or technical data"
}

violations contains msg if {
	not input.jurisdiction.technical_data_identified
	msg := "ITAR 22 CFR 120.33/121.1: USML-controlled technical data not identified and classified (jurisdiction/classification determinations not documented)"
}

# ── Access Restriction (the core safeguarding obligation) ────────────────────

violations contains msg if {
	not input.access.us_persons_only_enforced
	not input.access.foreign_person_authorization_documented
	msg := "ITAR 22 CFR 120.50/127.1: Access to ITAR technical data not restricted to U.S. persons, and no export authorization documented for foreign-person access (unauthorized foreign-person access is a deemed export)"
}

violations contains msg if {
	not input.access.system_access_controls
	msg := "ITAR: Logical access controls not implemented on systems storing ITAR technical data (authentication, authorization, segregation from general data)"
}

violations contains msg if {
	not input.access.physical_controls
	msg := "ITAR: Physical access controls not implemented where ITAR technical data or defense articles are located"
}

# ── §120.54 — Encrypted Transfer/Storage Carve-out ───────────────────────────
# Properly secured encrypted data is not an "export" — the condition
# set is specific: FIPS 140-validated end-to-end encryption, no
# decryption in a §126.1 country, keys not provided to foreign persons.

violations contains msg if {
	not input.encryption.end_to_end_fips_validated
	msg := "ITAR 22 CFR 120.54(a)(5)(i): Technical data transfers/cloud storage not secured with FIPS 140-validated end-to-end encryption — without it, transit or storage abroad is an export requiring authorization"
}

violations contains msg if {
	not input.encryption.no_decryption_in_proscribed_countries
	msg := "ITAR 22 CFR 120.54(a)(5)(ii): No assurance that encrypted technical data is not decrypted in §126.1 proscribed countries"
}

violations contains msg if {
	not input.encryption.keys_withheld_from_foreign_persons
	msg := "ITAR 22 CFR 120.54(a)(5)(iii): Decryption keys/means not withheld from foreign persons"
}

# ── Compliance Program (DDTC consent-agreement staples) ──────────────────────

violations contains msg if {
	not input.program.written_compliance_program
	msg := "ITAR: Written export compliance program not established (DDTC compliance program guidelines)"
}

violations contains msg if {
	not input.program.empowered_official_designated
	msg := "ITAR 22 CFR 120.67: Empowered Official not designated for export authorization decisions"
}

violations contains msg if {
	not input.program.training_provided
	msg := "ITAR: Export-control training not provided to personnel with access to ITAR technical data"
}

violations contains msg if {
	not input.program.subcontractor_flowdown
	msg := "ITAR: ITAR safeguarding obligations not flowed down to subcontractors and service providers handling technical data"
}

violations contains msg if {
	not input.program.violation_disclosure_process
	msg := "ITAR 22 CFR 127.12: Process for voluntary disclosure of suspected violations not established"
}

# ── Recordkeeping ────────────────────────────────────────────────────────────

violations contains msg if {
	not input.records.retention_5_years
	msg := "ITAR 22 CFR 122.5/123.22: Export-related records not maintained for the required 5-year period"
}

violations contains msg if {
	not input.records.access_logging
	msg := "ITAR: Access to ITAR technical data not logged (who accessed what, when — the record a deemed-export investigation requires)"
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

compliance_report := {
	"framework": "ITAR Technical Data Safeguarding",
	"regulation": "22 CFR Parts 120-130 (assessable data-safeguarding slice)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 15,
	"violations": violations,
	"violation_count": count(violations),
	"scope_note": "Covers the assessable data-safeguarding slice of ITAR. Licensing decisions, TAA/MLA agreements, and jurisdiction rulings are legal process outside technical assessment. Pair with NIST SP 800-171 for technical control depth on the same systems.",
}
