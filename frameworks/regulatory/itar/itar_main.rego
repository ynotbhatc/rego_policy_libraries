# METADATA
# title: "ITAR — International Traffic in Arms Regulations, 22 CFR Parts 120-130"
# custom:
#   class: compliance
#   framework: itar
#   source: us-state-dept
#   domains: [us-federal, defense, export-control]
#   coverage:
#     checks: 17
#     cited: 10
#     expected: 17
#     found: 17
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
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

# ── Evidence rule (bad input never passes, issue #301) ───────────────────────
# A yes/no fact passes only as the boolean true. A fact that is missing, null,
# a string such as "true" / "false" / "no", or a number is an evidence problem:
# the control fails and the finding says which ("evidence missing: <field> not
# collected" / "evidence invalid: <field> is not a boolean (got string)").
# Where a control accepts alternatives, any one alternative that is true
# satisfies it, but an alternative of the wrong type fails it: the verdict
# never rests on mistyped evidence.

_absent := "__absent__"

_value(path) := object.get(input, path, _absent)

_yes(path) if _value(path) == true

_collected(path) if _value(path) != _absent

_mistyped(path) if {
	_collected(path)
	not is_boolean(_value(path))
}

_unmet(facts) if {
	every path in facts {
		not _yes(path)
	}
}

_unmet(facts) if {
	some path in facts
	_mistyped(path)
}

_problem(path) := sprintf("evidence missing: input.%s not collected", [concat(".", path)]) if not _collected(path)

_problem(path) := sprintf("evidence invalid: input.%s is not a boolean (got %s)", [concat(".", path), type_name(_value(path))]) if _mistyped(path)

_evidence(facts) := sprintf(" [%s]", [concat("; ", problems)]) if {
	problems := [_problem(path) | some path in facts]
	count(problems) > 0
} else := ""

# ── Registration & Jurisdiction ──────────────────────────────────────────────

violations contains msg if {
	facts := [["registration", "ddtc_current"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 122.1: DDTC registration not current for manufacturer/exporter of defense articles or technical data", _evidence(facts)])
}

violations contains msg if {
	facts := [["jurisdiction", "technical_data_identified"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.33/121.1: USML-controlled technical data not identified and classified (jurisdiction/classification determinations not documented)", _evidence(facts)])
}

# The USML moved under us: revisions to §§121.0/121.1/126.9 effective
# 2025-09-15 (GNSS anti-spoof CRPAs, ACAS antennas and lead-free
# birdshot moved to the EAR; new §126.9(u) UUV exemption) and the Cat
# XX(a)(10)/(a)(11) UUV re-scope effective 2026-10-19. Pre-revision
# classification determinations may now be wrong in either direction.
violations contains msg if {
	facts := [["jurisdiction", "classification_reviewed_after_usml_revision"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 121.1 (as revised eff. 2025-09-15 and 2026-10-19): classification determinations not re-reviewed against the current USML — pre-revision determinations may misclassify items moved to or from the EAR", _evidence(facts)])
}

# ── Access Restriction (the core safeguarding obligation) ────────────────────

# Three satisfying paths: U.S.-persons-only, a documented export
# authorization, or documented AUKUS §126.7 exemption eligibility
# (final rule 90 FR 61053, eff. 2025-12-30) — all three §126.7 facts
# are required for that path.
_aukus_exemption_documented if {
	input.access.aukus.both_parties_on_authorized_user_list == true
	input.access.aukus.item_not_on_excluded_technology_list == true
	input.access.aukus.ddtc_registration_current == true
}

_aukus_facts := [
	["access", "aukus", "both_parties_on_authorized_user_list"],
	["access", "aukus", "item_not_on_excluded_technology_list"],
	["access", "aukus", "ddtc_registration_current"],
]

# No path satisfied, or any fact of any path sent with the wrong type.
_access_restriction_unmet(facts) if {
	not _aukus_exemption_documented
	_unmet(facts)
}

_access_restriction_unmet(facts) if {
	some path in array.concat(facts, _aukus_facts)
	_mistyped(path)
}

# The AUKUS facts are named only when they were sent with the wrong type: most entities do not use that path.
_aukus_note := sprintf(" [%s]", [concat("; ", problems)]) if {
	problems := [_problem(path) | some path in _aukus_facts; _mistyped(path)]
	count(problems) > 0
} else := ""

violations contains msg if {
	facts := [["access", "us_persons_only_enforced"], ["access", "foreign_person_authorization_documented"]]
	_access_restriction_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.50/127.1: Access to ITAR technical data not restricted to U.S. persons, with no export authorization documented and no AUKUS §126.7 exemption eligibility documented (authorized-user status both parties + item off the Excluded Technology List + current DDTC registration) — unauthorized foreign-person access is a deemed export", _evidence(facts), _aukus_note])
}

violations contains msg if {
	facts := [["access", "system_access_controls"]]
	_unmet(facts)
	msg := concat("", ["ITAR: Logical access controls not implemented on systems storing ITAR technical data (authentication, authorization, segregation from general data)", _evidence(facts)])
}

violations contains msg if {
	facts := [["access", "physical_controls"]]
	_unmet(facts)
	msg := concat("", ["ITAR: Physical access controls not implemented where ITAR technical data or defense articles are located", _evidence(facts)])
}

# ── §120.54 — Encrypted Transfer/Storage Carve-out ───────────────────────────
# Properly secured encrypted data is not an "export". The §120.54(a)(5)
# conditions: (i) unclassified; (ii) end-to-end encrypted; (iii) FIPS
# 140-compliant or equivalent (≥AES-128) modules; (iv) not intentionally
# sent to a person in, or stored in, a §126.1 proscribed country OR the
# Russian Federation (Russia is named separately — it is not a §126.1
# country); (v) not sent from such a country. Per §120.54(b)(1),
# end-to-end means the means of decryption are not provided to ANY
# third party.

violations contains msg if {
	facts := [["encryption", "end_to_end_fips_validated"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.54(a)(5)(ii)-(iii): Technical data transfers/cloud storage not secured with end-to-end encryption using FIPS 140-compliant (or equivalent, >=AES-128) modules — without it, transit or storage abroad is an export requiring authorization", _evidence(facts)])
}

violations contains msg if {
	facts := [["encryption", "no_storage_in_proscribed_or_russia"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.54(a)(5)(iv): No assurance that encrypted technical data is not intentionally sent to a person in, or stored in, a §126.1 proscribed country or the Russian Federation", _evidence(facts)])
}

violations contains msg if {
	facts := [["encryption", "not_sent_from_proscribed_or_russia"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.54(a)(5)(v): No assurance that encrypted technical data is not sent from a §126.1 proscribed country or the Russian Federation", _evidence(facts)])
}

violations contains msg if {
	facts := [["encryption", "keys_withheld_from_foreign_persons"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.54(b)(1): Means of decryption not withheld from third parties — end-to-end encryption requires that decryption capability is provided to no third party", _evidence(facts)])
}

# ── Compliance Program (DDTC consent-agreement staples) ──────────────────────

violations contains msg if {
	facts := [["program", "written_compliance_program"]]
	_unmet(facts)
	msg := concat("", ["ITAR: Written export compliance program not established (DDTC compliance program guidelines)", _evidence(facts)])
}

violations contains msg if {
	facts := [["program", "empowered_official_designated"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 120.67: Empowered Official not designated for export authorization decisions", _evidence(facts)])
}

violations contains msg if {
	facts := [["program", "training_provided"]]
	_unmet(facts)
	msg := concat("", ["ITAR: Export-control training not provided to personnel with access to ITAR technical data", _evidence(facts)])
}

violations contains msg if {
	facts := [["program", "subcontractor_flowdown"]]
	_unmet(facts)
	msg := concat("", ["ITAR: ITAR safeguarding obligations not flowed down to subcontractors and service providers handling technical data", _evidence(facts)])
}

violations contains msg if {
	facts := [["program", "violation_disclosure_process"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 127.12: Process for voluntary disclosure of suspected violations not established", _evidence(facts)])
}

# ── Recordkeeping ────────────────────────────────────────────────────────────

violations contains msg if {
	facts := [["records", "retention_5_years"]]
	_unmet(facts)
	msg := concat("", ["ITAR 22 CFR 122.5/123.22: Export-related records not maintained for the required 5-year period", _evidence(facts)])
}

violations contains msg if {
	facts := [["records", "access_logging"]]
	_unmet(facts)
	msg := concat("", ["ITAR: Access to ITAR technical data not logged (who accessed what, when — the record a deemed-export investigation requires)", _evidence(facts)])
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
	"total_controls": 17,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([17, count(violations)]),
	"scope_note": "Covers the assessable data-safeguarding slice of ITAR. Licensing decisions, TAA/MLA agreements, and jurisdiction rulings are legal process outside technical assessment. Pair with NIST SP 800-171 for technical control depth on the same systems.",
}
