# FERPA — Family Educational Rights and Privacy Act
# 20 U.S.C. § 1232g; regulations at 34 CFR Part 99
#
# Assessment target: an educational agency or institution (or an SEA/LEA)
# receiving funds under a program administered by the U.S. Department of
# Education. FERPA is a rights-and-disclosure statute, not a technical
# hardening baseline: nearly all of its obligations are program facts
# (notices published, procedures documented, agreements executed, logs
# kept), so the input contract is attestation/GRC-shaped rather than
# host-fact-shaped. Nothing here is collected from a device.
#
# Controls are grouped by the regulation's own structure:
#   §99.7          Annual notification of rights
#   §99.10–99.22   Access, amendment, and hearing rights
#   §99.30         Prior written consent
#   §99.31/33/35/36 Disclosure exceptions and their conditions
#   §99.37         Directory information
#   §99.32         Recordkeeping of disclosures
#   §99.5/99.8     Eligible students; law-enforcement-unit records
#
# Violation messages cite the specific section an auditor (or the
# Student Privacy Policy Office) would examine.
#
# Input contract (all fields boolean unless noted):
#   input.ferpa.notification.{published, includes_right_to_inspect,
#     includes_right_to_amend, includes_disclosure_conditions,
#     includes_complaint_right}
#   input.ferpa.access.{process_documented, response_deadline_enforced,
#     amendment_procedure_documented, hearing_available,
#     statement_right_provided}
#   input.ferpa.consent.{written_before_disclosure, specifies_scope,
#     records_retained}
#   input.ferpa.school_officials.{criteria_in_notification,
#     access_controls_enforced, contractors_under_direct_control}
#   input.ferpa.exceptions.{transfer_conditions_met,
#     audit_written_agreements, audit_data_destroyed,
#     studies_written_agreement, subpoena_notify_effort,
#     health_safety_threat_recorded}
#   input.ferpa.directory.{public_notice, opt_out_offered, opt_out_honored}
#   input.ferpa.records_of_disclosure.{log_maintained,
#     log_retained_with_records, redisclosure_recorded}
#   input.ferpa.redisclosure.{limits_communicated, violation_process}
#   input.ferpa.program.{eligible_student_rights_transfer,
#     leu_records_separated}
#
# Fail-closed: absent facts fire every control (the "violate if the fact
# does not say so" pattern), so an empty assessment reports non-compliant
# across all 32 controls — never a silent pass.
#
# OPA query path: /v1/data/ferpa/main/compliance_report

# METADATA
# title: "FERPA — Family Educational Rights and Privacy Act"
# custom:
#   class: compliance
#   framework: ferpa
#   source: us-federal
#   domains: [privacy, education]
#   coverage:
#     checks: 32
#     cited: 31
#     expected: 32
#     found: 32
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ferpa.main

import rego.v1

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

# ── §99.7 — Annual notification of rights ────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "notification", "published"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.7: Annual notification of FERPA rights not provided to parents / eligible students%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "notification", "includes_right_to_inspect"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.7(a)(2)(i): Annual notification does not state the right to inspect and review education records%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "notification", "includes_right_to_amend"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.7(a)(2)(ii): Annual notification does not state the right to seek amendment of records believed inaccurate or misleading%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "notification", "includes_disclosure_conditions"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.7(a)(2)(iii): Annual notification does not state the conditions under which records are disclosed with and without consent%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "notification", "includes_complaint_right"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.7(a)(2)(iv): Annual notification does not state the right to file a complaint with the U.S. Department of Education%s", [_evidence(facts)])
}

# ── §99.10–99.22 — Access, amendment, and hearing ────────────────────────────

violations contains msg if {
	facts := [["ferpa", "access", "process_documented"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.10: No documented process for parents / eligible students to inspect and review education records%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "access", "response_deadline_enforced"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.10(b): Access requests not fulfilled within the required 45 days of the request%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "access", "amendment_procedure_documented"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.20: No documented procedure to request amendment of inaccurate or misleading records%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "access", "hearing_available"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.21–99.22: Hearing opportunity on amendment denial not provided or does not meet minimum requirements%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "access", "statement_right_provided"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.21(b)(2): Right to place a statement of disagreement in the record after an unsuccessful amendment hearing not provided%s", [_evidence(facts)])
}

# ── §99.30 — Prior written consent ───────────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "consent", "written_before_disclosure"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.30(a): Signed and dated written consent not obtained before disclosing personally identifiable information from education records (outside §99.31 exceptions)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "consent", "specifies_scope"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.30(b): Consent instrument does not specify the records disclosed, the purpose, and the party or class of parties receiving them%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "consent", "records_retained"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.30: Executed consent records not retained as evidence of authorized disclosure%s", [_evidence(facts)])
}

# ── §99.31(a)(1) — School-official exception conditions ──────────────────────

violations contains msg if {
	facts := [["ferpa", "school_officials", "criteria_in_notification"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(1) / §99.7(a)(3)(iii): Criteria for who is a school official with legitimate educational interest not specified in the annual notification%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "school_officials", "access_controls_enforced"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(1)(ii): Reasonable methods (physical, technological, or administrative access controls) not used to limit school-official access to records in which they have a legitimate educational interest%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "school_officials", "contractors_under_direct_control"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(1)(i)(B): Contractors / consultants / volunteers acting as school officials not under the institution's direct control with respect to use and maintenance of education records%s", [_evidence(facts)])
}

# ── §99.31/99.33/99.35/99.36 — Other exception conditions ────────────────────

violations contains msg if {
	facts := [["ferpa", "exceptions", "transfer_conditions_met"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(2) / §99.34: Disclosures to schools of intended enrollment made without the required annual-notice statement or reasonable attempt to notify%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "exceptions", "audit_written_agreements"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.35(a)(3): Audit/evaluation disclosures to authorized representatives not governed by the required written agreement (designation, purpose, PII scope, destruction terms)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "exceptions", "audit_data_destroyed"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.35(b)(2): PII disclosed for audit/evaluation not destroyed when no longer needed for the stated purpose%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "exceptions", "studies_written_agreement"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(6)(iii)(C): Disclosures for studies not governed by the required written agreement (purpose/scope/duration, use limits, destruction)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "exceptions", "subpoena_notify_effort"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.31(a)(9)(ii): No reasonable effort to notify the parent / eligible student before complying with a subpoena or judicial order (where notification is not prohibited)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "exceptions", "health_safety_threat_recorded"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.36 / §99.32(a)(5): Health-or-safety-emergency disclosures made without recording the articulable and significant threat and the parties who received the information%s", [_evidence(facts)])
}

# ── §99.37 — Directory information ───────────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "directory", "public_notice"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.37(a)(1): Public notice of the types of PII designated as directory information not given%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "directory", "opt_out_offered"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.37(a)(2)-(3): Parents / eligible students not given the right and a reasonable period to refuse directory-information designation%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "directory", "opt_out_honored"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.37: Directory-information opt-outs not honored in actual disclosures%s", [_evidence(facts)])
}

# ── §99.32 — Recordkeeping of disclosures ────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "records_of_disclosure", "log_maintained"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.32(a)(1): Record of each request for and disclosure of PII from education records (parties and legitimate interests) not maintained%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "records_of_disclosure", "log_retained_with_records"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.32(a)(2): Disclosure record not retained as long as the education record it documents%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "records_of_disclosure", "redisclosure_recorded"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.32(b): Authorized redisclosures (parties and legitimate interests) not recorded%s", [_evidence(facts)])
}

# ── §99.33 — Redisclosure limits ─────────────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "redisclosure", "limits_communicated"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.33(d): Recipients not informed that PII may be used only for the disclosed purpose and not redisclosed except as permitted%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "redisclosure", "violation_process"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.33(e): No process to address improper redisclosure by a third party (including the five-year access bar the Department may impose)%s", [_evidence(facts)])
}

# ── §99.5 / §99.8 — Program controls ─────────────────────────────────────────

violations contains msg if {
	facts := [["ferpa", "program", "eligible_student_rights_transfer"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.5: Transfer of FERPA rights to the student at age 18 or postsecondary enrollment not recognized in procedures and notices%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["ferpa", "program", "leu_records_separated"]]
	_unmet(facts)
	msg := sprintf("FERPA §99.8: Law-enforcement-unit records not maintained separately from education records (commingling brings them under FERPA and defeats the exemption)%s", [_evidence(facts)])
}

# ── Per-area rollup ──────────────────────────────────────────────────────────

area_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

area_summary := {
	"annual_notification": count(area_violations("FERPA §99.7")),
	"access_and_amendment": count([v |
		some v in violations
		regex.match(`^FERPA §99\.(10|20|21|22)`, v)
	]),
	"consent": count(area_violations("FERPA §99.30")),
	"disclosure_exceptions": count([v |
		some v in violations
		regex.match(`^FERPA §99\.(31|33|34|35|36)`, v)
	]),
	"directory_information": count(area_violations("FERPA §99.37")),
	"recordkeeping": count(area_violations("FERPA §99.32")),
	"program": count([v |
		some v in violations
		regex.match(`^FERPA §99\.(5|8)`, v)
	]),
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — an undefined field would collapse the whole report object.
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

compliance_report := {
	"framework": "FERPA (Family Educational Rights and Privacy Act)",
	"version": "34 CFR Part 99 (20 U.S.C. § 1232g)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 32,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([32, count(violations)]),
	"area_summary": area_summary,
	"scope_note": "Program-level assessment of an educational agency/institution's FERPA obligations. Inputs are attestation/GRC facts, not device facts; a caller must wire an authoritative source (GRC export or attestation intake) before treating results as evidence.",
}
