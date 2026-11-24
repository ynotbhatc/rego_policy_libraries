# COPPA — Children's Online Privacy Protection Rule
# 16 CFR Part 312, as amended by 90 FR 16918 (published April 22, 2025;
# effective June 23, 2025; compliance date April 22, 2026 for most
# provisions). First rule update since 2013.
#
# Assessment target: an operator of a website or online service directed
# to children under 13 (or with actual knowledge of collecting children's
# personal information). Like FERPA, COPPA is a program/practices statute:
# the input contract is attestation/GRC-shaped, not host-fact-shaped.
#
# The 2025 amendments this module encodes (marked [2025] below):
#   - Separate verifiable parental consent for third-party disclosures,
#     including targeted advertising (§312.5)
#   - Data retention limits: only as long as reasonably necessary, written
#     public retention policy, no indefinite retention (§312.10)
#   - Written comprehensive information security program (§312.8)
#   - Expanded "personal information" definition: biometric identifiers
#     and government-issued identifiers (§312.2)
#   - Codified "mixed audience" site/service category (§312.2)
#
# Input contract (all fields boolean unless noted):
#   input.coppa.notice.{online_notice_posted, direct_notice_to_parents,
#     notice_content_complete}
#   input.coppa.consent.{verifiable_consent_before_collection,
#     approved_method_used, separate_consent_third_party_disclosure,
#     consent_records_retained}
#   input.coppa.parental_rights.{review_mechanism, deletion_mechanism,
#     refusal_mechanism}
#   input.coppa.collection.{not_conditioned_on_excess_data}
#   input.coppa.security.{written_program, safeguards_risk_based,
#     third_party_capability_assurances, program_reviewed}
#   input.coppa.retention.{limited_to_necessary, written_policy_public,
#     no_indefinite_retention}
#   input.coppa.scope.{pi_inventory_includes_new_categories,
#     audience_determination_documented}
#   input.coppa.safe_harbor.{participates, program_requirements_met}
#     (conditional — §312.11 applies only to participants)
#
# Fail-closed: absent facts fire every unconditional control.
#
# OPA query path: /v1/data/coppa/main/compliance_report

# METADATA
# title: "COPPA — Children's Online Privacy Protection Rule"
# custom:
#   class: compliance
#   framework: coppa
#   source: ftc
#   domains: [privacy, children]
#   coverage:
#     checks: 21
#     cited: 11
#     expected: 21
#     found: 21
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package coppa.main

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

# ── §312.4 — Notice ──────────────────────────────────────────────────────────

violations contains msg if {
	facts := [["coppa", "notice", "online_notice_posted"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.4(d): Clear and prominent online notice of information practices regarding children not posted", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "notice", "direct_notice_to_parents"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.4(b)-(c): Direct notice to parents not provided before collecting personal information from a child", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "notice", "notice_content_complete"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.4: Notice content incomplete — must state what is collected, how it is used, and disclosure practices, including the identities/categories of third-party recipients", _evidence(facts)])
}

# ── §312.5 — Verifiable parental consent ─────────────────────────────────────

violations contains msg if {
	facts := [["coppa", "consent", "verifiable_consent_before_collection"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.5(a)(1): Verifiable parental consent not obtained before collection, use, or disclosure of children's personal information", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "consent", "approved_method_used"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.5(b): Consent method is not among the approved verifiable-consent methods", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "consent", "separate_consent_third_party_disclosure"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.5 [2025]: No separate verifiable parental consent for disclosures of children's personal information to third parties, including for targeted advertising", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "consent", "consent_records_retained"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.5: Records of verifiable parental consent not retained as evidence", _evidence(facts)])
}

# ── §312.6 — Parental right to review and delete ─────────────────────────────

violations contains msg if {
	facts := [["coppa", "parental_rights", "review_mechanism"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.6(a)(2): No mechanism for a parent to review the personal information collected from their child", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "parental_rights", "deletion_mechanism"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.6(a)(2): No mechanism for a parent to direct deletion of their child's personal information", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "parental_rights", "refusal_mechanism"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.6(a)(1): No mechanism for a parent to refuse further collection or use of their child's personal information", _evidence(facts)])
}

# ── §312.7 — Conditioning participation ──────────────────────────────────────

violations contains msg if {
	facts := [["coppa", "collection", "not_conditioned_on_excess_data"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.7: Participation in a game, prize offering, or activity is conditioned on disclosing more personal information than reasonably necessary", _evidence(facts)])
}

# ── §312.8 — Confidentiality, security, and integrity ────────────────────────

violations contains msg if {
	facts := [["coppa", "security", "written_program"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.8 [2025]: No written comprehensive information security program for children's personal information", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "security", "safeguards_risk_based"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.8: Safeguards not appropriate to the sensitivity of children's personal information and the risks of its handling", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "security", "third_party_capability_assurances"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.8: Personal information released to third parties without assurances of their capability to maintain its confidentiality, security, and integrity", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "security", "program_reviewed"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.8 [2025]: Information security program not periodically reviewed and updated", _evidence(facts)])
}

# ── §312.10 — Data retention and deletion ────────────────────────────────────

violations contains msg if {
	facts := [["coppa", "retention", "limited_to_necessary"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.10 [2025]: Children's personal information retained longer than reasonably necessary for the purpose for which it was collected", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "retention", "written_policy_public"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.10 [2025]: No written, publicly available children's data retention policy", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "retention", "no_indefinite_retention"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.10 [2025]: Retention practices permit indefinite retention of children's personal information", _evidence(facts)])
}

# ── §312.2 — Definition scope (2025 expansions) ──────────────────────────────

violations contains msg if {
	facts := [["coppa", "scope", "pi_inventory_includes_new_categories"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.2 [2025]: Personal-information inventory does not cover the expanded definition — biometric identifiers and government-issued identifiers", _evidence(facts)])
}

violations contains msg if {
	facts := [["coppa", "scope", "audience_determination_documented"]]
	_unmet(facts)
	msg := concat("", ["COPPA §312.2 [2025]: No documented audience determination (child-directed / mixed audience / general audience) supporting the compliance posture", _evidence(facts)])
}

# ── §312.11 — Safe harbor (conditional: participants only) ───────────────────

default safe_harbor_ok := false

safe_harbor_ok if {
	input.coppa.safe_harbor.participates == false
}

safe_harbor_ok if {
	input.coppa.safe_harbor.participates == true
	input.coppa.safe_harbor.program_requirements_met == true
}

_safe_harbor_participates := ["coppa", "safe_harbor", "participates"]

_safe_harbor_met := ["coppa", "safe_harbor", "program_requirements_met"]

_safe_harbor_unmet if not safe_harbor_ok

_safe_harbor_unmet if {
	some path in [_safe_harbor_participates, _safe_harbor_met]
	_mistyped(path)
}

# The program-requirements fact is named when it was sent with the wrong type, or when a participant left it out.
_safe_harbor_facts := [_safe_harbor_participates, _safe_harbor_met] if {
	_yes(_safe_harbor_participates)
} else := [_safe_harbor_participates, _safe_harbor_met] if {
	_mistyped(_safe_harbor_met)
} else := [_safe_harbor_participates]

violations contains msg if {
	_safe_harbor_unmet
	msg := concat("", ["COPPA §312.11: Safe-harbor participation status undetermined, or program requirements not met by a participating operator", _evidence(_safe_harbor_facts)])
}

# ── Per-area rollup ──────────────────────────────────────────────────────────

area_summary := {
	"notice": count([v | some v in violations; startswith(v, "COPPA §312.4")]),
	"consent": count([v | some v in violations; startswith(v, "COPPA §312.5")]),
	"parental_rights": count([v | some v in violations; startswith(v, "COPPA §312.6")]),
	"conditioning": count([v | some v in violations; startswith(v, "COPPA §312.7")]),
	"security": count([v | some v in violations; startswith(v, "COPPA §312.8")]),
	"retention": count([v | some v in violations; startswith(v, "COPPA §312.10")]),
	"definition_scope": count([v | some v in violations; startswith(v, "COPPA §312.2")]),
	"safe_harbor": count([v | some v in violations; startswith(v, "COPPA §312.11")]),
}

# ── Compliance Report ────────────────────────────────────────────────────────

default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

compliance_report := {
	"framework": "COPPA (Children's Online Privacy Protection Rule)",
	"version": "16 CFR Part 312, as amended 90 FR 16918 (effective 2025-06-23; compliance date 2026-04-22)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 21,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([21, count(violations)]),
	"area_summary": area_summary,
	"scope_note": "Applies to operators of child-directed sites/services or with actual knowledge of collecting children's personal information. Program-level assessment over attestation/GRC facts; wire an authoritative source before treating results as evidence. Controls marked [2025] encode the 90 FR 16918 amendments.",
}
