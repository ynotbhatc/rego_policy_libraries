# METADATA
# title: "EU Digital Operational Resilience Act (DORA) — Regulation (EU) 2022/2554"
# custom:
#   class: compliance
#   framework: dora
#   source: eu
#   domains: [financial, eu]
#   coverage:
#     checks: 55
#     cited: 16
#     expected: 399
#     found: 429
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package dora.main

import rego.v1

# EU Digital Operational Resilience Act (DORA) — Regulation (EU) 2022/2554
# Mandatory for all EU financial entities from 17 January 2025.
#
# Five pillars (level-1 regulation) + three level-2 RTS modules:
#   RTS (EU) 2024/1774 — ICT risk management framework (Title II) and simplified framework (Title III),
#                        dora.rts_ict_risk: 308 rows (Title II 228, Title III 80), one title evaluated per
#                        entity by input.dora.rts.simplified_framework
#   RTS (EU) 2025/532  — ICT subcontracting (in force 2025-07-22)
#   RTS (EU) 2025/1190 — threat-led penetration testing (applicable 2025-07-08)
#
# Counts (the report total is computed from what was evaluated for this entity, not a fixed number):
#   total_controls   = Level-1 checks in this file
#                      + RTS 2025/532 checks + RTS 2025/1190 checks
#                      + the RTS 2024/1774 rows that apply to this entity: ONE title (II or III, by
#                        input.dora.rts.simplified_framework) and, in Title II, the rows its declared roles open.
#                      The two titles are alternatives, so the 308 rows the RTS module carries are never all
#                      evaluated for one entity; 308 is reported as rows_carried, not as controls.
#   failed_controls  = the checks among those that did not pass (computed, never clamped)
#   passed_controls  = total_controls - failed_controls, so passed + failed == total on every input
#   input_contract_violations = RTS 2024/1774 input-contract findings (gate or role undeclared, obligations
#                      container missing, unknown id). They are findings, not controls: they make the report
#                      non-compliant and are in violations / violation_count, but not in total or failed.
#                      So violation_count == failed_controls + input_contract_violations.
#   compliance_score = floor(100 * passed / total); 100 only when every evaluated check passed.
#
# A Level-1 check passes only on boolean true. Absent, null, a string ("true", "yes") or a number is not
# evidence and fails. A check is one `violations contains` rule with its own message, so one Level-1
# violation is one failed check. pillar_totals states how many rules each pillar holds; the tests pin it to
# the rules (on an empty input every rule fires, and the failing count per pillar must equal pillar_totals),
# so adding or removing a rule without updating pillar_totals fails the suite.
#
# Not evaluated here (scope the report does not narrow; the maintainer decides): Article 16(1) exempts the
# simplified-framework entities from Articles 5-15, and Article 26(1) limits TLPT to entities the competent
# authority identifies; this report evaluates the Level-1 Pillar 1 checks and the TLPT checks for every entity.
#
# Citations are to Regulation (EU) 2022/2554 (EUR-Lex CELEX 32022R2554, English HTML retrieved 2026-11-23,
# sha256 76baf17fb57ceda0cb7815359bef95dcceba483a48269eafb6eb9b29ebfb7f47). The incident-report time limits
# are not in Article 19; they are set under Article 20 by Delegated Regulation (EU) 2025/301, Article 5(1)
# (Publications Office, CELEX 32025R0301, retrieved 2026-11-23).
#
#   Pillar 1 — ICT Risk Management (Articles 5–16): checks cite Arts 5, 6, 8, 9, 11, 12, 13
#   Pillar 2 — ICT-Related Incident Reporting (Articles 17–23)
#   Pillar 3 — Digital Operational Resilience Testing (Articles 24–27): checks cite Arts 24, 26
#   Pillar 4 — ICT Third-Party Risk Management (Articles 28–44)
#   Pillar 5 — Information Sharing (Article 45)
#
# OPA endpoint: POST http://<host>:8182/v1/data/dora/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Pillar 1 — ICT Risk Management ──────────────────────────────────────────

violations contains msg if {
	not input.ict_risk_management.governance_framework.documented == true
	msg := "DORA Art.5: ICT risk management governance framework not documented"
}

violations contains msg if {
	not input.ict_risk_management.risk_appetite.defined == true
	msg := "DORA Art.6: ICT risk appetite and tolerance levels not formally defined"
}

violations contains msg if {
	not input.ict_risk_management.asset_inventory.maintained == true
	msg := "DORA Art.8: ICT asset inventory not maintained (hardware, software, data assets)"
}

violations contains msg if {
	not input.ict_risk_management.threat_intelligence.process_exists == true
	msg := "DORA Art.13: Threat intelligence gathering and monitoring process absent"
}

violations contains msg if {
	not input.ict_risk_management.recovery_objectives.rto_defined == true
	msg := "DORA Art.12: Recovery Time Objectives (RTO) not defined for critical ICT systems (Art.12(6))"
}

violations contains msg if {
	not input.ict_risk_management.recovery_objectives.rpo_defined == true
	msg := "DORA Art.12: Recovery Point Objectives (RPO) not defined for critical ICT systems (Art.12(6))"
}

violations contains msg if {
	not input.ict_risk_management.backup_policy.documented == true
	msg := "DORA Art.12: ICT backup policy not documented or tested"
}

violations contains msg if {
	not input.ict_risk_management.patch_management.process_exists == true
	msg := "DORA Art.9: Documented policies for patches and updates not established (Art.9(4)(f))"
}

violations contains msg if {
	not input.ict_risk_management.encryption.in_transit == true
	msg := "DORA Art.9: Data in transit not encrypted — encryption of sensitive data required"
}

violations contains msg if {
	not input.ict_risk_management.encryption.at_rest == true
	msg := "DORA Art.9: Data at rest not encrypted — encryption of sensitive data required"
}

violations contains msg if {
	not input.ict_risk_management.mfa.enabled == true
	msg := "DORA Art.9: Multi-factor authentication not enforced for ICT system access"
}

violations contains msg if {
	not input.ict_risk_management.privileged_access.managed == true
	msg := "DORA Art.9: Privileged access not managed — PAM controls required"
}

violations contains msg if {
	not input.ict_risk_management.annual_review.completed == true
	msg := "DORA Art.6: ICT risk management framework annual review not completed"
}

# ── Pillar 2 — ICT Incident Reporting ───────────────────────────────────────

violations contains msg if {
	not input.incident_reporting.classification_process.documented == true
	msg := "DORA Art.18: ICT incident classification and impact assessment process not documented"
}

violations contains msg if {
	not input.incident_reporting.initial_notification.within_4_hours == true
	msg := "DORA Art.19: Major incident initial notification to authority not within 4 hours of classification as major (Art.19(4)(a); time limit set by Delegated Regulation (EU) 2025/301 Art.5(1)(a))"
}

violations contains msg if {
	not input.incident_reporting.intermediate_report.within_72_hours == true
	msg := "DORA Art.19: Intermediate incident report to authority not within 72 hours of the initial notification (Art.19(4)(b); time limit set by Delegated Regulation (EU) 2025/301 Art.5(1)(b))"
}

violations contains msg if {
	not input.incident_reporting.final_report.within_1_month == true
	msg := "DORA Art.19: Final incident report to authority not within 1 month of the latest intermediate report (Art.19(4)(c); time limit set by Delegated Regulation (EU) 2025/301 Art.5(1)(c))"
}

violations contains msg if {
	not input.incident_reporting.incident_register.maintained == true
	msg := "DORA Art.17: ICT incident register not maintained with required details"
}

violations contains msg if {
	not input.incident_reporting.root_cause_analysis.performed == true
	msg := "DORA Art.17: Root cause analysis not performed for major ICT incidents"
}

# ── Pillar 3 — Digital Operational Resilience Testing ───────────────────────

violations contains msg if {
	not input.resilience_testing.basic_testing.annual == true
	msg := "DORA Art.24: Resilience tests (Art.25: vulnerability scans, penetration tests, ...) not conducted at least yearly on ICT systems supporting critical or important functions (Art.24(6))"
}

violations contains msg if {
	not input.resilience_testing.tlpt.conducted == true
	msg := "DORA Art.26: Threat-Led Penetration Testing (TLPT) not conducted (significant entities: every 3 years)"
}

violations contains msg if {
	not input.resilience_testing.test_results.remediated == true
	msg := "DORA Art.24: Critical findings from resilience testing not remediated in defined timeframe (Art.24(5))"
}

violations contains msg if {
	not input.resilience_testing.continuity_drills.conducted == true
	msg := "DORA Art.11: ICT business continuity plan tests and crisis communication plan tests not conducted (Art.11(6))"
}

# ── Pillar 4 — ICT Third-Party Risk Management ──────────────────────────────

violations contains msg if {
	not input.third_party_risk.register.maintained == true
	msg := "DORA Art.28: ICT third-party service provider register not maintained"
}

violations contains msg if {
	not input.third_party_risk.contracts.exit_strategy == true
	msg := "DORA Art.30: ICT service contracts do not include exit strategy and transition plan"
}

violations contains msg if {
	not input.third_party_risk.contracts.audit_rights == true
	msg := "DORA Art.30: ICT service contracts do not include audit and access rights"
}

violations contains msg if {
	not input.third_party_risk.contracts.sla_defined == true
	msg := "DORA Art.30: ICT service contracts lack SLA definitions for availability and performance"
}

violations contains msg if {
	not input.third_party_risk.concentration_risk.assessed == true
	msg := "DORA Art.29: ICT concentration risk not assessed (over-reliance on single provider)"
}

violations contains msg if {
	not input.third_party_risk.critical_providers.identified == true
	msg := "DORA Art.28: Critical ICT third-party providers not identified and assessed"
}

violations contains msg if {
	not input.third_party_risk.due_diligence.performed == true
	msg := "DORA Art.28: Due diligence not performed for ICT third-party providers"
}

# ── Pillar 5 — Information Sharing ──────────────────────────────────────────

violations contains msg if {
	not input.information_sharing.arrangements.in_place == true
	msg := "DORA Art.45: Cyber threat information sharing arrangements not established"
}

# ── Level-2 RTS modules — aggregated into the main violation set ─────────────

violations contains msg if {
	some msg in data.dora.rts_subcontracting.violation
}

violations contains msg if {
	some msg in data.dora.rts_tlpt.violation
}

violations contains msg if {
	some msg in data.dora.rts_ict_risk.violation
}

# ── Pillars ──────────────────────────────────────────────────────────────────

# Level-1 messages start "DORA Art.<n>:"; every RTS message starts "DORA RTS ", so neither set can be
# counted in the other.
level1_failed_checks contains v if {
	some v in violations
	startswith(v, "DORA Art.")
}

# Article of Regulation (EU) 2022/2554 -> pillar (the regulation's Chapters II-VI).
pillar_articles := {
	"ict_risk_management": {"5", "6", "8", "9", "11", "12", "13"},
	"incident_reporting": {"17", "18", "19"},
	"resilience_testing": {"24", "26"},
	"third_party_risk": {"28", "29", "30"},
	"information_sharing": {"45"},
}

pillar_violations[pillar] := vs if {
	some pillar, articles in pillar_articles
	vs := {v |
		some v in level1_failed_checks
		some a in articles
		startswith(v, sprintf("DORA Art.%v:", [a]))
	}
}

pillar1_violations := pillar_violations.ict_risk_management

pillar2_violations := pillar_violations.incident_reporting

pillar3_violations := pillar_violations.resilience_testing

pillar4_violations := pillar_violations.third_party_risk

pillar5_violations := pillar_violations.information_sharing

# ── Counts ───────────────────────────────────────────────────────────────────

# Level-1 checks per pillar: the number of `violations contains` rules above that cite the pillar's articles.
# Pinned to the rules by tests/test_dora_counts.rego (every rule fires on an empty input).
pillar_totals := {
	"ict_risk_management": 14,
	"incident_reporting": 6,
	"resilience_testing": 3,
	"third_party_risk": 7,
	"information_sharing": 1,
}

level1_total := sum([n | some n in pillar_totals])

level1_failed := count(level1_failed_checks)

_rts_532 := data.dora.rts_subcontracting.compliance_report

_rts_1190 := data.dora.rts_tlpt.compliance_report

_rts_1774 := data.dora.rts_ict_risk.compliance_report

total_controls := ((level1_total + _rts_532.total_controls) + _rts_1190.total_controls) + _rts_1774.total_controls

failed_controls := ((level1_failed + _rts_532.failed_controls) + _rts_1190.failed_controls) + _rts_1774.failed_controls

passed_controls := total_controls - failed_controls

compliance_score := floor((passed_controls * 100) / total_controls)

_counts(r) := {
	"total_controls": r.total_controls,
	"failed_controls": r.failed_controls,
	"passed_controls": r.passed_controls,
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

compliance_report := {
	"framework": "EU Digital Operational Resilience Act (DORA)",
	"regulation": "Regulation (EU) 2022/2554",
	"effective_date": "2025-01-17",
	"entity": entity_name,
	"entity_type": entity_type,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": total_controls,
	"passed_controls": passed_controls,
	"failed_controls": failed_controls,
	"compliance_score": compliance_score,
	"input_contract_violations": _rts_1774.input_contract_violations,
	"control_summary": {
		"level_1_regulation_2022_2554": {
			"total_controls": level1_total,
			"failed_controls": level1_failed,
			"passed_controls": level1_total - level1_failed,
			"pillars": {pillar: {
				"total_controls": pillar_totals[pillar],
				"failed_controls": count(pillar_violations[pillar]),
				"passed_controls": pillar_totals[pillar] - count(pillar_violations[pillar]),
			} |
				some pillar, _ in pillar_articles
			},
		},
		"rts_2025_532_subcontracting": _counts(_rts_532),
		"rts_2025_1190_tlpt": _counts(_rts_1190),
		"rts_2024_1774_ict_risk_management": object.union(
			_counts(_rts_1774),
			{
				"title_evaluated": _rts_1774.gate.title_evaluated,
				"rows_carried": _rts_1774.rows_carried,
				"input_contract_violations": _rts_1774.input_contract_violations,
			},
		),
	},
	"violations": violations,
	"violation_count": count(violations),
	"pillar_summary": {
		"ict_risk_management": pillar1_violations,
		"incident_reporting": pillar2_violations,
		"resilience_testing": pillar3_violations,
		"third_party_risk": pillar4_violations,
		"information_sharing": pillar5_violations,
		"rts_2025_532_subcontracting": data.dora.rts_subcontracting.violation,
		"rts_2025_1190_tlpt": data.dora.rts_tlpt.violation,
		"rts_2024_1774_ict_risk_management": data.dora.rts_ict_risk.violation,
	},
	"rts_2024_1774_ict_risk_management": {
		"gate": _rts_1774.gate,
		"entity_roles": _rts_1774.entity_roles,
		"rows_by_title": _rts_1774.rows_by_title,
		"controls_evaluated": _rts_1774.controls_evaluated,
		"attested": _rts_1774.attested,
		"chapters": _rts_1774.chapters,
		"violation_count": _rts_1774.violation_count,
		"compliant": _rts_1774.compliant,
	},
}
