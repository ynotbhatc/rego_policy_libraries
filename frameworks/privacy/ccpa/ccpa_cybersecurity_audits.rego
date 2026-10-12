# METADATA
# title: "CCPA — Cybersecurity Audits (11 CCR Article 9, §§7120–7124)"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 52
#     cited: 46
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.3.5
package ccpa.cybersecurity_audits

import rego.v1

# ---------------------------------------------------------------------------
# CCPA Regulations, Article 9 — Cybersecurity Audits (11 CCR §§7120–7124)
# Approved by the Office of Administrative Law 2025-09-22, effective
# 2026-01-01. Reference: cppa.ca.gov/regulations/ccpa_updates.html
# (approved text: ccpa_updates_cyber_risk_admt_appr_text.pdf).
#
# Applicability (§7120): a business presents "significant risk to consumers'
# security" if it meets Civ. Code §1798.140(d)(1)(C) (50%+ of revenue from
# selling/sharing PI), or meets §1798.140(d)(1)(A) (the revenue threshold)
# AND processed PI of 250,000+ consumers/households or sensitive PI of
# 50,000+ consumers in the preceding calendar year.
#
# First audit report due (§7121(a)): 2028-04-01 (2026 revenue > $100M),
# 2029-04-01 ($50M–$100M), 2030-04-01 (< $50M); annually thereafter.
# Certification to the Agency by April 1 following each audit year (§7124).
#
# Fail-closed: every required fact must be boolean true; absent is a
# violation. Applicability defaults to TRUE; a business may declare
# applicable=false, but if it also supplies threshold facts that meet §7120
# the declaration is itself a violation.
#
# Input contract — input.ccpa.cybersecurity_audits.*
#   applicable                       bool, default true
#   thresholds.revenue_majority_from_selling_or_sharing   bool  (§1798.140(d)(1)(C))
#   thresholds.meets_revenue_threshold                     bool  (§1798.140(d)(1)(A))
#   thresholds.consumers_processed_prior_year              int
#   thresholds.sensitive_consumers_processed_prior_year    int
#   revenue_tier                     "over_100m" | "50m_to_100m" | "under_50m"
#   audit.completed, audit.covers_required_period, audit.report_completed_on (RFC3339)
#   auditor.*  §7122 facts     components.assessed{} / components.not_applicable[]  §7123(c)
#   report.*   §7123(e) facts  certification.*  §7124 facts
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

# Absent section evaluates as {} so every required fact is a violation (fail-closed).
default _in := {}

_in := input.ccpa.cybersecurity_audits

default _applicable := true

_applicable := false if _in.applicable == false

_thresholds_met if _in.thresholds.revenue_majority_from_selling_or_sharing == true

_thresholds_met if {
	_in.thresholds.meets_revenue_threshold == true
	_in.thresholds.consumers_processed_prior_year >= 250000
}

_thresholds_met if {
	_in.thresholds.meets_revenue_threshold == true
	_in.thresholds.sensitive_consumers_processed_prior_year >= 50000
}

# A business that opts out of the Article while its own numbers meet §7120.
violations contains msg if {
	_in.applicable == false
	_thresholds_met
	msg := "CCPA §7120(b): business declares cybersecurity audits not applicable, but the supplied thresholds meet §7120 (revenue-from-selling test, or revenue threshold with 250,000+ consumers / 50,000+ sensitive-PI consumers)"
}

# ── §7120–§7121 — the audit itself and its deadline ───────────────────────

first_report_deadline := {
	"over_100m": "2028-04-01T00:00:00Z",
	"50m_to_100m": "2029-04-01T00:00:00Z",
	"under_50m": "2030-04-01T00:00:00Z",
}

violations contains msg if {
	_applicable
	not _in.audit.completed == true
	msg := "CCPA §7120(a): no cybersecurity audit completed — a business whose processing presents significant risk to consumers' security must complete one"
}

violations contains msg if {
	_applicable
	not _in.audit.covers_required_period == true
	msg := "CCPA §7121: cybersecurity audit does not cover the required 12-month period (Jan 1 through Jan 1 of the following year for the business's tier)"
}

violations contains msg if {
	_applicable
	not _in.revenue_tier in {"over_100m", "50m_to_100m", "under_50m"}
	msg := "CCPA §7121(a): revenue_tier must be one of over_100m, 50m_to_100m, under_50m — the first-report deadline (2028/2029/2030-04-01) depends on it"
}

violations contains msg if {
	_applicable
	deadline := first_report_deadline[_in.revenue_tier]
	time.now_ns() > time.parse_rfc3339_ns(deadline)
	not _in.audit.completed == true
	msg := sprintf("CCPA §7121(a): first cybersecurity audit report was due %v for tier %v and none is recorded", [substring(deadline, 0, 10), _in.revenue_tier])
}

# ── §7122 — thoroughness and independence ─────────────────────────────────

_auditor_checks := {
	"qualified": "CCPA §7122(a)(1): auditor lacks demonstrated knowledge of cybersecurity and of auditing a cybersecurity program",
	"uses_accepted_standards": "CCPA §7122(a): audit does not use procedures and standards accepted in the auditing profession (AICPA, PCAOB, ISACA, ISO)",
	"objective_and_independent": "CCPA §7122(a)(2): auditor is not free of influence from the business — objective and impartial judgment not evidenced",
	"no_participation_in_assessed_activities": "CCPA §7122(a)(2): auditor participated in activities they assess (developing procedures, preparing documents, recommending or operating the cybersecurity program)",
	"all_requested_information_provided": "CCPA §7122(b): business did not make all requested relevant information available to the auditor",
	"facts_disclosed_in_good_faith": "CCPA §7122(c): business did not disclose all relevant facts to the auditor in good faith / misrepresented a fact",
	"findings_rely_on_evidence_not_management_attestation": "CCPA §7122(d): audit findings rely primarily on management assertions or attestations rather than on specific evidence (documents, sampling and testing, interviews)",
	"report_delivered_to_responsible_executive": "CCPA §7122(f): audit report not provided to the executive with direct responsibility for the cybersecurity program",
	"documents_retained_five_years": "CCPA §7122(g): audit documents not retained for at least five years after completion (business and auditor)",
}

violations contains msg if {
	_applicable
	some key, msg in _auditor_checks
	not _in.auditor[key] == true
}

# Internal auditor independence (§7122(a)(3)) — only when the auditor is internal.
violations contains msg if {
	_applicable
	_in.auditor.internal == true
	not _in.auditor.reports_to_executive_without_cyber_responsibility == true
	msg := "CCPA §7122(a)(3): internal highest-ranking auditor does not report to an executive who lacks direct responsibility for the cybersecurity program (and whose evaluation/compensation that executive sets)"
}

# ── §7123(c) — the eighteen components the audit must assess ──────────────

components := {
	"c01_authentication": "§7123(c)(1): authentication — phishing-resistant MFA for personnel, service providers and contractors; strong unique passwords/passphrases",
	"c02_encryption": "§7123(c)(2): encryption of personal information at rest and in transit",
	"c03_account_management_access_control": "§7123(c)(3): account management and access controls — least privilege, privileged-account restriction and PAM, monitored account creation, physical access",
	"c04_inventory": "§7123(c)(4): inventory and management of personal information (maps, classification, tagging) and of hardware/software (allowlisting, approval processes)",
	"c05_secure_configuration": "§7123(c)(5): secure configuration — updates/upgrades, on-prem and cloud hardening, masking of sensitive PI by default, security patch management, change management",
	"c06_vulnerability_scans_pentest_disclosure": "§7123(c)(6): internal and external vulnerability scans, penetration testing, vulnerability disclosure and reporting",
	"c07_audit_log_management": "§7123(c)(7): audit-log management — centralized storage, retention and monitoring of logs",
	"c08_network_monitoring_defenses": "§7123(c)(8): network monitoring and defenses — bot/intrusion detection and prevention, data-loss prevention",
	"c09_antivirus_antimalware": "§7123(c)(9): antivirus and antimalware protections",
	"c10_segmentation": "§7123(c)(10): segmentation of the information system (firewalls, routers, switches)",
	"c11_ports_services_protocols": "§7123(c)(11): limitation and control of ports, services and protocols",
	"c12_cybersecurity_awareness": "§7123(c)(12): cybersecurity awareness — current knowledge of changing threats and countermeasures",
	"c13_education_training": "§7123(c)(13): cybersecurity education and training at start, annually, and after a breach, for everyone with system access",
	"c14_secure_development": "§7123(c)(14): secure development and coding best practices, including code review and testing",
	"c15_service_provider_oversight": "§7123(c)(15): oversight of service providers, contractors and third parties (§§7051, 7053)",
	"c16_retention_and_disposal": "§7123(c)(16): retention schedules and proper disposal (shredding, erasing, rendering unreadable)",
	"c17_incident_response": "§7123(c)(17): incident response management — documented plan and tested capabilities",
	"c18_bcdr_backups": "§7123(c)(18): business-continuity and disaster-recovery plans, data-recovery capabilities and backups",
}

_component_assessed(id) if _in.components.assessed[id] == true

# A component may be left out only when the auditor deemed it not applicable
# to the business's information system (§7123(b)(2)); record that explicitly.
_component_excused(id) if {
	some excused in _in.components.not_applicable
	excused == id
}

violations contains msg if {
	_applicable
	some id, text in components
	not _component_assessed(id)
	not _component_excused(id)
	msg := sprintf("CCPA %v — component not assessed by the cybersecurity audit and not recorded as not-applicable", [text])
}

violations contains msg if {
	_applicable
	not _in.components.program_documentation_assessed == true
	msg := "CCPA §7123(b)(1): audit did not assess the establishment, implementation and maintenance of the cybersecurity program and its written policies and procedures"
}

violations contains msg if {
	_applicable
	not _in.components.implementation_and_enforcement_assessed == true
	msg := "CCPA §7123(b)(3): audit did not assess how the business implements and enforces compliance with its cybersecurity program and the applicable components"
}

# ── §7123(e) — the audit report ───────────────────────────────────────────

_report_checks := {
	"describes_information_system": "CCPA §7123(e)(1): report does not describe the information system, the policies/procedures assessed, the criteria used and the specific evidence examined, with the justification for the findings",
	"identifies_components_and_effectiveness": "CCPA §7123(e)(2): report does not identify the applicable components, how the business implements and enforces them, and their effectiveness",
	"describes_gaps_and_weaknesses": "CCPA §7123(e)(3): report does not identify and describe in detail the status of gaps or weaknesses that increase risk to personal information",
	"documents_remediation_plan_with_timeframe": "CCPA §7123(e)(4): report does not document the business's plan and timeframe to address identified gaps and weaknesses",
	"identifies_corrections_to_prior_reports": "CCPA §7123(e)(5): report does not identify corrections or amendments to prior audit reports",
	"names_responsible_individuals": "CCPA §7123(e)(6): report does not include the titles of up to three qualified individuals responsible for the cybersecurity program",
	"names_auditor_and_qualifications": "CCPA §7123(e)(7): report does not include the auditor's name, affiliation and relevant qualifications",
	"signed_independence_statement": "CCPA §7123(e)(8): report lacks the highest-ranking auditor's signed, dated certification of independent review, impartial judgment, and no primary reliance on management attestations",
	"includes_breach_notifications_if_any": "CCPA §7123(e)(9)-(10): report does not include samples or descriptions of any consumer breach notifications (Civ. Code §1798.82) or regulator notifications made during the period, with dates, details and remediation",
}

violations contains msg if {
	_applicable
	some key, msg in _report_checks
	not _in.report[key] == true
}

# ── §7124 — certification of completion to the Agency ─────────────────────

_certification_checks := {
	"submitted_to_agency": "CCPA §7124(a): written certification of audit completion not submitted to the California Privacy Protection Agency",
	"submitted_by_april_1": "CCPA §7124(b): certification not submitted by April 1 following the audit year",
	"submitted_by_responsible_executive": "CCPA §7124(c): certification not completed by an executive directly responsible for audit compliance, with sufficient knowledge and authority to submit",
	"includes_required_contents": "CCPA §7124(d): certification lacks required contents — business name and contact, completion statement, period covered by month and year, electronically signed penalty-of-perjury attestation, submitter name/title/date",
}

violations contains msg if {
	_applicable
	some key, msg in _certification_checks
	not _in.certification[key] == true
}

# ── Report ────────────────────────────────────────────────────────────────

compliance_report := {
	"standard": "CCPA Regulations — Article 9 Cybersecurity Audits (11 CCR §§7120–7124, effective 2026-01-01)",
	"domain": "Cybersecurity Audits",
	"applicable": _applicable,
	"revenue_tier": object.get(_in, "revenue_tier", "unset"),
	"first_report_deadline": object.get(first_report_deadline, object.get(_in, "revenue_tier", ""), "unset — revenue_tier missing"),
	"components_required": count(components),
	"components_assessed": count([id | some id, _ in components; _component_assessed(id)]),
	"components_not_applicable": count([id | some id, _ in components; _component_excused(id)]),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
