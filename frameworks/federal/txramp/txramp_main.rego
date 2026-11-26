# METADATA
# title: "TX-RAMP (Texas Risk and Authorization Management Program) — Level 1 and Level 2 baselines: one result per baseline control, taken from the NIST SP 800-53 module"
# custom:
#   class: compliance
#   framework: txramp
#   source: txramp
#   domains: [us-state, cloud]
package txramp.main

import data.nist.sp800_53.index
import data.nist.sp800_53.main as nist
import data.txramp.index as txramp_index
import rego.v1

# =============================================================================
# TX-RAMP — Texas Risk and Authorization Management Program (Texas Department of Information Resources, DIR)
#
# Entry point: data.txramp.main.compliance_report (framework key `txramp`). Place in the library: next to fedramp and
# govramp under frameworks/federal/ (state-government audience, controls from NIST SP 800-53 Rev 5, no new category).
#
# FACTS CHECKED AGAINST THE PUBLISHER, fetched 2026-11-26 (UTC, about 03:50 to 04:10) with ordinary requests, all under
# https://dir.texas.gov unless stated:
#   - Programme manual: "Texas Risk and Authorization Management Program (TX-RAMP) Program Manual, version 4.0", effective
#     2026-02-12 (item page /resource-library-item/texas-risk-and-authorization-management-program-manual-30, "Last Updated:
#     February 11, 2026"; file /sites/default/files/2026-02/TX-RAMP%20Program%20Manual%204.0.pdf, sha256 403c24f1...cc38).
#     Version history in the manual (section 22): 1.0 2021-10-28; 2.0 2022-10-20 (controls aligned with NIST SP 800-53
#     Revision 5); 3.0 2023-12-01; 3.1 2025-05-14 (added GovRAMP Core); 4.0 2026-02-12 (recertification, continuous
#     monitoring and significant-change updates). A banner on the site says House Bill 150 (89R) moved DIR's cybersecurity
#     functions to the Texas Cyber Command (https://www.txcc.texas.gov); the pages of that site fetched the same day carry no
#     TX-RAMP content, so dir.texas.gov is the source used. UNVERIFIED: whether and when TX-RAMP moves to the Cyber Command.
#   - Certification types (manual section 3 and 9.1): Provisional, Level 1 (low impact information resources), Level 2
#     (moderate or high impact). A certification is reached by a TX-RAMP-conducted assessment, by an equivalent status in
#     another RAMP, or by the Fast Track route (a qualifying third-party report, section 15, which is a route to TX-RAMP's own
#     review and never a pass of its own; it is not modelled as a pass here). Provisional "does not indicate compliance with
#     TX-RAMP security baseline standards" (section 10.1): it has no control list and is never reported as compliant.
#   - Baselines (manual section 7 and Appendix A): two, Level 1 with 117 controls and enhancements and Level 2 with 223
#     (family tables in Appendix A; the figures are recorded in scripts/txramp_baselines.json and the generator refuses a
#     workbook that does not reproduce them). Control lists: "TX-RAMP Control Baselines 2.0" workbook, item page
#     /resource-library-item/tx-ramp-control-baselines-20 ("Last Updated: November 14, 2022"), file
#     /sites/default/files/2022-11/TX-RAMP%202.0%20Control%20Baselines.xlsx, sha256 795336ea...1569; Combined sheet columns
#     Level 1 and Level 2 (Level 1 is inside Level 2), cross-checked against the Level 1 and Level 2 sheets. Appendix A names
#     the file "TX-RAMP Baseline Controls 2.0.xlsx" (embedded as an icon in the PDF, not extractable); the downloaded
#     workbook reproduces every published count, so it is taken to be that file. UNVERIFIED: byte identity with the embedded
#     one. Not used: the 2021-11-29 workbook (Rev 4 wording, 122 and 322 rows), superseded by version 2.0 in 2022. Control
#     ids only are used; TX-RAMP's parameter values are not reproduced and not applied (see "Parameters").
#   - Equivalence (manual section 9.2 and 10.3): a service with a FedRAMP or GovRAMP (StateRAMP) status may request a
#     reciprocal TX-RAMP certification; it stays valid while the external status is maintained, and the loss of the external
#     status revokes it (sections 9.2, 19). FedRAMP Authorized gives the corresponding level (Low impact: Level 1; Moderate
#     or High: Level 2); FedRAMP In Process and FedRAMP Ready give Provisional only. TX-RAMP "does not have a Low-impact SaaS
#     equivalent": FedRAMP Low-impact SaaS authorizations do not inherit a certification. GovRAMP Core, Ready, Provisionally
#     Authorized and Authorized each give Level 2 (the manual states no impact level for them: UNVERIFIED whether a GovRAMP Low
#     authorization earns Level 1, so none is modelled); GovRAMP Snapshot and Progressing Snapshot give Provisional only.
#   - Continuous monitoring (section 17): quarterly vulnerability reports for Level 2, annual for Level 1, through SPECTRIM;
#     a service certified through FedRAMP or GovRAMP equivalence does not send them (17.1). Breach of system security:
#     notice to TX-RAMP within 48 hours (17.3). Significant change: reported within 30 days (17.4).
#   - Other process facts used: Acknowledgment and Inventory questionnaire completed by all providers (14.1); assessment
#     questionnaire with the Security Plan Workbook (14.2, Appendix B); a POA&M for each deficient control, revisited at
#     least quarterly (14.4); certification valid three years (20); the recertification review of 38 (Level 1) and 48
#     (Level 2) control requirements (20.1) has no published list and is not modelled. UNVERIFIED: which controls those are.
#   - Inconsistencies in the sources, noted not resolved: the manual says provisional certification is effective for 12
#     months (sections 3, 10) and elsewhere speaks of an 18-month provisional period (10.3, 12); the resources page
#     lists the manual as "Last updated: 2/4/2025" while its item page says February 11, 2026; the version 3.0 history says the
#     baselines were "revised/aligned" while the only workbook is dated 2022-11-14. The newest sources are used.
# Id lists, versions, URLs and sha256 of every source file: scripts/txramp_baselines.json, written by
# scripts/gen_txramp_framework_maps.py into txramp_index.rego (read by this module) and crosswalk/framework_maps/data.json
# (maps txramp_level_1 and txramp_level_2, for the crosswalk's coverage report).
#
# How a control gets its result. The control checks are the NIST SP 800-53 module's (data.nist.sp800_53.main): every
# control TX-RAMP selects, except the two named next, is one of the 544 ids that module evaluates, with the same fail-closed
# behaviour and the same input contract (its per-family sections of the input). This module takes that module's row for each
# selected control and does not copy a rule body:
#   pass              the 800-53 module has no finding for the control
#   fail              a finding that is not about missing evidence
#   evidence_missing  the facts the check reads were not collected
#   not_attested      an organizational control without its signed attestation
#   not_evaluated     the 800-53 module has no row for the control: AC-17(9) and SA-10(1), both Level 2 only. They are
#                     counted as failed and listed in not_evaluated_control_ids, so on the assessment path Level 2 cannot
#                     report compliant until that module evaluates them; Level 1 has none.
# total_controls is a fixed property of the level: Level 1 117, Level 2 223. Only the boolean true passes a yes/no fact (the
# 800-53 module's rule). passed_controls + failed_controls + not_applicable_controls = total_controls. failed_controls
# counts every control that is not a pass. not_applicable_controls is always 0: a control is not applicable only by an
# explicit statement and the 800-53 module has no such statement yet.
#
# Benchmark results (optional): input.reports / input.findings in the shapes data.crosswalk.correlation reads. The 800-53
# module carries them through the STIG -> CCI -> 800-53 spine; a gap fails the control whatever its declared evidence
# says (the rule of that module, fedramp and govramp), also when the certification is accepted by equivalence. Gaps on
# controls outside the selected scope are listed under benchmark_gaps_outside_scope and are not TX-RAMP findings.
#
# Certification basis. certification_basis is "assessment" unless an equivalence is accepted, then "equivalence".
#   input.certification_level                   level_1 | level_2, required. "provisional" is a finding (no control list); a
#                                               missing, unknown or wrong-type value is a finding. Until it is usable the Level 2
#                                               baseline is assessed. Never a "compliant".
#   input.equivalence (optional; absent = no equivalence claimed; present = claimed, and any problem is a finding)
#     program                                   fedramp | govramp (stateramp is read as govramp)
#     status                                    fedramp: authorized | in_process | ready; govramp: core | ready |
#                                               provisionally_authorized | authorized | snapshot | progressing_snapshot
#     impact_level                              fedramp only: low | moderate | high | li_saas
#     status_current                            boolean true: the external status is listed today (9.2, 19)
#     reciprocal_certification_granted          boolean true: TX-RAMP granted the reciprocal certification (6, 9.2)
#   The equivalence is accepted only when the status earns a level at or above the declared one (a higher level
#   satisfies the lower baseline, which is inside it) and both booleans are the boolean true. Accepted: every control row
#   reads status "pass", basis "equivalence", with the 800-53 module's own verdict kept in evidence_status, the report says
#   certification_basis "equivalence", and the control facts are not asked for. An in-scope benchmark gap still fails its row.
#   Not accepted: each reason is a finding and the assessment path applies in full.
#
# Programme findings, all attestations (booleans or numbers the provider or TX-RAMP states; nothing here is measured):
#   both bases   certification.acknowledgment_inventory_approved       A&I questionnaire (14.1)
#                continuous_monitoring.breach_notices_within_48_hours  true when every breach of system security was notified within 48 hours, or there was none (17.3)
#                continuous_monitoring.significant_changes_reported_within_30_days   same for significant changes (17.4)
#   assessment   certification.assessment_questionnaire_approved       TX-RAMP approved the assessment questionnaire (11, 14.2)
#                certification.security_plan_workbook_submitted         Security Plan Workbook (14.2, Appendix B)
#                certification.poam_current                             a POA&M for each deficient control, revisited quarterly (14.4)
#                certification.valid_days_remaining                     number; three-year validity, negative is expired (20)
#                continuous_monitoring.vulnerability_reports_on_schedule   quarterly Level 2, annual Level 1 (17.2)
#   equivalence  (none beyond the equivalence facts above: the external status stands in for the assessment, 9.2; vulnerability
#                reports are not required of a reciprocal certification, 17.1)
#
# Parameters. TX-RAMP sets its own parameter values in the workbook (a column of the Combined sheet). The control checks here
# are the 800-53 module's, with its parameter values; TX-RAMP's are NOT applied. A pass reads as "passes the 800-53
# module's check", not as "meets TX-RAMP's parameter".
# =============================================================================

# The certification levels and the sizes of their scopes (the generated index holds the ids; these are the expected sizes,
# the fail-closed count when the index is not loaded, and a figure the tests compare with the index).
baseline_sizes := {"level_1": 117, "level_2": 223}

_levels := {"level_1", "level_2"}

_rank := {"level_1": 1, "level_2": 2}

default level := "unknown"

level := lower(trim_space(input.certification_level)) if {
	is_string(input.certification_level)
	lower(trim_space(input.certification_level)) in _levels
}

level := "provisional" if {
	is_string(input.certification_level)
	lower(trim_space(input.certification_level)) == "provisional"
}

# The scope assessed: the declared level, or the strictest one until the declaration is usable.
default scope_level := "level_2"

scope_level := level if level in _levels

_map_key := concat("", ["txramp_", scope_level])

# The ids come from the generated index (txramp_index.rego), a rego file next to this one. When it is absent this is
# undefined, which reads as "could not be evaluated", never as "no controls".
_scope_set := txramp_index.scopes[scope_level]

default scope_loaded := false

scope_loaded if {
	count(_scope_set) > 0
	count(nist.evaluated_controls) > 0
}

_scope_ids := {id | scope_loaded; some id in _scope_set}

default total_controls := 0

total_controls := count(_scope_ids) if scope_loaded

total_controls := baseline_sizes[scope_level] if not scope_loaded

# ---------------------------------------------------------------------------
# Equivalence (Program Manual 9.2, 10.3)
# ---------------------------------------------------------------------------

default _claimed := false

_claimed if {
	_ = input.equivalence
}

_eq := value if {
	value := object.get(input, "equivalence", null)
	is_object(value)
} else := {}

_text(field) := lower(trim_space(_eq[field])) if is_string(_eq[field])

_program := "fedramp" if _text("program") == "fedramp"

_program := "govramp" if _text("program") in {"govramp", "stateramp"}

# The TX-RAMP level an external status earns; provisional, none_li_saas or unknown otherwise.
_earned := "unknown" if {
	not _program
} else := "unknown" if {
	not _text("status")
} else := _earned_fedramp if {
	_program == "fedramp"
} else := _earned_govramp

_earned_fedramp := "provisional" if _text("status") in {"in_process", "ready"}

_earned_fedramp := "none_li_saas" if {
	_text("status") == "authorized"
	_text("impact_level") == "li_saas"
}

_earned_fedramp := "level_1" if {
	_text("status") == "authorized"
	_text("impact_level") == "low"
}

_earned_fedramp := "level_2" if {
	_text("status") == "authorized"
	_text("impact_level") in {"moderate", "high"}
}

default _earned_fedramp := "unknown"

_earned_govramp := "level_2" if _text("status") in {"core", "ready", "provisionally_authorized", "authorized"}

_earned_govramp := "provisional" if _text("status") in {"snapshot", "progressing_snapshot"}

default _earned_govramp := "unknown"

default _impact_ok := false

_impact_ok if _text("impact_level") in {"low", "moderate", "high", "li_saas"}

default _fedramp_status_ok := false

_fedramp_status_ok if _text("status") in {"authorized", "in_process", "ready"}

# Why a claimed equivalence is not accepted. Empty set = accepted (when a usable level is declared).
_eq_problems contains msg if {
	_claimed
	not is_object(object.get(input, "equivalence", null))
	msg := "TX-RAMP EQUIVALENCE: evidence invalid — input.equivalence is not an object; no equivalence is accepted"
}

_eq_problems contains msg if {
	_claimed
	is_object(object.get(input, "equivalence", null))
	not _program
	msg := "TX-RAMP EQUIVALENCE: evidence missing or invalid — input.equivalence.program must be fedramp or govramp (stateramp is read as govramp)"
}

_eq_problems contains msg if {
	_program
	not _text("status")
	msg := "TX-RAMP EQUIVALENCE: evidence missing or invalid — input.equivalence.status is not a string; no equivalence is accepted"
}

_eq_problems contains msg if {
	_program == "fedramp"
	_text("status") == "authorized"
	not _impact_ok
	msg := "TX-RAMP EQUIVALENCE: evidence missing or invalid — input.equivalence.impact_level must be low, moderate, high or li_saas for a FedRAMP authorization"
}

_eq_problems contains msg if {
	_earned == "none_li_saas"
	msg := "TX-RAMP EQUIVALENCE: a FedRAMP Low-impact SaaS authorization does not inherit a TX-RAMP certification (Program Manual 9.2); no equivalence is accepted"
}

_eq_problems contains msg if {
	_earned == "provisional"
	msg := "TX-RAMP EQUIVALENCE: this external status earns TX-RAMP Provisional certification only (Program Manual 9.2, 10.3), which does not indicate compliance with the baseline; no equivalence is accepted"
}

_eq_problems contains msg if {
	_program == "govramp"
	_text("status")
	_earned == "unknown"
	msg := "TX-RAMP EQUIVALENCE: input.equivalence.status is not a status the Program Manual maps to a TX-RAMP level; no equivalence is accepted"
}

_eq_problems contains msg if {
	_program == "fedramp"
	_text("status")
	not _fedramp_status_ok
	msg := "TX-RAMP EQUIVALENCE: input.equivalence.status is not a status the Program Manual maps to a TX-RAMP level; no equivalence is accepted"
}

_eq_problems contains msg if {
	_earned in _levels
	level in _levels
	_rank[_earned] < _rank[level]
	msg := sprintf("TX-RAMP EQUIVALENCE: the external status earns %s, below the declared %s; no equivalence is accepted (Program Manual 9.2)", [_earned, level])
}

_eq_problems contains msg if {
	_claimed
	not _eq.status_current == true
	msg := sprintf("TX-RAMP EQUIVALENCE: attestation — a reciprocal certification stays valid only while the external status is maintained (Program Manual 9.2, 19); input.equivalence.status_current is not true.%s", [_bool_problem(_eq, "equivalence", "status_current")])
}

_eq_problems contains msg if {
	_claimed
	not _eq.reciprocal_certification_granted == true
	msg := sprintf("TX-RAMP EQUIVALENCE: attestation — the external status counts once TX-RAMP grants the reciprocal certification on request (Program Manual 6, 9.2); input.equivalence.reciprocal_certification_granted is not true.%s", [_bool_problem(_eq, "equivalence", "reciprocal_certification_granted")])
}

default equivalence_accepted := false

equivalence_accepted if {
	_claimed
	count(_eq_problems) == 0
	level in _levels
	_earned in _levels
	_rank[_earned] >= _rank[level]
}

certification_basis := "equivalence" if equivalence_accepted

default certification_basis := "assessment"

# ---------------------------------------------------------------------------
# Programme findings
# ---------------------------------------------------------------------------

# A section that is absent, null or not an object reads as empty, so every check on it reports missing evidence.
_section(key) := value if {
	value := object.get(input, key, null)
	is_object(value)
} else := {}

_cert := _section("certification")

_cm := _section("continuous_monitoring")

# Why a yes/no fact did not count: boolean false keeps the plain finding, anything else is named.
_bool_problem(section, name, field) := "" if {
	section[field] == false
} else := sprintf(" [evidence missing: input.%s.%s not collected]", [name, field]) if {
	object.get(section, field, null) == null
} else := sprintf(" [evidence invalid: input.%s.%s is not a boolean (got %s)]", [name, field, type_name(section[field])])

violation_selector contains msg if {
	level == "unknown"
	msg := "TX-RAMP LEVEL: evidence missing or invalid — input.certification_level must be one of level_1, level_2. The Level 2 baseline (223 controls) is assessed until the certification level is declared."
}

violation_selector contains msg if {
	level == "provisional"
	msg := "TX-RAMP LEVEL: Provisional certification does not indicate compliance with the TX-RAMP security baseline standards (Program Manual 10.1) and has no control list; it is never a compliant result. The Level 2 baseline (223 controls) is assessed."
}

violation_assessment contains msg if {
	not _cert.acknowledgment_inventory_approved == true
	msg := sprintf("TX-RAMP CERTIFICATION: attestation — every provider completes the Acknowledgment and Inventory questionnaire (Program Manual 14.1); input.certification.acknowledgment_inventory_approved is not true.%s", [_bool_problem(_cert, "certification", "acknowledgment_inventory_approved")])
}

violation_assessment contains msg if {
	certification_basis == "assessment"
	not _cert.assessment_questionnaire_approved == true
	msg := sprintf("TX-RAMP CERTIFICATION: attestation — TX-RAMP reviews and approves the assessment questionnaire before a Level 1 or Level 2 certification is conferred (Program Manual 9.1, 11, 14.2); input.certification.assessment_questionnaire_approved is not true.%s", [_bool_problem(_cert, "certification", "assessment_questionnaire_approved")])
}

violation_assessment contains msg if {
	certification_basis == "assessment"
	not _cert.security_plan_workbook_submitted == true
	msg := sprintf("TX-RAMP CERTIFICATION: attestation — the Security Plan Workbook is submitted with the assessment questionnaire (Program Manual 14.2, Appendix B); input.certification.security_plan_workbook_submitted is not true.%s", [_bool_problem(_cert, "certification", "security_plan_workbook_submitted")])
}

violation_assessment contains msg if {
	certification_basis == "assessment"
	not _cert.poam_current == true
	msg := sprintf("TX-RAMP CERTIFICATION: attestation — a POA&M exists for each deficient control and is revisited at least quarterly (Program Manual 14.4); input.certification.poam_current is not true.%s", [_bool_problem(_cert, "certification", "poam_current")])
}

# The three-year validity; only a number is evidence.
violation_assessment contains msg if {
	certification_basis == "assessment"
	not is_number(object.get(_cert, "valid_days_remaining", null))
	msg := "TX-RAMP CERTIFICATION: evidence missing — input.certification.valid_days_remaining (days left of the three-year certification, Program Manual 20) not collected, or not a number"
}

violation_assessment contains msg if {
	certification_basis == "assessment"
	is_number(_cert.valid_days_remaining)
	_cert.valid_days_remaining < 0
	msg := sprintf("TX-RAMP CERTIFICATION: the certification expired %v days ago; Level 1 and Level 2 certifications are valid for three years and are renewed by recertification (Program Manual 20)", [abs(_cert.valid_days_remaining)])
}

_cadence := "quarterly" if scope_level == "level_2"

default _cadence := "annual"

violation_conmon contains msg if {
	certification_basis == "assessment"
	not _cm.vulnerability_reports_on_schedule == true
	msg := sprintf("TX-RAMP CONMON: attestation — vulnerability reports are due %s for %s through SPECTRIM (Program Manual 17.2); input.continuous_monitoring.vulnerability_reports_on_schedule is not true.%s", [_cadence, scope_level, _bool_problem(_cm, "continuous_monitoring", "vulnerability_reports_on_schedule")])
}

violation_conmon contains msg if {
	not _cm.breach_notices_within_48_hours == true
	msg := sprintf("TX-RAMP CONMON: attestation — a breach of system security is notified to TX-RAMP within 48 hours (Program Manual 17.3); input.continuous_monitoring.breach_notices_within_48_hours is not true.%s", [_bool_problem(_cm, "continuous_monitoring", "breach_notices_within_48_hours")])
}

violation_conmon contains msg if {
	not _cm.significant_changes_reported_within_30_days == true
	msg := sprintf("TX-RAMP CONMON: attestation — a significant change is reported to TX-RAMP within 30 days (Program Manual 17.4); input.continuous_monitoring.significant_changes_reported_within_30_days is not true.%s", [_bool_problem(_cm, "continuous_monitoring", "significant_changes_reported_within_30_days")])
}

# ---------------------------------------------------------------------------
# One result per control of the selected scope
# ---------------------------------------------------------------------------

# The 800-53 module's rows for the scope's controls, built once.
_nist_rows := {r.id: r | some r in nist.control_results; r.id in _scope_ids}

# "NIST AC-2: ..." is the 800-53 module's finding; the same finding is reported under this framework's name.
_txramp_message(m) := concat("", ["TX-RAMP ", trim_prefix(m, "NIST ")])

_has_gap(r) if r.benchmark.status == "gap"

_bench_part(r) := {"benchmark": r.benchmark} if {
	is_object(object.get(r, "benchmark", null))
} else := {}

# Assessment path: the 800-53 module's row under this framework's name.
_row(id) := object.union(base, _bench_part(r)) if {
	certification_basis == "assessment"
	r := _nist_rows[id]
	base := {
		"id": id,
		"status": r.status,
		"basis": r.basis,
		"findings": [_txramp_message(m) | some m in r.findings],
	}
}

_row(id) := {
	"id": id,
	"status": "not_evaluated",
	"basis": "none",
	"findings": [sprintf("TX-RAMP %s: not evaluated — the NIST SP 800-53 module has no check for this control, so it cannot pass", [id])],
} if {
	certification_basis == "assessment"
	not _nist_rows[id]
	id in _scope_ids
}

# Equivalence path: the control is accepted on the external status, shown as such; the 800-53 verdict is kept beside it.
# A benchmark gap on the control still fails it.
_row(id) := object.union(base, _bench_part(r)) if {
	certification_basis == "equivalence"
	r := _nist_rows[id]
	not _has_gap(r)
	base := {
		"id": id,
		"status": "pass",
		"basis": "equivalence",
		"evidence_status": r.status,
		"findings": [],
	}
}

_row(id) := object.union(base, _bench_part(r)) if {
	certification_basis == "equivalence"
	r := _nist_rows[id]
	_has_gap(r)
	base := {
		"id": id,
		"status": "fail",
		"basis": r.basis,
		"evidence_status": r.status,
		"findings": [_txramp_message(m) | some m in r.findings; contains(m, ": benchmark results show a gap")],
	}
}

_row(id) := {
	"id": id,
	"status": "pass",
	"basis": "equivalence",
	"evidence_status": "not_evaluated",
	"findings": [],
} if {
	certification_basis == "equivalence"
	not _nist_rows[id]
	id in _scope_ids
}

# The rows in the 800-53 module's natural id order (AC-2 before AC-10, AC-2 before AC-2(1)); an id that module does not
# list follows, sorted.
_order_set := {x | some x in index.order}

_ordered_ids := array.concat([id | some id in index.order; id in _scope_ids], sort([id | some id in _scope_ids; not id in _order_set]))

control_results := [_row(id) | some id in _ordered_ids]

control_result_counts := {s: count([r | some r in control_results; r.status == s]) |
	some s in ["pass", "fail", "evidence_missing", "not_attested", "not_evaluated"]
}

passed_controls := count([r | some r in control_results; r.status == "pass"]) if scope_loaded

passed_controls := 0 if not scope_loaded

_passed_ids := {r.id | some r in control_results; r.status == "pass"}

failed_control_ids := [id | some id in _ordered_ids; not id in _passed_ids]

failed_controls := count(failed_control_ids) if scope_loaded

failed_controls := total_controls if not scope_loaded

not_applicable_controls := 0

# The controls of the scope the 800-53 module has no row for (AC-17(9) and SA-10(1) at Level 2).
not_evaluated_control_ids := [id | some id in _ordered_ids; not _nist_rows[id]]

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

_control_findings := {m | some r in control_results; some m in r.findings}

# Findings of the 800-53 module that name no control: the benchmark FAIL-CLOSED notices.
_notices := {v | some v in nist.violations; startswith(v, "FAIL-CLOSED")}

violation_fail_closed contains msg if {
	not scope_loaded
	msg := "FAIL-CLOSED: the TX-RAMP control index (txramp_index.rego, generated) or the NIST SP 800-53 module (frameworks/federal/nist/sp_800_53/) is not loaded next to this module, so no control could be evaluated; this is not a passing result"
}

_programme_findings := ((((violation_selector | violation_assessment) | violation_conmon) | violation_fail_closed) | _eq_problems) | _notices

violations := array.concat(sort(_programme_findings), sort(_control_findings))

default compliant := false

compliant if count(violations) == 0

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

default assessed_at := "unknown"

assessed_at := input.assessment_date

# Verdicts on controls the scope does not select: shown, never a finding at this level.
_nist_by_id := {r.id: r | some r in nist.control_results}

benchmark_gaps_outside_scope := sort([id |
	some id in index.order
	not id in _scope_ids
	_nist_by_id[id].benchmark.status == "gap"
])

default _benchmark_evidence := {}

_benchmark_evidence := {"benchmark_evidence": nist.compliance_report.benchmark_evidence} if {
	_ = input.reports
}

_benchmark_evidence := {"benchmark_evidence": nist.compliance_report.benchmark_evidence} if {
	_ = input.findings
}

default _earned_report := "none"

_earned_report := _earned if _claimed

compliance_report := object.union(_report, _benchmark_evidence)

_report := {
	"framework": "TX-RAMP",
	"regulation": "Texas Risk and Authorization Management Program (TX-RAMP) Program Manual 4.0 (effective 2026-02-12): Level 1 and Level 2 certification baselines of the TX-RAMP Control Baselines 2.0 (NIST SP 800-53 Rev 5 controls), by assessment or by FedRAMP / GovRAMP equivalence",
	"assessed_at": assessed_at,
	"certification_level": level,
	"certification_basis": certification_basis,
	"scope": {"certification_level": scope_level, "map": _map_key, "basis": certification_basis},
	"equivalence": {
		"claimed": _claimed,
		"accepted": equivalence_accepted,
		"earned_level": _earned_report,
		"problems": sort([m | some m in _eq_problems]),
	},
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"total_controls": total_controls,
	"passed_controls": passed_controls,
	"failed_controls": failed_controls,
	"not_applicable_controls": not_applicable_controls,
	"failed_control_ids": failed_control_ids,
	"not_evaluated_control_ids": not_evaluated_control_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"baseline_size": baseline_sizes[scope_level],
	"baseline_sizes": baseline_sizes,
	"benchmark_gaps_outside_scope": benchmark_gaps_outside_scope,
	"coverage_note": "total_controls is the number of controls the TX-RAMP Control Baselines 2.0 select for the declared level; each is checked by the NIST SP 800-53 module with that module's parameter values, not TX-RAMP's. Where certification_basis is equivalence, the controls are accepted on the external FedRAMP or GovRAMP status and were not assessed by this report. Not a TX-RAMP certification.",
}
