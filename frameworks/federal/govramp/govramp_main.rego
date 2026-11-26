# METADATA
# title: "GovRAMP (formerly StateRAMP) — Low / Moderate / High baselines and Core / Ready / Authorized statuses: one result per baseline control, taken from the NIST SP 800-53 module"
# custom:
#   class: compliance
#   framework: govramp
#   source: govramp
#   domains: [us-state, cloud]
#   coverage:
#     checks: 14
#     cited: 4
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package govramp.main

import data.govramp.index as govramp_index
import data.nist.sp800_53.index
import data.nist.sp800_53.main as nist
import rego.v1

# =============================================================================
# GovRAMP (formerly StateRAMP) — baseline and verification-status check
#
# Entry point: data.govramp.main.compliance_report (framework key `govramp`). StateRAMP is the same programme under
# its former name (GovRAMP is the name since 2025: the publisher's bylaws are titled "StateRAMP dba GovRAMP"); there is
# no second key. Place in the library: next to fedramp, cjis and irs_1075 under frameworks/federal/ (state and local
# government is the audience, the controls are NIST SP 800-53 Rev 5, no new category directory).
#
# FACTS CHECKED AGAINST THE PUBLISHER, fetched 2026-11-26 (UTC, 01:12 to 01:17), all under https://govramp.org:
#   - Name: "GovRAMP", formerly StateRAMP (/hubfs/StateRAMP%20dba%20GovRAMP%20Adopted%20Bylaws.pdf; Security
#     Assessment Framework revision 4.1, 09/20/2025: "Updated to reflect DBA").
#   - Framework: Security Assessment Framework, version 4.2, revision of 02/24/2026, file name "(July 2026)"
#     (/hubfs/GovRAMP%20Security%20Assessment%20Framework%20(July%202026).pdf, sha256 4ae5641e...0cfe). Sections 1.5.3,
#     1.5.5, 1.5.6, 1.5.7 and 1.5.11 define the verified statuses used below.
#   - Baselines: "Built on NIST SP 800-53 Rev. 5" (https://govramp.org/security-program). Impact levels Low, Moderate and
#     High, "Aligned with ... based on FedRAMP Rev. 5 Low/Moderate/High Control Baselines" (SAF 1.5.4). Aligned and based
#     on: the publisher does NOT say they are the same control set, and they are not (next item).
#   - Control counts, from the publisher's own Controls Matrix workbooks (the "Controls" sheet; ids only are used):
#         Low       153  Controls Matrix Low Rev 5 V1.05 (in the Low Impact Service Provider Package zip)
#         Moderate  319  Controls Matrix Moderate Rev 5 V1.06 (https://govramp.org/hubfs/GovRAMP-Controls-Matrix_Mod_Rev5_V1.06.xlsx)
#         High      406  Controls Matrix High Rev 5 V1.1 (in the High Impact Service Provider Package zip)
#     FedRAMP Rev 5 selects 156 / 323 / 410 (see package fedramp). GovRAMP selects no control FedRAMP does not; it does
#     not select IA-2(12), IA-8(1) and SA-4(10) at any level, nor CA-8(2) at Moderate and High. Low is inside Moderate is
#     inside High. The Federal Overlay (v1.0, February 2026) is a side-by-side with FedRAMP and disagrees with the matrices
#     in two places (see "Owner decisions" in the pull request); the matrices are the authority used here.
#   - Statuses: Core (60 controls, Moderate only, assessed by the GovRAMP PMO, no 3PAO, quarterly continuous monitoring),
#     Ready (Required-for-Ready column of the matrix: Low 29, Moderate 80, High 90; independent 3PAO Readiness Assessment
#     Report), Provisionally Authorized and Authorized (every control of the level; 3PAO Security Assessment Report;
#     sponsoring-body approval; monthly continuous monitoring). Core is a subset of Ready is a subset of Authorized at
#     Moderate. Snapshot and Progressing Snapshot are maturity assessments, not verified statuses, and are not modelled.
#   - Versions: the Core page links an older Moderate package (matrix V1.04, 2025-04-21); its control list is identical to
#     V1.06. The Core Controls workbook is v1.0 (2025-02-14).
# Pages and files read (all fetched 2026-11-26 UTC): https://govramp.org/ (stateramp.org redirects to it),
# /security-program, /core, /document-library; /hubfs/GovRAMP%20Federal%20Overlay%20(Low_Moderate_High).xlsx,
# /hubfs/GovRAMP%20Core%20Controls.xlsx, /hubfs/Continuous%20Monitoring%20Guide%20and%20Escalation%20Process.pdf,
# the Ready Minimum Mandatory Requirements workbook; the exact URLs and sha256 are in scripts/govramp_baselines.json.
# UNVERIFIED: the GovRAMP Standards and Technical Committee's reasoning for each deselected control; whether a Low or High
# Ready list published separately from the matrices differs from the matrices' Ready column; the direction of each Federal
# Overlay parameter difference; a published control count per status other than Core (60) and Ready (80, Moderate).
# Not obtained: the Low and High impact Ready lists beyond the matrices' Ready column (the Ready Minimum Mandatory
# Requirements workbook, v3.0 October 2023, covers Moderate only and agrees with the matrix); GovRAMP's own parameter
# values are not reproduced (licensing and size) and are not evaluated, see "Parameters" below.
# Id lists, versions, URLs and sha256 of every source file: scripts/govramp_baselines.json, written by
# scripts/gen_govramp_framework_maps.py into govramp_index.rego (read by this module) and crosswalk/framework_maps/data.json
# (maps govramp_<level>[_ready|_core], for the crosswalk's coverage report).
#
# How a control gets its result. The control checks are the NIST SP 800-53 module's (data.nist.sp800_53.main): every
# control GovRAMP selects at the declared level and status is one of the 544 ids that module evaluates, with the same
# fail-closed behaviour and the same input contract (its per-family sections of the input). This module takes that
# module's row for each selected control and does not copy a rule body:
#   pass              the 800-53 module has no finding for the control
#   fail              a finding that is not about missing evidence
#   evidence_missing  the facts the check reads were not collected
#   not_attested      an organizational control without its signed attestation
#   not_evaluated     the 800-53 module has no row for the control (never happens with the shipped maps; counted as failed)
# total_controls is the size of the selected scope, a fixed property of (impact level, status): Low 153, Moderate 319,
# High 406 for Authorized and Provisionally Authorized; Ready 29 / 80 / 90; Core 60. Only the boolean true passes a yes/no
# fact (the 800-53 module's rule). passed_controls + failed_controls + not_applicable_controls = total_controls.
# failed_controls counts every control that is not a pass. not_applicable_controls is always 0: a control is not
# applicable only by an explicit statement and the 800-53 module has no such statement yet.
#
# Benchmark results (optional): input.reports / input.findings in the shapes data.crosswalk.correlation reads. The
# 800-53 module carries them through the STIG -> CCI -> 800-53 spine; a gap fails the control whatever its declared
# evidence says (the rule of that module and of fedramp). Gaps on controls outside the selected scope are listed under
# benchmark_gaps_outside_scope and are not GovRAMP findings at this level and status.
#
# Programme findings, all attestations (boolean or numeric facts the provider or the PMO states; nothing here is measured):
#   input.impact_level                          low | moderate | high, required
#   input.verification_status                   core | ready | authorized | provisionally_authorized, required; core only
#                                               exists at moderate
#   input.verification.pmo_assessment_completed             Core: assessed by the GovRAMP PMO (SAF 1.5.3, 1.5.11)
#   input.verification.third_party_assessment_completed     Ready, Provisionally Authorized, Authorized: a 3PAO
#                                               assessment, RAR for Ready, SAR for the other two (SAF 1.5.5, 1.5.7, 1.5.11)
#   input.verification.sponsoring_body_approved Provisionally Authorized and Authorized: a government sponsor or the
#                                               Approvals Committee (SAF 1.5.6, 1.5.7, 1.5.11)
#   input.verification.status_valid_days_remaining          number, days left of the 12-month validity of the verified
#                                               status; a negative number is an expired status (SAF 1.5.3: "valid for
#                                               12 months", "like other GovRAMP verified statuses")
#   input.continuous_monitoring.reports_submitted_on_schedule  quarterly for Core, monthly for the other statuses
#                                               (Continuous Monitoring Guide v2.0, section 3.2, sha256 bf65d85f...1db4)
# Until the impact level is declared the High baseline is assessed; until the status is declared (or when it cannot
# exist at the level) Authorized is assessed; each is a finding. This is the fail-closed choice, never a "compliant".
#
# Parameters. GovRAMP sets some parameter values and adds requirements that differ from FedRAMP's. The Federal Overlay v1.0
# lists them: Low AU-11 and CA-6; Moderate also CP-9(8), IA-2(6), MP-5, SC-8(1), SC-13; High also SI-4(10). The control checks
# here are the 800-53 module's, with its parameter values; GovRAMP's own parameter values are NOT applied. A row for
# one of those controls carries federal_overlay_differs_from_fedramp: true, so a pass on it is read as "passes the 800-53
# module's check", not as "meets GovRAMP's parameter". Which direction each delta goes was not assessed (UNVERIFIED).
# =============================================================================

# Impact levels, statuses and the sizes of their scopes (the committed maps hold the ids; these are the expected sizes,
# the fail-closed count when the maps are not loaded, and a figure the tests compare with the maps).
baseline_sizes := {"low": 153, "moderate": 319, "high": 406}

fedramp_rev5_baseline_sizes := {"low": 156, "moderate": 323, "high": 410}

_scope_sizes := {
	"low": {"authorized": 153, "ready": 29},
	"moderate": {"authorized": 319, "ready": 80, "core": 60},
	"high": {"authorized": 406, "ready": 90},
}

_levels := {"low", "moderate", "high"}

_statuses := {"core", "ready", "authorized", "provisionally_authorized"}

default level := "unknown"

level := lower(trim_space(input.impact_level)) if {
	is_string(input.impact_level)
	lower(trim_space(input.impact_level)) in _levels
}

default status := "unknown"

status := lower(trim_space(input.verification_status)) if {
	is_string(input.verification_status)
	lower(trim_space(input.verification_status)) in _statuses
}

_combination_ok if {
	level != "unknown"
	status in {"ready", "authorized", "provisionally_authorized"}
}

_combination_ok if {
	level == "moderate"
	status == "core"
}

# The scope assessed: the declared one, or the strictest one that fits until the declaration is usable.
default scope_level := "high"

scope_level := level if level != "unknown"

default scope_status := "authorized"

scope_status := status if _combination_ok

# Authorized and Provisionally Authorized share one control list (every control of the level).
_scope_kind := scope_status if scope_status in {"core", "ready"}

default _scope_kind := "authorized"

# The map this scope corresponds to in crosswalk/framework_maps/data.json (the same lists; the crosswalk's coverage
# report reads those), named in the report.
_map_key := concat("", ["govramp_", scope_level]) if _scope_kind == "authorized"

_map_key := concat("", ["govramp_", scope_level, "_", _scope_kind]) if _scope_kind != "authorized"

# The ids come from the generated index (govramp_index.rego), a rego file next to this one. When it is absent this is
# undefined, which reads as "could not be evaluated", never as "no controls".
_scope_set := govramp_index.scopes[scope_level][_scope_kind]

default scope_loaded := false

scope_loaded if {
	count(_scope_set) > 0
	count(nist.evaluated_controls) > 0
}

_scope_ids := {id | scope_loaded; some id in _scope_set}

_expected_total := _scope_sizes[scope_level][_scope_kind]

default total_controls := 0

total_controls := count(_scope_ids) if scope_loaded

total_controls := _expected_total if not scope_loaded

# ---------------------------------------------------------------------------
# Programme findings
# ---------------------------------------------------------------------------

# A section that is absent, null or not an object reads as empty, so every check on it reports missing evidence.
_section(key) := value if {
	value := object.get(input, key, null)
	is_object(value)
} else := {}

_ver := _section("verification")

_cm := _section("continuous_monitoring")

# Why a yes/no fact did not count: boolean false keeps the plain finding, anything else is named.
_bool_problem(section, name, field) := "" if {
	section[field] == false
} else := sprintf(" [evidence missing: input.%s.%s not collected]", [name, field]) if {
	object.get(section, field, null) == null
} else := sprintf(" [evidence invalid: input.%s.%s is not a boolean (got %s)]", [name, field, type_name(section[field])])

violation_selector contains msg if {
	level == "unknown"
	msg := "GovRAMP IMPACT: evidence missing or invalid — input.impact_level must be one of low, moderate, high. The High baseline (406 controls, Authorized) is assessed until the impact level is declared."
}

violation_selector contains msg if {
	status == "unknown"
	msg := "GovRAMP STATUS: evidence missing or invalid — input.verification_status must be one of core, ready, authorized, provisionally_authorized. The Authorized scope is assessed until the status is declared."
}

violation_selector contains msg if {
	status == "core"
	level != "moderate"
	msg := "GovRAMP STATUS: Core exists at the Moderate impact level only (the Core controls are a column of the Moderate Controls Matrix). The Authorized scope of the declared level is assessed."
}

violation_assessment contains msg if {
	status == "core"
	not _ver.pmo_assessment_completed == true
	msg := sprintf("GovRAMP STATUS: attestation — Core is assessed by the GovRAMP PMO (Security Assessment Framework 1.5.3); input.verification.pmo_assessment_completed is not true.%s", [_bool_problem(_ver, "verification", "pmo_assessment_completed")])
}

violation_assessment contains msg if {
	status in {"ready", "authorized", "provisionally_authorized"}
	not _ver.third_party_assessment_completed == true
	msg := sprintf("GovRAMP STATUS: attestation — %s requires an independent 3PAO assessment (Security Assessment Framework 1.5.5, 1.5.7, 1.5.11); input.verification.third_party_assessment_completed is not true.%s", [status, _bool_problem(_ver, "verification", "third_party_assessment_completed")])
}

violation_assessment contains msg if {
	status in {"authorized", "provisionally_authorized"}
	not _ver.sponsoring_body_approved == true
	msg := sprintf("GovRAMP STATUS: attestation — %s requires approval by a sponsoring government or the Approvals Committee (Security Assessment Framework 1.5.6, 1.5.7); input.verification.sponsoring_body_approved is not true.%s", [status, _bool_problem(_ver, "verification", "sponsoring_body_approved")])
}

# The 12-month validity of a verified status; only a number is evidence. Checked once a status is declared.
violation_assessment contains msg if {
	status != "unknown"
	not is_number(object.get(_ver, "status_valid_days_remaining", null))
	msg := "GovRAMP STATUS: evidence missing — input.verification.status_valid_days_remaining (days left of the 12-month validity of the verified status) not collected, or not a number"
}

violation_assessment contains msg if {
	status != "unknown"
	is_number(_ver.status_valid_days_remaining)
	_ver.status_valid_days_remaining < 0
	msg := sprintf("GovRAMP STATUS: the verified status expired %v days ago; a verified GovRAMP status is valid for 12 months and is extended by an annual assessment before it expires (Security Assessment Framework 1.5.3)", [abs(_ver.status_valid_days_remaining)])
}

_cadence := "quarterly" if status == "core"

default _cadence := "monthly"

violation_conmon contains msg if {
	not _cm.reports_submitted_on_schedule == true
	msg := sprintf("GovRAMP CONMON: attestation — continuous monitoring reports are due %s for %s (Continuous Monitoring Guide 3.2); input.continuous_monitoring.reports_submitted_on_schedule is not true.%s", [_cadence, _status_label, _bool_problem(_cm, "continuous_monitoring", "reports_submitted_on_schedule")])
}

default _status_label := "an undeclared status (monthly is applied)"

_status_label := status if status != "unknown"

# ---------------------------------------------------------------------------
# One result per control of the selected scope
# ---------------------------------------------------------------------------

# The 800-53 module's rows for the scope's controls, built once.
_nist_rows := {r.id: r | some r in nist.control_results; r.id in _scope_ids}

# Controls whose GovRAMP requirement or parameter differs from FedRAMP's (Federal Overlay v1.0), from the index.
_delta_ids := {id | some id in govramp_index.federal_overlay_differs_from_fedramp[scope_level]}

# "NIST AC-2: ..." is the 800-53 module's finding; the same finding is reported under this framework's name.
_govramp_message(m) := concat("", ["GovRAMP ", trim_prefix(m, "NIST ")])

_row(id) := object.union(base, bench) if {
	r := _nist_rows[id]
	base := {
		"id": id,
		"status": r.status,
		"basis": r.basis,
		"federal_overlay_differs_from_fedramp": id in _delta_ids,
		"findings": [_govramp_message(m) | some m in r.findings],
	}
	bench := _bench_part(r)
}

_bench_part(r) := {"benchmark": r.benchmark} if {
	is_object(object.get(r, "benchmark", null))
} else := {}

_row(id) := {
	"id": id,
	"status": "not_evaluated",
	"basis": "none",
	"federal_overlay_differs_from_fedramp": id in _delta_ids,
	"findings": [sprintf("GovRAMP %s: not evaluated — the NIST SP 800-53 module has no check for this control, so it cannot pass", [id])],
} if {
	not _nist_rows[id]
	id in _scope_ids
}

# The rows in the 800-53 module's natural id order (AC-2 before AC-10, AC-2 before AC-2(1)); an id that module does
# not list (none with the shipped maps) follows, sorted.
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

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

_control_findings := {m | some r in control_results; some m in r.findings}

# Findings of the 800-53 module that name no control: the benchmark FAIL-CLOSED notices.
_notices := {v | some v in nist.violations; startswith(v, "FAIL-CLOSED")}

violation_fail_closed contains msg if {
	not scope_loaded
	msg := "FAIL-CLOSED: the GovRAMP control index (govramp_index.rego, generated) or the NIST SP 800-53 module (frameworks/federal/nist/sp_800_53/) is not loaded next to this module, so no control could be evaluated; this is not a passing result"
}

_programme_findings := violation_selector | violation_assessment | violation_conmon | violation_fail_closed | _notices

violations := array.concat(sort(_programme_findings), sort(_control_findings))

default compliant := false

compliant if count(violations) == 0

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

default assessed_at := "unknown"

assessed_at := input.assessment_date

# Verdicts on controls the scope does not select: shown, never a finding at this level and status.
_nist_by_id := {r.id: r | some r in nist.control_results}

benchmark_gaps_outside_scope := sort([id |
	some id in index.order
	not id in _scope_ids
	_nist_by_id[id].benchmark.status == "gap"
])

default not_selected_from_fedramp_rev5 := []

not_selected_from_fedramp_rev5 := govramp_index.not_selected_from_fedramp_rev5[scope_level]

default _benchmark_evidence := {}

_benchmark_evidence := {"benchmark_evidence": nist.compliance_report.benchmark_evidence} if {
	_ = input.reports
}

_benchmark_evidence := {"benchmark_evidence": nist.compliance_report.benchmark_evidence} if {
	_ = input.findings
}

compliance_report := object.union(_report, _benchmark_evidence)

_report := {
	"framework": "GovRAMP",
	"formerly": "StateRAMP",
	"regulation": "GovRAMP Security Assessment Framework v4.2 (2026-02-24 revision): verified statuses Core, Ready, Provisionally Authorized, Authorized at the Low, Moderate and High impact levels, controls from NIST SP 800-53 Rev 5 as selected by the GovRAMP Controls Matrices",
	"assessed_at": assessed_at,
	"impact_level": level,
	"verification_status": status,
	"scope": {"impact_level": scope_level, "status": scope_status, "map": _map_key},
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"total_controls": total_controls,
	"passed_controls": passed_controls,
	"failed_controls": failed_controls,
	"not_applicable_controls": not_applicable_controls,
	"failed_control_ids": failed_control_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"baseline_size": baseline_sizes[scope_level],
	"baseline_sizes": baseline_sizes,
	"fedramp_rev5_baseline_sizes": fedramp_rev5_baseline_sizes,
	"not_selected_from_fedramp_rev5": not_selected_from_fedramp_rev5,
	"benchmark_gaps_outside_scope": benchmark_gaps_outside_scope,
	"coverage_note": "total_controls is the number of controls the GovRAMP Controls Matrix selects for the declared impact level and status; each is checked by the NIST SP 800-53 module with that module's parameter values, not GovRAMP's (see federal_overlay_differs_from_fedramp on the rows). Not a GovRAMP verification or authorization.",
}
