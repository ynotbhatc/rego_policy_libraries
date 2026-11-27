# METADATA
# title: "ISO/IEC 27018:2019 — the 25 Annex A extended controls for PII in public clouds acting as PII processors, one attested result per control"
# custom:
#   class: compliance
#   framework: iso_27018
#   source: iso
#   domains: [privacy, cloud]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iso_27018.main

import data.iso_27018.index
import rego.v1

# =============================================================================
# ISO/IEC 27018 — protection of personally identifiable information (PII) in public clouds acting as PII processors
#
# Entry point: data.iso_27018.main.compliance_report (framework key `iso_27018`).
# Place in the library: frameworks/privacy/, beside iso27701 (the PII-management standard built on the same ISMS).
#
# EDITION BUILT: ISO/IEC 27018:2019 (second edition, 2019-01), Annex A (normative): 25 extended controls, A.2.1 to A.12.2.
# A NEWER EDITION EXISTS and is NOT covered: ISO/IEC 27018:2025 (third edition, 2025-08) cancels and replaces the 2019
# edition, is aligned with ISO/IEC 27002:2022, makes Annex A informative and adds an Annex B that maps it to the 2019
# edition. The public previews of the 2025 edition stop before its Annex A sub-clauses, so its control identifiers are
# UNVERIFIED and may be renumbered; the 2019 identifiers were the ones that could be checked. Same approach as iso27701,
# which also builds the 2019 edition and says so.
#
# FACTS CHECKED, fetched 2026-11-27 (UTC); URL and sha256 of every file are in scripts/iso_cloud_controls.json:
#   - DIN's public table of contents of ISO/IEC 27018:2019 lists Annex A with sub-clauses A.1 to A.12 and the control
#     identifiers A.2.1, A.3.1, A.3.2, A.5.1, A.6.1, A.6.2, A.8.1, A.10.1 to A.10.3, A.11.1 to A.11.13, A.12.1, A.12.2:
#     25 controls in 8 groups (A.4, A.7 and A.9 are principle headings without a control; A.1 is general text).
#     https://www.din.de/de/mitwirken/normenausschuesse/nia/veroeffentlichungen/wdc-beuth:din21:301539764/toc-3041120/download
#   - The publisher's preview of the 2019 edition (VDE Verlag) confirms: second edition 2019-01, Annex A normative,
#     cancels and replaces ISO/IEC 27018:2014 (minor revision, an editorial correction in Annex A).
#     https://assets.vde-verlag.de/iec-normen/preview-pdf/info_isoiec27018%7Bed2.0%7Den.pdf
#   - The publisher's preview of the 2025 edition confirms: third edition 2025-08, cancels and replaces the 2019 edition,
#     aligned with ISO/IEC 27002:2022, Annex A informative (page 22), Annex B correspondence with the 2019 edition (page 30).
#     https://assets.vde-verlag.de/iec-normen/preview-pdf/info_isoiec27018%7Bed3.0%7Den.pdf
#   - A vendor's published statement of applicability lists the same 25 identifiers (cross-check only).
#   - iso.org catalogue pages answered HTTP 403 to automated requests; that was not worked around.
# UNVERIFIED: the 2025 Annex A identifiers; whether the 2025 edition keeps, renumbers, merges or drops any of the 25; the
# control text (the full standard is a paid document and no text is reproduced here).
#
# LICENCE POSITION. ISO/IEC standards are copyrighted and are not licensed for reproduction. This module carries only the
# identifiers (which locate a control in the owner's own copy of the standard), the clause structure (group numbers) and
# this library's own short labels, which are not the standard's titles. No control text or guidance is reproduced. It is an
# independent work, not issued or endorsed by ISO or IEC, and not a conformity assessment or certification report.
#
# A DELTA ON ISO/IEC 27001. ISO/IEC 27018 is used together with the ISO/IEC 27002 controls inside an ISO/IEC 27001 ISMS.
# This module therefore evaluates only what 27018 adds. It does NOT re-evaluate ISO/IEC 27001 Annex A (the iso27001 module
# does that). The link to the base is an explicit required attestation, input.iso_27018.iso27001_isms_in_place: an ISMS
# certified or operated to ISO/IEC 27001 that covers the public cloud service is in place. Why not import data.iso27001:
# the library's reports for other standards compose by import only where the controls ARE the other standard's controls
# (GovRAMP imports nist_800_53); the 27018 controls are not 27001 Annex A controls, and an import would demand the full
# set of 27001 inputs from a caller who only wants the 27018 delta. A caller who runs both reports can read the
# iso27001 verdict and attest the boolean from it.
#
# Input contract (everything under input.iso_27018):
#   public_cloud_pii_processor    boolean, required: the organization acts as a PII processor in a public cloud service.
#                                 true: the 25 controls are assessed. false: ISO/IEC 27018 does not apply; every control
#                                 is reported not_applicable with not_applicable_reason, applicable is false and
#                                 compliant is false (nothing was assessed, so there is nothing to certify). Missing or
#                                 not a boolean: a finding, and the 25 controls are assessed (absence never narrows scope).
#   not_applicable_reason         non-empty string, required when public_cloud_pii_processor is false.
#   iso27001_isms_in_place        boolean, required when the standard applies: an ISO/IEC 27001 ISMS covering the
#                                 cloud service is in place. Missing, null, non-boolean or false is a finding; the 25
#                                 controls are still evaluated and compliant is false.
#   controls                      object: control id -> boolean attested result, e.g. {"A.11.6": true, "A.12.1": false}.
#   not_applicable                object: control id -> reason (non-empty string) for a control the assessor judged not to
#                                 apply, e.g. {"A.11.7": "no hardcopy is produced"}. A blank or non-string reason, an
#                                 unknown id, or an id that also has a result is a finding.
#
# Report contract: total_controls is 25, a fixed property of the standard (also when the standard does not apply).
# passed_controls + failed_controls + not_applicable_controls == total_controls; failed_controls counts every control that
# is neither passed nor not applicable, however many findings it has. control_results lists the 25 controls in the
# standard's order with status pass | fail | evidence_missing | evidence_invalid | not_applicable. compliant means: the
# standard applies and is declared, the ISMS attestation is true, no finding, and at least one control passed.
#
# OPA endpoint: POST http://<host>:8182/v1/data/iso_27018/main/compliance_report

# ── Input, read defensively ──────────────────────────────────────────────────

_raw := object.get(input, "iso_27018", null)

_in := _raw if is_object(_raw)

else := {}

_raw_controls := object.get(_in, "controls", null)

_results := _raw_controls if is_object(_raw_controls)

else := {}

_raw_na := object.get(_in, "not_applicable", null)

_na := _raw_na if is_object(_raw_na)

else := {}

# ── Does the standard apply? ─────────────────────────────────────────────────

_declared := object.get(_in, "public_cloud_pii_processor", null)

declared_processor if _declared == true

out_of_scope if _declared == false

default standard_applies := true

standard_applies := false if out_of_scope

_scope_reason := object.get(_in, "not_applicable_reason", null)

_scope_reason_ok if {
	is_string(_scope_reason)
	trim_space(_scope_reason) != ""
}

default isms_in_place := false

isms_in_place if object.get(_in, "iso27001_isms_in_place", null) == true

# ── Per-control status ───────────────────────────────────────────────────────

_all := {id | some id in index.order}

# The controls assessed one by one: all 25, unless the organization declared that it is not a public cloud PII processor.
_assessed := _all if not out_of_scope

else := set()

_has_result(id) if _ = _results[id]

_has_na(id) if _ = _na[id]

# The controls, sorted into disjoint classes with set operations (a per-control function is slow on the oldest supported
# OPA when a table is large; the habit is kept here). A marker with a usable reason and no result is "not applicable"; a
# marker that is unusable, or that sits beside a result, is invalid; without a marker, true passes, false fails, a missing
# or null result is evidence missing and any other value is invalid.
_present := {id | some id, _ in _results}

_marked := {id | some id, _ in _na}

_marked_ok := {id | some id, reason in _na; is_string(reason); trim_space(reason) != ""}

_true_ids := {id | some id, v in _results; v == true}

_false_ids := {id | some id, v in _results; v == false}

_null_ids := {id | some id, v in _results; v == null}

_not_applicable := _all if out_of_scope

else := (_marked_ok & _all) - _present

_passed := (_true_ids & _assessed) - _marked

_failed := (_false_ids & _assessed) - _marked

_missing := ((_assessed - _present) - _marked) | ((_null_ids & _assessed) - _marked)

_invalid := (((_assessed - _not_applicable) - _passed) - _failed) - _missing

_status_of := object.union_n([
	{id: "pass" | some id in _passed},
	{id: "fail" | some id in _failed},
	{id: "evidence_missing" | some id in _missing},
	{id: "evidence_invalid" | some id in _invalid},
	{id: "not_applicable" | some id in _not_applicable},
])

_detail(_, "fail") := "attested result is false: the control is not met"

_detail(id, "evidence_missing") := sprintf("evidence missing: input.iso_27018.controls[%q] not collected", [id]) if not _has_result(id)

_detail(id, "evidence_missing") := sprintf("evidence missing: input.iso_27018.controls[%q] is null", [id]) if _has_result(id)

_detail(id, "evidence_invalid") := sprintf("input.iso_27018.controls[%q] is not a boolean (got %v)", [id, type_name(_results[id])]) if {
	not _has_na(id)
	_has_result(id)
}

_detail(id, "evidence_invalid") := sprintf("input.iso_27018.not_applicable[%q] needs a non-empty string reason (got %v)", [id, type_name(_na[id])]) if {
	_has_na(id)
	not _has_result(id)
}

_detail(id, "evidence_invalid") := sprintf("input.iso_27018.not_applicable[%q] conflicts with input.iso_27018.controls[%q]: a control has a result or is not applicable, not both", [id, id]) if {
	_has_na(id)
	_has_result(id)
}

_finding(id, st) := sprintf("ISO/IEC 27018 %v: %v (%v)", [id, _detail(id, st), index.labels[id]])

_control_messages := {_finding(id, st) |
	some id, st in _status_of
	st != "pass"
	st != "not_applicable"
}

# ── Input problems that are not controls but still block a compliant result ──

_input_notes contains "ISO/IEC 27018 input: input.iso_27018 is missing or not an object; no attested result was supplied" if {
	not is_object(_raw)
}

_input_notes contains "ISO/IEC 27018 input: input.iso_27018.public_cloud_pii_processor is missing or not a boolean; the 25 controls are assessed" if {
	not declared_processor
	not out_of_scope
}

_input_notes contains "ISO/IEC 27018 input: input.iso_27018.not_applicable_reason is missing or blank; a declaration that the organization is not a public cloud PII processor needs a written reason" if {
	out_of_scope
	not _scope_reason_ok
}

_input_notes contains "ISO/IEC 27018 base: input.iso_27018.iso27001_isms_in_place is missing; evidence missing: an ISO/IEC 27001 ISMS covering the cloud service is not attested" if {
	not out_of_scope
	not "iso27001_isms_in_place" in object.keys(_in)
}

_input_notes contains "ISO/IEC 27018 base: input.iso_27018.iso27001_isms_in_place is null; evidence missing: an ISO/IEC 27001 ISMS covering the cloud service is not attested" if {
	not out_of_scope
	object.get(_in, "iso27001_isms_in_place", 0) == null
}

_input_notes contains sprintf("ISO/IEC 27018 base: input.iso_27018.iso27001_isms_in_place is not a boolean (got %v)", [type_name(v)]) if {
	not out_of_scope
	v := _in.iso27001_isms_in_place
	v != null
	type_name(v) != "boolean"
}

_input_notes contains "ISO/IEC 27018 base: input.iso_27018.iso27001_isms_in_place is false; no ISO/IEC 27001 ISMS covering the cloud service is in place" if {
	not out_of_scope
	_in.iso27001_isms_in_place == false
}

_input_notes contains "ISO/IEC 27018 input: input.iso_27018.controls is not an object (control id -> boolean)" if {
	_raw_controls != null
	not is_object(_raw_controls)
}

_input_notes contains "ISO/IEC 27018 input: input.iso_27018.not_applicable is not an object (control id -> reason)" if {
	_raw_na != null
	not is_object(_raw_na)
}

_input_notes contains sprintf("ISO/IEC 27018 input: controls[%q] is not a control id of ISO/IEC 27018:2019 Annex A", [id]) if {
	all := _all
	some id, _ in _results
	not id in all
}

_input_notes contains sprintf("ISO/IEC 27018 input: not_applicable[%q] is not a control id of ISO/IEC 27018:2019 Annex A", [id]) if {
	all := _all
	some id, _ in _na
	not id in all
}

violations := _control_messages | _input_notes

# ── Report ───────────────────────────────────────────────────────────────────

control_results := [{
	"id": id,
	"group": index.groups[id],
	"label": index.labels[id],
	"status": st,
	"findings": [_finding(id, st) | st != "pass"; st != "not_applicable"],
} |
	status_of := _status_of
	some id in index.order
	st := status_of[id]
]

passed_ids := [id | passed := _passed; some id in index.order; id in passed]

not_applicable_ids := [id | na := _not_applicable; some id in index.order; id in na]

failed_control_ids := [id | status_of := _status_of; some id in index.order; st := status_of[id]; st != "pass"; st != "not_applicable"]

control_result_counts := {
	"pass": count(_passed),
	"fail": count(_failed),
	"evidence_missing": count(_missing),
	"evidence_invalid": count(_invalid),
	"not_applicable": count(_not_applicable),
}

group_results[g] := {
	"label": index.group_labels[g],
	"total": count(ids),
	"passed": count(ids & passed),
	"not_applicable": count(ids & na),
	"failed": (count(ids) - count(ids & passed)) - count(ids & na),
} if {
	passed := _passed
	na := _not_applicable
	some g, members in index.by_group
	ids := {id | some id in members}
}

default compliant := false

compliant if {
	declared_processor
	isms_in_place
	count(violations) == 0
	count(passed_ids) > 0
}

compliance_report := {
	"framework": "ISO/IEC 27018:2019 Annex A — PII protection in public clouds acting as PII processors (delta on ISO/IEC 27001 / 27002)",
	"framework_key": "iso_27018",
	"standard_version": "2019",
	"edition": "second edition, 2019-01",
	"newer_edition_not_covered": "ISO/IEC 27018:2025 (third edition, 2025-08); its Annex A identifiers are unverified",
	"approval": "Not issued or endorsed by ISO or IEC: an independent check set over the assessor's attested results, not a conformity assessment",
	"attribution": "ISO/IEC 27018:2019 © ISO/IEC; control identifiers and clause numbers only, with this library's own labels; no standard text is reproduced",
	"applicable": standard_applies,
	"public_cloud_pii_processor": _declared,
	"not_applicable_reason": _scope_reason,
	"base_isms_attested": isms_in_place,
	"compliant": compliant,
	"total_controls": count(index.order),
	"passed_controls": count(passed_ids),
	"failed_controls": count(failed_control_ids),
	"not_applicable_controls": count(not_applicable_ids),
	"failed_control_ids": failed_control_ids,
	"not_applicable_ids": not_applicable_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"group_results": group_results,
	"violations": violations,
	"violation_count": count(violations),
}
