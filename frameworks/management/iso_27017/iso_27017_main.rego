# METADATA
# title: "ISO/IEC 27017:2026 — the 4 additional cloud controls (CLD) of ISO/IEC 27002-based cloud security guidance, one attested result per control and role"
# custom:
#   class: compliance
#   framework: iso_27017
#   source: iso
#   domains: [cloud, isms]
package iso_27017.main

import data.iso_27017.index
import rego.v1

# =============================================================================
# ISO/IEC 27017 — information security controls based on ISO/IEC 27002 for cloud services
#
# Entry point: data.iso_27017.main.compliance_report (framework key `iso_27017`).
# Place in the library: frameworks/management/, beside iso27001 (the ISMS standard whose Annex A it extends).
#
# EDITION BUILT: ISO/IEC 27017:2026 (second edition, published 2026-07). It cancels and replaces ISO/IEC 27017:2015 | ITU-T
# X.1631:2015, which had seven cloud-specific controls numbered CLD.x.y.z (CLD.6.3.1 ... CLD.13.1.4). The 2026 edition is
# aligned with ISO/IEC 27002:2022: its additional controls are numbered inside the 27002:2022 clause structure and are marked
# CLD in its contents. THIS MODULE DOES NOT COVER THE 2015 EDITION: its identifiers are not carried and an input that uses
# one is reported as an unknown id.
#
# FACTS CHECKED, fetched 2026-11-27 (UTC); URL and sha256 of every file are in scripts/iso_cloud_controls.json:
#   - The publisher's public preview of the 2026 edition (VDE Verlag): "Second edition 2026-07"; the contents list four
#     controls marked CLD: 5.38 (shared roles and responsibilities within a cloud computing environment), 5.39 (agreement on
#     the roles and responsibilities of the cloud service partner), 8.35 (segregation in virtual computing environments) and
#     8.36 (detection and prevention of unauthorized use of cloud services); Annex A of the edition is the correspondence
#     with the 2015 edition and Annex B is "Monitoring of cloud services" (neither is a control). The foreword says the
#     second edition cancels and replaces the first, the structure was changed, and some controls were merged, some removed
#     and several introduced; the scope says the guidance is for cloud service customers (CSC) and cloud service providers (CSP).
#     https://assets.vde-verlag.de/iec-normen/preview-pdf/info_isoiec27017%7Bed2.0%7Den.pdf
#   - IEC webstore: edition 2.0, publication date 2026-07-27, https://webstore.iec.ch/en/publication/115400 ; the Estonian
#     standards body lists ISO/IEC 27017:2026 valid from 2026-07-27, https://www.evs.ee/en/iso-iec-27017-2026 .
#   - iso.org catalogue pages answered HTTP 403 to automated requests; that was not worked around.
# UNVERIFIED: which of the four controls carry guidance for the customer, the provider or both (the contents do not say);
# how the seven 2015 controls map onto the 2026 numbering (Annex A of the edition is not in the preview); which ISO/IEC
# 27002:2022 controls carry added cloud guidance (outside this delta module); that iso.org lists the 2015 edition as withdrawn.
#
# LICENCE POSITION. ISO/IEC standards are copyrighted and are not licensed for reproduction. This module carries only the
# four control identifiers (which locate a control in the owner's own copy of the standard), the clause theme and this
# library's own short labels, which are not the standard's titles. No control text or guidance is reproduced. It is an
# independent work, not issued or endorsed by ISO or IEC, and not a conformity assessment or certification report.
#
# A DELTA ON ISO/IEC 27001. ISO/IEC 27017 is used with the ISO/IEC 27002 controls inside an ISO/IEC 27001 ISMS. This module
# evaluates only what 27017 adds (the four additional controls and the customer/provider role selector). It does NOT
# re-evaluate ISO/IEC 27001 Annex A (the iso27001 module does that). The link to the base is an explicit required
# attestation, input.iso_27017.iso27001_isms_in_place: an ISMS operated to ISO/IEC 27001 that covers the cloud service is in
# place. Why not import data.iso27001: the library's reports compose by import only where the controls ARE the other
# standard's controls (GovRAMP imports nist_800_53); the 27017 controls are not 27001 Annex A controls, and an import would
# demand the full set of 27001 inputs from a caller who only wants the 27017 delta. A caller who runs both reports can read
# the iso27001 verdict and attest the boolean from it.
#
# Input contract (everything under input.iso_27017):
#   role                      "customer" | "provider" | "both", required: which side of the cloud relationship is assessed.
#                             Missing or any other value is a finding and "both", the widest scope, is assessed.
#   iso27001_isms_in_place    boolean, required: an ISO/IEC 27001 ISMS covering the cloud service is in place. Missing, null,
#                             non-boolean or false is a finding; the controls are still evaluated and compliant is false.
#   controls                  object: control id -> object role -> boolean attested result, e.g.
#                             {"5.38": {"customer": true, "provider": true}, "8.35": {"provider": false}}. One result is
#                             asked for per control and per role in scope. Only the role(s) in scope are assessed: a result
#                             for the other role is ignored and listed in results_outside_role.
#   not_applicable            object: control id -> object role -> reason (non-empty string), for a control and role the
#                             assessor judged not to apply, e.g. {"8.35": {"customer": "the provider operates the hypervisor"}}.
#                             A blank or non-string reason, an unknown id or role, or a role that also has a result is a finding.
#                             Absence of a result is never read as "does not apply".
#
# Report contract: total_controls is 4, a fixed property of the standard. A control passes when every role in scope passed
# or is not applicable and at least one passed; it is not applicable when every role in scope is; otherwise it failed.
# passed_controls + failed_controls + not_applicable_controls == total_controls; failed_controls counts every control that is
# neither passed nor not applicable, however many findings it has. control_results lists the controls in the standard's order
# with the control status and, under "roles", the status of each role in scope: pass | fail | evidence_missing |
# evidence_invalid | not_applicable. compliant means: a valid role, the ISMS attestation is true, no finding, and at least
# one control passed.
#
# OPA endpoint: POST http://<host>:8182/v1/data/iso_27017/main/compliance_report

# ── Input, read defensively ──────────────────────────────────────────────────

_raw := object.get(input, "iso_27017", null)

_in := _raw if is_object(_raw)

else := {}

_raw_controls := object.get(_in, "controls", null)

_results := _raw_controls if is_object(_raw_controls)

else := {}

_raw_na := object.get(_in, "not_applicable", null)

_na := _raw_na if is_object(_raw_na)

else := {}

# The entries that are objects (role -> value); an entry of another type is reported and read as no result.
_res_e := {id: e | some id, e in _results; is_object(e)}

_na_e := {id: e | some id, e in _na; is_object(e)}

default isms_in_place := false

isms_in_place if object.get(_in, "iso27001_isms_in_place", null) == true

# ── Role ─────────────────────────────────────────────────────────────────────

_role_raw := object.get(_in, "role", null)

role_declared if _role_raw in {"customer", "provider", "both"}

default assessed_role := "both"

assessed_role := _role_raw if role_declared

roles_in_scope := {"customer"} if assessed_role == "customer"

roles_in_scope := {"provider"} if assessed_role == "provider"

roles_in_scope := {"customer", "provider"} if assessed_role == "both"

_all_roles := {"customer", "provider"}

# ── Per-(control, role) status ───────────────────────────────────────────────

_all := {id | some id in index.order}

# The cells to assess: every control for every role in scope. A cell is the array [control id, role]; arrays compare as
# values, so the classes below are plain set operations.
_scope := {[id, r] | some id in index.order; some r in roles_in_scope}

_present := {[id, r] | some id, e in _res_e; some r, _ in e}

_marked := {[id, r] | some id, e in _na_e; some r, _ in e}

_marked_ok := {[id, r] | some id, e in _na_e; some r, reason in e; is_string(reason); trim_space(reason) != ""}

_true_cells := {[id, r] | some id, e in _res_e; some r, v in e; v == true}

_false_cells := {[id, r] | some id, e in _res_e; some r, v in e; v == false}

_null_cells := {[id, r] | some id, e in _res_e; some r, v in e; v == null}

_not_applicable := (_marked_ok & _scope) - _present

_passed := (_true_cells & _scope) - _marked

_failed := (_false_cells & _scope) - _marked

_missing := ((_scope - _present) - _marked) | ((_null_cells & _scope) - _marked)

_invalid := (((_scope - _not_applicable) - _passed) - _failed) - _missing

_has_result(id, r) if _ = _res_e[id][r]

_has_na(id, r) if _ = _na_e[id][r]

_detail(_, _, "fail") := "attested result is false: the control is not met"

_detail(id, r, "evidence_missing") := sprintf("evidence missing: input.iso_27017.controls[%q].%v not collected", [id, r]) if not _has_result(id, r)

_detail(id, r, "evidence_missing") := sprintf("evidence missing: input.iso_27017.controls[%q].%v is null", [id, r]) if _has_result(id, r)

_detail(id, r, "evidence_invalid") := sprintf("input.iso_27017.controls[%q].%v is not a boolean (got %v)", [id, r, type_name(_res_e[id][r])]) if {
	not _has_na(id, r)
	_has_result(id, r)
}

_detail(id, r, "evidence_invalid") := sprintf("input.iso_27017.not_applicable[%q].%v needs a non-empty string reason (got %v)", [id, r, type_name(_na_e[id][r])]) if {
	_has_na(id, r)
	not _has_result(id, r)
}

_detail(id, r, "evidence_invalid") := sprintf("input.iso_27017.not_applicable[%q].%v conflicts with input.iso_27017.controls[%q].%v: a control and role has a result or is not applicable, not both", [id, r, id, r]) if {
	_has_na(id, r)
	_has_result(id, r)
}

_finding(id, r, st) := sprintf("ISO/IEC 27017 %v: %v (%v role; %v)", [id, _detail(id, r, st), r, index.labels[id]])

_cell_messages contains _finding(cell[0], cell[1], "fail") if some cell in _failed

_cell_messages contains _finding(cell[0], cell[1], "evidence_missing") if some cell in _missing

_cell_messages contains _finding(cell[0], cell[1], "evidence_invalid") if some cell in _invalid

_cell_status(id, r) := "pass" if [id, r] in _passed

_cell_status(id, r) := "fail" if [id, r] in _failed

_cell_status(id, r) := "evidence_missing" if [id, r] in _missing

_cell_status(id, r) := "evidence_invalid" if [id, r] in _invalid

_cell_status(id, r) := "not_applicable" if [id, r] in _not_applicable

# ── Per-control status ───────────────────────────────────────────────────────

_ok_cells := _passed | _not_applicable

# Sets are bound before the loops: on the oldest supported OPA a rule referenced inside a loop is evaluated again per element.
_failed_ids := {id |
	ok := _ok_cells
	roles := roles_in_scope
	some id in index.order
	some r in roles
	not [id, r] in ok
}

_na_ids := {id |
	na := _not_applicable
	roles := roles_in_scope
	some id in index.order
	count({r | some r in roles; [id, r] in na}) == count(roles)
}

_passed_ids := (_all - _failed_ids) - _na_ids

_control_status(id) := "pass" if id in _passed_ids

_control_status(id) := "fail" if id in _failed_ids

_control_status(id) := "not_applicable" if id in _na_ids

# ── Input problems that are not controls but still block a compliant result ──

_input_notes contains "ISO/IEC 27017 input: input.iso_27017 is missing or not an object; no attested result was supplied" if {
	not is_object(_raw)
}

_input_notes contains "ISO/IEC 27017 input: input.iso_27017.role is missing or is not \"customer\", \"provider\" or \"both\"; both roles are assessed" if {
	not role_declared
}

_input_notes contains "ISO/IEC 27017 base: input.iso_27017.iso27001_isms_in_place is missing; evidence missing: an ISO/IEC 27001 ISMS covering the cloud service is not attested" if {
	not "iso27001_isms_in_place" in object.keys(_in)
}

_input_notes contains "ISO/IEC 27017 base: input.iso_27017.iso27001_isms_in_place is null; evidence missing: an ISO/IEC 27001 ISMS covering the cloud service is not attested" if {
	object.get(_in, "iso27001_isms_in_place", 0) == null
}

_input_notes contains sprintf("ISO/IEC 27017 base: input.iso_27017.iso27001_isms_in_place is not a boolean (got %v)", [type_name(v)]) if {
	v := _in.iso27001_isms_in_place
	v != null
	type_name(v) != "boolean"
}

_input_notes contains "ISO/IEC 27017 base: input.iso_27017.iso27001_isms_in_place is false; no ISO/IEC 27001 ISMS covering the cloud service is in place" if {
	_in.iso27001_isms_in_place == false
}

_input_notes contains "ISO/IEC 27017 input: input.iso_27017.controls is not an object (control id -> role -> boolean)" if {
	_raw_controls != null
	not is_object(_raw_controls)
}

_input_notes contains "ISO/IEC 27017 input: input.iso_27017.not_applicable is not an object (control id -> role -> reason)" if {
	_raw_na != null
	not is_object(_raw_na)
}

_input_notes contains sprintf("ISO/IEC 27017 input: controls[%q] is not a control id of ISO/IEC 27017:2026", [id]) if {
	all := _all
	some id, _ in _results
	not id in all
}

_input_notes contains sprintf("ISO/IEC 27017 input: not_applicable[%q] is not a control id of ISO/IEC 27017:2026", [id]) if {
	all := _all
	some id, _ in _na
	not id in all
}

_input_notes contains sprintf("ISO/IEC 27017 input: controls[%q] is not an object of the form {\"customer\": <boolean>, \"provider\": <boolean>} (got %v)", [id, type_name(v)]) if {
	all := _all
	some id, v in _results
	id in all
	not is_object(v)
}

_input_notes contains sprintf("ISO/IEC 27017 input: not_applicable[%q] is not an object of the form {\"customer\": <reason>, \"provider\": <reason>} (got %v)", [id, type_name(v)]) if {
	all := _all
	some id, v in _na
	id in all
	not is_object(v)
}

_input_notes contains sprintf("ISO/IEC 27017 input: controls[%q] names the role %q; the roles are customer and provider", [id, r]) if {
	roles := _all_roles
	some id, e in _res_e
	some r, _ in e
	not r in roles
}

_input_notes contains sprintf("ISO/IEC 27017 input: not_applicable[%q] names the role %q; the roles are customer and provider", [id, r]) if {
	roles := _all_roles
	some id, e in _na_e
	some r, _ in e
	not r in roles
}

violations := _cell_messages | _input_notes

# ── Report ───────────────────────────────────────────────────────────────────

# Results and markers for a known control and role that the declared role leaves out of scope: ignored, but listed.
results_outside_role := sort([sprintf("%v.%v", [cell[0], cell[1]]) |
	scope := _scope
	all := _all
	roles := _all_roles
	some cell in (_present | _marked)
	cell[0] in all
	cell[1] in roles
	not cell in scope
])

control_results := [{
	"id": id,
	"theme": index.themes[id],
	"label": index.labels[id],
	"status": _control_status(id),
	"roles": {r: _cell_status(id, r) | some r in roles_in_scope},
	"findings": sort([_finding(id, r, st) |
		some r in roles_in_scope
		st := _cell_status(id, r)
		st != "pass"
		st != "not_applicable"
	]),
} |
	some id in index.order
]

passed_control_ids := [id | passed := _passed_ids; some id in index.order; id in passed]

not_applicable_ids := [id | na := _na_ids; some id in index.order; id in na]

failed_control_ids := [id | failed := _failed_ids; some id in index.order; id in failed]

cell_result_counts := {
	"pass": count(_passed),
	"fail": count(_failed),
	"evidence_missing": count(_missing),
	"evidence_invalid": count(_invalid),
	"not_applicable": count(_not_applicable),
}

default compliant := false

compliant if {
	role_declared
	isms_in_place
	count(violations) == 0
	count(passed_control_ids) > 0
}

compliance_report := {
	"framework": "ISO/IEC 27017:2026 — additional cloud controls (delta on ISO/IEC 27001 / 27002)",
	"framework_key": "iso_27017",
	"standard_version": "2026",
	"edition": "second edition, 2026-07",
	"replaces_edition_not_covered": "ISO/IEC 27017:2015 | ITU-T X.1631:2015 (seven CLD.x.y.z controls)",
	"approval": "Not issued or endorsed by ISO or IEC: an independent check set over the assessor's attested results, not a conformity assessment",
	"attribution": "ISO/IEC 27017:2026 © ISO/IEC; control identifiers and themes only, with this library's own labels; no standard text is reproduced",
	"declared_role": _role_raw,
	"assessed_role": assessed_role,
	"roles_in_scope": sort(roles_in_scope),
	"base_isms_attested": isms_in_place,
	"compliant": compliant,
	"total_controls": count(index.order),
	"passed_controls": count(passed_control_ids),
	"failed_controls": count(failed_control_ids),
	"not_applicable_controls": count(not_applicable_ids),
	"failed_control_ids": failed_control_ids,
	"not_applicable_ids": not_applicable_ids,
	"control_results": control_results,
	"cell_result_counts": cell_result_counts,
	"results_outside_role": results_outside_role,
	"violations": violations,
	"violation_count": count(violations),
}
