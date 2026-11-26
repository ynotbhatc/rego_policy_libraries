# METADATA
# title: "OWASP ASVS 5.0.0 — verification results for the requirements of the declared level, one result per requirement"
# custom:
#   class: governance
#   framework: owasp_asvs
#   source: owasp
#   domains: [secure-development]
package owasp_asvs.main

import data.owasp_asvs.index
import rego.v1

# =============================================================================
# OWASP Application Security Verification Standard (ASVS) 5.0.0
#
# Entry point: data.owasp_asvs.main.compliance_report (framework key `owasp_asvs`).
# Place in the library: governance/, next to owasp_top10 and owasp_llm (the other OWASP application-security modules).
#
# FACTS CHECKED AGAINST THE PUBLISHER, fetched 2026-11-26 (UTC):
#   - Release: ASVS 5.0.0, GitHub release tag v5.0.0_release (commit 5cf9b032440b), published 2025-05-30,
#     https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release. It is the latest stable release (the repository's moving
#     "latest" release is a rebuild of master; its 5.0.0 JSON file has the identical sha256 on 2026-11-26).
#   - Machine-readable file used: OWASP_Application_Security_Verification_Standard_5.0.0_en.json from that release,
#     sha256 bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35 (the .csv and .flat.json assets carry the
#     same 345 ids, checked). Structure: 17 chapters (V1 to V17), 80 sections, 345 requirements.
#   - Requirement id: <chapter>.<section>.<requirement>, written V1.2.5 in the machine-readable files (the standard's
#     "What is the ASVS" chapter also gives the version-qualified form v5.0.0-1.2.5, preferred in reports). This module's
#     input and findings use the machine-readable form V<chapter>.<section>.<requirement>; the version is in the report.
#   - Levels: L1, L2, L3. Each requirement carries the lowest level that includes it: 70 are L1, 183 are L2, 92 are L3.
#     The levels are cumulative ("an application needs to implement around 70% of the requirements in the ASVS (all of the L1
#     and L2 requirements) in order to comply with L2"), so Level 1 assesses 70, Level 2 assesses 253 and Level 3 assesses 345.
#   - Licence: CC BY-SA 4.0, "Copyright (c) 2008-2025 The OWASP Foundation". The licence text was read from the repository's
#     LICENSE.md (SPDX CC-BY-SA-4.0).
# UNVERIFIED: whether OWASP regards a table of requirement ids, sections and levels as adapted material under the
# ShareAlike clause (this module copies none of the requirement text; see NOTICE and the pull request).
#
# NOT APPROVED BY OWASP. This module is an independent work, not issued or endorsed by the OWASP Foundation, and not an
# ASVS certification or verification report. Attribution: OWASP Application Security Verification Standard 5.0.0,
# (c) The OWASP Foundation, CC BY-SA 4.0, https://owasp.org/www-project-application-security-verification-standard/.
# Only requirement ids, chapter and section numbers and levels (generated into owasp_asvs_index.rego by
# scripts/gen_owasp_asvs_index.py) and this library's own short chapter labels are used. No requirement text is carried.
#
# WHAT IS CHECKED. An ASVS requirement is verified by review or testing; this module cannot run that verification. It takes
# the verifier's result for each requirement as an attestation and applies the library's evidence rule: only the boolean
# true passes; false is a failed requirement; a missing, null or non-boolean result is a finding naming the id.
#
# Input contract (everything under input.owasp_asvs):
#   level                     the ASVS level the application is verified against: the JSON number 1, 2 or 3. Required. A
#                             missing or other value is a finding and Level 3, the widest scope, is assessed, so a bad
#                             declaration never narrows the scope.
#   requirements              object: requirement id -> boolean verification result, e.g. {"V1.2.3": true, "V6.1.1": false}.
#                             Only requirements of the selected level are assessed. A result for a known id above the
#                             selected level is ignored (and counted in results_above_level); an id the standard does not
#                             have is a finding.
#   not_applicable            object: requirement id -> reason (a non-empty string). Marks a requirement the verifier
#                             judged not to apply to this application, e.g. {"V17.1.1": "no WebRTC components"}. Counted in
#                             not_applicable_controls. Only for a requirement of the selected level: a marker for an id above
#                             it, an unknown id, a blank or non-string reason, or an id that also has a result is a finding.
#                             Absence of a result is never read as "does not apply".
#
# Report contract: total_controls is the number of requirements at the selected level (70, 253 or 345), a fixed property
# of the standard. passed_controls + failed_controls + not_applicable_controls == total_controls; failed_controls counts
# every requirement that is neither passed nor marked not applicable, however many findings it has. control_results lists
# every requirement in scope in the standard's order with status pass | fail | evidence_missing | evidence_invalid |
# not_applicable. chapter_results summarises per chapter. compliant means: a valid level, no finding, and at least one
# requirement passed.
#
# OPA endpoint: POST http://<host>:8182/v1/data/owasp_asvs/main/compliance_report

requirements_total := 345 # requirements of ASVS 5.0.0 (all levels); the tests check the index against it. Not named standard_total on

# purpose: the coverage stamp would read it as a declared check count, and the checks here are table-driven (no literal rule per id).

# ── Input, read defensively ──────────────────────────────────────────────────

_raw := object.get(input, "owasp_asvs", null)

_in := _raw if is_object(_raw)

else := {}

_raw_results := object.get(_in, "requirements", null)

_results := _raw_results if is_object(_raw_results)

else := {}

_raw_na := object.get(_in, "not_applicable", null)

_na := _raw_na if is_object(_raw_na)

else := {}

# ── Level ────────────────────────────────────────────────────────────────────

level_declared if _in.level in {1, 2, 3}

default assessed_level := 3

assessed_level := _in.level if level_declared

# ── Scope ────────────────────────────────────────────────────────────────────

# Comprehensions below bind the sets they test membership in before the loop: on the oldest supported OPA a rule that
# is referenced inside a loop is evaluated again for every element.
# The level of every requirement of the standard: id -> 1, 2 or 3 (the lowest level that includes it).
_level_of := {id: to_number(n) | some n, ids in index.levels; some id in ids}

in_scope := {id | lvl := assessed_level; levels := _level_of; some id, l in levels; l <= lvl}

# ── Per-requirement status ───────────────────────────────────────────────────

_has_result(id) if _ = _results[id]

_has_na(id) if _ = _na[id]

# The requirements of the scope, sorted into disjoint classes with set operations (a per-requirement function over 345
# requirements is slow on the oldest supported OPA). A marker with a usable reason and no result is "not applicable"; a
# marker that is unusable, or that sits beside a result, is invalid; without a marker, true passes, false fails, a missing
# or null result is evidence missing and any other value is invalid.
_present := {id | some id, _ in _results}

_marked := {id | some id, _ in _na}

_marked_ok := {id | some id, reason in _na; is_string(reason); trim_space(reason) != ""}

_true_ids := {id | some id, v in _results; v == true}

_false_ids := {id | some id, v in _results; v == false}

_null_ids := {id | some id, v in _results; v == null}

_not_applicable := (_marked_ok & in_scope) - _present

_passed := (_true_ids & in_scope) - _marked

_failed := (_false_ids & in_scope) - _marked

_missing := ((in_scope - _present) - _marked) | ((_null_ids & in_scope) - _marked)

_invalid := (((in_scope - _not_applicable) - _passed) - _failed) - _missing

_status_of := object.union_n([
	{id: "pass" | some id in _passed},
	{id: "fail" | some id in _failed},
	{id: "evidence_missing" | some id in _missing},
	{id: "evidence_invalid" | some id in _invalid},
	{id: "not_applicable" | some id in _not_applicable},
])

_detail(_, "fail") := "verification result is false: the requirement is not met"

_detail(id, "evidence_missing") := sprintf("evidence missing: input.owasp_asvs.requirements[%q] not collected", [id]) if not _has_result(id)

_detail(id, "evidence_missing") := sprintf("evidence missing: input.owasp_asvs.requirements[%q] is null", [id]) if _has_result(id)

_detail(id, "evidence_invalid") := sprintf("input.owasp_asvs.requirements[%q] is not a boolean (got %v)", [id, type_name(_results[id])]) if {
	not _has_na(id)
	_has_result(id)
}

_detail(id, "evidence_invalid") := sprintf("input.owasp_asvs.not_applicable[%q] needs a non-empty string reason (got %v)", [id, type_name(_na[id])]) if {
	_has_na(id)
	not _has_result(id)
}

_detail(id, "evidence_invalid") := sprintf("input.owasp_asvs.not_applicable[%q] conflicts with input.owasp_asvs.requirements[%q]: a requirement has a result or is not applicable, not both", [id, id]) if {
	_has_na(id)
	_has_result(id)
}

_finding(id, st, lv) := sprintf("OWASP ASVS %v: %v (a Level %v requirement)", [id, _detail(id, st), lv])

_control_messages := {_finding(id, st, lv) |
	levels := _level_of
	some id, st in _status_of
	st != "pass"
	st != "not_applicable"
	lv := levels[id]
}

# ── Input problems that are not requirements but still block a compliant result ──

_input_notes contains "OWASP ASVS input: input.owasp_asvs.level is missing or is not the number 1, 2 or 3; Level 3 (all 345 requirements) is assessed" if {
	not level_declared
}

_input_notes contains "OWASP ASVS input: input.owasp_asvs is missing or not an object; no verification result was supplied" if {
	not is_object(_raw)
}

_input_notes contains "OWASP ASVS input: input.owasp_asvs.requirements is missing or not an object" if {
	is_object(_raw)
	not is_object(_raw_results)
}

_input_notes contains "OWASP ASVS input: input.owasp_asvs.not_applicable is not an object (requirement id -> reason)" if {
	_raw_na != null
	not is_object(_raw_na)
}

_input_notes contains sprintf("OWASP ASVS input: requirements[%q] is not a requirement id of ASVS 5.0.0", [id]) if {
	levels := _level_of
	some id, _ in _results
	not levels[id]
}

_input_notes contains sprintf("OWASP ASVS input: not_applicable[%q] is not a requirement id of ASVS 5.0.0", [id]) if {
	levels := _level_of
	some id, _ in _na
	not levels[id]
}

_input_notes contains sprintf("OWASP ASVS input: not_applicable[%q] is a Level %v requirement and is outside the Level %v scope; a requirement outside the scope cannot be marked not applicable", [id, lv, assessed_level]) if {
	scope := in_scope
	levels := _level_of
	some id, _ in _na
	lv := levels[id]
	not id in scope
}

violations := _control_messages | _input_notes

# ── Report ───────────────────────────────────────────────────────────────────

control_results := [{
	"id": id,
	"chapter": parts[0],
	"section": concat(".", [parts[0], parts[1]]),
	"level": lv,
	"status": st,
	"findings": [_finding(id, st, lv) | st != "pass"; st != "not_applicable"],
} |
	status_of := _status_of
	levels := _level_of
	some id in index.order
	st := status_of[id]
	lv := levels[id]
	parts := split(id, ".")
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

chapter_results[ch] := {
	"label": index.chapters[ch],
	"total": count(ids),
	"passed": count(ids & passed),
	"not_applicable": count(ids & na),
	"failed": (count(ids) - count(ids & passed)) - count(ids & na),
} if {
	scope := in_scope
	passed := _passed
	na := _not_applicable
	some ch, members in index.by_chapter
	ids := {id | some id in members; id in scope}
}

results_above_level := sort([id | scope := in_scope; levels := _level_of; some id, _ in _results; levels[id]; not id in scope])

default compliant := false

compliant if {
	level_declared
	count(violations) == 0
	count(passed_ids) > 0
}

compliance_report := {
	"framework": "OWASP Application Security Verification Standard (ASVS) 5.0.0",
	"framework_key": "owasp_asvs",
	"standard_version": "5.0.0",
	"release_tag": "v5.0.0_release",
	"approval": "Not approved by OWASP: an independent check set over the verifier's results, not an ASVS verification report",
	"attribution": "OWASP Application Security Verification Standard 5.0.0, (c) The OWASP Foundation, CC BY-SA 4.0; ids, chapter and section numbers and levels only, no requirement text",
	"requirements_total": requirements_total,
	"declared_level": object.get(_in, "level", null),
	"assessed_level": assessed_level,
	"compliant": compliant,
	"total_controls": count(in_scope),
	"passed_controls": count(passed_ids),
	"failed_controls": count(failed_control_ids),
	"not_applicable_controls": count(not_applicable_ids),
	"failed_control_ids": failed_control_ids,
	"not_applicable_ids": not_applicable_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"chapter_results": chapter_results,
	"results_above_level": results_above_level,
	"violations": violations,
	"violation_count": count(violations),
}
