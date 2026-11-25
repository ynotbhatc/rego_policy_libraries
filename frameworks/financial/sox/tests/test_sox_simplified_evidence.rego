package sox.simplified_test

import rego.v1

# Audit 2026-11-24: the evidence rule on sox.simplified, data-driven over the all-pass fixture `full`
# (test_sox_simplified_missing_fields.rego). The module reads input.sox only.

_bool_paths := [path | walk(full, [path, value]); is_boolean(value)]

_adv_paths := {
	["sox", "section_409", "disclosure_process", "automated"],
	["sox", "section_409", "event_detection", "real_time"],
	["sox", "section_404", "continuous_monitoring", "active"],
}

_scored := [path | some path in _bool_paths; not path in _adv_paths]

_patched(path, value) := json.patch(full, [{"op": "replace", "path": concat("/", array.concat([""], path)), "value": value}])

_removed(path) := json.patch(full, [{"op": "remove", "path": concat("/", array.concat([""], path))}])

_one_fails(a) if {
	a.compliance_status == false
	a.failed_controls == 1
	a.passed_controls == 19
	a.compliance_level != "FULLY_COMPLIANT"
	_adds_up(a)
}

test_fixture_has_20_scored_facts if {
	count(_scored) == 20
	a := _assessment(full)
	a.passed_controls == 20
	a.compliance_status == true
	a.evidence_source == "input"
}

test_no_scored_fact_passes_on_a_value_that_is_not_true if {
	failures := [[path, value] |
		some path in _scored
		some value in ["false", "true", "no", null, 0, 1, false]
		not _one_fails(_assessment(_patched(path, value)))
	]
	count(failures) == 0
}

test_no_scored_fact_passes_when_removed if {
	failures := [path |
		some path in _scored
		not _one_fails(_assessment(_removed(path)))
	]
	count(failures) == 0
}

test_finding_names_the_evidence_problem if {
	path := ["sox", "itgc", "backup_recovery", "tested"]
	f := data.sox.simplified.itgc_findings with input as _patched(path, "true")
	f[0].detail == "input.sox.itgc.backup_recovery.tested is not a boolean (got string)"
	g := data.sox.simplified.itgc_findings with input as _removed(path)
	g[0].detail == "evidence missing: input.sox.itgc.backup_recovery.tested not collected"
	h := data.sox.simplified.itgc_findings with input as _patched(path, false)
	h[0].detail == "input.sox.itgc.backup_recovery.tested is false"
}

# Before: with no input document at all the check list was undefined and sox_compliant was true.
test_no_input_document_is_not_compliant if {
	not data.sox.simplified.sox_compliant
	a := data.sox.simplified.overall_sox_assessment
	a.failed_controls == 20
	a.evidence_source == "none"
}

test_unusable_input_sox_fails_every_check if {
	values := [null, "true", [], {}]
	held := [value |
		some value in values
		a := _assessment({"sox": value})
		a.failed_controls == 20
		a.evidence_missing_controls == 20
		a.compliance_status == false
	]
	count(held) == count(values)
}

# This module never reads data.sox.
test_loaded_data_is_never_read if {
	a := data.sox.simplified.overall_sox_assessment with data.sox.section_302 as full.sox.section_302
		with data.sox.section_404 as full.sox.section_404
		with data.sox.section_409 as full.sox.section_409
	a.passed_controls == 0
	a.evidence_source == "none"
}
