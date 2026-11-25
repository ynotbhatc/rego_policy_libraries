package sox.main_test

import rego.v1

# Audit 2026-11-24: sox.main read its facts from data.sox, so a caller that posted them as the input document
# (as the playbooks, the portal and every other module in the library do) got 31 of 31 failed with the facts
# present. Facts are now read from input.sox; data.sox is read only when the input has no "sox" key, and the two
# are never merged. Area fixtures (s302, s404, s409, mgmt, itgc_ok, app_ok) are in test_sox_main_gating.rego.

# The all-pass input document: the 31 scored facts, true. The four advisory facts are left out on purpose. They
# are never scored, so a bad value on one leaves the report passing by design, and the bad-input harness
# (scripts/check_bad_input_fails.py), which takes this rule as the module's fixture, would count that as a false
# pass. The advisories are covered by test_advisory_facts_never_score_on_input, on _with_advisories.
all_pass_input := {"sox": {
	"section_302": s302,
	"section_404": object.remove(s404, ["continuous_monitoring"]),
	"section_409": object.remove(s409, ["disclosure_process", "event_detection"]),
	"management": object.remove(mgmt, ["continuous_monitoring"]),
	"itgc": itgc_ok,
	"application_controls": app_ok,
}}

# A function, so the harness (which reads complete rules) does not take the 35-fact document as the fixture.
_with_advisories(doc) := object.union(doc, {"sox": {
	"section_404": {"continuous_monitoring": {"active": true}},
	"section_409": {"disclosure_process": {"automated": true}, "event_detection": {"real_time": true}},
	"management": {"continuous_monitoring": {"implemented": true}},
}})

ceo_only := {"section_302": {"ceo_certification": {"provided": true}}}

ceo_path := "sox.section_302.ceo_certification.provided"

_input_report(inp) := r if {
	r := data.sox.main.compliance_report with input as inp
}

# Every area loaded as data.sox, all true, and `inp` posted as the input.
_report_with_data_loaded(inp) := r if {
	r := data.sox.main.compliance_report with input as inp
		with data.sox.section_302 as s302
		with data.sox.section_404 as s404
		with data.sox.section_409 as s409
		with data.sox.management as mgmt
		with data.sox.itgc as itgc_ok
		with data.sox.application_controls as app_ok
}

_set(path, value) := json.patch(_with_advisories(all_pass_input), [{"op": "replace", "path": concat("/", array.concat([""], path)), "value": value}])

_unset(path) := json.patch(_with_advisories(all_pass_input), [{"op": "remove", "path": concat("/", array.concat([""], path))}])

_boolean_paths := [path | walk(_with_advisories(all_pass_input), [path, value]); is_boolean(value)]

_advisory_paths := {
	["sox", "section_409", "disclosure_process", "automated"],
	["sox", "section_409", "event_detection", "real_time"],
	["sox", "section_404", "continuous_monitoring", "active"],
	["sox", "management", "continuous_monitoring", "implemented"],
}

_scored_paths := [path | some path in _boolean_paths; not path in _advisory_paths]

# Values that are not the boolean true. None of them is evidence that a control is in place.
bad_values := ["false", "true", "no", null, 0, 1, false]

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_scored_paths_3 if {
	sum([count(_slice(_scored_paths, i, 3)) | some i in numbers.range(0, 2)]) == count(_scored_paths)
	every j, x in _scored_paths {
		x in _slice(_scored_paths, j % 3, 3)
	}
}

test_fixture_has_31_scored_facts_and_4_advisory_facts if {
	count(_scored_paths) == 31
	count(_boolean_paths) == 35
}

# ── The defect: the same fact, posted as input, was not read ────────────────

test_ceo_certification_posted_as_input_moves_passed_from_0_to_1 if {
	before := _input_report({})
	before.passed_controls == 0
	before.failed_controls == 31
	before.evidence_source == "none"
	after := _input_report({"sox": ceo_only})
	after.passed_controls == 1
	after.failed_controls == 30
	after.evidence_missing_controls == 30
	after.total_controls == 31
	after.evidence_source == "input"
	after.data_sox_ignored == false
	_adds_up(after)
	not "CEO Certification" in {v.control_name | some v in after.violations}
	every v in after.violations {
		startswith(v.evidence, "input.sox.")
	}
}

test_ceo_certification_loaded_as_data_still_read_when_no_input_sox if {
	r := data.sox.main.compliance_report with data.sox.section_302 as ceo_only.section_302
	r.passed_controls == 1
	r.failed_controls == 30
	r.evidence_source == "data"
	r.data_sox_ignored == false
	_adds_up(r)
	every v in r.violations {
		startswith(v.evidence, "data.sox.")
		startswith(v.detail, "evidence missing: data.sox.")
	}
}

# An input for another framework, with no "sox" key, does not switch the source.
test_input_without_sox_key_falls_back_to_data if {
	r := _report_with_data_loaded({"hosts": []})
	r.evidence_source == "data"
	r.passed_controls == 31
	r.compliant == true
	no_input := _report(all_ok)
	no_input.evidence_source == "data"
	no_input.passed_controls == 31
}

test_all_pass_input_passes_every_check if {
	scored_only := _input_report(all_pass_input)
	scored_only.passed_controls == 31
	scored_only.compliant == true
	every a in scored_only.advisories {
		a.status == "NOT_REPORTED"
	}
	r := _input_report(_with_advisories(all_pass_input))
	r.total_controls == 31
	r.passed_controls == 31
	r.failed_controls == 0
	r.not_applicable_controls == 0
	r.compliant == true
	r.compliance_score == 100
	r.compliance_level == "FULLY_COMPLIANT"
	r.evidence_source == "input"
	count(r.advisories) == 4
	every a in r.advisories {
		a.scored == false
		a.status == "MET"
		startswith(a.evidence, "input.sox.")
	}
	_adds_up(r)
}

# ── Both present: input wins, nothing is merged, and the report says so ─────

test_posted_input_is_never_filled_in_from_loaded_data if {
	r := _report_with_data_loaded({"sox": ceo_only})
	r.evidence_source == "input"
	r.data_sox_ignored == true
	r.passed_controls == 1
	r.failed_controls == 30
	r.compliant == false
	_adds_up(r)
}

test_loaded_data_cannot_override_a_posted_false if {
	r := _report_with_data_loaded(_set(split(ceo_path, "."), false))
	r.evidence_source == "input"
	r.data_sox_ignored == true
	r.failed_controls == 1
	r.compliant == false
	r.violations[0].control_name == "CEO Certification"
	r.violations[0].status == "NON_COMPLIANT"
	r.violations[0].detail == "input.sox.section_302.ceo_certification.provided is false"
}

# input.sox posted as null, a string, a list or an empty object is still a posted input: nothing is read from data.
test_unusable_input_sox_does_not_fall_back_to_data if {
	values := [null, "true", [], {}, 1, true]
	held := [value |
		some value in values
		r := _report_with_data_loaded({"sox": value})
		r.evidence_source == "input"
		r.data_sox_ignored == true
		r.passed_controls == 0
		r.failed_controls == 31
		r.evidence_missing_controls == 31
		r.compliant == false
		_adds_up(r)
	]
	count(held) == count(values)
}

test_data_sox_ignored_is_false_without_loaded_data if {
	_input_report(all_pass_input).data_sox_ignored == false
	_input_report({}).data_sox_ignored == false
}

# ── The evidence rule on the input document ─────────────────────────────────

test_no_scored_fact_passes_on_a_value_that_is_not_true_slice_0 if {
	failures := [[path, value] |
		some path in _slice(_scored_paths, 0, 3)
		some value in bad_values
		r := _input_report(_set(path, value))
		not _one_check_fails(r)
	]
	count(failures) == 0
}

test_no_scored_fact_passes_on_a_value_that_is_not_true_slice_1 if {
	failures := [[path, value] |
		some path in _slice(_scored_paths, 1, 3)
		some value in bad_values
		r := _input_report(_set(path, value))
		not _one_check_fails(r)
	]
	count(failures) == 0
}

test_no_scored_fact_passes_on_a_value_that_is_not_true_slice_2 if {
	failures := [[path, value] |
		some path in _slice(_scored_paths, 2, 3)
		some value in bad_values
		r := _input_report(_set(path, value))
		not _one_check_fails(r)
	]
	count(failures) == 0
}

test_no_scored_fact_passes_when_removed if {
	failures := [path |
		some path in _scored_paths
		r := _input_report(_unset(path))
		not _one_check_fails(r)
	]
	count(failures) == 0
	every path in _scored_paths {
		r := _input_report(_unset(path))
		r.evidence_missing_controls == 1
		r.violations[0].detail == sprintf("evidence missing: input.%s not collected", [concat(".", path)])
	}
}

_one_check_fails(r) if {
	r.compliant == false
	r.failed_controls == 1
	r.passed_controls == 30
	r.compliance_score < 100
	r.compliance_level != "FULLY_COMPLIANT"
	_adds_up(r)
}

test_finding_names_the_evidence_problem if {
	path := split(ceo_path, ".")
	_input_report(_set(path, "true")).violations[0].detail == "input.sox.section_302.ceo_certification.provided is not a boolean (got string)"
	_input_report(_set(path, 1)).violations[0].detail == "input.sox.section_302.ceo_certification.provided is not a boolean (got number)"
	_input_report(_set(path, null)).violations[0].detail == "evidence missing: input.sox.section_302.ceo_certification.provided not collected"
	_input_report(_set(path, "true")).violations[0].status == "EVIDENCE_MISSING"
	_input_report(_set(path, false)).violations[0].status == "NON_COMPLIANT"
}

# A whole area posted as null or a string reads as empty: its checks are missing evidence, the rest still pass.
test_null_area_fails_only_that_area if {
	values := [null, "true"]
	held := [value |
		some value in values
		r := _input_report(_set(["sox", "section_302"], value))
		r.failed_controls == 6
		r.evidence_missing_controls == 6
		r.passed_controls == 25
		r.compliant == false
		_adds_up(r)
	]
	count(held) == count(values)
}

# The four advisories are reported and never scored, whatever is posted for them.
test_advisory_facts_never_score_on_input if {
	changed := [[path, value] |
		some path in _advisory_paths
		some value in bad_values
		r := _input_report(_set(path, value))
		r.total_controls == 31
		r.passed_controls == 31
		r.compliant == true
		count(r.advisories) == 4
		count([a | some a in r.advisories; a.status != "MET"]) == 1
	]
	count(changed) == count(_advisory_paths) * count(bad_values)
}

# The Section 404(b) exemption is an explicit statement in the input; it is never inferred.
test_exemption_read_from_input if {
	exempt := json.patch(all_pass_input, [{"op": "replace", "path": "/sox/section_404/external_auditor_attestation", "value": {"required": false, "exemption": "non_accelerated_filer"}}])
	r := _input_report(exempt)
	r.not_applicable_controls == 1
	r.passed_controls == 30
	r.failed_controls == 0
	r.compliant == true
	_adds_up(r)
	stringy := json.patch(all_pass_input, [{"op": "replace", "path": "/sox/section_404/external_auditor_attestation", "value": {"required": "false", "exemption": "non_accelerated_filer"}}])
	s := _input_report(stringy)
	s.not_applicable_controls == 0
	s.failed_controls == 1
	s.compliant == false
}

# An exemption loaded as data does not exempt an issuer whose posted input lacks it.
test_exemption_in_loaded_data_does_not_apply_to_posted_input if {
	posted := _unset(["sox", "section_404", "external_auditor_attestation"])
	r := data.sox.main.compliance_report with input as posted
		with data.sox.section_404 as {"external_auditor_attestation": {"required": false, "exemption": "emerging_growth_company"}}
	r.not_applicable_controls == 0
	r.failed_controls == 1
	r.data_sox_ignored == true
	r.violations[0].control_name == "Auditor Attestation"
}
