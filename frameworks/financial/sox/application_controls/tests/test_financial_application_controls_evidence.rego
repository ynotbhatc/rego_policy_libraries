package sox.application_controls_evidence_test

import rego.v1

# Audit 2026-11-24: sox.application_controls read its facts from data.sox. Facts are now read from input.sox; data.sox is read only
# when the input has no "sox" key, and the two are never merged. The evidence rule is tested over every fact the
# module names: only the boolean true passes.

_paths := {path | some paths in data.sox.application_controls._facts; some path in paths}

_leaf([a, b, c]) := {a: {b: {c: true}}}

_leaf([a, b, c, d]) := {a: {b: {c: {d: true}}}}

# The all-pass input document: every fact the module names, true.
all_pass_input := {"sox": object.union_n([_leaf(split(path, ".")) | some path in _paths])}

_pointer(path) := concat("/", array.concat(["", "sox"], split(path, ".")))

_set(path, value) := json.patch(all_pass_input, [{"op": "replace", "path": _pointer(path), "value": value}])

_unset(path) := json.patch(all_pass_input, [{"op": "remove", "path": _pointer(path)}])

_fails(inp) if {
	not data.sox.application_controls.application_controls_compliant with input as inp
	c := data.sox.application_controls.control_counts with input as inp
	c.failed_controls >= 1
	c.passed_controls + c.failed_controls == c.total_controls
	c.total_controls == 35
}

_problems(inp) := p if {
	p := data.sox.application_controls.evidence_problems with input as inp
}

test_module_names_133_facts if {
	count(_paths) == 133
}

test_no_input_and_empty_input_fail_every_check if {
	c := data.sox.application_controls.control_counts
	c.failed_controls == 35
	c.evidence_source == "none"
	e := data.sox.application_controls.control_counts with input as {}
	e.failed_controls == 35
	e.passed_controls == 0
	e.evidence_source == "none"
	count(_problems({})) == 133
	every problem in _problems({}) {
		startswith(problem, "evidence missing: input.sox.")
		endswith(problem, " not collected")
	}
}

test_all_pass_input_passes_every_check if {
	data.sox.application_controls.application_controls_compliant with input as all_pass_input
	c := data.sox.application_controls.control_counts with input as all_pass_input
	c.total_controls == 35
	c.passed_controls == 35
	c.failed_controls == 0
	c.evidence_source == "input"
	c.data_sox_ignored == false
	_problems(all_pass_input) == []
}

test_no_fact_passes_on_a_value_that_is_not_true if {
	failures := [[path, value] |
		some path in _paths
		some value in ["false", "true", "no", null, 0, 1, false]
		not _fails(_set(path, value))
	]
	count(failures) == 0
}

test_no_fact_passes_when_removed if {
	failures := [path |
		some path in _paths
		not _fails(_unset(path))
	]
	count(failures) == 0
}

test_every_bad_fact_is_named if {
	every path in _paths {
		_problems(_set(path, "true")) == [sprintf("input.sox.%s is not a boolean (got string)", [path])]
		_problems(_set(path, 1)) == [sprintf("input.sox.%s is not a boolean (got number)", [path])]
		_problems(_set(path, null)) == [sprintf("evidence missing: input.sox.%s not collected", [path])]
		_problems(_unset(path)) == [sprintf("evidence missing: input.sox.%s not collected", [path])]

		# a boolean false is evidence: the check fails with its own message and no evidence problem
		_problems(_set(path, false)) == []
	}
}

test_unusable_input_sox_fails_every_check if {
	values := [null, "true", [], {}]
	held := [value |
		some value in values
		c := data.sox.application_controls.control_counts with input as {"sox": value}
		c.failed_controls == 35
		c.evidence_source == "input"
	]
	count(held) == count(values)
}

# ── data.sox: read only when the input has no "sox" key, never merged ──────

_area := object.get(all_pass_input.sox, split("input_validation", "."), null)

test_loaded_data_is_read_when_no_input_sox if {
	c := data.sox.application_controls.control_counts with data.sox.input_validation as _area
	c.evidence_source == "data"
	c.passed_controls == 1
	p := data.sox.application_controls.evidence_problems with data.sox.input_validation as _area
	count(p) == 133 - count([path | some path in _paths; startswith(path, "input_validation.")])
	every problem in p {
		startswith(problem, "evidence missing: data.sox.")
	}
	other := data.sox.application_controls.control_counts with data.sox.input_validation as _area with input as {"hosts": []}
	other.evidence_source == "data"
	other.passed_controls == 1
}

test_posted_input_is_never_filled_in_from_loaded_data if {
	posted := _unset("input_validation.range_validation.implemented")
	not data.sox.application_controls.application_controls_compliant with input as posted with data.sox.input_validation as _area
	c := data.sox.application_controls.control_counts with input as posted with data.sox.input_validation as _area
	c.evidence_source == "input"
	c.data_sox_ignored == true
	c.failed_controls >= 1
	p := data.sox.application_controls.evidence_problems with input as posted with data.sox.input_validation as _area
	p == ["evidence missing: input.sox.input_validation.range_validation.implemented not collected"]
	empty := data.sox.application_controls.control_counts with input as {"sox": null} with data.sox.input_validation as _area
	empty.evidence_source == "input"
	empty.passed_controls == 0
}
