# Bad input never passes (issue #301, audit 2026-11-24). Data-driven: the facts each module reads are listed
# in its own _boolean_facts, so a fact added to a module is covered here without editing this file.
package eu_ai_act.bad_input_test

import rego.v1

import data.eu_ai_act.main
import data.eu_ai_act.main_test.clean_minimal as ok

_bad_values := ["true", "false", "no", null, 0, 1]

_modules := {
	"prohibited": data.eu_ai_act.prohibited._boolean_facts,
	"transparency": data.eu_ai_act.transparency._boolean_facts,
	"high_risk": data.eu_ai_act.high_risk._boolean_facts,
	"gpai": data.eu_ai_act.gpai._boolean_facts,
	"governance": data.eu_ai_act.governance._boolean_facts,
}

_violations("prohibited", inp) := vs if vs := data.eu_ai_act.prohibited.violations with input as inp

_violations("transparency", inp) := vs if vs := data.eu_ai_act.transparency.violations with input as inp

_violations("high_risk", inp) := vs if vs := data.eu_ai_act.high_risk.violations with input as inp

_violations("gpai", inp) := vs if vs := data.eu_ai_act.gpai.violations with input as inp

_violations("governance", inp) := vs if vs := data.eu_ai_act.governance.violations with input as inp

# {"eu_ai_act": {<module>: {<path>: value}}}
_single(module, path, value) := json.patch({"eu_ai_act": {module: {}}}, array.concat(
	[{"op": "add", "path": array.concat(["eu_ai_act", module], array.slice(path, 0, i)), "value": {}} |
		some i in numbers.range(1, count(path) - 1)
	],
	[{"op": "add", "path": array.concat(["eu_ai_act", module], path), "value": value}],
))

_invalid_msg(module, path, value) := sprintf("evidence invalid — eu_ai_act.%s.%s is not a boolean (got %s)", [module, concat(".", path), type_name(value)])

test_every_module_lists_its_facts if {
	every _, facts in _modules {
		count(facts) > 20
	}
}

# Every fact of every module, sent with each wrong type, is reported and the module is not compliant.
test_mistyped_fact_is_reported_in_every_module if {
	every module, facts in _modules {
		every path in facts {
			every value in _bad_values {
				vs := _violations(module, _single(module, path, value))
				some v in vs
				endswith(v, _invalid_msg(module, path, value))
			}
		}
	}
}

# A boolean is never reported as mistyped.
test_boolean_fact_is_not_reported_as_invalid if {
	every module, facts in _modules {
		every path in facts {
			every value in [true, false] {
				every v in _violations(module, _single(module, path, value)) {
					not contains(v, "evidence invalid")
				}
			}
		}
	}
}

# ── End to end on the all-pass fixture (minimal-risk system, every Article 5 practice assessed false) ────────
_fixture_paths := {path |
	walk(ok, [path, value])
	is_boolean(value)
}

test_fixture_passes if {
	r := main.compliance_report with input as ok
	r.compliant == true
	count(r.violations) == 0
	count(_fixture_paths) == 10
}

test_empty_input_fails if {
	r := main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_mistyped_fixture_fact_never_passes if {
	every path in _fixture_paths {
		every value in _bad_values {
			r := main.compliance_report with input as json.patch(ok, [{"op": "replace", "path": path, "value": value}])
			r.compliant == false
			r.overall_compliant == false
			some v in r.violations
			contains(v, "evidence invalid")
		}
	}
}

test_removed_fixture_fact_never_passes if {
	every path in _fixture_paths {
		r := main.compliance_report with input as json.patch(ok, [{"op": "remove", "path": path}])
		r.compliant == false
		some v in r.violations
		contains(v, "evidence missing")
	}
}

# The string "false" on a prohibited practice used to read as "practice assessed, not present".
test_string_false_prohibited_flag_names_the_article if {
	inp := json.patch(ok, [{"op": "replace", "path": "/eu_ai_act/prohibited/csam/can_generate_csam", "value": "false"}])
	"Article 5(1)(bb): evidence invalid — eu_ai_act.prohibited.csam.can_generate_csam is not a boolean (got string)" in data.eu_ai_act.prohibited.violations with input as inp
}

# ── High-risk: "does not apply" is an explicit false ────────────────────────────────────────────────────────
_applicability := {
	["data_governance", "processes_personal_data"],
	["record_keeping", "is_biometric_system"],
	["accuracy_robustness", "safety_critical_system"],
	["provider_obligations", "ce_marking_required"],
}

# OPA 1.10.0 (the oldest supported version) cannot type a patch list built from a function argument, so the
# sections are added first and the argument is passed through _any.
_high_risk_sections := json.patch(
	{"eu_ai_act": {"high_risk": {}}},
	[{"op": "add", "path": ["eu_ai_act", "high_risk", section], "value": {}} | some section in {p[0] | some p in _modules.high_risk}],
)

_high_risk_all(value) := json.patch(
	_high_risk_sections,
	[{"op": "add", "path": array.concat(["eu_ai_act", "high_risk"], path), "value": _any(value)} | some path in _modules.high_risk],
)

# The argument's type is unknown to the checker; object.get returns `any`, which json.patch accepts.
_any(value) := object.get({"v": value}, "v", null)

test_high_risk_all_true_is_compliant if {
	data.eu_ai_act.high_risk.compliant with input as _high_risk_all(true)
}

test_high_risk_missing_applicability_fact_fails if {
	every path in _applicability {
		inp := json.patch(_high_risk_all(true), [{"op": "remove", "path": array.concat(["eu_ai_act", "high_risk"], path)}])
		vs := data.eu_ai_act.high_risk.violations with input as inp
		some v in vs
		endswith(v, sprintf("evidence missing — eu_ai_act.high_risk.%s not collected; applicability undetermined", [concat(".", path)]))
	}
}

test_high_risk_explicit_not_applicable_passes if {
	patches := [{"op": "replace", "path": array.concat(["eu_ai_act", "high_risk"], path), "value": false} | some path in _applicability]
	data.eu_ai_act.high_risk.compliant with input as json.patch(_high_risk_all(true), patches)
}

test_high_risk_string_facts_never_pass if {
	every value in ["true", "false"] {
		not data.eu_ai_act.high_risk.compliant with input as _high_risk_all(value)
	}
}
