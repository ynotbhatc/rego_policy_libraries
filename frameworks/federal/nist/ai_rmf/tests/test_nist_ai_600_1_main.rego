# Tests for nist.ai_600_1.main — NIST AI 600-1 Generative AI Profile, sha256 6e73620ab6b64e90ef2c04bf0e0d6246185a2f4b1b13cab0df494496cff89b6a.
package nist.ai_600_1.main_test

import rego.v1

import data.nist.ai_600_1.main
import data.nist.ai_rmf.main as rmf

_all := {aid: true | some aid, _ in main.actions}

_green := {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": _all}}

_codes := {"GV": "GOVERN", "MP": "MAP", "MS": "MEASURE", "MG": "MANAGE"}

test_counts_match_ai_600_1 if {
	count(main.actions) == 212
	count(main.gai_risks) == 12
	count([a | some a in main.actions; a.function == "GOVERN"]) == 58
	count([a | some a in main.actions; a.function == "MAP"]) == 39
	count([a | some a in main.actions; a.function == "MEASURE"]) == 72
	count([a | some a in main.actions; a.function == "MANAGE"]) == 43
	count({a.subcategory | some a in main.actions}) == 49
}

test_every_parent_is_one_of_the_72_ai_rmf_subcategories if {
	count({aid | some aid, a in main.actions; not rmf.subcategories[a.subcategory]}) == 0
	count({aid | some aid, a in main.actions; rmf.subcategories[a.subcategory].function != a.function}) == 0
}

test_every_id_agrees_with_its_parent if {
	bad := {aid |
		some aid, a in main.actions
		parts := split(aid, "-")
		concat(" ", [_codes[parts[0]], parts[1]]) != a.subcategory
	}
	count(bad) == 0
}

test_every_risk_tag_resolves_to_the_12 if {
	count({aid | some aid, a in main.actions; some t in a.gai_risks; not main.gai_risks[t]}) == 0
	count({aid | some aid, a in main.actions; count(a.gai_risks) == 0}) == 0
	main.other_tags == {"GV-1.4-002": ["Civil Rights violations"]}
}

test_verbatim_rows if {
	main.actions["GV-1.1-001"].text == "Align GAI development and use with applicable laws and regulations, including those related to data privacy, copyright and intellectual property law."
	main.actions["GV-1.1-001"].gai_risks == ["Data Privacy", "Harmful Bias or Homogenization", "Intellectual Property"]
	main.actions["GV-4.3-001"].printed_id == "GV4.3--001"
	main.actions["MG-3.2-004"].gai_risks_as_printed == "Human-AI Configuration, Dangerous, Violent, or Hateful Content"
	not "GV-1.1-002" in object.keys(main.actions)
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.scope == "undeclared"
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.violation_count == 1
}

test_non_boolean_gate_fails_closed if {
	r := main.compliance_report with input as {"nist_ai_600_1": {"scope": {"generative_ai": "yes"}, "actions": _all}}
	r.compliant == false
	r.scope == "undeclared"
	some v in r.violations
	contains(v, "scope flag")
}

test_gate_false_is_not_applicable_and_compliant if {
	r := main.compliance_report with input as {"nist_ai_600_1": {"scope": {"generative_ai": false}}}
	r.compliant == true
	r.scope == "not_applicable"
	r.applicable == false
	r.violation_count == 0
	r.actions_satisfied == 0
}

test_gate_true_without_actions_fails_closed if {
	r := main.compliance_report with input as {"nist_ai_600_1": {"scope": {"generative_ai": true}}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations")
	r.violation_count == 213
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.actions_satisfied == 212
	r.functions.MEASURE.actions_satisfied == 72
	r.gai_risks["Information Integrity"].actions_satisfied == r.gai_risks["Information Integrity"].actions_total
}

test_one_action_false_is_named if {
	r := main.compliance_report with input as {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": object.union(_all, {"MS-2.11-001": false})}}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	startswith(v, "NIST AI 600-1 MS-2.11-001 (MEASURE 2.11): suggested action not attested")
	r.functions.MEASURE.not_satisfied == ["MS-2.11-001"]
	r.subcategories["MEASURE 2.11"].not_satisfied == ["MS-2.11-001"]
	r.gai_risks["Harmful Bias or Homogenization"].not_satisfied == ["MS-2.11-001"]
}

test_unknown_id_is_a_violation if {
	r := main.compliance_report with input as {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": object.union(_all, {"GV4.3--001": true})}}
	r.compliant == false
	some v in r.violations
	contains(v, "unknown suggested action id GV4.3--001")
}

test_risk_rollup_counts if {
	r := main.compliance_report with input as {}
	r.gai_risks["CBRN Information or Capabilities"].actions_total == 31
	r.gai_risks["Harmful Bias or Homogenization"].actions_total == 57
	r.gai_risks_total == 12
}
