# Tests for nist.sp800_172.main — NIST SP 800-172 Rev 3 + SP 800-172A Rev 3 determinations.
package nist.sp800_172.main_test

import rego.v1

import data.nist.sp800_172.main

_stmts := {id: true | some id, _ in main.statements}

_dets := {id: true | some id, _ in main.determination_text}

_full := {"nist_sp_800_172": {"requirements": _stmts, "determinations": _dets}}

test_table_matches_cprt_export_counts if {
	count(main.statements) == 137
	main.compliance_report.total_controls == count(main.statements)
	count(main.determination_text) == 199
	count(main.families) == 17
	count(main.titles) == 103
	count(main.withdrawn) == 12
	main.export_counts.enhanced_security_requirement_statements == 174
	main.export_counts.active_statements == 162
	(main.export_counts.parent_statements_without_text + main.export_counts.lead_in_statements) + main.export_counts.leaf_statements == 162
}

test_every_determination_belongs_to_exactly_one_statement if {
	owners := [d | some _, s in main.statements; some d in s.determinations]
	count(owners) == 199
	{d | some d in owners} == {d | some d, _ in main.determination_text}
}

test_every_statement_has_determinations_text_family_and_requirement if {
	count({id | some id, s in main.statements; count(s.determinations) == 0}) == 0
	count({id | some id, s in main.statements; s.text == ""}) == 0
	count({id | some id, s in main.statements; not main.families[s.family]}) == 0
	count({id | some id, s in main.statements; not main.titles[s.requirement]}) == 0
	count({id | some id, s in main.statements; not startswith(id, concat("", ["ES-", s.requirement]))}) == 0
}

test_withdrawn_are_not_controls if {
	count({w | some w, _ in main.withdrawn; main.titles[w]}) == 0
	not "ES-03.01.03E" in object.keys(main.statements)
}

test_methods_carried_as_data if {
	count(main.assessment_methods) == 103
	count({r | some r, m in main.assessment_methods; m.examine; m.interview}) == 103
	count({r | some r, m in main.assessment_methods; m.test}) == 98
}

test_lead_in_carried_on_children if {
	main.statements["ES-03.02.01E-a-1"].lead_in == "Provide security literacy training to system users:"
	main.statements["ES-03.02.01E-a-1"].parent == "ES-03.02.01E-a"
	main.statements["ES-03.01.05E"].determinations == ["DS-A.03.01.05E[01]", "DS-A.03.01.05E[02]"]
}

test_empty_input_fails_closed_with_explicit_violation if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED - facts 'input.nist_sp_800_172' were not supplied")

	# FAIL-CLOSED + one per statement (not one per determination)
	r.violation_count == 138
	r.statements_satisfied == 0
	r.determinations_satisfied == 0
}

test_all_true_is_compliant if {
	main.compliant with input as _full
	r := main.compliance_report with input as _full
	r.compliant == true
	r.violation_count == 0
	r.statements_satisfied == 137
	r.determinations_satisfied == 199
	r.requirements_satisfied == 103
	r.families["3.14"].requirements == 15
	r.families["3.14"].requirements_withdrawn == 4
}

test_statements_without_determinations_are_not_satisfied if {
	inp := {"nist_sp_800_172": {"requirements": _stmts, "determinations": {}}}
	r := main.compliance_report with input as inp
	r.statements_attested == 137
	r.requirements_attested == 103
	r.statements_satisfied == 0
	r.requirements_satisfied == 0
	r.violation_count == 137
}

test_one_false_statement_is_named_in_report if {
	inp := {"nist_sp_800_172": {"requirements": object.union(_stmts, {"ES-03.01.08E-b": false}), "determinations": _dets}}
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.families["3.1"].gaps == ["ES-03.01.08E-b"]
	r.families["3.1"].statements_attested == r.families["3.1"].statements - 1
	r.families["3.1"].determinations_satisfied == r.families["3.1"].determinations
	r.requirements_satisfied == 102
	some m in r.violations
	startswith(m, "NIST SP 800-172 Rev 3 ES-03.01.08E-b (03.01.08E Account Monitoring for Atypical Usage, 3.1 Access Control):")
	endswith(m, "— statement not attested")
}

test_one_false_determination_is_one_violation_naming_both if {
	inp := {"nist_sp_800_172": {"requirements": _stmts, "determinations": object.union(_dets, {"DS-A.03.01.05E[02]": false})}}
	r := main.compliance_report with input as inp
	r.violation_count == 1
	r.statements_attested == 137
	r.statements_satisfied == 136
	r.determinations_satisfied == 198
	r.families["3.1"].gaps == ["ES-03.01.05E"]
	some m in r.violations
	contains(m, "ES-03.01.05E (03.01.05E")
	endswith(m, "SP 800-172A determinations not satisfied: DS-A.03.01.05E[02]")
}

test_unknown_withdrawn_and_parent_ids_flagged if {
	extra := {"ES-03.99.01E": true, "ES-03.01.03E": true, "ES-03.01.08E": true}
	inp := {"nist_sp_800_172": {"requirements": object.union(_stmts, extra), "determinations": object.union(_dets, {"A.03.01.05E[01]": true})}}
	v := main.violations with input as inp
	count(v) == 4
	some m1 in v
	contains(m1, "unknown statement id ES-03.99.01E")
	some m2 in v
	contains(m2, "withdrawn requirement ES-03.01.03E")
	some m3 in v
	contains(m3, "ES-03.01.08E is a parent or lead-in statement — attest its leaf statements (ES-03.01.08E-a, ES-03.01.08E-b)")
	some m4 in v
	contains(m4, "unknown determination id A.03.01.05E[01]")
}

test_string_true_rejected if {
	inp := {"nist_sp_800_172": {"requirements": object.union(_stmts, {"ES-03.01.01E": "true"}), "determinations": _dets}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "NIST SP 800-172 Rev 3 ES-03.01.01E ")
}

test_malformed_containers if {
	v := main.violations with input as {"nist_sp_800_172": {"requirements": [], "determinations": "all"}}
	count({m | some m in v; contains(m, "must be an object")}) == 2
	count(v) == 139
}
