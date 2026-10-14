# Tests for nist.sp800_171a_r2.main — NIST SP 800-171A (June 2018) objectives, PDF sha256 21bf3acc43f4284f723639b82eb71e3ce597fa3610f7e9dcf5e8484e22bc0f71.
package nist.sp800_171a_r2.main_test

import rego.v1

import data.nist.sp800_171a_r2.main

_all := {id: true | some id, _ in main.determinations}

_green := {"nist_sp_800_171a_r2": {"determinations": _all}}

# the 110 requirement ids of frameworks/federal/nist/sp_800_171_r2/nist_800_171_r2_main.rego (CPRT SP_800_171_2_0_0)
_rev2_ids := {"3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.9", "3.1.10", "3.1.11", "3.1.12", "3.1.13", "3.1.14", "3.1.15", "3.1.16", "3.1.17", "3.1.18", "3.1.19", "3.1.20", "3.1.21", "3.1.22", "3.2.1", "3.2.2", "3.2.3", "3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3.7", "3.3.8", "3.3.9", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.7", "3.4.8", "3.4.9", "3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6", "3.5.7", "3.5.8", "3.5.9", "3.5.10", "3.5.11", "3.6.1", "3.6.2", "3.6.3", "3.7.1", "3.7.2", "3.7.3", "3.7.4", "3.7.5", "3.7.6", "3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5", "3.8.6", "3.8.7", "3.8.8", "3.8.9", "3.9.1", "3.9.2", "3.10.1", "3.10.2", "3.10.3", "3.10.4", "3.10.5", "3.10.6", "3.11.1", "3.11.2", "3.11.3", "3.12.1", "3.12.2", "3.12.3", "3.12.4", "3.13.1", "3.13.2", "3.13.3", "3.13.4", "3.13.5", "3.13.6", "3.13.7", "3.13.8", "3.13.9", "3.13.10", "3.13.11", "3.13.12", "3.13.13", "3.13.14", "3.13.15", "3.13.16", "3.14.1", "3.14.2", "3.14.3", "3.14.4", "3.14.5", "3.14.6", "3.14.7"}

# measured in the PDF; the document itself states no total
test_table_counts_pinned if {
	count(main.objectives) == 320
	count(main.determinations) == 320
	count([o | some o in main.objectives; o.labelled]) == 297
	count([o | some o in main.objectives; not o.labelled]) == 23
	count(main.requirements) == 110
	count(main.families) == 14
	count([r | some r, q in main.requirements; count(q.methods.examine) == 1; count(q.methods.interview) == 1; count(q.methods.test) == 1]) == 110
}

test_per_family_objective_counts if {
	r := main.compliance_report with input as {}
	r.families["3.1"].determinations_total == 70
	r.families["3.2"].determinations_total == 9
	r.families["3.3"].determinations_total == 29
	r.families["3.4"].determinations_total == 44
	r.families["3.5"].determinations_total == 25
	r.families["3.6"].determinations_total == 14
	r.families["3.7"].determinations_total == 10
	r.families["3.8"].determinations_total == 15
	r.families["3.9"].determinations_total == 4
	r.families["3.10"].determinations_total == 16
	r.families["3.11"].determinations_total == 9
	r.families["3.12"].determinations_total == 14
	r.families["3.13"].determinations_total == 41
	r.families["3.14"].determinations_total == 20
}

test_parent_ids_are_the_rev2_requirements if {
	count(_rev2_ids) == 110
	{r | some r, _ in main.requirements} == _rev2_ids
	count({id | some id, d in main.determinations; not d.requirement in _rev2_ids}) == 0
}

test_ids_spell_their_parent if {
	count({id | some id, d in main.determinations; d.labelled; not startswith(id, concat("", [d.requirement, "["]))}) == 0
	count({id | some id, d in main.determinations; not d.labelled; id != d.requirement}) == 0
	count({f | some _, q in main.requirements; f := q.family; not main.families[f]}) == 0
}

test_every_requirement_has_objectives if {
	count({r | some r, _ in main.requirements; count(main._by_requirement[r]) == 0}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.requirements_satisfied == 0
	r.violation_count == 321
}

test_non_object_determinations_fail_closed if {
	r := main.compliance_report with input as {"nist_sp_800_171a_r2": {"determinations": true}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.determinations_satisfied == 320
	r.requirements_satisfied == 110
}

test_one_objective_per_family_resolves if {
	r := main.compliance_report with input as _green
	main.determinations["3.1.1[a]"].requirement == "3.1.1"
	main.determinations["3.1.1[a]"].text == "authorized users are identified."
	r.families["3.1"].requirements_satisfied == r.families["3.1"].requirements_total
	main.determinations["3.2.1[a]"].requirement == "3.2.1"
	main.determinations["3.2.1[a]"].text == "security risks associated with organizational activities involving CUI are identified."
	r.families["3.2"].requirements_satisfied == r.families["3.2"].requirements_total
	main.determinations["3.3.1[a]"].requirement == "3.3.1"
	main.determinations["3.3.1[a]"].text == "audit logs needed (i.e., event types to be logged) to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity are specified."
	r.families["3.3"].requirements_satisfied == r.families["3.3"].requirements_total
	main.determinations["3.4.1[a]"].requirement == "3.4.1"
	main.determinations["3.4.1[a]"].text == "a baseline configuration is established."
	r.families["3.4"].requirements_satisfied == r.families["3.4"].requirements_total
	main.determinations["3.5.1[a]"].requirement == "3.5.1"
	main.determinations["3.5.1[a]"].text == "system users are identified."
	r.families["3.5"].requirements_satisfied == r.families["3.5"].requirements_total
	main.determinations["3.6.1[a]"].requirement == "3.6.1"
	main.determinations["3.6.1[a]"].text == "an operational incident-handling capability is established."
	r.families["3.6"].requirements_satisfied == r.families["3.6"].requirements_total
	main.determinations["3.7.1"].requirement == "3.7.1"
	main.determinations["3.7.1"].text == "system maintenance is performed."
	r.families["3.7"].requirements_satisfied == r.families["3.7"].requirements_total
	main.determinations["3.8.1[a]"].requirement == "3.8.1"
	main.determinations["3.8.1[a]"].text == "paper media containing CUI is physically controlled."
	r.families["3.8"].requirements_satisfied == r.families["3.8"].requirements_total
	main.determinations["3.9.1"].requirement == "3.9.1"
	main.determinations["3.9.1"].text == "individuals are screened prior to authorizing access to organizational systems containing CUI."
	r.families["3.9"].requirements_satisfied == r.families["3.9"].requirements_total
	main.determinations["3.10.1[a]"].requirement == "3.10.1"
	main.determinations["3.10.1[a]"].text == "authorized individuals allowed physical access are identified."
	r.families["3.10"].requirements_satisfied == r.families["3.10"].requirements_total
	main.determinations["3.11.1[a]"].requirement == "3.11.1"
	main.determinations["3.11.1[a]"].text == "the frequency to assess risk to organizational operations, organizational assets, and individuals is defined."
	r.families["3.11"].requirements_satisfied == r.families["3.11"].requirements_total
	main.determinations["3.12.1[a]"].requirement == "3.12.1"
	main.determinations["3.12.1[a]"].text == "the frequency of security control assessments is defined."
	r.families["3.12"].requirements_satisfied == r.families["3.12"].requirements_total
	main.determinations["3.13.1[a]"].requirement == "3.13.1"
	main.determinations["3.13.1[a]"].text == "the external system boundary is defined."
	r.families["3.13"].requirements_satisfied == r.families["3.13"].requirements_total
	main.determinations["3.14.1[a]"].requirement == "3.14.1"
	main.determinations["3.14.1[a]"].text == "the time within which to identify system flaws is specified."
	r.families["3.14"].requirements_satisfied == r.families["3.14"].requirements_total
}

test_one_objective_false_names_objective_and_requirement if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171a_r2/determinations/3.14.7[b]", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.requirements["3.14.7"].satisfied == false
	r.requirements["3.14.7"].not_satisfied == ["3.14.7[b]"]
	r.families["3.14"].requirements_not_satisfied == ["3.14.7"]
	r.families["3.14"].determinations_satisfied == r.families["3.14"].determinations_total - 1
	r.requirements_satisfied == 109
	some v in r.violations
	contains(v, "3.14.7[b] (requirement 3.14.7)")
}

test_unlabelled_objective_false_fails_its_requirement if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171a_r2/determinations/3.4.4", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.requirements["3.4.4"].satisfied == false
	r.requirements["3.4.4"].not_satisfied == ["3.4.4"]
	some v in r.violations
	contains(v, "3.4.4 (requirement 3.4.4)")
}

test_non_true_value_is_not_satisfied if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171a_r2/determinations/3.1.1[a]", "value": "yes"}])
	r := main.compliance_report with input as inp
	r.requirements["3.1.1"].satisfied == false
	r.compliant == false
}

test_unknown_determination_id_is_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_sp_800_171a_r2/determinations/3.4.4[a]", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unknown determination id 3.4.4[a]")
}

test_rev3_id_is_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_sp_800_171a_r2/determinations/DS-A.03.01.01.a[01]", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
}

test_methods_carried_as_data if {
	r := main.compliance_report with input as {}
	startswith(r.requirements["3.1.1"].methods.examine[0], "[SELECT FROM: Access control policy;")
	startswith(r.requirements["3.14.7"].methods.test[0], "[SELECT FROM: Organizational processes for system monitoring;")
}
