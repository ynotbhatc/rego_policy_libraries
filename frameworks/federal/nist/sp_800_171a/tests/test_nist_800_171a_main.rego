# Tests for nist.sp800_171a.main — NIST SP 800-171A Rev 3 determinations (CPRT ids, sha256 19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa).
package nist.sp800_171a.main_test

import rego.v1

import data.nist.sp800_171a.main

_all := {id: true | some id, _ in main.determinations}

_green := {"nist_sp_800_171a": {"determinations": _all}}

test_table_counts_match_cprt if {
	count(main.determinations) == 422
	count(main.requirements) == 97
	count(main.families) == 17
	count([r | some r, q in main.requirements; count(q.methods.examine) > 0]) == 95
	count([r | some r, q in main.requirements; count(q.methods.interview) > 0]) == 95
	count([r | some r, q in main.requirements; count(q.methods.test) > 0]) == 91
}

test_every_determination_belongs_to_a_known_requirement if {
	count({id | some id, d in main.determinations; not main.requirements[d.requirement]}) == 0
	count({id | some id, d in main.determinations; not startswith(id, concat("", ["DS-A.", d.requirement]))}) == 0
	count({id | some id, d in main.determinations; not startswith(d.statement, concat("", ["SR-", d.requirement]))}) == 0
}

test_every_requirement_has_determinations if {
	count({r | some r, _ in main.requirements; count(main._by_requirement[r]) == 0}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.requirements_satisfied == 0
	r.violation_count == 423
}

test_non_object_determinations_fail_closed if {
	r := main.compliance_report with input as {"nist_sp_800_171a": {"determinations": true}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.determinations_satisfied == 422
	r.requirements_satisfied == 97
}

test_one_requirement_per_family_resolves if {
	r := main.compliance_report with input as _green
	main.determinations["DS-A.03.01.01.a[01]"].requirement == "03.01.01"
	main.determinations["DS-A.03.01.01.a[01]"].text == "system account types allowed are defined."
	r.families["03.01"].requirements_satisfied == r.families["03.01"].requirements_total
	main.determinations["DS-A.03.02.01.a.01[01]"].requirement == "03.02.01"
	main.determinations["DS-A.03.02.01.a.01[01]"].text == "security literacy training is provided to system users as part of initial training for new users."
	r.families["03.02"].requirements_satisfied == r.families["03.02"].requirements_total
	main.determinations["DS-A.03.03.01.a"].requirement == "03.03.01"
	main.determinations["DS-A.03.03.01.a"].text == "the following event types are specified for logging within the system: <A.03.03.01.ODP[01]: event types>."
	r.families["03.03"].requirements_satisfied == r.families["03.03"].requirements_total
	main.determinations["DS-A.03.04.01.a[01]"].requirement == "03.04.01"
	main.determinations["DS-A.03.04.01.a[01]"].text == "a current baseline configuration of the system is developed."
	r.families["03.04"].requirements_satisfied == r.families["03.04"].requirements_total
	main.determinations["DS-A.03.05.01.a[01]"].requirement == "03.05.01"
	main.determinations["DS-A.03.05.01.a[01]"].text == "system users are uniquely identified."
	r.families["03.05"].requirements_satisfied == r.families["03.05"].requirements_total
	main.determinations["DS-A.03.06.01[01]"].requirement == "03.06.01"
	main.determinations["DS-A.03.06.01[01]"].text == "an incident-handling capability that is consistent with the incident response plan is implemented."
	r.families["03.06"].requirements_satisfied == r.families["03.06"].requirements_total
	main.determinations["DS-A.03.07.04.a[01]"].requirement == "03.07.04"
	main.determinations["DS-A.03.07.04.a[01]"].text == "the use of system maintenance tools is approved."
	r.families["03.07"].requirements_satisfied == r.families["03.07"].requirements_total
	main.determinations["DS-A.03.08.01[01]"].requirement == "03.08.01"
	main.determinations["DS-A.03.08.01[01]"].text == "system media that contain CUI are physically controlled."
	r.families["03.08"].requirements_satisfied == r.families["03.08"].requirements_total
	main.determinations["DS-A.03.09.01.a"].requirement == "03.09.01"
	main.determinations["DS-A.03.09.01.a"].text == "individuals are screened prior to authorizing access to the system."
	r.families["03.09"].requirements_satisfied == r.families["03.09"].requirements_total
	main.determinations["DS-A.03.10.01.a[01]"].requirement == "03.10.01"
	main.determinations["DS-A.03.10.01.a[01]"].text == "a list of individuals with authorized access to the facility where the system resides is developed."
	r.families["03.10"].requirements_satisfied == r.families["03.10"].requirements_total
	main.determinations["DS-A.03.11.01.a"].requirement == "03.11.01"
	main.determinations["DS-A.03.11.01.a"].text == "the risk (including supply chain risk) of unauthorized disclosure resulting from the processing, storage, or transmission of CUI is assessed."
	r.families["03.11"].requirements_satisfied == r.families["03.11"].requirements_total
	main.determinations["DS-A.03.12.01"].requirement == "03.12.01"
	main.determinations["DS-A.03.12.01"].text == "the security requirements for the system and its environment of operation are assessed <A.03.12.01.ODP[01]: frequency> to determine if the requirements have been satisfied."
	r.families["03.12"].requirements_satisfied == r.families["03.12"].requirements_total
	main.determinations["DS-A.03.13.01.a[01]"].requirement == "03.13.01"
	main.determinations["DS-A.03.13.01.a[01]"].text == "communications at external managed interfaces to the system are monitored."
	r.families["03.13"].requirements_satisfied == r.families["03.13"].requirements_total
	main.determinations["DS-A.03.14.01.a[01]"].requirement == "03.14.01"
	main.determinations["DS-A.03.14.01.a[01]"].text == "system flaws are identified."
	r.families["03.14"].requirements_satisfied == r.families["03.14"].requirements_total
	main.determinations["DS-A.03.15.01.a[01]"].requirement == "03.15.01"
	main.determinations["DS-A.03.15.01.a[01]"].text == "policies needed to satisfy the security requirements for the protection of CUI are developed and documented."
	r.families["03.15"].requirements_satisfied == r.families["03.15"].requirements_total
	main.determinations["DS-A.03.16.01"].requirement == "03.16.01"
	main.determinations["DS-A.03.16.01"].text == "<A.03.16.01.ODP[01]: systems security engineering principles> are applied to the development or modification of the system and system components."
	r.families["03.16"].requirements_satisfied == r.families["03.16"].requirements_total
	main.determinations["DS-A.03.17.01.a[01]"].requirement == "03.17.01"
	main.determinations["DS-A.03.17.01.a[01]"].text == "a plan for managing supply chain risks is developed."
	r.families["03.17"].requirements_satisfied == r.families["03.17"].requirements_total
}

test_one_determination_false_fails_its_requirement if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171a/determinations/DS-A.03.14.01.a[02]", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.requirements["03.14.01"].satisfied == false
	r.requirements["03.14.01"].not_satisfied == ["DS-A.03.14.01.a[02]"]
	r.families["03.14"].requirements_not_satisfied == ["03.14.01"]
	r.families["03.14"].determinations_satisfied == r.families["03.14"].determinations_total - 1
	r.requirements_satisfied == 96
	some v in r.violations
	contains(v, "DS-A.03.14.01.a[02]")
}

test_non_true_value_is_not_satisfied if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171a/determinations/DS-A.03.14.01.a[02]", "value": "yes"}])
	r := main.compliance_report with input as inp
	r.requirements["03.14.01"].satisfied == false
}

test_unknown_determination_id_is_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_sp_800_171a/determinations/3.14.1[a]", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	some v in r.violations
	contains(v, "unknown determination id 3.14.1[a]")
}

test_methods_carried_as_data if {
	r := main.compliance_report with input as {}
	r.requirements["03.14.01"].methods.examine[0].id == "E-03.14.01"
	r.requirements["03.01.22"].methods.examine == []
}
