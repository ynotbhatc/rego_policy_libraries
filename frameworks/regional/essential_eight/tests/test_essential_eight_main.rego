# Tests for the ACSC Essential Eight master orchestrator — including the
# "overall maturity = lowest strategy's level" scoring rule.
package essential_eight.main_test

import rego.v1

import data.essential_eight.main

_strats := {
	"application_control": data.essential_eight.application_control.requirements,
	"patch_applications": data.essential_eight.patch_applications.requirements,
	"office_macros": data.essential_eight.office_macros.requirements,
	"user_application_hardening": data.essential_eight.user_application_hardening.requirements,
	"restrict_admin_privileges": data.essential_eight.restrict_admin_privileges.requirements,
	"patch_operating_systems": data.essential_eight.patch_operating_systems.requirements,
	"multi_factor_authentication": data.essential_eight.multi_factor_authentication.requirements,
	"regular_backups": data.essential_eight.regular_backups.requirements,
}

# Build an input attesting every requirement up to and including maturity level `maxlvl`.
_input(maxlvl) := {"essential_eight": {strat: {"requirements": {id: true |
	some id, m in reqs
	m.level <= maxlvl
}} |
	some strat, reqs in _strats
}}

test_empty_input_level_zero if {
	r := main.compliance_report with input as {}
	r.strategies_evaluated == 8
	r.total_requirements > 0
	r.violation_count == r.total_requirements
	r.requirements_met == 0
	r.overall_maturity_level == 0
	r.compliant == false
}

test_ml1_only_is_level_one if {
	r := main.compliance_report with input as _input(1)
	r.overall_maturity_level == 1
	r.compliant == false # ML2/ML3 gaps remain
	r.violation_count > 0
}

test_ml1_ml2_is_level_two if {
	r := main.compliance_report with input as _input(2)
	r.overall_maturity_level == 2
}

test_all_attested_is_level_three_and_compliant if {
	r := main.compliance_report with input as _input(3)
	r.overall_maturity_level == 3
	r.violation_count == 0
	r.compliant == true
	r.requirements_met == r.total_requirements
}
