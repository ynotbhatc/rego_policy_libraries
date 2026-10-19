package cmmc_test

import rego.v1

# Decisions 2026-10-19: Level 1 is judged from each domain's Level 1 practices
# (level_1_passing), not from the whole-domain compliant flag, which includes
# Level 2 practices.

l1_ok := {"compliant": false, "passing": 0, "violations": ["L2 only"], "level_1_passing": true}

l1_bad := {"compliant": true, "passing": 0, "violations": [], "level_1_passing": false}

test_level_1_ignores_level_2_failures_in_domain if {
	data.cmmc.cmmc_level_1_compliant with data.cmmc.ac_report as l1_ok
		with data.cmmc.ia_report as l1_ok
		with data.cmmc.pe_report as l1_ok
		with data.cmmc.sc_report as l1_ok
		with data.cmmc.si_report as l1_ok
}

test_level_1_fails_when_a_domain_level_1_practice_fails if {
	not data.cmmc.cmmc_level_1_compliant with data.cmmc.ac_report as l1_ok
		with data.cmmc.ia_report as l1_ok
		with data.cmmc.pe_report as l1_bad
		with data.cmmc.sc_report as l1_ok
		with data.cmmc.si_report as l1_ok
}

test_level_1_false_on_empty_input if {
	not data.cmmc.cmmc_level_1_compliant with input as {}
}

mixed(l1_compliant) := [
	{"id": "a", "level": 1, "compliant": true},
	{"id": "b", "level": 1, "compliant": l1_compliant},
	{"id": "c", "level": 2, "compliant": false},
]

test_ia_level_1_passing_ignores_level_2_practice if {
	data.cmmc.identification_authentication.level_1_passing with data.cmmc.identification_authentication.practices as mixed(true)
	not data.cmmc.identification_authentication.level_1_passing with data.cmmc.identification_authentication.practices as mixed(false)
}

test_pe_level_1_passing_ignores_level_2_practice if {
	data.cmmc.physical_protection.level_1_passing with data.cmmc.physical_protection.practices as mixed(true)
	not data.cmmc.physical_protection.level_1_passing with data.cmmc.physical_protection.practices as mixed(false)
}

test_sc_level_1_passing_ignores_level_2_practice if {
	data.cmmc.system_communications_protection.level_1_passing with data.cmmc.system_communications_protection.practices as mixed(true)
	not data.cmmc.system_communications_protection.level_1_passing with data.cmmc.system_communications_protection.practices as mixed(false)
}

test_si_level_1_passing_ignores_level_2_practice if {
	data.cmmc.system_information_integrity.level_1_passing with data.cmmc.system_information_integrity.practices as mixed(true)
	not data.cmmc.system_information_integrity.level_1_passing with data.cmmc.system_information_integrity.practices as mixed(false)
}

test_domain_reports_expose_level_1_passing if {
	r := data.cmmc.identification_authentication.compliance_report with input as {}
	r.level_1_passing == false
}
