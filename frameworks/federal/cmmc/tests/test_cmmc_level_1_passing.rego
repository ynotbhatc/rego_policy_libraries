package cmmc_test

import rego.v1

# Each domain's level_1_passing reads only its Level 1 practices. The Level 1
# verdict of the framework itself is scored in data.cmmc from the registry
# (tests/test_cmmc_scoring.rego).

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

test_mp_level_1_passing_ignores_level_2_practice if {
	data.cmmc.media_protection.level_1_passing with data.cmmc.media_protection.practices as mixed(true)
	not data.cmmc.media_protection.level_1_passing with data.cmmc.media_protection.practices as mixed(false)
}

# The Level 1 tags in the domain files match the FAR 52.204-21 mapping.
test_domain_level_1_tags_match_registry if {
	reports := data.cmmc.domain_reports with input as {}
	tagged := {p.id | some r in reports; some p in r.practices; p.level == 1}
	registry := {n | some x in data.cmmc.level_1_requirements; some n in x.nist}
	tagged == registry
}

test_domain_reports_expose_level_1_passing if {
	r := data.cmmc.identification_authentication.compliance_report with input as {}
	r.level_1_passing == false
}
