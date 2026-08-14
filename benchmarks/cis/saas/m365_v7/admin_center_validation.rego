# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 1 -- Microsoft 365 admin center
#
# Every control id cited below is verified against the benchmark by
# scripts/check_cis_ids.py, which fails CI if an id does not exist or if
# the message does not correspond to the control that id names.
#
# Input contract (from the aac.m365 collection):
#   input.identity.global_admins[]  - {id, display_name, user_principal_name,
#                                      mfa_methods[], has_strong_mfa}
#   input.identity.collected        - bool; false/absent means the collector
#                                     did not run, which must NOT read as pass

package cis_m365_v7.admin_center

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	is_array(input.identity.global_admins)
}

global_admin_count := count(input.identity.global_admins) if {
	facts_present
} else := -1

# CIS 1.1.3 -- the benchmark requires the number of global admins to sit
# between two and four inclusive.
violation contains msg if {
	facts_present
	global_admin_count < 2
	msg := sprintf("CIS 1.1.3: only %d global admin(s) designated; fewer than two risks lockout with no second administrator", [global_admin_count])
}

violation contains msg if {
	facts_present
	global_admin_count > 4
	msg := sprintf("CIS 1.1.3: %d global admins designated; more than four widens standing privilege beyond what the benchmark permits", [global_admin_count])
}

# Fail closed: absent facts are reported, never silently treated as a pass.
violation contains msg if {
	not facts_present
	msg := "CIS 1.1.3: global admin facts not collected -- control could not be evaluated (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "1",
	"name": "Microsoft 365 admin center",
	"section_total_controls": 15,
	"controls_evaluated": 1,
	"controls": ["1.1.3"],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
