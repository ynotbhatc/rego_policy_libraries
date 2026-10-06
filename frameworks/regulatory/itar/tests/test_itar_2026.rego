# Regression tests for the 2025-2026 final-rule reconciliation.

package itar.main_2026_test

import rego.v1

import data.itar.main

test_classification_recency_flagged if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "re-reviewed against the current USML")]) == 1
}

test_aukus_path_satisfies_access_rule if {
	inp := {"access": {"aukus": {
		"both_parties_on_authorized_user_list": true,
		"item_not_on_excluded_technology_list": true,
		"ddtc_registration_current": true,
	}}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "120.50/127.1")]) == 0
}

test_aukus_partial_facts_fail_closed if {
	inp := {"access": {"aukus": {
		"both_parties_on_authorized_user_list": true,
		"item_not_on_excluded_technology_list": "true",
		"ddtc_registration_current": true,
	}}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "120.50/127.1")]) == 1
}

test_sent_from_condition_present if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "120.54(a)(5)(v)")]) == 1
}

test_corrected_cites_present if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "120.54(a)(5)(ii)-(iii)")]) == 1
	count([m | some m in v; contains(m, "120.54(a)(5)(iv)")]) == 1
	count([m | some m in v; contains(m, "120.54(b)(1)")]) == 1
	count([m | some m in v; contains(m, "120.54(a)(5)(i):")]) == 0
}
