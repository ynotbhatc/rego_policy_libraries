package pci_dss_tests.access_control.requirement_7_test
import rego.v1

import data.pci_dss.access_control.requirement_7 as r7

# Audit 2026-11-17 follow-up (SAQ D row 7.2.4: every six months, no separate quarterly privileged review).

_review(freq) := {"pci": {"access_review": {
	"performed": true, "frequency_months": freq, "all_accounts": {"included": true},
	"results": {"documented": true}, "inappropriate_access": {"removed": true},
}}}

test_7_2_4_six_months_without_quarterly_privileged_passes if r7.user_access_reviews with input as _review(6)

test_7_2_4_seven_months_fails if not r7.user_access_reviews with input as _review(7)

test_7_2_4_string_frequency_fails if not r7.user_access_reviews with input as _review("3")

test_7_1_1_policies_without_annual_review_flag_pass if {
	r7.access_control_policies_established with input as {"pci": {"access_control": {"policies": {"documented": true, "approved": true, "current": true}}}}
}
