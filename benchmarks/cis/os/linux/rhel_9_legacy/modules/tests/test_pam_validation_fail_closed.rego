package cis_rhel9.pam_validation_test

import rego.v1

test_notice_without_facts if {
	v := data.cis_rhel9.pam_validation.violations with input as {}
	count(v) > 0
}
