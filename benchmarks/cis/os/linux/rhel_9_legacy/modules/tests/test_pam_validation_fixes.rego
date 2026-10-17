package cis_rhel9.pam_validation_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

pw(minclass, d, u, l, o) := {"pam": {"pwquality": {"minlen": 14, "minclass": minclass, "dcredit": d, "ucredit": u, "lcredit": l, "ocredit": o}}}

ids(v) := {x.control_id | some x in v; x.control_id}

test_pam_positive_credits_not_complexity if {
	v := data.cis_rhel9.pam_validation.violations with input as pw(1, 2, 2, 2, 2)
	"5.2.1" in ids(v)
}

test_pam_negative_credits_are_complexity if {
	v := data.cis_rhel9.pam_validation.violations with input as pw(1, -1, -1, -1, -1)
	not "5.2.1" in ids(v)
}

test_pam_minclass_4_is_complexity if {
	v := data.cis_rhel9.pam_validation.violations with input as pw(4, 0, 0, 0, 0)
	not "5.2.1" in ids(v)
}

test_pam_root_gid_numeric_zero_ok if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"root_user": {"gid": 0}}}
	not "5.2.13" in ids(v)
}

test_pam_root_gid_string_zero_ok if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"root_user": {"gid": "0"}}}
	not "5.2.13" in ids(v)
}

test_pam_root_gid_nonzero_flagged if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"root_user": {"gid": 10}}}
	"5.2.13" in ids(v)
}

test_pam_umask_0027_ok if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"default_umask": "0027"}}
	not "5.2.14" in ids(v)
}

test_pam_umask_0077_ok if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"default_umask": "0077"}}
	not "5.2.14" in ids(v)
}

test_pam_umask_022_flagged if {
	v := data.cis_rhel9.pam_validation.violations with input as {"pam": {"default_umask": "022"}}
	"5.2.14" in ids(v)
}
