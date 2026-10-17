package cis_ubuntu_20_04.pam_test

import rego.v1

# Validation fix pass 2026-10-17.

good_pam := {
	"pwquality_conf_raw": "# pwquality\nminlen = 14\ndcredit = -1\n",
	"common_password_raw": "password [success=1 default=ignore] pam_unix.so obscure sha512\n",
	"default_umask": "027",
	"faillock_configured": true, "faillock_deny": 5, "faillock_unlock_time": 900,
	"remember_configured": true, "remember_count": 5,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7, "inactive_days": 30,
	"tmout_configured": true, "tmout_value": 600,
}

with_pam(overrides) := {"pam": object.union(good_pam, overrides)}

test_good_input_compliant if {
	data.cis_ubuntu_20_04.pam.compliant with input as with_pam({})
}

test_commented_out_directives_do_not_satisfy_pwquality if {
	v := data.cis_ubuntu_20_04.pam.pwquality_violations with input as with_pam({"pwquality_conf_raw": "# minlen = 14\n# dcredit = -1"})
	count(v) == 2
}

test_commented_out_hash_does_not_satisfy_5_4_4 if {
	v := data.cis_ubuntu_20_04.pam.pwquality_violations with input as with_pam({"common_password_raw": "# password pam_unix.so sha512\npassword pam_unix.so md5"})
	some m in v
	startswith(m, "CIS 5.4.4")
}

test_yescrypt_accepted if {
	v := data.cis_ubuntu_20_04.pam.pwquality_violations with input as with_pam({"common_password_raw": "password [success=1] pam_unix.so yescrypt"})
	count(v) == 0
}

test_short_minlen_flagged_last_value_wins if {
	v := data.cis_ubuntu_20_04.pam.pwquality_violations with input as with_pam({"pwquality_conf_raw": "minlen = 8\ndcredit = -1"})
	count(v) == 1
	v2 := data.cis_ubuntu_20_04.pam.pwquality_violations with input as with_pam({"pwquality_conf_raw": "minlen = 8\nminlen = 16\ndcredit = -1"})
	count(v2) == 0
}

test_missing_raw_files_flagged if {
	inp := {"pam": json.remove(good_pam, ["pwquality_conf_raw", "common_password_raw", "default_umask"])}
	v := data.cis_ubuntu_20_04.pam.violations with input as inp
	count({m | some m in v; contains(m, "evidence missing")}) == 3
}

test_umask_equivalent_forms_accepted if {
	every u in ["027", "0027", "077", "0077", "037", "0o27"] {
		v := data.cis_ubuntu_20_04.pam.account_violations with input as with_pam({"default_umask": u})
		count(v) == 0
	}
}

test_umask_022_flagged if {
	v := data.cis_ubuntu_20_04.pam.account_violations with input as with_pam({"default_umask": "0022"})
	count(v) == 1
}
