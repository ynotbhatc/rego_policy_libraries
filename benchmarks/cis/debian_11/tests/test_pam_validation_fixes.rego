package cis_debian_11.pam_test

import rego.v1

good := {"pam": {
	"pwquality_conf_raw": "minlen = 14\ndcredit = -1\n",
	"common_password_raw": "password [success=1 default=ignore] pam_unix.so obscure use_authtok yescrypt\n",
	"faillock_configured": true, "faillock_deny": 5, "faillock_unlock_time": 900,
	"remember_configured": true, "remember_count": 5,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7, "inactive_days": 30,
	"users_with_future_password_change": [], "system_accounts_with_login_shell": [],
	"tmout_configured": true, "tmout_value": 900, "default_umask": "027",
}}

test_good_compliant if {
	data.cis_debian_11.pam.compliant with input as good
}

test_umask_0027_compliant if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": "0027"}])
	data.cis_debian_11.pam.compliant with input as i
}

test_umask_0077_compliant if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": "0077"}])
	data.cis_debian_11.pam.compliant with input as i
}

test_umask_022_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": "0022"}])
	not data.cis_debian_11.pam.compliant with input as i
}

test_commented_minlen_does_not_satisfy if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/pwquality_conf_raw", "value": "# minlen = 14\ndcredit = -1\n"}])
	some m in data.cis_debian_11.pam.pwquality_violations with input as i
	contains(m, "minlen) not configured")
}

test_short_minlen_last_wins if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/pwquality_conf_raw", "value": "minlen = 14\nminlen = 8\ndcredit = -1\n"}])
	some m in data.cis_debian_11.pam.pwquality_violations with input as i
	contains(m, "should be at least 14")
}

test_commented_hash_does_not_satisfy if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/common_password_raw", "value": "# pam_unix.so sha512\npassword required pam_unix.so md5\n"}])
	not data.cis_debian_11.pam.compliant with input as i
}

test_missing_pass_max_days_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/pam/pass_max_days"}])
	some m in data.cis_debian_11.pam.account_violations with input as i
	contains(m, "evidence missing")
}

test_missing_faillock_deny_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/pam/faillock_deny"}])
	not data.cis_debian_11.pam.compliant with input as i
}
