package cis_ubuntu_22_04.pam_test

import rego.v1

# Validation fix 2026-10-17: commented pwquality defaults counted as configured; umask compared
# as an exact string; absent hash/numeric evidence passed.

pkg := data.cis_ubuntu_22_04.pam

good_pam := {
	"pwquality_conf_raw": "minlen = 14\nminclass = 3\n",
	"common_password_raw": "password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt\n",
	"faillock_configured": true, "faillock_deny": 5, "faillock_unlock_time": 900,
	"remember_configured": true, "remember_count": 5,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7, "inactive_days": 30,
	"tmout_configured": true, "tmout_value": 600,
	"default_umask": "027",
}

inp(p) := {"pam": p}

test_good_compliant if {
	pkg.compliant with input as inp(good_pam)
}

test_commented_defaults_do_not_count if {
	p := object.union(good_pam, {"pwquality_conf_raw": "# minlen = 8\n# minclass = 3\n"})
	v := pkg.pwquality_violations with input as inp(p)
	"CIS 5.4.1.1: Password minimum length (minlen) not configured in pwquality.conf" in v
	"CIS 5.4.1.2: Password complexity not configured (minclass or dcredit not set)" in v
}

test_short_minlen_after_comment_violates if {
	p := object.union(good_pam, {"pwquality_conf_raw": "# minlen = 20\nminlen = 8\nminclass = 3\n"})
	v := pkg.pwquality_violations with input as inp(p)
	"CIS 5.4.1.1: Password minimum length is 8, should be at least 14" in v
}

test_last_minlen_wins if {
	p := object.union(good_pam, {"pwquality_conf_raw": "minlen = 8\nminlen = 16\ndcredit = -1\n"})
	pkg.compliant with input as inp(p)
}

test_umask_0027_ok if {
	pkg.compliant with input as inp(object.union(good_pam, {"default_umask": "0027"}))
}

test_umask_077_ok if {
	pkg.compliant with input as inp(object.union(good_pam, {"default_umask": "077"}))
}

test_umask_022_violates if {
	not pkg.compliant with input as inp(object.union(good_pam, {"default_umask": "022"}))
	not pkg.compliant with input as inp(object.union(good_pam, {"default_umask": "0026"}))
}

test_umask_absent_violates if {
	not pkg.compliant with input as inp(object.remove(good_pam, ["default_umask"]))
}

test_hash_evidence_absent_violates if {
	v := pkg.pwquality_violations with input as inp(object.remove(good_pam, ["common_password_raw"]))
	"CIS 5.4.4: Password hashing algorithm is not SHA-512 or yescrypt" in v
}

test_commented_hash_does_not_count if {
	p := object.union(good_pam, {"common_password_raw": "# password pam_unix.so sha512\npassword pam_unix.so md5\n"})
	not pkg.compliant with input as inp(p)
}

test_numeric_evidence_absent_violates if {
	every key in ["pass_min_days", "pass_max_days", "pass_warn_age", "inactive_days", "faillock_deny", "remember_count", "tmout_value"] {
		not pkg.compliant with input as inp(object.remove(good_pam, [key]))
	}
}
