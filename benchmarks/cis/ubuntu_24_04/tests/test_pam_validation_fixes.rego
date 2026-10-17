package cis_ubuntu_24_04.pam_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {"pam": {
	"pwquality_conf_raw": "minlen = 14\nminclass = 4\n",
	"common_password_raw": "password [success=1 default=ignore] pam_unix.so obscure yescrypt",
	"faillock_configured": true, "faillock_deny": 5, "faillock_unlock_time": 900,
	"remember_configured": true, "remember_count": 5,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7,
	"inactive_days": 30,
	"tmout_configured": true, "tmout_value": 900,
	"default_umask": "027",
}}

test_pam_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.pam.compliant with input as good
}

test_pam_commented_defaults_do_not_satisfy_pwquality if {
	i := object.union(good, {"pam": {"pwquality_conf_raw": "# minlen = 14\n# dcredit = -1\n"}})
	v := data.cis_ubuntu_24_04.pam.pwquality_violations with input as i
	"CIS 5.4.1.1: Password minimum length (minlen) not configured in pwquality.conf" in v
	"CIS 5.4.1.2: Password complexity not configured (minclass or dcredit not set)" in v
}

test_pam_commented_minlen_not_misread_beside_active if {
	i := object.union(good, {"pam": {"pwquality_conf_raw": "# minlen = 4\nminlen = 14\nminclass = 3\n"}})
	data.cis_ubuntu_24_04.pam.compliant with input as i
}

test_pam_active_short_minlen_flagged if {
	i := object.union(good, {"pam": {"pwquality_conf_raw": "minlen = 8\nminclass = 3\n"}})
	"CIS 5.4.1.1: Password minimum length is 8, should be at least 14" in data.cis_ubuntu_24_04.pam.pwquality_violations with input as i
}

test_pam_last_minlen_wins if {
	i := object.union(good, {"pam": {"pwquality_conf_raw": "minlen = 8\nminlen = 14\nminclass = 3\n"}})
	data.cis_ubuntu_24_04.pam.compliant with input as i
}

test_pam_commented_hash_does_not_count if {
	i := object.union(good, {"pam": {"common_password_raw": "# password pam_unix.so sha512\npassword pam_unix.so md5"}})
	not data.cis_ubuntu_24_04.pam.compliant with input as i
}

test_pam_missing_hash_evidence_is_violation if {
	not data.cis_ubuntu_24_04.pam.compliant with input as json.remove(good, ["pam/common_password_raw"])
}

test_pam_umask_more_restrictive_accepted if {
	every u in ["027", "037", "077", "0027"] {
		data.cis_ubuntu_24_04.pam.compliant with input as object.union(good, {"pam": {"default_umask": u}})
	}
}

test_pam_umask_looser_flagged if {
	every u in ["022", "002", "026"] {
		not data.cis_ubuntu_24_04.pam.compliant with input as object.union(good, {"pam": {"default_umask": u}})
	}
}

test_pam_missing_umask_is_violation if {
	not data.cis_ubuntu_24_04.pam.compliant with input as json.remove(good, ["pam/default_umask"])
}

test_pam_missing_aging_values_are_violations if {
	every k in ["pass_min_days", "pass_max_days", "pass_warn_age"] {
		not data.cis_ubuntu_24_04.pam.compliant with input as json.remove(good, [concat("/", ["pam", k])])
	}
}
