package cis_rhel8.pam_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good_auth := "auth required pam_faillock.so preauth deny=5 unlock_time=900\npassword requisite pam_pwhistory.so remember=5 enforce_for_root\npassword sufficient pam_unix.so sha512"

good := {"pam": {
	"pwquality_installed": true,
	"pwquality_conf_raw": "minlen = 14\nminclass = 4\n",
	"system_auth": good_auth, "password_auth": good_auth,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7,
	"inactive_days": 30, "root_gid": 0,
	"default_umask": "027", "tmout": 900,
}}

test_pam_fully_evidenced_is_compliant if {
	data.cis_rhel8.pam.compliant with input as good
}

test_pam_umask_022_is_violation if {
	i := object.union(good, {"pam": {"default_umask": "022"}})
	not data.cis_rhel8.pam.compliant with input as i
}

test_pam_umask_more_restrictive_accepted if {
	every u in ["027", "037", "077", "0027"] {
		data.cis_rhel8.pam.compliant with input as object.union(good, {"pam": {"default_umask": u}})
	}
}

test_pam_umask_looser_flagged if {
	every u in ["022", "002", "000", "026"] {
		not data.cis_rhel8.pam.compliant with input as object.union(good, {"pam": {"default_umask": u}})
	}
}

test_pam_commented_faillock_does_not_count if {
	a := "# auth required pam_faillock.so preauth deny=5 unlock_time=900\npassword requisite pam_pwhistory.so remember=5 enforce_for_root\npassword sufficient pam_unix.so sha512"
	i := object.union(good, {"pam": {"system_auth": a, "password_auth": a}})
	"CIS 5.4.2: pam_faillock not configured in PAM" in data.cis_rhel8.pam.violations with input as i
}

test_pam_commented_deny_does_not_count if {
	a := "auth required pam_faillock.so preauth unlock_time=900\n# deny=5\npassword requisite pam_pwhistory.so remember=5 enforce_for_root\npassword sufficient pam_unix.so sha512"
	i := object.union(good, {"pam": {"system_auth": a}})
	"CIS 5.4.2: Account lockout threshold (deny) not configured" in data.cis_rhel8.pam.violations with input as i
}

test_pam_missing_aging_values_are_violations if {
	every k in ["pass_min_days", "pass_max_days", "pass_warn_age", "root_gid"] {
		not data.cis_rhel8.pam.compliant with input as json.remove(good, [concat("/", ["pam", k])])
	}
}

test_pam_missing_pass_max_days_message if {
	i := json.remove(good, ["pam/pass_max_days"])
	"CIS 5.5.1.2: evidence missing — pass_max_days not collected" in data.cis_rhel8.pam.violations with input as i
}
