package cis_rhel9.pam_test

import rego.v1

# Validation fixes 2026-10-17: octal umask, comment-aware PAM matching, missing login.defs evidence.

pam_text := "auth required pam_faillock.so preauth deny=5 unlock_time=900\npassword requisite pam_pwhistory.so remember=5\npassword sufficient pam_unix.so sha512\n"

good := {"pam": {
	"pwquality_installed": true,
	"pwquality_conf_raw": "minlen = 14\nminclass = 4\n",
	"system_auth": pam_text,
	"password_auth": pam_text,
	"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7, "inactive_days": 30,
	"root_gid": 0, "default_umask": "027", "tmout": 600,
}}

test_pam_good_input_compliant if {
	data.cis_rhel9.pam.compliant with input as good
}

test_pam_umask_022_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": "022"}])
	not data.cis_rhel9.pam.compliant with input as i
}

test_pam_umask_numeric_22_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": 22}])
	not data.cis_rhel9.pam.compliant with input as i
}

test_pam_umask_stricter_values_ok if {
	every u in ["027", "0027", "077", "0077", "37", "037", "077"] {
		i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": u}])
		data.cis_rhel9.pam.compliant with input as i
	}
}

test_pam_umask_unparsable_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/default_umask", "value": "rwxr-x---"}])
	not data.cis_rhel9.pam.compliant with input as i
}

test_pam_commented_faillock_does_not_satisfy if {
	t := "# auth required pam_faillock.so preauth deny=5 unlock_time=900\npassword requisite pam_pwhistory.so remember=5\npassword sufficient pam_unix.so sha512\n"
	i := json.patch(good, [{"op": "replace", "path": "/pam/system_auth", "value": t}, {"op": "replace", "path": "/pam/password_auth", "value": t}])
	"CIS 5.4.2: pam_faillock not configured in PAM" in data.cis_rhel9.pam.violations with input as i
}

test_pam_commented_deny_does_not_satisfy if {
	t := "auth required pam_faillock.so preauth unlock_time=900\n# deny=5\npassword requisite pam_pwhistory.so remember=5\npassword sufficient pam_unix.so sha512\n"
	i := json.patch(good, [{"op": "replace", "path": "/pam/system_auth", "value": t}])
	"CIS 5.4.2: Account lockout threshold (deny) not configured" in data.cis_rhel9.pam.violations with input as i
}

test_pam_commented_sha512_does_not_satisfy if {
	t := "auth required pam_faillock.so preauth deny=5 unlock_time=900\npassword requisite pam_pwhistory.so remember=5\n# password sufficient pam_unix.so sha512\n"
	i := json.patch(good, [{"op": "replace", "path": "/pam/system_auth", "value": t}, {"op": "replace", "path": "/pam/password_auth", "value": t}])
	"CIS 5.4.4: Password hashing algorithm not set to SHA-512 or yescrypt" in data.cis_rhel9.pam.violations with input as i
}

test_pam_missing_login_defs_values_are_violations if {
	every f in ["pass_min_days", "pass_max_days", "pass_warn_age", "root_gid"] {
		not data.cis_rhel9.pam.compliant with input as json.remove(good, [concat("", ["/pam/", f])])
	}
}
