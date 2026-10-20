package cis_rhel9.pam_test

import rego.v1

# Validation fixes 2026-10-17: octal umask, comment-aware PAM matching, missing login.defs evidence.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 5.4.x/5.5.x -> v3 5.3.x/5.4.x. faillock deny is read from faillock.conf in v3 (module arguments
# may only tighten it); PASS_MIN_DAYS (v3 5.4.1.2) is Manual and root_gid is not a v3 recommendation.

good := {"pam": {"package_versions": {"pam": "1.5.1-14.el9", "authselect": "1.2.6-1.el9", "libpwquality": "1.4.4-8.el9"}, "authselect_profile": "sssd", "authselect_check_valid": true, "system_auth": "auth        required      pam_faillock.so preauth silent\nauth        sufficient    pam_unix.so\nauth        required      pam_faillock.so authfail\naccount     required      pam_faillock.so\naccount     required      pam_unix.so\npassword    requisite     pam_pwquality.so local_users_only\npassword    required      pam_pwhistory.so use_authtok\npassword    sufficient    pam_unix.so sha512 shadow use_authtok\nsession     required      pam_unix.so", "password_auth": "auth        required      pam_faillock.so preauth silent\nauth        sufficient    pam_unix.so\nauth        required      pam_faillock.so authfail\naccount     required      pam_faillock.so\naccount     required      pam_unix.so\npassword    requisite     pam_pwquality.so local_users_only\npassword    required      pam_pwhistory.so use_authtok\npassword    sufficient    pam_unix.so sha512 shadow use_authtok\nsession     required      pam_unix.so", "faillock_conf_raw": "deny = 5\nunlock_time = 900\ndeny = 5\neven_deny_root\nroot_unlock_time = 60", "pwquality_conf_raw": "difok = 2\nminlen = 14\nmaxrepeat = 3\nmaxsequence = 3\ndictcheck = 1\nminlen = 14\nenforce_for_root", "pwhistory_conf_raw": "remember = 24\nremember = 24\nenforce_for_root", "pass_max_days": 365, "pass_warn_age": 7, "encrypt_method": "SHA512", "inactive_days": 30, "system_accounts_with_login_shell": [], "tmout": 900, "tmout_readonly_exported": true, "login_defs_umask": "027", "default_umask": "027"}, "attest": {"password_complexity_reviewed": true, "minimum_password_days_reviewed": true}, "user_group": {"shadow_entries": [{"user": "alice", "has_password": true, "max_days": 365, "warn_days": 7, "inactive": 30, "last_change": 19000}], "uid_zero_accounts": ["root"], "gid_zero_accounts": ["root", "sync"], "gid_zero_groups": ["root"], "root_password_status": "PS", "root_path": "/usr/sbin:/usr/bin", "root_path_nonexistent_dirs": [], "root_path_writable_dirs": [], "root_path_entries": [{"path": "/usr/bin", "owner": "root", "mode": "0755"}], "root_umask": "0027", "unlocked_accounts_without_shell": [], "shells_content": "/bin/bash\n/bin/sh"}}

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
	t := "# auth        required      pam_faillock.so preauth silent\nauth        sufficient    pam_unix.so\n# auth        required      pam_faillock.so authfail\n# account     required      pam_faillock.so\naccount     required      pam_unix.so\npassword    requisite     pam_pwquality.so local_users_only\npassword    required      pam_pwhistory.so use_authtok\npassword    sufficient    pam_unix.so sha512 shadow use_authtok\nsession     required      pam_unix.so"
	i := json.patch(good, [{"op": "replace", "path": "/pam/system_auth", "value": t}, {"op": "replace", "path": "/pam/password_auth", "value": t}])
	"5.3.2.2: not met — Ensure pam_faillock module is enabled" in data.cis_rhel9.pam.violations with input as i
}

test_pam_commented_deny_does_not_satisfy if {
	i := json.patch(good, [{"op": "replace", "path": "/pam/faillock_conf_raw", "value": "# deny = 5\nunlock_time = 900\neven_deny_root\nroot_unlock_time = 60"}])
	"5.3.3.1.1: not met — Ensure password failed attempts lockout is configured" in data.cis_rhel9.pam.violations with input as i
}

test_pam_commented_sha512_does_not_satisfy if {
	t := "auth        required      pam_faillock.so preauth silent\nauth        sufficient    pam_unix.so\nauth        required      pam_faillock.so authfail\naccount     required      pam_faillock.so\naccount     required      pam_unix.so\npassword    requisite     pam_pwquality.so local_users_only\npassword    required      pam_pwhistory.so use_authtok\n# password    sufficient    pam_unix.so sha512 shadow use_authtok\nsession     required      pam_unix.so"
	i := json.patch(good, [{"op": "replace", "path": "/pam/system_auth", "value": t}, {"op": "replace", "path": "/pam/password_auth", "value": t}])
	"5.3.3.4.3: not met — Ensure pam_unix includes a strong password hashing algorithm" in data.cis_rhel9.pam.violations with input as i
}

test_pam_missing_login_defs_values_are_violations if {
	every f in ["pass_max_days", "pass_warn_age", "inactive_days", "encrypt_method", "default_umask", "login_defs_umask"] {
		not data.cis_rhel9.pam.compliant with input as json.remove(good, [concat("", ["/pam/", f])])
	}
}

# a module argument on the PAM line that undercuts faillock.conf fails 5.3.3.1.1
test_pam_module_deny_argument_undercuts_conf if {
	t := replace(good.pam.password_auth, "pam_faillock.so authfail", "pam_faillock.so authfail deny=10")
	i := json.patch(good, [{"op": "replace", "path": "/pam/password_auth", "value": t}])
	"5.3.3.1.1: not met — Ensure password failed attempts lockout is configured" in data.cis_rhel9.pam.violations with input as i
}
