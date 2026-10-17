package cis_amazon_linux_2023.pam_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_pam_commented_faillock_does_not_count if {
	i := {"pam": {
		"system_auth": "#auth required pam_faillock.so preauth deny=5 unlock_time=900\n",
		"password_auth": "# auth required pam_faillock.so\n",
	}}
	v := data.cis_amazon_linux_2023.pam.violations with input as i
	has("CIS 5.4.2: pam_faillock not configured", v)
}

test_pam_active_faillock_counts if {
	i := {"pam": {"system_auth": "auth required pam_faillock.so preauth deny=5 unlock_time=900\n", "password_auth": ""}}
	v := data.cis_amazon_linux_2023.pam.violations with input as i
	not has("CIS 5.4.2", v)
}

test_pam_commented_deny_does_not_count if {
	i := {"pam": {"system_auth": "auth required pam_faillock.so preauth\n# deny=5 unlock_time=900\n"}}
	v := data.cis_amazon_linux_2023.pam.violations with input as i
	has("CIS 5.4.2: Account lockout threshold", v)
	has("CIS 5.4.2: Account lockout time", v)
}

test_pam_commented_remember_does_not_count if {
	i := {"pam": {"system_auth": "# password sufficient pam_unix.so remember=5 sha512\n", "password_auth": ""}}
	v := data.cis_amazon_linux_2023.pam.violations with input as i
	has("CIS 5.4.3: Password reuse limitation not configured", v)
}

test_pam_umask_022_flagged if {
	v := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"default_umask": "022"}}
	has("CIS 5.5.4: Default umask is 022", v)
}

test_pam_umask_027_077_ok if {
	v1 := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"default_umask": "027"}}
	v2 := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"default_umask": "0077"}}
	not has("CIS 5.5.4: Default umask is", v1)
	not has("CIS 5.5.4: Default umask is", v2)
}

test_pam_umask_garbage_flagged if {
	v := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"default_umask": "abc"}}
	has("CIS 5.5.4: Default umask is", v)
}

test_pam_inactive_minus_one_flagged if {
	v := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"inactive_days": "-1"}}
	has("CIS 5.5.1.4: Inactive password lock is disabled", v)
}

test_pam_inactive_30_ok if {
	v := data.cis_amazon_linux_2023.pam.violations with input as {"pam": {"inactive_days": "30"}}
	not has("CIS 5.5.1.4", v)
}
