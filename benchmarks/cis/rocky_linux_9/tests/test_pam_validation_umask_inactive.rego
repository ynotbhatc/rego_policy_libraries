package cis_rocky_linux_9.pam_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.pam.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_umask_022_flagged if has("CIS 5.5.4: Default umask is", {"pam": {"default_umask": "022"}})
test_umask_002_flagged if has("CIS 5.5.4: Default umask is", {"pam": {"default_umask": "0002"}})
test_umask_027_ok if not has("CIS 5.5.4", {"pam": {"default_umask": "027"}})
test_umask_0027_ok if not has("CIS 5.5.4", {"pam": {"default_umask": "0027"}})
test_umask_077_ok if not has("CIS 5.5.4", {"pam": {"default_umask": "077"}})
test_umask_037_ok if not has("CIS 5.5.4", {"pam": {"default_umask": "037"}})
test_umask_unparsable_flagged if has("CIS 5.5.4: Default umask is", {"pam": {"default_umask": "u=rwx"}})

test_inactive_minus_one_flagged if has("CIS 5.5.1.4", {"pam": {"inactive_days": "-1"}})
test_inactive_45_flagged if has("CIS 5.5.1.4", {"pam": {"inactive_days": "45"}})
test_inactive_30_ok if not has("CIS 5.5.1.4", {"pam": {"inactive_days": "30"}})
