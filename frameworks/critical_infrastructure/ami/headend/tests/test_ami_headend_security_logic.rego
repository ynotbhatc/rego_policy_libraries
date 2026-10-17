package ami.headend.security_test

import rego.v1

# Validation 2026-10-17: a missing retention_days must still raise HEADEND-AUD-2.

test_missing_retention_days_raises_aud2 if {
	v := data.ami.headend.security.violations with input as {"mdms": {"audit_logging": {"encrypted": true}}}
	count([m | some m in v; startswith(m, "HEADEND-AUD-2")]) == 1
}

test_short_retention_days_raises_aud2 if {
	v := data.ami.headend.security.violations with input as {"mdms": {"audit_logging": {"retention_days": 30}}}
	count([m | some m in v; startswith(m, "HEADEND-AUD-2")]) == 1
}

test_adequate_retention_no_aud2 if {
	v := data.ami.headend.security.violations with input as {"mdms": {"audit_logging": {"retention_days": 400}}}
	count([m | some m in v; startswith(m, "HEADEND-AUD-2")]) == 0
}
