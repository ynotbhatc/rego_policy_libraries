package cis_rhel9.mapper_findings_test

import rego.v1

# Found while building the compliance-side collectors (2026-10-19).
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# INACTIVE: v2 5.5.1.4 -> v3 5.4.1.5 (limit 45 days in v3.0.0); -1 still disables the lock and fails.

shadow_ok := [{"user": "alice", "has_password": true, "inactive": 30}]

# CIS 5.4.1.5 (v2 5.5.1.4): -1 disables the inactive lock and must fail.
test_inactive_days_minus_one_is_violation if {
	some v in data.cis_rhel9.pam.violations with input as {"pam": {"inactive_days": -1}, "user_group": {"shadow_entries": shadow_ok}}
	startswith(v, "5.4.1.5: not met — Ensure inactive password lock is configured")
}

test_inactive_days_30_passes if {
	vs := data.cis_rhel9.pam.violations with input as {"pam": {"inactive_days": 30}, "user_group": {"shadow_entries": shadow_ok}}
	every v in vs {
		not startswith(v, "5.4.1.5: ")
	}
}

# a user whose own INACTIVE is -1 fails as well (v3 also checks /etc/shadow)
test_inactive_user_minus_one_is_violation if {
	some v in data.cis_rhel9.pam.violations with input as {"pam": {"inactive_days": 30}, "user_group": {"shadow_entries": [{"user": "bob", "has_password": true, "inactive": -1}]}}
	startswith(v, "5.4.1.5: not met")
}

# Absent certificates evidence is reported as missing, not as a modified bundle.
test_absent_ca_bundle_is_evidence_missing_not_modified if {
	vs := data.cis_rhel9.certificate_validation.violations with input as {}
	"NIST SC-17: evidence missing — certificates.ca_bundle_intact not collected" in vs
	every v in vs {
		not contains(v, "has been modified outside of package management")
	}
}

test_modified_ca_bundle_still_reported if {
	vs := data.cis_rhel9.certificate_validation.violations with input as {"certificates": {"ca_bundle_intact": false}}
	some v in vs
	contains(v, "has been modified outside of package management")
}

# The network section counts an emitted ipv6 key (was misspelled "ipv").
test_network_section_assessed_from_ipv6 if {
	data.cis_rhel9.section_assessment.section_3_network.assessed with input as {"ipv6": {"status": "enabled"}}
}

# Fail closed on missing applicability: an "IF <x>" recommendation passes only on a COLLECTED fact that the
# condition does not hold, never on its absence (GDM, IPv6, at, rsyslog, MTA, wireless, PQ policy module).
test_missing_applicability_is_evidence_missing if {
	vs := data.cis_rhel9.initial_setup.violations with input as {"initial_setup": {"crypto_policy": "DEFAULT"}}
	some v in vs
	startswith(v, "1.8.1: evidence missing")
	some w in vs
	startswith(w, "1.6.7: evidence missing")
	nv := data.cis_rhel9.network.violations with input as {"sysctl_parameters": {"analysis": []}}
	some x in nv
	startswith(x, "3.3.2.1: evidence missing")
	nv2 := data.cis_rhel9.network.violations with input as {"ipv6": {"disabled": true}}
	count([y | some y in nv2; startswith(y, "3.3.2.1: ")]) == 0
}
