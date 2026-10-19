package cis_rhel9.mapper_findings_test

import rego.v1

# Found while building the compliance-side collectors (2026-10-19).

# CIS 5.5.1.4: -1 disables the inactive lock and must fail.
test_inactive_days_minus_one_is_violation if {
	some v in data.cis_rhel9.pam.violations with input as {"pam": {"inactive_days": -1}}
	startswith(v, "CIS 5.5.1.4: Inactive password lock is -1")
}

test_inactive_days_30_passes if {
	vs := data.cis_rhel9.pam.violations with input as {"pam": {"inactive_days": 30}}
	every v in vs {
		not startswith(v, "CIS 5.5.1.4: Inactive password lock is")
	}
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
