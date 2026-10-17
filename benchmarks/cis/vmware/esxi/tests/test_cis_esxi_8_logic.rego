package cis_esxi_8_test

import rego.v1

# Validation fix 2026-10-17: one undefined condition rule made its whole section's violations
# array undefined, so a partly-configured host was compliant with no violations.

pkg := data.cis_esxi_8

test_failing_control_reports_violation_and_not_compliant if {
	inp := {"esxi": {"host": {"ssh": {"enabled": true, "disabled": false}}}}
	v := pkg.violations with input as inp
	"1.2 Ensure ESXi host SSH service is configured securely" in v
	not pkg.compliant with input as inp
}

test_every_section_reports_when_only_esxi_present if {
	v := pkg.violations with input as {"esxi": {}}
	count(v) == 96
	count(pkg.host_configuration_violations) > 0 with input as {"esxi": {}}
	count(pkg.compliance_monitoring_violations) > 0 with input as {"esxi": {}}
}

test_secure_ssh_control_still_passes if {
	inp := {"esxi": {"host": {"ssh": {"disabled": true}}}}
	v := pkg.violations with input as inp
	not "1.2 Ensure ESXi host SSH service is configured securely" in v
	count(v) == 95
}

test_findings_populated_for_partial_input if {
	f := pkg.findings with input as {"esxi": {"host": {"ssh": {"enabled": true}}}}
	f[0].violations[_] == "1.2 Ensure ESXi host SSH service is configured securely"
}
