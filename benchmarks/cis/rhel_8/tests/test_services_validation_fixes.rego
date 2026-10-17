package cis_rhel8.services_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes: a violation must survive absent descriptive fields.

test_chronyd_no_time_sources_reported_without_counts if {
	i := {"time_synchronization": {"active_service": "chronyd", "has_active_service": true, "compliant": true, "services": []}, "chronyd": {"service_active": true, "service_enabled": true, "has_time_sources": false}}
	some v in data.cis_rhel8.services.time_sync_violations with input as i
	startswith(v, "CIS 2.1.1.1: chronyd has no time sources configured")
}

test_unnecessary_service_reported_without_risk_level if {
	i := {"unnecessary_services": {"non_compliant": [{"service": "cups", "active": true}]}}
	some v in data.cis_rhel8.services.unnecessary_service_violations with input as i
	startswith(v, "CIS 2.2.x: Unnecessary service 'cups' is active")
}

test_webserver_package_reported_without_version if {
	i := {"webserver": {"any_installed": true, "packages": [{"package": "httpd", "installed": true}]}}
	v := data.cis_rhel8.services.package_violations with input as i
	count(v) == 1
}

test_client_package_reported_without_severity if {
	i := {"client_packages": {"any_installed": true, "installed_packages": [{"package": "talk"}]}}
	v := data.cis_rhel8.services.package_violations with input as i
	count(v) == 1
}

test_x11_package_reported_without_version if {
	i := {"x11": {"any_installed": true, "packages": [{"package": "xorg-x11-server-Xorg", "installed": true}]}}
	v := data.cis_rhel8.services.package_violations with input as i
	count(v) == 1
}
