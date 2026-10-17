package cis_ubuntu_24_04.services_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes: a violation must survive absent descriptive fields.

test_unnecessary_service_reported_without_risk_level if {
	i := {"unnecessary_services": {"non_compliant": [{"service": "cups", "active": true}, {"service": "rpcbind", "enabled": true}]}}
	v := data.cis_ubuntu_24_04.services.unnecessary_service_violations with input as i
	count(v) == 2
}

test_webserver_package_reported_without_version if {
	i := {"webserver": {"any_installed": true, "packages": [{"package": "apache2", "installed": true}]}}
	v := data.cis_ubuntu_24_04.services.package_violations with input as i
	count(v) == 1
}

test_client_package_reported_without_severity if {
	i := {"client_packages": {"any_installed": true, "installed_packages": [{"package": "talk"}]}}
	v := data.cis_ubuntu_24_04.services.package_violations with input as i
	count(v) == 1
}

test_x11_package_reported_without_version if {
	i := {"x11": {"any_installed": true, "packages": [{"package": "xserver-xorg", "installed": true}]}}
	v := data.cis_ubuntu_24_04.services.package_violations with input as i
	count(v) == 1
}
