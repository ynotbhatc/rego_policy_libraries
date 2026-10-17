package cis_ubuntu_22_04.services_test

import rego.v1

# Validation fix 2026-10-17: sections that were not collected (webserver, x11, client packages,
# unnecessary services, autofs) passed silently.

pkg := data.cis_ubuntu_22_04.services

good := {
	"autofs": {"installed": false, "active": false, "enabled": false},
	"time_synchronization": {"has_active_service": true, "compliant": true, "active_service": "chronyd"},
	"chronyd": {"service_active": true, "has_time_sources": true},
	"unnecessary_services": {"non_compliant": [], "analysis": []},
	"webserver": {"any_installed": false, "packages": []},
	"client_packages": {"any_installed": false, "installed_packages": [], "analysis": []},
	"x11": {"any_installed": false, "packages": []},
}

test_good_compliant if {
	pkg.compliant with input as good
}

test_each_missing_section_violates if {
	every section in ["autofs", "unnecessary_services", "webserver", "client_packages", "x11"] {
		not pkg.compliant with input as object.remove(good, [section])
	}
}

test_missing_section_message if {
	v := pkg.violations with input as object.remove(good, ["x11"])
	"CIS 2.x: evidence missing — x11.any_installed not collected" in v
}

test_active_telnet_still_violates if {
	svc := {"non_compliant": [], "analysis": [{"service": "telnet", "active": true}]}
	not pkg.compliant with input as object.union(good, {"unnecessary_services": svc})
}

test_web_server_installed_still_violates if {
	ws := {"any_installed": true, "packages": [{"package": "apache2", "version": "2.4", "installed": true}]}
	not pkg.compliant with input as object.union(good, {"webserver": ws})
}
