package cis_rocky_linux_9.services_test

import rego.v1

good := {
	"autofs": {"installed": false, "compliant": true},
	"time_synchronization": {"has_active_service": true, "compliant": true, "services": [{"service": "chronyd", "active": true}], "active_service": "chronyd"},
	"chronyd": {"service_active": true, "service_enabled": true, "has_time_sources": true},
	"unnecessary_services": {"analysis": [], "non_compliant": []},
	"webserver": {"any_installed": false, "packages": []},
	"client_packages": {"any_installed": false, "analysis": [], "installed_packages": []},
	"x11": {"any_installed": false, "packages": []},
}

test_full_facts_compliant if data.cis_rocky_linux_9.services.compliant with input as good

test_missing_package_and_service_facts_not_compliant if {
	inp := {
		"autofs": {"installed": false, "compliant": true},
		"time_synchronization": good.time_synchronization,
		"chronyd": good.chronyd,
	}
	not data.cis_rocky_linux_9.services.compliant with input as inp
	v := data.cis_rocky_linux_9.services.violations with input as inp
	count([x | some x in v; contains(x, "evidence missing")]) == 4
}

test_each_missing_section_flagged if {
	every k in ["unnecessary_services", "webserver", "client_packages", "x11"] {
		not data.cis_rocky_linux_9.services.compliant with input as object.remove(good, [k])
	}
}

test_active_telnet_still_flagged if {
	inp := object.union(good, {"unnecessary_services": {"analysis": [{"service": "telnet.socket", "active": true}]}})
	v := data.cis_rocky_linux_9.services.violations with input as inp
	some x in v
	startswith(x, "CIS 2.2.14")
}
