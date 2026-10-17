package cis_debian_11.services_test

import rego.v1

good := {
	"autofs": {"installed": false},
	"time_synchronization": {"has_active_service": true, "compliant": true},
	"unnecessary_services": {"non_compliant": [], "analysis": []},
	"webserver": {"any_installed": false, "packages": []},
	"client_packages": {"any_installed": false, "installed_packages": [], "analysis": []},
	"x11": {"any_installed": false, "packages": []},
}

test_good_compliant if {
	data.cis_debian_11.services.compliant with input as good
}

test_client_package_without_severity_still_violates if {
	i := json.patch(good, [
		{"op": "replace", "path": "/client_packages/any_installed", "value": true},
		{"op": "replace", "path": "/client_packages/installed_packages", "value": [{"package": "talk"}]},
	])
	some m in data.cis_debian_11.services.package_violations with input as i
	contains(m, "talk")
}

test_webserver_package_without_version_still_violates if {
	i := json.patch(good, [
		{"op": "replace", "path": "/webserver", "value": {"any_installed": true, "packages": [{"package": "apache2", "installed": true}]}},
	])
	not data.cis_debian_11.services.compliant with input as i
}

test_unnecessary_service_without_risk_level_still_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/unnecessary_services/non_compliant", "value": [{"service": "rpcbind", "active": true}]}])
	some m in data.cis_debian_11.services.unnecessary_service_violations with input as i
	contains(m, "rpcbind")
}

test_each_missing_section_violates if {
	some k in ["autofs", "unnecessary_services", "webserver", "client_packages", "x11"]
	not data.cis_debian_11.services.compliant with input as object.remove(good, [k])
}
