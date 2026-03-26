package cis_rocky_linux_8.services

# CIS Rocky Linux 8 Benchmark v2.0.0 - Sections 1.1.23, 2.1.x, 2.2.x, 2.3.x: Service Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		[v | some v in autofs_violations],
		[v | some v in time_sync_violations],
	),
	array.concat(
		[v | some v in unnecessary_service_violations],
		[v | some v in package_violations],
	),
)

# CIS 1.1.23: Disable automounting
autofs_violations contains violation if {
	input.autofs.installed
	input.autofs.active
	violation := "CIS 1.1.23: autofs service is active (should be disabled)"
}

autofs_violations contains violation if {
	input.autofs.installed
	input.autofs.enabled
	violation := "CIS 1.1.23: autofs service is enabled (should be disabled)"
}

autofs_violations contains violation if {
	not input.autofs.compliant
	violation := "CIS 1.1.23: autofs is not compliant (should be disabled/masked)"
}

# CIS 2.1.1: Time synchronization
time_sync_violations contains violation if {
	not input.time_synchronization.has_active_service
	violation := "CIS 2.1.1: No time synchronization service is active"
}

time_sync_violations contains violation if {
	not input.time_synchronization.compliant
	violation := sprintf("CIS 2.1.1: Time synchronization not properly configured (active services: %d)", [
		count([s | some s in input.time_synchronization.services; s.active]),
	])
}

time_sync_violations contains violation if {
	count([s | some s in input.time_synchronization.services; s.active]) > 1
	violation := sprintf("CIS 2.1.1: Multiple time synchronization services active (should only have one): %v", [
		[name | some s in input.time_synchronization.services; s.active; name := s.service],
	])
}

# CIS 2.1.1.1: chronyd configuration
time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	not input.chronyd.service_active
	violation := "CIS 2.1.1.1: chronyd is selected but not active"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	not input.chronyd.service_enabled
	violation := "CIS 2.1.1.1: chronyd is selected but not enabled"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	not input.chronyd.has_time_sources
	violation := sprintf("CIS 2.1.1.1: chronyd has no time sources configured (servers: %d, pools: %d)", [
		input.chronyd.servers_configured,
		input.chronyd.pools_configured,
	])
}

# CIS 2.2.x: Unnecessary services
unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.non_compliant
	service.active
	violation := sprintf("CIS 2.2.x: Unnecessary service '%s' is active (risk: %s)", [
		service.service,
		service.risk_level,
	])
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.non_compliant
	service.enabled
	not service.active
	violation := sprintf("CIS 2.2.x: Unnecessary service '%s' is enabled (risk: %s)", [
		service.service,
		service.risk_level,
	])
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "telnet.socket"
	service.active
	violation := "CIS 2.2.14: telnet server is active (CRITICAL: uses cleartext authentication)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "rsh.socket"
	service.active
	violation := "CIS 2.3.1: rsh server is active (CRITICAL: uses cleartext authentication)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "vsftpd"
	service.active
	violation := "CIS 2.2.11: FTP server is active (WARNING: may use cleartext authentication)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "avahi-daemon"
	service.active
	violation := "CIS 2.2.2: Avahi server is active (WARNING: broadcasts system information)"
}

# CIS 2.2.12: Web server packages
package_violations contains violation if {
	input.webserver.any_installed
	some pkg in input.webserver.packages
	pkg.installed
	violation := sprintf("CIS 2.2.12: Web server package installed: %s (%s)", [
		pkg["package"],
		pkg.version,
	])
}

# CIS 2.3.x: Client packages
package_violations contains violation if {
	input.client_packages.any_installed
	some pkg in input.client_packages.installed_packages
	violation := sprintf("CIS 2.3.x: Unnecessary client package installed: %s (%s, severity: %s)", [
		pkg["package"],
		pkg.version,
		pkg.severity,
	])
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "telnet"
	pkg.installed
	violation := "CIS 2.3.4: telnet client is installed (CRITICAL: cleartext protocol)"
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "rsh"
	pkg.installed
	violation := "CIS 2.3.2: rsh client is installed (CRITICAL: cleartext protocol)"
}

# CIS 2.2.1: X Window System
package_violations contains violation if {
	input.x11.any_installed
	some pkg in input.x11.packages
	pkg.installed
	violation := sprintf("CIS 2.2.1: X Window System package installed on server: %s (%s)", [
		pkg["package"],
		pkg.version,
	])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"autofs_violations": count(autofs_violations),
	"time_sync_violations": count(time_sync_violations),
	"unnecessary_service_violations": count(unnecessary_service_violations),
	"package_violations": count(package_violations),
	"controls_checked": 20,
	"section": "1.1.23, 2.1-2.3 Service Configuration",
	"benchmark": "CIS Rocky Linux 8 v2.0.0",
}
