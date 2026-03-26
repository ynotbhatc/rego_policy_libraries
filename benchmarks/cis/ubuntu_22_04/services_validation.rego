package cis_ubuntu_22_04.services

# CIS Ubuntu 22.04 LTS Benchmark v1.0.0 - Sections 2.1.x, 2.2.x, 2.3.x: Service Configuration

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

# CIS 2.1.x: Disable automounting
autofs_violations contains violation if {
	input.autofs.installed
	input.autofs.active
	violation := "CIS 2.1.x: autofs service is active (should be disabled)"
}

autofs_violations contains violation if {
	input.autofs.installed
	input.autofs.enabled
	violation := "CIS 2.1.x: autofs service is enabled (should be disabled)"
}

# CIS 2.1.1: Time synchronization
time_sync_violations contains violation if {
	not input.time_synchronization.has_active_service
	violation := "CIS 2.1.1: No time synchronization service is active (chrony, systemd-timesyncd, or ntp)"
}

time_sync_violations contains violation if {
	not input.time_synchronization.compliant
	violation := "CIS 2.1.1: Time synchronization not properly configured"
}

# systemd-timesyncd (Ubuntu default) or chrony
time_sync_violations contains violation if {
	input.time_synchronization.active_service == "systemd-timesyncd"
	not input.timesyncd.service_active
	violation := "CIS 2.1.1: systemd-timesyncd is selected but not active"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	not input.chronyd.service_active
	violation := "CIS 2.1.1: chronyd is selected but not active"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	not input.chronyd.has_time_sources
	violation := "CIS 2.1.1: chronyd has no time sources configured"
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
	service.service == "inetd"
	service.active
	violation := "CIS 2.2.x: inetd is active (legacy super-server should be removed)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "telnet"
	service.active
	violation := "CIS 2.3.4: telnet server is active (CRITICAL: uses cleartext authentication)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "avahi-daemon"
	service.active
	violation := "CIS 2.2.2: Avahi server is active (WARNING: broadcasts system information)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "cups"
	service.active
	violation := "CIS 2.2.4: CUPS print server is active (should be disabled on non-print servers)"
}

# CIS 2.2.x: Web server packages
package_violations contains violation if {
	input.webserver.any_installed
	some pkg in input.webserver.packages
	pkg.installed
	violation := sprintf("CIS 2.2.12: Web server package installed: %s (%s)", [
		pkg["package"],
		pkg.version,
	])
}

# CIS 2.3.x: Client packages (Ubuntu uses apt names)
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
	pkg["package"] == "rsh-client"
	pkg.installed
	violation := "CIS 2.3.2: rsh client is installed (CRITICAL: cleartext protocol)"
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "nis"
	pkg.installed
	violation := "CIS 2.3.1: NIS client (nis) is installed (CRITICAL: legacy authentication)"
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
	"controls_checked": 18,
	"section": "2.1-2.3 Service Configuration",
	"benchmark": "CIS Ubuntu 22.04 v1.0.0",
}
