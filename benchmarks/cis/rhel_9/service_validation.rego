package cis_rhel9.services

# CIS RHEL 9 Sections 1.1.23, 2.1.x, 2.2.x, 2.3.x - Service Configuration
# Validates service status, time synchronization, and unnecessary packages

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

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

# =============================================================================
# CIS 1.1.23 - DISABLE AUTOMOUNTING
# =============================================================================

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

# =============================================================================
# CIS 2.1.1 - TIME SYNCHRONIZATION
# =============================================================================

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

# Multiple time sync services running (conflict)
time_sync_violations contains violation if {
	count([s | some s in input.time_synchronization.services; s.active]) > 1
	violation := sprintf("CIS 2.1.1: Multiple time synchronization services active (should only have one): %v", [
		[name | some s in input.time_synchronization.services; s.active; name := s.service],
	])
}

# =============================================================================
# CIS 2.1.1.1 - CHRONYD
# =============================================================================

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

# =============================================================================
# CIS 2.2.x - UNNECESSARY SERVICES
# =============================================================================

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

# High-risk services get specific violations
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

# =============================================================================
# CIS 2.2.12 - WEB SERVER PACKAGES
# =============================================================================

package_violations contains violation if {
	input.webserver.any_installed
	some pkg in input.webserver.packages
	pkg.installed
	violation := sprintf("CIS 2.2.12: Web server package installed: %s (%s)", [
		pkg["package"],
		pkg.version,
	])
}

# =============================================================================
# CIS 2.3.x - CLIENT PACKAGES
# =============================================================================

package_violations contains violation if {
	input.client_packages.any_installed
	some pkg in input.client_packages.installed_packages
	violation := sprintf("CIS 2.3.x: Unnecessary client package installed: %s (%s, severity: %s)", [
		pkg["package"],
		pkg.version,
		pkg.severity,
	])
}

# Specific high-severity client packages
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

# =============================================================================
# CIS 2.2.1 - X11 (X WINDOW SYSTEM)
# =============================================================================

package_violations contains violation if {
	input.x11.any_installed
	some pkg in input.x11.packages
	pkg.installed
	violation := sprintf("CIS 2.2.1: X Window System package installed on server: %s (%s)", [
		pkg["package"],
		pkg.version,
	])
}

# =============================================================================
# MAIL TRANSFER AGENT
# =============================================================================

# MTA should be configured for local-only mode (not a violation to have MTA)
# This is informational
mta_info := {
	"has_mta": input.mta.has_mta,
	"active_mta": input.mta.active_mta,
	"packages": [p["package"] |
		some p in input.mta.packages
		p.installed
	],
}

# =============================================================================
# COMPLIANCE CHECKS
# =============================================================================

compliance_summary := {
	"autofs_disabled": input.compliance_checks.autofs_disabled,
	"time_sync_configured": input.compliance_checks.time_sync_configured,
	"chronyd_running": input.compliance_checks.chronyd_running,
	"chronyd_has_servers": input.compliance_checks.chronyd_has_servers,
	"no_unnecessary_services": input.compliance_checks.no_unnecessary_services,
	"no_webserver": input.compliance_checks.no_webserver,
	"no_client_packages": input.compliance_checks.no_client_packages,
	"no_x11": input.compliance_checks.no_x11,
	"overall_compliant": count(violations) == 0,
}

# =============================================================================
# DETAILED REPORTING
# =============================================================================

# Active unnecessary services (high priority)
active_unnecessary_services contains service if {
	some s in input.unnecessary_services.analysis
	s.active
	service := {
		"service": s.service,
		"state": s.state,
		"risk_level": s.risk_level,
	}
}

# Enabled but inactive services (medium priority)
enabled_unnecessary_services contains service if {
	some s in input.unnecessary_services.analysis
	s.enabled
	not s.active
	service := {
		"service": s.service,
		"unit_file_state": s.unit_file_state,
		"risk_level": s.risk_level,
	}
}

# Installed unnecessary packages
installed_unnecessary_packages := {
	"webserver": [p["package"] |
		some p in input.webserver.packages
		p.installed
	],
	"client_packages": [p["package"] |
		some p in input.client_packages.analysis
		p.installed
	],
	"x11": [p["package"] |
		some p in input.x11.packages
		p.installed
	],
}

# Time synchronization status
time_sync_status := {
	"active_service": input.time_synchronization.active_service,
	"has_active_service": input.time_synchronization.has_active_service,
	"chronyd_installed": input.chronyd.installed,
	"chronyd_active": input.chronyd.service_active,
	"chronyd_enabled": input.chronyd.service_enabled,
	"chronyd_servers": input.chronyd.servers_configured,
	"chronyd_pools": input.chronyd.pools_configured,
}

# Service inventory summary
service_inventory := {
	"total_enabled": input.all_services.enabled.count,
	"total_active": input.all_services.active.count,
	"unnecessary_found_active": input.unnecessary_services.found_active,
	"unnecessary_found_enabled": input.unnecessary_services.found_enabled,
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"active_unnecessary_services": active_unnecessary_services,
	"enabled_unnecessary_services": enabled_unnecessary_services,
	"installed_unnecessary_packages": installed_unnecessary_packages,
	"time_sync_status": time_sync_status,
	"service_inventory": service_inventory,
	"mta_info": mta_info,
	"collection_timestamp": input.collection_timestamp,
}

