# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 2.1.x, 2.2.x, 2.3.x:..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 31
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_debian_11.services

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 2.1.x, 2.2.x, 2.3.x: Service Configuration

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

# Missing evidence fails closed.
# (reported per fact at the end of this file: autofs.installed, the two unnecessary_services lists and
# <section>.any_installed for webserver, client_packages and x11)

# CIS 2.1.x: Disable automounting
autofs_violations contains violation if {
	input.autofs.installed == true
	input.autofs.active == true
	violation := "CIS 2.1.x: autofs service is active (should be disabled)"
}

autofs_violations contains violation if {
	input.autofs.installed == true
	input.autofs.enabled == true
	violation := "CIS 2.1.x: autofs service is enabled (should be disabled)"
}

# CIS 2.1.1: Time synchronization
time_sync_violations contains violation if {
	input.time_synchronization.has_active_service == false
	violation := "CIS 2.1.1: No time synchronization service is active (chrony, systemd-timesyncd, or ntp)"
}

time_sync_violations contains violation if {
	input.time_synchronization.compliant == false
	violation := "CIS 2.1.1: Time synchronization not properly configured"
}

# systemd-timesyncd (Ubuntu default) or chrony
time_sync_violations contains violation if {
	input.time_synchronization.active_service == "systemd-timesyncd"
	input.timesyncd.service_active == false
	violation := "CIS 2.1.1: systemd-timesyncd is selected but not active"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	input.chronyd.service_active == false
	violation := "CIS 2.1.1: chronyd is selected but not active"
}

time_sync_violations contains violation if {
	input.time_synchronization.active_service == "chronyd"
	input.chronyd.has_time_sources == false
	violation := "CIS 2.1.1: chronyd has no time sources configured"
}

# CIS 2.2.x: Unnecessary services
unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.non_compliant
	service.active == true
	violation := sprintf("CIS 2.2.x: Unnecessary service '%s' is active (risk: %s)", [
		service.service,
		object.get(service, "risk_level", "unknown"),
	])
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.non_compliant
	service.enabled == true
	service.active == false
	violation := sprintf("CIS 2.2.x: Unnecessary service '%s' is enabled (risk: %s)", [
		service.service,
		object.get(service, "risk_level", "unknown"),
	])
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "inetd"
	service.active == true
	violation := "CIS 2.2.x: inetd is active (legacy super-server should be removed)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "telnet"
	service.active == true
	violation := "CIS 2.3.4: telnet server is active (CRITICAL: uses cleartext authentication)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "avahi-daemon"
	service.active == true
	violation := "CIS 2.2.2: Avahi server is active (WARNING: broadcasts system information)"
}

unnecessary_service_violations contains violation if {
	some service in input.unnecessary_services.analysis
	service.service == "cups"
	service.active == true
	violation := "CIS 2.2.4: CUPS print server is active (should be disabled on non-print servers)"
}

# CIS 2.2.x: Web server packages
package_violations contains violation if {
	input.webserver.any_installed == true
	some pkg in input.webserver.packages
	pkg.installed == true
	violation := sprintf("CIS 2.2.12: Web server package installed: %s (%s)", [
		pkg["package"],
		object.get(pkg, "version", "unknown"),
	])
}

# CIS 2.3.x: Client packages (Ubuntu uses apt names)
package_violations contains violation if {
	input.client_packages.any_installed == true
	some pkg in input.client_packages.installed_packages
	violation := sprintf("CIS 2.3.x: Unnecessary client package installed: %s (%s, severity: %s)", [
		pkg["package"],
		object.get(pkg, "version", "unknown"),
		object.get(pkg, "severity", "unknown"),
	])
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "telnet"
	pkg.installed == true
	violation := "CIS 2.3.4: telnet client is installed (CRITICAL: cleartext protocol)"
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "rsh-client"
	pkg.installed == true
	violation := "CIS 2.3.2: rsh client is installed (CRITICAL: cleartext protocol)"
}

package_violations contains violation if {
	some pkg in input.client_packages.analysis
	pkg["package"] == "nis"
	pkg.installed == true
	violation := "CIS 2.3.1: NIS client (nis) is installed (CRITICAL: legacy authentication)"
}

# CIS 2.2.1: X Window System
package_violations contains violation if {
	input.x11.any_installed == true
	some pkg in input.x11.packages
	pkg.installed == true
	violation := sprintf("CIS 2.2.1: X Window System package installed on server: %s (%s)", [
		pkg["package"],
		object.get(pkg, "version", "unknown"),
	])
}

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# the same for a yes/no field of one collected row
row_flag_problem(row, key) := "not collected" if is_null(object.get(row, key, null))

row_flag_problem(row, key) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(row, key, null)
	not is_null(v)
	not is_boolean(v)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags := [
	["CIS 2.1.1", ["time_synchronization", "has_active_service"]],
	["CIS 2.1.1", ["time_synchronization", "compliant"]],
]

time_sync_violations contains msg if {
	some [prefix, path] in required_flags
	msg := flag_evidence(prefix, path)
}

# autofs state is judged only when autofs is installed; autofs.installed itself must be an answer
autofs_violations contains msg if {
	msg := flag_evidence("CIS 2.1.x", ["autofs", "installed"])
}

autofs_violations contains msg if {
	input.autofs.installed == true
	some key in ["active", "enabled"]
	msg := flag_evidence("CIS 2.1.x", ["autofs", key])
}

# the facts of the selected time service
time_service_flags := {
	"systemd-timesyncd": [["timesyncd", "service_active"]],
	"chronyd": [["chronyd", "service_active"], ["chronyd", "has_time_sources"]],
}

time_sync_violations contains msg if {
	some path in time_service_flags[input.time_synchronization.active_service]
	msg := flag_evidence("CIS 2.1.1", path)
}

# package summaries: any_installed must be an answer
package_summaries := {"webserver": "2.2.12", "client_packages": "2.3.x", "x11": "2.2.1"}

package_violations contains msg if {
	some section, ctl in package_summaries
	msg := flag_evidence(sprintf("CIS %s", [ctl]), [section, "any_installed"])
}

# yes/no fields of collected rows: every row must answer with a boolean
unnecessary_service_violations contains msg if {
	some i, row in input.unnecessary_services.non_compliant
	some key in ["active", "enabled"]
	msg := sprintf("CIS 2.2.x: evidence missing — unnecessary_services.non_compliant[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
unnecessary_service_violations contains msg if {
	some i, row in input.unnecessary_services.analysis
	some key in ["active"]
	msg := sprintf("CIS 2.2.x: evidence missing — unnecessary_services.analysis[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
package_violations contains msg if {
	some i, row in input.webserver.packages
	some key in ["installed"]
	msg := sprintf("CIS 2.2.12: evidence missing — webserver.packages[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
package_violations contains msg if {
	some i, row in input.client_packages.analysis
	some key in ["installed"]
	msg := sprintf("CIS 2.3.x: evidence missing — client_packages.analysis[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
package_violations contains msg if {
	some i, row in input.x11.packages
	some key in ["installed"]
	msg := sprintf("CIS 2.2.1: evidence missing — x11.packages[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# the service lists and the name of the selected time service are what 2.2.x and 2.1.1 judge
unnecessary_service_violations contains msg if {
	some key in ["analysis", "non_compliant"]
	not is_array(object.get(input, ["unnecessary_services", key], null))
	msg := sprintf("CIS 2.2.x: evidence missing — unnecessary_services.%s not collected", [key])
}

time_sync_violations contains msg if {
	not is_string(object.get(input, ["time_synchronization", "active_service"], null))
	msg := "CIS 2.1.1: evidence missing — time_synchronization.active_service not collected"
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
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
