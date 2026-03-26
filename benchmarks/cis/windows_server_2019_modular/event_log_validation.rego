package cis_windows_server_2019.event_log

# CIS Windows Server 2019 Benchmark v3.0.0 - Section 18.9: Event Log Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in application_log_violations], [v | some v in security_log_violations]),
	[v | some v in system_log_violations],
)

# CIS 18.9.26.1.1: Application log maximum size >= 32768 KB (32 MB)
application_log_violations contains msg if {
	input.event_log.application_max_size < 32768
	msg := sprintf("CIS 18.9.26.1.1: Application event log maximum size is %d KB, should be 32768 KB or more", [input.event_log.application_max_size])
}

# CIS 18.9.26.1.2: Application log retention method = Overwrite events as needed
application_log_violations contains msg if {
	input.event_log.application_retention != "OverwriteAsNeeded"
	msg := sprintf("CIS 18.9.26.1.2: Application log retention is '%s', should be 'OverwriteAsNeeded'", [input.event_log.application_retention])
}

# CIS 18.9.26.2.1: Security log maximum size >= 196608 KB (192 MB)
security_log_violations contains msg if {
	input.event_log.security_max_size < 196608
	msg := sprintf("CIS 18.9.26.2.1: Security event log maximum size is %d KB, should be 196608 KB or more", [input.event_log.security_max_size])
}

# CIS 18.9.26.2.2: Security log retention method = Overwrite events as needed
security_log_violations contains msg if {
	input.event_log.security_retention != "OverwriteAsNeeded"
	msg := sprintf("CIS 18.9.26.2.2: Security log retention is '%s', should be 'OverwriteAsNeeded'", [input.event_log.security_retention])
}

# CIS 18.9.26.3.1: Setup log maximum size >= 32768 KB
setup_log_violations contains msg if {
	input.event_log.setup_max_size < 32768
	msg := sprintf("CIS 18.9.26.3.1: Setup event log maximum size is %d KB, should be 32768 KB or more", [input.event_log.setup_max_size])
}

# CIS 18.9.26.3.2: Setup log retention method = Overwrite events as needed
setup_log_violations contains msg if {
	input.event_log.setup_retention != "OverwriteAsNeeded"
	msg := sprintf("CIS 18.9.26.3.2: Setup log retention is '%s', should be 'OverwriteAsNeeded'", [input.event_log.setup_retention])
}

# CIS 18.9.26.4.1: System log maximum size >= 32768 KB
system_log_violations contains msg if {
	input.event_log.system_max_size < 32768
	msg := sprintf("CIS 18.9.26.4.1: System event log maximum size is %d KB, should be 32768 KB or more", [input.event_log.system_max_size])
}

# CIS 18.9.26.4.2: System log retention method = Overwrite events as needed
system_log_violations contains msg if {
	input.event_log.system_retention != "OverwriteAsNeeded"
	msg := sprintf("CIS 18.9.26.4.2: System log retention is '%s', should be 'OverwriteAsNeeded'", [input.event_log.system_retention])
}

# CIS 18.10.25.1: Event Log Service must be protected
security_log_violations contains msg if {
	not input.event_log.log_service_protected
	msg := "CIS 18.10.25: Event Log service must be protected from tampering"
}

# Windows Event Forwarding
security_log_violations contains msg if {
	not input.event_log.forwarding_configured
	input.require_event_forwarding == true
	msg := "CIS 18.9.27: Windows Event Log forwarding is not configured"
}

all_violations := array.concat(
	array.concat([v | some v in application_log_violations], [v | some v in security_log_violations]),
	array.concat([v | some v in setup_log_violations], [v | some v in system_log_violations]),
)

report := {
	"compliant": compliant,
	"total_violations": count(all_violations),
	"violations": all_violations,
	"application_log_violations": count(application_log_violations),
	"security_log_violations": count(security_log_violations),
	"system_log_violations": count(system_log_violations),
	"event_log_sizes": {
		"application_kb": input.event_log.application_max_size,
		"security_kb": input.event_log.security_max_size,
		"system_kb": input.event_log.system_max_size,
	},
	"controls_checked": 9,
	"section": "18.9.26 Event Log Service",
	"benchmark": "CIS Windows Server 2019 v3.0.0",
}
