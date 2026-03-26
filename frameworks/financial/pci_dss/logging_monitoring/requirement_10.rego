# PCI DSS v4.0 Requirement 10 - Log and Monitor All Access to System Components
# and Cardholder Data

package pci_dss.logging_monitoring.requirement_10

import rego.v1

# =================================================================
# 10.1 - Processes and mechanisms for logging and monitoring
# =================================================================

logging_policies_established if {
	input.pci.logging.policies.documented == true
	input.pci.logging.policies.approved == true
	input.pci.logging.policies.current == true
	input.pci.logging.policies.reviewed_annually == true
}

logging_roles_defined if {
	input.pci.logging.roles.defined == true
	input.pci.logging.responsibilities.assigned == true
}

# =================================================================
# 10.2 - Audit logs capture all individual user access to cardholder data
# =================================================================

# All required events are logged
required_events_logged if {
	input.pci.audit_logs.events.user_access_to_chd == true
	input.pci.audit_logs.events.privileged_user_actions == true
	input.pci.audit_logs.events.invalid_logical_access_attempts == true
	input.pci.audit_logs.events.use_of_identification_mechanisms == true
	input.pci.audit_logs.events.initialization_of_audit_logs == true
	input.pci.audit_logs.events.deletion_of_audit_logs == true
	input.pci.audit_logs.events.system_object_creation_deletion == true
}

# Audit log records contain required data elements
audit_log_data_elements if {
	input.pci.audit_logs.data.user_identification == true
	input.pci.audit_logs.data.event_type == true
	input.pci.audit_logs.data.date_and_time == true
	input.pci.audit_logs.data.success_or_failure == true
	input.pci.audit_logs.data.origination_of_event == true
	input.pci.audit_logs.data.identity_of_affected_data == true
}

# =================================================================
# 10.3 - Audit logs protected from destruction and unauthorized modifications
# =================================================================

audit_log_protection if {
	input.pci.audit_logs.protection.write_access_limited == true
	input.pci.audit_logs.protection.backup.promptly_backed_up == true
	input.pci.audit_logs.protection.centralized.implemented == true
	input.pci.audit_logs.protection.immutable_storage.enabled == true
	input.pci.audit_logs.protection.integrity.checksums_or_hashing == true
}

# External log server (separate from CDE)
external_log_server if {
	input.pci.audit_logs.external_server.implemented == true
	input.pci.audit_logs.external_server.separate_from_cde == true
	input.pci.audit_logs.external_server.write_only_from_cde == true
}

# =================================================================
# 10.4 - Audit logs reviewed to identify anomalies
# =================================================================

# Daily log review
daily_log_review if {
	input.pci.log_review.daily.performed == true
	input.pci.log_review.daily.all_security_events == true
	input.pci.log_review.daily.privileged_component_logs == true
	input.pci.log_review.daily.critical_system_logs == true
	input.pci.log_review.daily.security_controls_logs == true
}

# Automated log analysis
automated_log_analysis if {
	input.pci.log_review.automated.enabled == true
	input.pci.log_review.automated.siem.deployed == true
	input.pci.log_review.automated.alerts.configured == true
	input.pci.log_review.automated.correlation.enabled == true
	input.pci.log_review.automated.anomaly_detection.enabled == true
}

# Periodic review of all other logs
periodic_log_review if {
	input.pci.log_review.periodic.performed == true
	input.pci.log_review.periodic.frequency_days <= 7
	input.pci.log_review.periodic.documented == true
}

# Log review exceptions followed up
log_exceptions_followed_up if {
	input.pci.log_review.exceptions.tracked == true
	input.pci.log_review.exceptions.investigation.timely == true
	input.pci.log_review.exceptions.remediation.documented == true
}

# =================================================================
# 10.5 - Audit log history retained for at least 12 months
# =================================================================

log_retention if {
	input.pci.log_retention.total_months >= 12
	input.pci.log_retention.online_months >= 3
	input.pci.log_retention.policy.documented == true
	input.pci.log_retention.older_logs.accessible_within_24_hours == true
}

# =================================================================
# 10.6 - Time synchronization mechanisms support consistent time settings
# =================================================================

time_synchronization if {
	input.pci.time_sync.ntp.implemented == true
	input.pci.time_sync.authoritative_time_source.used == true
	input.pci.time_sync.internal_servers.synced_from_authoritative == true
	input.pci.time_sync.cde_systems.synchronized == true
	input.pci.time_sync.max_drift_seconds <= 1
}

time_data_protected if {
	input.pci.time_data.receiving.only_from_designated_central_servers == true
	input.pci.time_data.changes.logged == true
	input.pci.time_data.changes.alerts.configured == true
}

# =================================================================
# 10.7 - Failures of critical security controls detected and reported
# =================================================================

security_control_failure_detection if {
	input.pci.failure_detection.security_controls_monitored == true
	input.pci.failure_detection.ids_ips.monitoring == true
	input.pci.failure_detection.fim.monitoring == true
	input.pci.failure_detection.antivirus.monitoring == true
	input.pci.failure_detection.physical_access.monitoring == true
	input.pci.failure_detection.logical_access.monitoring == true
	input.pci.failure_detection.audit_log.monitoring == true
	input.pci.failure_detection.network_security_controls.monitoring == true
}

security_failure_response if {
	input.pci.failure_response.alert.immediate == true
	input.pci.failure_response.restore.timely == true
	input.pci.failure_response.compensating_controls.during_failure == true
	input.pci.failure_response.root_cause.documented == true
}

# =================================================================
# SIEM Integration
# =================================================================

siem_deployed if {
	input.pci.siem.deployed == true
	input.pci.siem.all_cde_sources.integrated == true
	input.pci.siem.use_cases.pci_specific == true
	input.pci.siem.threat_intelligence.integrated == true
	input.pci.siem.tuned.false_positives_managed == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_10_compliant if {
	logging_policies_established
	logging_roles_defined
	required_events_logged
	audit_log_data_elements
	audit_log_protection
	external_log_server
	daily_log_review
	automated_log_analysis
	periodic_log_review
	log_exceptions_followed_up
	log_retention
	time_synchronization
	security_control_failure_detection
	security_failure_response
}

pci_requirement_10_score := score if {
	controls := [
		logging_policies_established,
		logging_roles_defined,
		required_events_logged,
		audit_log_data_elements,
		audit_log_protection,
		external_log_server,
		daily_log_review,
		automated_log_analysis,
		periodic_log_review,
		log_exceptions_followed_up,
		log_retention,
		time_synchronization,
		time_data_protected,
		security_control_failure_detection,
		security_failure_response,
		siem_deployed,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_10_findings := {
	"requirement_10_1": {
		"policies_established": logging_policies_established,
		"roles_defined": logging_roles_defined,
	},
	"requirement_10_2": {
		"required_events_logged": required_events_logged,
		"data_elements": audit_log_data_elements,
	},
	"requirement_10_3": {
		"log_protection": audit_log_protection,
		"external_log_server": external_log_server,
	},
	"requirement_10_4": {
		"daily_review": daily_log_review,
		"automated_analysis": automated_log_analysis,
		"periodic_review": periodic_log_review,
		"exceptions_followed_up": log_exceptions_followed_up,
	},
	"requirement_10_5": {
		"retention_12_months": log_retention,
	},
	"requirement_10_6": {
		"time_synchronization": time_synchronization,
		"time_data_protected": time_data_protected,
	},
	"requirement_10_7": {
		"failure_detection": security_control_failure_detection,
		"failure_response": security_failure_response,
	},
	"siem": siem_deployed,
	"overall_score": pci_requirement_10_score,
	"overall_compliant": pci_requirement_10_compliant,
}
