# PCI DSS v4.0.1 Requirement 10 - Log and Monitor All Access to System Components
# and Cardholder Data

# METADATA
# title: "PCI DSS v4.0.1 Requirement 10 - Log and Monitor All Access to System Components"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 11
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.logging_monitoring.requirement_10

import rego.v1

# Numbers are compared only when they are numbers: OPA orders every string above every number, so a string
# such as "5" would otherwise satisfy `>= 12` (audit 2026-11-17 follow-up).
_num_ge(x, n) if {
	is_number(x)
	x >= n
}

# A frequency the entity defines in its targeted risk analysis (12.3.1): both the defined value and the
# actual value must be numbers, and the actual must not exceed the defined one.
_within_defined(actual, defined) if {
	is_number(actual)
	is_number(defined)
	defined > 0
	actual <= defined
}

# =================================================================
# 10.1 - Processes and mechanisms for logging and monitoring
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
logging_policies_established if {
	input.pci.logging.policies.documented == true
	input.pci.logging.policies.approved == true
	input.pci.logging.policies.current == true
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

# 10.4.1.1: automated mechanisms are used to perform audit log reviews. A SIEM, correlation and anomaly
# detection are ways to do it, not parameters, and no longer gate this control.
automated_log_analysis if input.pci.log_review.automated.enabled == true

# Periodic review of all other logs
periodic_log_review if {
	input.pci.log_review.periodic.performed == true

	# 10.4.2.1: the review frequency is the one the entity's targeted risk analysis defines
	_within_defined(input.pci.log_review.periodic.frequency_days, input.pci.log_review.periodic.tra_defined_frequency_days)
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
	_num_ge(input.pci.log_retention.total_months, 12)
	_num_ge(input.pci.log_retention.online_months, 3)
	input.pci.log_retention.policy.documented == true
}

# =================================================================
# 10.6 - Time synchronization mechanisms support consistent time settings
# =================================================================

time_synchronization if {
	input.pci.time_sync.ntp.implemented == true
	input.pci.time_sync.authoritative_time_source.used == true
	input.pci.time_sync.internal_servers.synced_from_authoritative == true
	input.pci.time_sync.cde_systems.synchronized == true
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

# A SIEM with these features is not a requirement (10.4.1.1 asks for automated review mechanisms). Informational; does not gate requirement 10 (audit 2026-11-17 follow-up).
siem_deployed if {
	input.pci.siem.deployed == true
	input.pci.siem.all_cde_sources.integrated == true
	input.pci.siem.use_cases.pci_specific == true
	input.pci.siem.threat_intelligence.integrated == true
	input.pci.siem.tuned.false_positives_managed == true
}

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default logging_policies_established := false

default logging_roles_defined := false

default required_events_logged := false

default audit_log_data_elements := false

default audit_log_protection := false

default external_log_server := false

default daily_log_review := false

default automated_log_analysis := false

default periodic_log_review := false

default log_exceptions_followed_up := false

default log_retention := false

default time_synchronization := false

default time_data_protected := false

default security_control_failure_detection := false

default security_failure_response := false

default siem_deployed := false

default pci_requirement_10_compliant := false

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
	time_data_protected
	security_control_failure_detection
	security_failure_response
}

default pci_requirement_10_score := 0

default pci_requirement_10_findings := {}

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
	"requirement_10_5": {"retention_12_months": log_retention},
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

# BEGIN evidence_spec (generated by scripts/gen_pci_dss_evidence_spec.py; do not edit by hand)
# The facts each check that gates pci_requirement_10_compliant reads, for pci_dss.main: a failing check is
# "evidence missing" when no alternative holds a present, non-compliant fact and some fact is absent or of
# the wrong type. Term tests are described in the generator's docstring.
evidence_spec := {
	"logging_policies_established": {
		"passed": logging_policies_established,
		"alternatives": [
			[["pci.logging.policies.documented", "true"], ["pci.logging.policies.approved", "true"], ["pci.logging.policies.current", "true"]],
		],
	},
	"logging_roles_defined": {
		"passed": logging_roles_defined,
		"alternatives": [
			[["pci.logging.roles.defined", "true"], ["pci.logging.responsibilities.assigned", "true"]],
		],
	},
	"required_events_logged": {
		"passed": required_events_logged,
		"alternatives": [
			[["pci.audit_logs.events.user_access_to_chd", "true"], ["pci.audit_logs.events.privileged_user_actions", "true"], ["pci.audit_logs.events.invalid_logical_access_attempts", "true"], ["pci.audit_logs.events.use_of_identification_mechanisms", "true"], ["pci.audit_logs.events.initialization_of_audit_logs", "true"], ["pci.audit_logs.events.deletion_of_audit_logs", "true"], ["pci.audit_logs.events.system_object_creation_deletion", "true"]],
		],
	},
	"audit_log_data_elements": {
		"passed": audit_log_data_elements,
		"alternatives": [
			[["pci.audit_logs.data.user_identification", "true"], ["pci.audit_logs.data.event_type", "true"], ["pci.audit_logs.data.date_and_time", "true"], ["pci.audit_logs.data.success_or_failure", "true"], ["pci.audit_logs.data.origination_of_event", "true"], ["pci.audit_logs.data.identity_of_affected_data", "true"]],
		],
	},
	"audit_log_protection": {
		"passed": audit_log_protection,
		"alternatives": [
			[["pci.audit_logs.protection.write_access_limited", "true"], ["pci.audit_logs.protection.backup.promptly_backed_up", "true"], ["pci.audit_logs.protection.centralized.implemented", "true"], ["pci.audit_logs.protection.immutable_storage.enabled", "true"], ["pci.audit_logs.protection.integrity.checksums_or_hashing", "true"]],
		],
	},
	"external_log_server": {
		"passed": external_log_server,
		"alternatives": [
			[["pci.audit_logs.external_server.implemented", "true"], ["pci.audit_logs.external_server.separate_from_cde", "true"], ["pci.audit_logs.external_server.write_only_from_cde", "true"]],
		],
	},
	"daily_log_review": {
		"passed": daily_log_review,
		"alternatives": [
			[["pci.log_review.daily.performed", "true"], ["pci.log_review.daily.all_security_events", "true"], ["pci.log_review.daily.privileged_component_logs", "true"], ["pci.log_review.daily.critical_system_logs", "true"], ["pci.log_review.daily.security_controls_logs", "true"]],
		],
	},
	"automated_log_analysis": {
		"passed": automated_log_analysis,
		"alternatives": [
			[["pci.log_review.automated.enabled", "true"]],
		],
	},
	"periodic_log_review": {
		"passed": periodic_log_review,
		"alternatives": [
			[["pci.log_review.periodic.performed", "true"], ["pci.log_review.periodic.frequency_days", "within", "pci.log_review.periodic.tra_defined_frequency_days"], ["pci.log_review.periodic.documented", "true"]],
		],
	},
	"log_exceptions_followed_up": {
		"passed": log_exceptions_followed_up,
		"alternatives": [
			[["pci.log_review.exceptions.tracked", "true"], ["pci.log_review.exceptions.investigation.timely", "true"], ["pci.log_review.exceptions.remediation.documented", "true"]],
		],
	},
	"log_retention": {
		"passed": log_retention,
		"alternatives": [
			[["pci.log_retention.total_months", "ge", 12], ["pci.log_retention.online_months", "ge", 3], ["pci.log_retention.policy.documented", "true"]],
		],
	},
	"time_synchronization": {
		"passed": time_synchronization,
		"alternatives": [
			[["pci.time_sync.ntp.implemented", "true"], ["pci.time_sync.authoritative_time_source.used", "true"], ["pci.time_sync.internal_servers.synced_from_authoritative", "true"], ["pci.time_sync.cde_systems.synchronized", "true"]],
		],
	},
	"time_data_protected": {
		"passed": time_data_protected,
		"alternatives": [
			[["pci.time_data.receiving.only_from_designated_central_servers", "true"], ["pci.time_data.changes.logged", "true"], ["pci.time_data.changes.alerts.configured", "true"]],
		],
	},
	"security_control_failure_detection": {
		"passed": security_control_failure_detection,
		"alternatives": [
			[["pci.failure_detection.security_controls_monitored", "true"], ["pci.failure_detection.ids_ips.monitoring", "true"], ["pci.failure_detection.fim.monitoring", "true"], ["pci.failure_detection.antivirus.monitoring", "true"], ["pci.failure_detection.physical_access.monitoring", "true"], ["pci.failure_detection.logical_access.monitoring", "true"], ["pci.failure_detection.audit_log.monitoring", "true"], ["pci.failure_detection.network_security_controls.monitoring", "true"]],
		],
	},
	"security_failure_response": {
		"passed": security_failure_response,
		"alternatives": [
			[["pci.failure_response.alert.immediate", "true"], ["pci.failure_response.restore.timely", "true"], ["pci.failure_response.compensating_controls.during_failure", "true"], ["pci.failure_response.root_cause.documented", "true"]],
		],
	},
}

# END evidence_spec
