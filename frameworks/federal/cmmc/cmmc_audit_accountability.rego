# METADATA
# title: "CMMC 2.0 — Domain 3.3: Audit & Accountability"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 41
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cmmc.audit_accountability

import rego.v1

# Organisation-defined parameters. Where NIST SP 800-171 R2 leaves a period,
# frequency or count to the organisation ("a defined period", "periodically",
# "a specified number"; NIST SP 800-171A objectives "... is defined"), the
# organisation's value is read from input.org_defined.<name> and the observed
# value is compared with it. Either one missing, or not a number, is a finding.
# is_number guards every comparison: OPA orders null below numbers and strings
# above them.
_odp(name) := v if {
	v := input.org_defined[name]
	is_number(v)
}

_actual(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

_at_most(path, name) if _actual(path) <= _odp(name)

_at_least(path, name) if _actual(path) >= _odp(name)

# 32 CFR 170.14(d): "periodically" means an organisation-defined interval of no
# more than one year.
_periodic_ok(name) if _odp(name) <= 365

# =============================================================================
# CMMC 2.0 — Domain 3.3: Audit & Accountability
# NIST SP 800-171 Rev 2 — 9 Practices
# =============================================================================

# ---------------------------------------------------------------------------
# 3.3.1 — Create and retain system audit logs and records to the extent needed
#          to enable the monitoring, analysis, investigation, and reporting of
#          unlawful or unauthorized system activity. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_1 := false

compliant_3_3_1 if {
	input.audit.logging_enabled == true
	_at_least(["audit", "log_retention_days"], "audit_log_retention_days")
	input.audit.auditd_active == true
}

violation_3_3_1 contains msg if {
	not input.audit.logging_enabled
	msg := "3.3.1: System audit logging is not enabled"
}

violation_3_3_1 contains "3.3.1: evidence missing - input.org_defined.audit_log_retention_days (organisation-defined value, NIST SP 800-171A 3.3.1[e]) not supplied or not a number" if {
	not _odp("audit_log_retention_days")
}

violation_3_3_1 contains "3.3.1: evidence missing - input.audit.log_retention_days not collected or not a number" if {
	not _actual(["audit", "log_retention_days"])
}

violation_3_3_1 contains msg if {
	_actual(["audit", "log_retention_days"]) < _odp("audit_log_retention_days")
	msg := sprintf("3.3.1: audit records retained %v days, less than the organisation-defined %v days", [_actual(["audit", "log_retention_days"]), _odp("audit_log_retention_days")])
}

violation_3_3_1 contains msg if {
	not input.audit.auditd_active
	msg := "3.3.1: auditd service is not active"
}

# ---------------------------------------------------------------------------
# 3.3.2 — Ensure that the actions of individual system users can be uniquely
#          traced to those users so they can be held accountable. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_2 := false

compliant_3_3_2 if {
	input.audit.user_activity_tracked == true
	input.audit.audit_rules_configured == true
	count(input.audit.privileged_command_rules) > 0
}

violation_3_3_2 contains msg if {
	not input.audit.user_activity_tracked
	msg := "3.3.2: Individual user activity is not uniquely tracked in audit logs"
}

violation_3_3_2 contains msg if {
	not input.audit.audit_rules_configured
	msg := "3.3.2: Audit rules are not configured to trace user actions"
}

violation_3_3_2 contains msg if {
	count(input.audit.privileged_command_rules) == 0
	msg := "3.3.2: No audit rules configured for privileged command execution"
}

# ---------------------------------------------------------------------------
# 3.3.3 — Review and update logged events. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_3 := false

compliant_3_3_3 if {
	input.audit.event_review_process == true
	_at_most(["audit", "last_review_days_ago"], "audit_event_review_interval_days")
}

violation_3_3_3 contains msg if {
	not input.audit.event_review_process
	msg := "3.3.3: No documented process for reviewing and updating logged audit events"
}

violation_3_3_3 contains "3.3.3: evidence missing - input.org_defined.audit_event_review_interval_days (organisation-defined value, NIST SP 800-171A 3.3.3[a]) not supplied or not a number" if {
	not _odp("audit_event_review_interval_days")
}

violation_3_3_3 contains "3.3.3: evidence missing - input.audit.last_review_days_ago not collected or not a number" if {
	not _actual(["audit", "last_review_days_ago"])
}

violation_3_3_3 contains msg if {
	_actual(["audit", "last_review_days_ago"]) > _odp("audit_event_review_interval_days")
	msg := sprintf("3.3.3: logged event types last reviewed %v days ago, beyond the organisation-defined review interval of %v days", [_actual(["audit", "last_review_days_ago"]), _odp("audit_event_review_interval_days")])
}

# ---------------------------------------------------------------------------
# 3.3.4 — Alert in the event of audit logging process failures. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_4 := false

compliant_3_3_4 if {
	input.audit.failure_alerting_enabled == true
	input.audit.space_left_action != "ignore"
	input.audit.admin_space_left_action != "ignore"
}

violation_3_3_4 contains msg if {
	not input.audit.failure_alerting_enabled
	msg := "3.3.4: Alerting for audit log process failures is not configured"
}

violation_3_3_4 contains msg if {
	input.audit.space_left_action == "ignore"
	msg := "3.3.4: auditd space_left_action is set to 'ignore' — disk full events will not be alerted"
}

violation_3_3_4 contains msg if {
	input.audit.admin_space_left_action == "ignore"
	msg := "3.3.4: auditd admin_space_left_action is set to 'ignore' — critical disk events will not be alerted"
}

# ---------------------------------------------------------------------------
# 3.3.5 — Correlate audit record review, analysis, and reporting processes
#          for investigation and response. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_5 := false

compliant_3_3_5 if {
	input.audit.centralized_logging == true
	input.audit.siem_integrated == true
}

violation_3_3_5 contains msg if {
	not input.audit.centralized_logging
	msg := "3.3.5: Audit logs are not centralized — cannot correlate across systems"
}

violation_3_3_5 contains msg if {
	not input.audit.siem_integrated
	msg := "3.3.5: No SIEM or log correlation tool integrated for audit analysis"
}

# ---------------------------------------------------------------------------
# 3.3.6 — Provide audit record reduction and report generation to support
#          on-demand analysis and reporting. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_6 := false

compliant_3_3_6 if {
	input.audit.report_generation_capability == true
	input.audit.log_analysis_tool != ""
}

violation_3_3_6 contains msg if {
	not input.audit.report_generation_capability
	msg := "3.3.6: No capability for audit record reduction and report generation"
}

violation_3_3_6 contains msg if {
	input.audit.log_analysis_tool == ""
	msg := "3.3.6: No log analysis tool configured for on-demand audit reporting"
}

# ---------------------------------------------------------------------------
# 3.3.7 — Provide a system capability that compares and synchronizes internal
#          system clocks with an authoritative source. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_7 := false

compliant_3_3_7 if {
	input.audit.ntp_configured == true
	count(input.audit.ntp_servers) >= 1
	input.audit.time_sync_active == true
}

violation_3_3_7 contains msg if {
	not input.audit.ntp_configured
	msg := "3.3.7: NTP/chrony is not configured for clock synchronization"
}

violation_3_3_7 contains msg if {
	count(input.audit.ntp_servers) == 0
	msg := "3.3.7: No authoritative NTP time sources configured"
}

violation_3_3_7 contains msg if {
	not input.audit.time_sync_active
	msg := "3.3.7: Time synchronization service (chronyd/ntpd) is not active"
}

# ---------------------------------------------------------------------------
# 3.3.8 — Protect audit information and audit tools from unauthorized access,
#          modification, and deletion. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_8 := false

compliant_3_3_8 if {
	input.audit.log_file_permissions_correct == true
	input.audit.log_dir_permissions_correct == true
	input.audit.auditd_immutable_config == true
}

violation_3_3_8 contains msg if {
	not input.audit.log_file_permissions_correct
	msg := "3.3.8: Audit log file permissions allow unauthorized access"
}

violation_3_3_8 contains msg if {
	not input.audit.log_dir_permissions_correct
	msg := "3.3.8: Audit log directory permissions allow unauthorized access"
}

violation_3_3_8 contains msg if {
	not input.audit.auditd_immutable_config
	msg := "3.3.8: auditd configuration is not protected from modification (missing -e 2)"
}

# ---------------------------------------------------------------------------
# 3.3.9 — Limit management of audit logging to a subset of privileged users. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_9 := false

compliant_3_3_9 if {
	input.audit.management_restricted == true
	count(input.audit.audit_admins) > 0
	_admins_within_defined_subset
}

# 3.3.9: the subset of privileged users is organisation-defined (NIST SP 800-171A
# 3.3.9[a]); the former fixed maximum of 5 is replaced by membership of that subset.
_defined_subset := {u | some u in input.org_defined.audit_logging_managers} if is_array(input.org_defined.audit_logging_managers)

_admins_within_defined_subset if {
	_defined_subset
	is_array(input.audit.audit_admins)
	every a in input.audit.audit_admins {
		a in _defined_subset
	}
}

violation_3_3_9 contains "3.3.9: evidence missing - input.org_defined.audit_logging_managers (organisation-defined subset of privileged users, NIST SP 800-171A 3.3.9[a]) not supplied or not an array" if {
	not is_array(object.get(input, ["org_defined", "audit_logging_managers"], null))
}

violation_3_3_9 contains msg if {
	_defined_subset
	some a in input.audit.audit_admins
	not a in _defined_subset
	msg := sprintf("3.3.9: '%v' manages audit logging but is not in the organisation-defined subset of privileged users", [a])
}

violation_3_3_9 contains msg if {
	not input.audit.management_restricted
	msg := "3.3.9: Audit log management is not restricted to privileged users"
}

violation_3_3_9 contains msg if {
	count(input.audit.audit_admins) == 0
	msg := "3.3.9: No designated privileged users for audit management"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

base_violations := array.concat(
	array.concat(
		array.concat(
			[v | some v in violation_3_3_1],
			[v | some v in violation_3_3_2],
		),
		array.concat(
			[v | some v in violation_3_3_3],
			[v | some v in violation_3_3_4],
		),
	),
	array.concat(
		array.concat(
			[v | some v in violation_3_3_5],
			[v | some v in violation_3_3_6],
		),
		array.concat(
			array.concat(
				[v | some v in violation_3_3_7],
				[v | some v in violation_3_3_8],
			),
			[v | some v in violation_3_3_9],
		),
	),
)

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing or failing must surface a violation, so that the domain verdict
#   (count(all_violations) == 0) can never be true while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	not compliant_3_3_1
	count(violation_3_3_1) == 0
	msg := "3.3.1: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_2
	count(violation_3_3_2) == 0
	msg := "3.3.2: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_3
	count(violation_3_3_3) == 0
	msg := "3.3.3: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_4
	count(violation_3_3_4) == 0
	msg := "3.3.4: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_5
	count(violation_3_3_5) == 0
	msg := "3.3.5: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_6
	count(violation_3_3_6) == 0
	msg := "3.3.6: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_7
	count(violation_3_3_7) == 0
	msg := "3.3.7: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_8
	count(violation_3_3_8) == 0
	msg := "3.3.8: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_3_9
	count(violation_3_3_9) == 0
	msg := "3.3.9: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

all_violations := array.concat(base_violations, [m | some m in violation_unmet])

practices := [
	{"id": "3.3.1", "level": 2, "compliant": compliant_3_3_1},
	{"id": "3.3.2", "level": 2, "compliant": compliant_3_3_2},
	{"id": "3.3.3", "level": 2, "compliant": compliant_3_3_3},
	{"id": "3.3.4", "level": 2, "compliant": compliant_3_3_4},
	{"id": "3.3.5", "level": 2, "compliant": compliant_3_3_5},
	{"id": "3.3.6", "level": 2, "compliant": compliant_3_3_6},
	{"id": "3.3.7", "level": 2, "compliant": compliant_3_3_7},
	{"id": "3.3.8", "level": 2, "compliant": compliant_3_3_8},
	{"id": "3.3.9", "level": 2, "compliant": compliant_3_3_9},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"domain": "Audit & Accountability",
	"domain_id": "3.3",
	"total_practices": 9,
	"passing": passing_count,
	"failing": 9 - passing_count,
	"compliant": compliant,
	"violations": all_violations,
	"practices": practices,
}
