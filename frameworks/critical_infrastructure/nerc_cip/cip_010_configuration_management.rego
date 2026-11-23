# METADATA
# title: "CIP-010-4: Configuration Change Management and Vulnerability Assessments"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 23
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_010

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default active_vulnerability_monitoring := false

default authenticated_scanning_used := false

default baseline_configurations_established := false

default change_management_process_documented := false

default configuration_changes_authorized := false

default configuration_monitoring_timely := false

default post_change_assessment := false

default software_integrity_verification := false

default transient_asset_config_managed := false

default unauthorized_change_monitoring := false

default vulnerability_assessments_performed := false

default vulnerability_remediation_tracked := false

# -----------------------------------------------------------------------------
# Dated evidence
# -----------------------------------------------------------------------------

# Date normaliser: RFC 3339 strings or epoch nanoseconds; anything else is
# undefined, so the caller fails closed.
date_ns(v) := n if {
	is_string(v)
	n := time.parse_rfc3339_ns(v)
}

date_ns(v) := v if is_number(v)

# Evaluation clock. Tests pin it with `with time.now_ns as <ns>`.
now_ns := time.now_ns()

ns_per_day := 86400000000000

# Age in days of a dated record. Undefined when the date is absent, not a date,
# or later than the evaluation time: an activity dated in the future has not
# happened yet and is not evidence that it was done.
age_days(v) := (now_ns - date_ns(v)) / ns_per_day if date_ns(v) <= now_ns

# Days from start to end. Undefined when either date is absent or not a date,
# or when the end date is later than the evaluation time.
days_between(start, end) := (date_ns(end) - date_ns(start)) / ns_per_day if date_ns(end) <= now_ns

# Why a dated record cannot be used: "future", or "missing" when it is absent,
# of the wrong type or not RFC 3339. Undefined for a usable date.
date_problem(v) := "future" if date_ns(v) > now_ns

date_problem(v) := "missing" if not date_ns(v)

# Per-system requirements need the BES Cyber System inventory to have been collected.
bes_inventory_present if is_array(input.bes_cyber_systems)

# CIP-010-4: Configuration Change Management and Vulnerability Assessments
# Requirement: Prevent and detect unauthorized changes to BES Cyber Systems
# by specifying configuration change management and vulnerability assessment
# requirements.
#
# NERC Standards Reference: CIP-010-4
# (mandatory and enforceable in the United States; CIP-010-5 is approved with an
# effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-010-4.pdf
#
# Requirement parts of CIP-010-4 and the checks that read them:
#   R1  change management: 1.1 baseline configuration (1.1.1-1.1.5), 1.2 authorize
#       and document changes, 1.3 update the baseline within 30 days (inside the
#       1.2 check), 1.4 verify security controls after a change, 1.5 test changes
#       (not implemented), 1.6 software source identity and integrity
#   R2  2.1 monitor for baseline changes at least once every 35 calendar days
#   R3  vulnerability assessments: 3.1 every 15 calendar months, 3.2 active
#       assessment every 36 calendar months (not implemented), 3.3 before adding
#       a new Cyber Asset (not implemented), 3.4 results and action plan
#   R4  Transient Cyber Assets and Removable Media (Attachment 1)
#
# Monitoring of vulnerability announcements is not a numbered part of CIP-010-4
# (patch source tracking is CIP-007-6 R2 Part 2.1); it is kept as a supporting
# check under R3 and says so.

# =============================================================================
# R1: Configuration Change Management
# =============================================================================

# R1 - Documented configuration change management process
change_management_process_documented if {
	input.configuration_change_management.process_documented == true
	input.configuration_change_management.approval_process_defined == true
	input.configuration_change_management.testing_requirements_defined == true
	input.configuration_change_management.rollback_procedures_defined == true
}

# R1.1 - Baseline configuration for each applicable BES Cyber System
baseline_configurations_established if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not baseline_configuration_exists(system)
	]
	count(violations) == 0
}

baseline_configuration_exists(system) if {
	baseline := input.baseline_configurations[system.system_id]
	baseline.documented == true
	baseline.current == true
	baseline.authorized == true
	baseline.change_controlled == true

	# Baseline must include: OS/firmware, commercially available software, custom software,
	# logical network accessible ports, security patches
	baseline.includes_os_firmware == true
	baseline.includes_commercial_software == true
	baseline.includes_logical_ports == true
	baseline.includes_security_patches == true
}

# R1.2 - Authorize and document changes that deviate from the baseline (with
# Part 1.3, baseline updated after the change)
configuration_changes_authorized if {
	violations := [change |
		change := input.configuration_changes[_]
		not change_control_adequate(change)
	]
	count(violations) == 0
}

change_control_adequate(change) if {
	change.approval_required == true
	change.approval_documented == true
	change.testing_performed == true
	change.implementation_documented == true
	change.rollback_plan_defined == true
	change.post_implementation_baseline_update == true
}

# R2.1 - Monitor for changes to the baseline configuration; document and
# investigate detected unauthorized changes
unauthorized_change_monitoring if {
	bes_inventory_present

	# Judge only high/medium systems: a low impact system is out of scope and must
	# not make the whole requirement false.
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		sys_monitoring := input.configuration_monitoring[system.system_id]
		sys_monitoring.enabled == true
		sys_monitoring.change_detection == true
		sys_monitoring.alerting_configured == true
		sys_monitoring.baseline_comparison == true
	}
}

# R3 (supporting) - Monitor for vulnerability announcements; not a numbered
# part of CIP-010-4
active_vulnerability_monitoring if {
	input.vulnerability_monitoring.ics_cert_monitoring == true
	input.vulnerability_monitoring.vendor_advisories_monitored == true
	input.vulnerability_monitoring.response_process_documented == true
}

# R1.6 - Verify the identity of the software source (1.6.1) and the integrity of
# the software (1.6.2)
software_integrity_verification if {
	input.software_integrity.verification_process_documented == true
	input.software_integrity.hash_verification == true
	input.software_integrity.vendor_verification == true
}

# =============================================================================
# R2: Configuration Monitoring
# =============================================================================

# R2.1 - ...at least once every 35 calendar days
configuration_monitoring_timely if {
	bes_inventory_present
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		sys_monitoring := input.configuration_monitoring[system.system_id]
		age_days(sys_monitoring.last_review_date) <= 35
	}
}

# =============================================================================
# R3: Vulnerability Assessments
# =============================================================================

# R3.1 - Conduct vulnerability assessments at least every 15 calendar months
vulnerability_assessments_performed if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not vulnerability_assessment_current(system)
	]
	count(violations) == 0
}

vulnerability_assessment_current(system) if {
	assessment := input.vulnerability_assessments[system.system_id]
	age_days(assessment.completion_date) <= 455 # 15 calendar months
	assessment.documented == true
	assessment.remediation_plan_exists == true
}

# R3.4 - Document the results and the action plan to remediate or mitigate the
# vulnerabilities identified
vulnerability_remediation_tracked if {
	every assessment in input.vulnerability_assessments {
		assessment.vulnerabilities_tracked == true
		assessment.remediation_status_documented == true
		assessment.risk_accepted_documented_if_not_remediated == true
	}
}

# R3 (advisory) - Where possible, perform authenticated scanning. Not a numbered
# part: Part 3.2 is an active assessment every 36 calendar months.
# ADVISORY (decisions 2026-10-19): "where possible" is not a "shall", so this is
# reported in `requirements` but deliberately does not feed `compliant`.
authenticated_scanning_used if {
	bes_inventory_present
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		sys_scan := input.vulnerability_assessments[system.system_id]
		sys_scan.authenticated_scan_used == true
	}
}

# R1.4 - After a change, verify that the required cyber security controls are
# not adversely affected (read here from the post-change assessment flag)
post_change_assessment if {
	violations := [change |
		change := input.configuration_changes[_]
		change.is_major_change == true
		not change.post_change_vulnerability_assessment_performed == true
	]
	count(violations) == 0
}

# =============================================================================
# R4: Transient Cyber Assets (TCA) Configuration (Attachment 1)

# Dated evidence the recency checks read.
dated_evidence contains {"requirement": e.requirement, "path": sprintf("%s[%v].%s", [e.collection, system.system_id, e.field]), "value": object.get(input, [e.collection, system.system_id, e.field], null)} if {
	some system in input.bes_cyber_systems
	system.impact_categorization in ["high", "medium"]
	some e in [
		{"requirement": "R2.1", "collection": "configuration_monitoring", "field": "last_review_date"},
		{"requirement": "R3.1", "collection": "vulnerability_assessments", "field": "completion_date"},
	]
}
# =============================================================================

# Transient Cyber Assets connected to High/Medium Impact BES Cyber Systems
transient_asset_config_managed if {
	input.transient_cyber_assets.config_management.policy_documented == true
	input.transient_cyber_assets.config_management.inventory_maintained == true
	input.transient_cyber_assets.config_management.security_controls_applied == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not change_management_process_documented
	v := {
		"standard": "CIP-010",
		"requirement": "R1",
		"severity": "high",
		"description": "Configuration change management process not documented",
		"remediation": "Document change management process with approval, testing, and rollback requirements",
	}
}

violations contains v if {
	not baseline_configurations_established
	v := {
		"standard": "CIP-010",
		"requirement": "R1.1",
		"severity": "critical",
		"description": "Baseline configurations not established for one or more High/Medium Impact BES Cyber Systems",
		"remediation": "Establish and maintain baseline configurations including OS, software, ports, and patches",
	}
}

violations contains v if {
	not configuration_changes_authorized
	v := {
		"standard": "CIP-010",
		"requirement": "R1.2",
		"severity": "critical",
		"description": "Unauthorized configuration changes detected or change control process inadequate",
		"remediation": "Implement change control requiring authorization, testing, documentation, and baseline update",
	}
}

violations contains v if {
	not unauthorized_change_monitoring
	v := {
		"standard": "CIP-010",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Unauthorized change monitoring not implemented for all applicable systems",
		"remediation": "Implement continuous monitoring comparing current configuration to authorized baseline",
	}
}

violations contains v if {
	not configuration_monitoring_timely
	v := {
		"standard": "CIP-010",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Configuration monitoring review not performed within 35 days for some systems",
		"remediation": "Perform configuration monitoring review at least every 35 days",
	}
}

violations contains v if {
	not vulnerability_assessments_performed
	v := {
		"standard": "CIP-010",
		"requirement": "R3.1",
		"severity": "high",
		"description": "Vulnerability assessments not performed within 15 calendar months for some systems",
		"remediation": "Conduct vulnerability assessments at least every 15 calendar months",
	}
}

violations contains v if {
	not vulnerability_remediation_tracked
	v := {
		"standard": "CIP-010",
		"requirement": "R3.4",
		"severity": "high",
		"description": "Identified vulnerabilities not being tracked and remediated",
		"remediation": "Track all identified vulnerabilities with remediation status; document accepted risks",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not active_vulnerability_monitoring
	v := {
		"standard": "CIP-010",
		"requirement": "R3",
		"severity": "medium",
		"description": "CIP-010 R3: active vulnerability monitoring requirement not met",
		"remediation": "Satisfy and evidence the active vulnerability monitoring requirement (CIP-010 R3)",
	}
}

violations contains v if {
	not software_integrity_verification
	v := {
		"standard": "CIP-010",
		"requirement": "R1.6",
		"severity": "medium",
		"description": "CIP-010 R1.6: software integrity verification requirement not met",
		"remediation": "Satisfy and evidence the software integrity verification requirement (CIP-010 R1.6)",
	}
}

violations contains v if {
	not post_change_assessment
	v := {
		"standard": "CIP-010",
		"requirement": "R1.4",
		"severity": "medium",
		"description": "CIP-010 R1.4: post change assessment requirement not met",
		"remediation": "Satisfy and evidence the post change assessment requirement (CIP-010 R1.4)",
	}
}

violations contains v if {
	not transient_asset_config_managed
	v := {
		"standard": "CIP-010",
		"requirement": "R4",
		"severity": "medium",
		"description": "CIP-010 R4: transient asset config managed requirement not met",
		"remediation": "Satisfy and evidence the transient asset config managed requirement (CIP-010 R4)",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-010",
		"requirement": e.requirement,
		"severity": "medium",
		"description": sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [e.path]),
		"remediation": sprintf("Collect input.%s as an RFC 3339 timestamp", [e.path]),
	}
}

violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "future"
	v := {
		"standard": "CIP-010",
		"requirement": e.requirement,
		"severity": "high",
		"description": sprintf("input.%s (%v) is later than the evaluation time — a future date is not evidence of a completed activity", [e.path, e.value]),
		"remediation": sprintf("Record in input.%s the date the activity was actually completed", [e.path]),
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	change_management_process_documented
	baseline_configurations_established
	configuration_changes_authorized
	unauthorized_change_monitoring
	active_vulnerability_monitoring
	software_integrity_verification
	configuration_monitoring_timely
	vulnerability_assessments_performed
	vulnerability_remediation_tracked
	post_change_assessment
	transient_asset_config_managed
}

report := {
	"standard": "CIP-010-4",
	"title": "Configuration Change Management and Vulnerability Assessments",
	"compliant": compliant,
	"requirements": {
		"R1_change_management_process": change_management_process_documented,
		"R1_1_baselines_established": baseline_configurations_established,
		"R1_2_changes_authorized": configuration_changes_authorized,
		"R1_4_post_change_assessment": post_change_assessment,
		"R1_6_software_integrity": software_integrity_verification,
		"R2_1_unauthorized_change_monitoring": unauthorized_change_monitoring,
		"R2_1_monitoring_timely": configuration_monitoring_timely,
		"R3_1_vulnerability_assessments": vulnerability_assessments_performed,
		"R3_4_remediation_tracked": vulnerability_remediation_tracked,
		"R3_supporting_vulnerability_monitoring": active_vulnerability_monitoring,
		"R3_advisory_authenticated_scanning": authenticated_scanning_used,
		"R4_transient_asset_config": transient_asset_config_managed,
	},
	"violations": violations,
	"violation_count": count(violations),
}
