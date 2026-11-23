# METADATA
# title: "CIP-012-2: Communications Between Control Centers"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 24
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_012

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default backup_communication_protected := false

default communication_authentication := false

default communication_availability_protected := false

default communication_contingency_plans_established := false

default communication_data_classified := false

default communication_encryption := false

default communication_log_review := false

default communication_monitoring_enabled := false

default communication_plan_current := false

default communication_protection_implemented := false

default communication_protection_tested := false

default communication_recovery_methods_identified := false

default communication_responsibilities_identified := false

default control_center_communications_identified := false

# CIP-012-2: Communications Between Control Centers
# Purpose: Protect the confidentiality, integrity, and availability of Real-time
# Assessment and Real-time monitoring data transmitted between Control Centers.
#
# Applicability: Responsible Entities (BA, GOP, GO, RC, TOP, TO) that own or
# operate a Control Center.
#
# NERC Standards Reference: CIP-012-2 (FERC Docket No. RD24-3-000; mandatory and
# enforceable in the United States from 2026-07-01, replacing CIP-012-1).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-012-2.pdf
#
# The standard has ONE requirement, R1: implement one or more documented plan(s)
# to mitigate the risks posed by unauthorized disclosure, unauthorized
# modification, and loss of availability of the data in transit. The plan shall
# include:
#   1.1  method(s) against unauthorized disclosure and unauthorized modification
#   1.2  method(s) against the loss of the ability to communicate the data   (new in -2)
#   1.3  method(s) to initiate the recovery of communication links           (new in -2)
#   1.4  where the methods of Parts 1.1 and 1.2 are implemented
#   1.5  responsibilities of each Responsible Entity when the Control Centers
#        are owned or operated by different Responsible Entities
#
# CIP-012-2 has no numbered part for monitoring, log review, plan review or
# testing (earlier releases of this module labelled them R3 and R5, which do not
# exist). They are kept as evidence that the R1 plan is implemented (Measure M1:
# "documentation demonstrating the implementation of the plan(s)"), are labelled
# R1, and say in the finding that they are supporting checks.

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

# Why a dated record cannot be used: "future", or "missing" when it is absent,
# of the wrong type or not RFC 3339. Undefined for a usable date.
date_problem(v) := "future" if date_ns(v) > now_ns

date_problem(v) := "missing" if not date_ns(v)

# The link inventory must have been collected and be non-empty for any per-link
# part to be judged: no links is no evidence.
links_present if {
	is_array(input.control_center_communications.links)
	count(input.control_center_communications.links) > 0
}

# =============================================================================
# R1 Part 1.4: Where the methods are implemented
# =============================================================================

# R1.4 - Identify where the methods of Parts 1.1 and 1.2 are implemented: every
# communication link that carries Real-time Assessment or Real-time monitoring
# data between Control Centers

control_center_communications_identified if {
	input.control_center_communications.inventory_maintained == true
	input.control_center_communications.criticality_assessed == true
	input.control_center_communications.protection_requirements_defined == true
	count(object.get(input, ["control_center_communications", "links"], [])) > 0
}

# All communication links must have their data types classified
communication_data_classified if {
	every link in input.control_center_communications.links {
		link.data_types_identified == true
		link.real_time_assessment_data_flag
		link.real_time_monitoring_data_flag
	}
}

# =============================================================================
# R1 Part 1.1: Unauthorized disclosure and unauthorized modification
# =============================================================================

# R1.1 - Method(s) used to mitigate the risk(s) posed by unauthorized disclosure
# and unauthorized modification of the data while it is being transmitted

communication_protection_implemented if {
	violations := [link |
		link := input.control_center_communications.links[_]
		not communication_protection_adequate(link)
	]
	count(violations) == 0
}

communication_protection_adequate(link) if {
	link.encryption_enabled == true
	link.authentication_implemented == true
	link.integrity_protection == true
}

# Encryption requirements for communication links
communication_encryption if {
	every link in input.control_center_communications.links {
		link.encryption.algorithm_documented == true
		link.encryption.key_management_documented == true
		link.encryption.minimum_strength_adequate == true # at least AES-128
	}
}

# Authentication for control center to control center links
communication_authentication if {
	every link in input.control_center_communications.links {
		link.authentication.method_documented == true
		link.authentication.bidirectional == true
	}
}

# =============================================================================
# R1 (supporting): Communication Monitoring — implementation evidence
# =============================================================================

# Monitor real-time communication links for unauthorized activity
communication_monitoring_enabled if {
	input.communication_monitoring.enabled == true
	input.communication_monitoring.logging_implemented == true
	input.communication_monitoring.anomaly_detection == true
	input.communication_monitoring.alerting_configured == true
}

# Review communication link logs regularly
communication_log_review if {
	age_days(input.communication_monitoring.last_review_date) <= 35
}

# =============================================================================
# R1 Part 1.2: Loss of the ability to communicate (availability)
# =============================================================================

# R1.2 - Method(s) used to mitigate the risk(s) posed by the loss of the ability
# to communicate the data between Control Centers (new in CIP-012-2). Measure M1
# gives alternative communication paths, procedures for alternative methods,
# carrier service levels and availability reports as examples.
communication_contingency_plans_established if {
	input.communication_contingency.plans_documented == true
	input.communication_contingency.backup_communications == true
	input.communication_contingency.testing_performed == true
}

# Every link has an identified availability method.
communication_availability_protected if {
	links_present
	every link in input.control_center_communications.links {
		link.availability_protection == true
	}
}

# =============================================================================
# R1 Part 1.3: Recovery of communication links
# =============================================================================

# R1.3 - Method(s) used to initiate the recovery of communication links used to
# transmit the data between Control Centers (new in CIP-012-2)
communication_recovery_methods_identified if {
	input.communication_contingency.recovery_procedures == true
}

# =============================================================================
# R1 Part 1.5: Responsibilities between Responsible Entities
# =============================================================================

# R1.5 - If the Control Centers are owned or operated by different Responsible
# Entities, the responsibilities of each for the methods of Parts 1.1, 1.2 and
# 1.3 are identified. Each link states `other_entity_operated` as a boolean; an
# absent statement is evidence missing, not "same entity".
communication_responsibilities_identified if {
	links_present
	every link in input.control_center_communications.links {
		link_responsibilities_identified(link)
	}
}

link_responsibilities_identified(link) if link.other_entity_operated == false

link_responsibilities_identified(link) if {
	link.other_entity_operated == true
	link.responsibilities_documented == true
}

# R1.1 - Backup communication links carry the same data and need the same
# protection against disclosure and modification.
# Backup links are judged whenever they are listed, whether or not backup_links_exist
# is set. A missing backup_links_exist flag is not a waiver: only an explicit
# `backup_links_exist: false` with no listed backup links means there are none.
backup_communication_protected if {
	input.communication_contingency.backup_links_exist == false
	count(object.get(input, ["communication_contingency", "backup_links"], [])) == 0
} else if {
	is_array(input.communication_contingency.backup_links)
	count(input.communication_contingency.backup_links) > 0
	every link in input.communication_contingency.backup_links {
		link.same_protection_level == true
		link.encryption_enabled == true
		link.authentication_implemented == true
	}
}

# =============================================================================
# R1 (supporting): Plan Review and Testing — implementation evidence
# =============================================================================

# Review communication security plan at least every 15 calendar months
communication_plan_current if {
	age_days(input.control_center_communications.last_review_date) <= 455
}

# Test communication protection methods
communication_protection_tested if {
	age_days(input.control_center_communications.last_test_date) <= 455
	input.control_center_communications.test_documented == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not control_center_communications_identified
	v := {
		"standard": "CIP-012",
		"requirement": "R1.4",
		"severity": "high",
		"description": "Control Center communications links not identified or inventory not maintained",
		"remediation": "Identify and document all communication links transferring real-time data between Control Centers",
	}
}

violations contains v if {
	not communication_data_classified
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "medium",
		"description": "Data types on communication links not classified (real-time assessment vs monitoring)",
		"remediation": "Classify data types on all inter-Control Center communication links",
	}
}

violations contains v if {
	not communication_protection_implemented
	v := {
		"standard": "CIP-012",
		"requirement": "R1.1",
		"severity": "critical",
		"description": "One or more Control Center communication links lack adequate encryption and integrity protection",
		"remediation": "Implement encryption, authentication, and integrity protection on all applicable communication links",
	}
}

violations contains v if {
	not communication_encryption
	v := {
		"standard": "CIP-012",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "CIP-012 R1.1: communication encryption requirement not met",
		"remediation": "Satisfy and evidence the communication encryption requirement (CIP-012 R1.1)",
	}
}

violations contains v if {
	not communication_authentication
	v := {
		"standard": "CIP-012",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "CIP-012 R1.1: communication authentication requirement not met",
		"remediation": "Satisfy and evidence the communication authentication requirement (CIP-012 R1.1)",
	}
}

violations contains v if {
	not backup_communication_protected
	v := {
		"standard": "CIP-012",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "CIP-012 R1.1: backup communication protected requirement not met",
		"remediation": "Satisfy and evidence the backup communication protected requirement (CIP-012 R1.1)",
	}
}

violations contains v if {
	not communication_contingency_plans_established
	v := {
		"standard": "CIP-012",
		"requirement": "R1.2",
		"severity": "medium",
		"description": "Communication contingency plans not documented or backup communications not established",
		"remediation": "Establish and test contingency plans with backup communication methods",
	}
}

violations contains v if {
	not communication_availability_protected
	v := {
		"standard": "CIP-012",
		"requirement": "R1.2",
		"severity": "high",
		"description": "One or more Control Center communication links have no identified method against the loss of the ability to communicate (availability)",
		"remediation": "Identify an availability method for every link: an alternative path or method, carrier service levels or equivalent",
	}
}

violations contains v if {
	not communication_recovery_methods_identified
	v := {
		"standard": "CIP-012",
		"requirement": "R1.3",
		"severity": "medium",
		"description": "Methods to initiate the recovery of communication links between Control Centers not identified",
		"remediation": "Document the procedures used to initiate recovery of each communication link",
	}
}

violations contains v if {
	not communication_responsibilities_identified
	v := {
		"standard": "CIP-012",
		"requirement": "R1.5",
		"severity": "medium",
		"description": "Responsibilities between Responsible Entities not identified for one or more Control Center communication links, or other_entity_operated not declared",
		"remediation": "State for every link whether another Responsible Entity owns or operates the far-end Control Center and, where one does, document each entity's responsibilities for Parts 1.1, 1.2 and 1.3",
	}
}

# Supporting checks: implementation evidence for the R1 plan, not numbered parts.
violations contains v if {
	not communication_monitoring_enabled
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "high",
		"description": "Communication link monitoring not enabled or alerting not configured (R1 supporting check: implementation evidence, not a numbered part of CIP-012-2)",
		"remediation": "Implement monitoring, logging, and anomaly detection for all Control Center communication links",
	}
}

violations contains v if {
	not communication_log_review
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "medium",
		"description": "Communication link logs not reviewed within 35 days (R1 supporting check: implementation evidence, not a numbered part of CIP-012-2)",
		"remediation": "Review communication monitoring logs at least every 35 days",
	}
}

violations contains v if {
	not communication_plan_current
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "medium",
		"description": "Communication security plan not reviewed within 15 calendar months (R1 supporting check: implementation evidence, not a numbered part of CIP-012-2)",
		"remediation": "Review and update communication security plan within 15 calendar months",
	}
}

violations contains v if {
	not communication_protection_tested
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "medium",
		"description": "CIP-012 R1: communication protection tested requirement not met (supporting check: implementation evidence, not a numbered part of CIP-012-2)",
		"remediation": "Test the communication protection methods within 15 calendar months and document the test",
	}
}

# Dated evidence the recency checks read.
dated_evidence contains {"requirement": "R1", "path": "communication_monitoring.last_review_date", "value": object.get(input, ["communication_monitoring", "last_review_date"], null)}

dated_evidence contains {"requirement": "R1", "path": "control_center_communications.last_review_date", "value": object.get(input, ["control_center_communications", "last_review_date"], null)}

dated_evidence contains {"requirement": "R1", "path": "control_center_communications.last_test_date", "value": object.get(input, ["control_center_communications", "last_test_date"], null)}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-012",
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
		"standard": "CIP-012",
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
	control_center_communications_identified
	communication_data_classified
	communication_protection_implemented
	communication_encryption
	communication_authentication
	backup_communication_protected
	communication_contingency_plans_established
	communication_availability_protected
	communication_recovery_methods_identified
	communication_responsibilities_identified
	communication_monitoring_enabled
	communication_log_review
	communication_plan_current
	communication_protection_tested
}

report := {
	"standard": "CIP-012-2",
	"title": "Communications Between Control Centers",
	"compliant": compliant,
	"requirements": {
		"R1_data_classified": communication_data_classified,
		"R1_1_protection_implemented": communication_protection_implemented,
		"R1_1_encryption": communication_encryption,
		"R1_1_authentication": communication_authentication,
		"R1_1_backup_protected": backup_communication_protected,
		"R1_2_contingency_plans": communication_contingency_plans_established,
		"R1_2_availability_protected": communication_availability_protected,
		"R1_3_recovery_methods": communication_recovery_methods_identified,
		"R1_4_communications_identified": control_center_communications_identified,
		"R1_5_responsibilities_identified": communication_responsibilities_identified,
	},
	"supporting": {
		"R1_monitoring_enabled": communication_monitoring_enabled,
		"R1_log_review": communication_log_review,
		"R1_plan_current": communication_plan_current,
		"R1_protection_tested": communication_protection_tested,
	},
	"link_summary": {
		"total_links": count(object.get(input, ["control_center_communications", "links"], [])),
		"protected_links": count([l | l := input.control_center_communications.links[_]; l.encryption_enabled == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
