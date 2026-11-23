# METADATA
# title: "NERC CIP-015-1: Internal Network Security Monitoring (INSM)"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 10
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package nerc_cip_cip015

import rego.v1

# NERC CIP-015-1: Internal Network Security Monitoring (INSM)
# NERC Board adoption 2024-05-09; FERC order issued 2025-06-26 (Docket No.
# RM24-7-000). US status on 2026-11-23: subject to future enforcement, effective
# date of the requirements 2028-10-01 (NERC US Effective Date Status workbook).
# CIP-015-2 is approved (2026-08-10) with an effective date of 2029-10-01.
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-015-1.pdf
#
# Applies to networks protected by the Electronic Security Perimeter(s) of:
#   - High Impact BES Cyber Systems
#   - Medium Impact BES Cyber Systems with External Routable Connectivity (ERC)
#
# Requirements of CIP-015-1:
#   R1 - documented process(es) for INSM: 1.1 network data feeds chosen with a
#        risk-based rationale, 1.2 method(s) to detect anomalous network
#        activity, 1.3 method(s) to evaluate anomalous activity
#   R2 - retain INSM data associated with anomalous activity
#   R3 - protect INSM data from unauthorized deletion or modification
#
# What this module checks, and under which part it reports:
#   r1_*   scoping of the systems that need INSM and a yearly review of that
#          scope: supporting checks for R1 (CIP-015-1 has no categorization or
#          annual review requirement)
#   r2_1, r2_2, r2_3   network baseline, anomaly detection, malicious
#          communication detection: R1 Part 1.2
#   r2_4   response process for anomalous or malicious communications: R1 Part 1.3
#   r3_*   INSM documentation exists (R1, "documented process(es)") and was
#          reviewed within 15 calendar months (supporting check)
# The rule names keep their historical r1/r2/r3 prefixes; the findings carry the
# CIP-015-1 part. Not implemented: R1 Part 1.1, R2 (retention), R3 (protection).

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

# ---------------------------------------------------------------------------
# R1: INSM Categorization
# Identify BES Cyber Systems with ERC that require INSM, review annually
# ---------------------------------------------------------------------------

r1_compliant if {
	r1_systems_identified
	r1_annual_review_current
}

# At least one system must be evaluated for INSM applicability. Systems that are
# explicitly out of scope (low impact, or no External Routable Connectivity) are
# not judged: listing one must not make R1 false.
r1_systems_identified if {
	count(input.insm.systems) > 0
	every system in [s | some s in input.insm.systems; not insm_out_of_scope(s)] {
		system.system_id
		system.impact_categorization in ["high", "medium"]
		system.has_external_routable_connectivity == true
		system.esp_name
	}
}

insm_out_of_scope(system) if system.impact_categorization == "low"

insm_out_of_scope(system) if system.has_external_routable_connectivity == false

r1_annual_review_current if {
	age_days(input.insm.categorization_review_date) <= 365
}

# ---------------------------------------------------------------------------
# R2: INSM Implementation
# For each system in R1, implement monitoring within each ESP
# ---------------------------------------------------------------------------

# No INSM system inventory is no evidence: R2 cannot be reported compliant.
insm_systems_present if {
	is_array(input.insm.systems)
	count(input.insm.systems) > 0
}

# Systems in scope for R2 (High/Medium impact with External Routable Connectivity)
r2_applicable(system) if {
	system.impact_categorization in ["high", "medium"]
	system.has_external_routable_connectivity == true
}

# Each sub-requirement needs ALL of its elements (they were previously OR-ed, so
# one satisfied element reported the whole sub-requirement as met).
r2_1_ok(system) if {
	system.network_baseline.established == true
	system.network_baseline.documented == true
}

r2_2_ok(system) if {
	system.anomaly_detection.implemented == true
	system.anomaly_detection.covers_esp == true
}

r2_3_ok(system) if {
	system.malicious_comm_detection.capability_documented == true
	count(system.malicious_comm_detection.tools) > 0
}

r2_4_ok(system) if {
	system.response_process.documented == true
	system.response_process.includes_notification == true
	system.response_process.includes_investigation == true
}

r2_compliant if {
	insm_systems_present
	count(r2_violations) == 0
}

# CIP-015-1 R1.2: Network baseline established for each applicable system's ESP
r2_1_compliant if {
	insm_systems_present
	violations := [system |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_1_ok(system)
	]
	count(violations) == 0
}

# CIP-015-1 R1.2: Anomaly detection implemented within each ESP
r2_2_compliant if {
	insm_systems_present
	violations := [system |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_2_ok(system)
	]
	count(violations) == 0
}

# CIP-015-1 R1.2: Capability to identify malicious communications within the ESP
r2_3_compliant if {
	insm_systems_present
	violations := [system |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_3_ok(system)
	]
	count(violations) == 0
}

# CIP-015-1 R1.3: Response process for malicious or anomalous communications
r2_4_compliant if {
	insm_systems_present
	violations := [system |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_4_ok(system)
	]
	count(violations) == 0
}

# Aggregate R2 sub-requirement violations
r2_violations := violations if {
	r2_1_v := [v |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_1_ok(system)
		v := {
			"system_id": system.system_id,
			"sub_requirement": "R1.2",
			"finding": "Network baseline not established and documented for ESP",
			"esp": system.esp_name,
		}
	]
	r2_2_v := [v |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_2_ok(system)
		v := {
			"system_id": system.system_id,
			"sub_requirement": "R1.2",
			"finding": "Anomaly detection not implemented across the ESP",
			"esp": system.esp_name,
		}
	]
	r2_3_v := [v |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_3_ok(system)
		v := {
			"system_id": system.system_id,
			"sub_requirement": "R1.2",
			"finding": "Malicious communication detection capability not documented or no tools identified",
			"esp": system.esp_name,
		}
	]
	r2_4_v := [v |
		system := input.insm.systems[_]
		r2_applicable(system)
		not r2_4_ok(system)
		v := {
			"system_id": system.system_id,
			"sub_requirement": "R1.3",
			"finding": "Response process for anomalous/malicious communications not fully documented (documented, notification, investigation)",
			"esp": system.esp_name,
		}
	]
	v_1_2 := array.concat(r2_1_v, r2_2_v)
	v_1_2_3 := array.concat(v_1_2, r2_3_v)
	violations := array.concat(v_1_2_3, r2_4_v)
}

# ---------------------------------------------------------------------------
# R3: Documentation Management
# Review and update INSM documentation within 15 calendar months (455 days)
# ---------------------------------------------------------------------------

r3_compliant if {
	r3_documentation_exists
	r3_review_current
}

r3_documentation_exists if {
	input.insm.documentation_review.documented == true
	input.insm.documentation_review.reviewer
}

r3_review_current if {
	age_days(input.insm.documentation_review.last_review_date) <= 455
}

# ---------------------------------------------------------------------------
# Overall CIP-015 Compliance
# ---------------------------------------------------------------------------

default r1_compliant := false

default r2_compliant := false

default r3_compliant := false

default r2_1_compliant := false

default r2_2_compliant := false

default r2_3_compliant := false

default r2_4_compliant := false

default r3_documentation_exists := false

default r3_review_current := false

default r1_systems_identified := false

default r1_annual_review_current := false

cip_015_compliant if {
	r1_compliant
	r2_compliant
	r3_compliant
}

default cip_015_compliant := false

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

r1_violations := [violation |
	not r1_systems_identified
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": "R1 - INSM scope (supporting check)",
		"severity": "high",
		"description": "BES Cyber Systems requiring INSM not properly identified or documented",
		"remediation": "Identify all High Impact and Medium Impact (with External Routable Connectivity) BES Cyber Systems whose ESP networks need INSM",
	}
]

r1_review_violations := [violation |
	not r1_annual_review_current
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": "R1 - scope review (supporting check, not a part of CIP-015-1)",
		"severity": "medium",
		"description": "INSM categorization review not performed within the last 365 days",
		"remediation": "Perform and document annual review of INSM categorization",
	}
]

r2_agg_violations := [violation |
	v := r2_violations[_]
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": v.sub_requirement,
		"severity": "critical",
		"description": v.finding,
		"system_id": v.system_id,
		"esp": v.esp,
		"remediation": "Implement required INSM capability within the Electronic Security Perimeter",
	}
]

r3_violations := [violation |
	not r3_documentation_exists
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": "R1 - documented process(es)",
		"severity": "medium",
		"description": "INSM documentation not established or missing required fields",
		"remediation": "Create and maintain INSM documentation with reviewer identification",
	}
]

r3_review_violations := [violation |
	not r3_review_current
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": "R1 - documentation review (supporting check, not a part of CIP-015-1)",
		"severity": "medium",
		"description": "INSM documentation not reviewed within 15 calendar months (455 days)",
		"remediation": "Review and update INSM documentation within the required 15-month window",
	}
]

# Dated evidence the recency checks read. A date that is absent, not a date, or
# later than the evaluation time gets its own finding: missing evidence is not
# reported as "overdue" and a future date is never read as a completed review.
dated_evidence := [
	{"path": "insm.categorization_review_date", "value": object.get(input, ["insm", "categorization_review_date"], null)},
	{"path": "insm.documentation_review.last_review_date", "value": object.get(input, ["insm", "documentation_review", "last_review_date"], null)},
]

date_violations := [violation |
	some e in dated_evidence
	problem := date_problem(e.value)
	violation := {
		"standard": "CIP-015",
		"requirement": "R1",
		"sub_requirement": "R1 - dated evidence (supporting check)",
		"severity": {"missing": "medium", "future": "high"}[problem],
		"description": {
			"missing": sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [e.path]),
			"future": sprintf("input.%s (%v) is later than the evaluation time — a future date is not evidence of a completed activity", [e.path, e.value]),
		}[problem],
		"remediation": sprintf("Record in input.%s the RFC 3339 date the review was actually completed", [e.path]),
	}
]

cip_015_violations := violations if {
	v_r1 := array.concat(r1_violations, r1_review_violations)
	v_r1_r2 := array.concat(v_r1, r2_agg_violations)
	v_r1_r2_r3 := array.concat(v_r1_r2, r3_violations)
	v_reviews := array.concat(v_r1_r2_r3, r3_review_violations)
	violations := array.concat(v_reviews, date_violations)
}

# ---------------------------------------------------------------------------
# Compliance Score
# ---------------------------------------------------------------------------

default cip_015_score := 0

cip_015_score := score if {
	checks := [
		r1_systems_identified,
		r1_annual_review_current,
		r2_1_compliant,
		r2_2_compliant,
		r2_3_compliant,
		r2_4_compliant,
		r3_documentation_exists,
		r3_review_current,
	]
	passed := count([c | c := checks[_]; c == true])
	score := (passed * 100) / count(checks)
}

# ---------------------------------------------------------------------------
# Compliance Report
# ---------------------------------------------------------------------------

cip_015_compliance_report := {
	"standard": "CIP-015-1",
	"title": "Internal Network Security Monitoring (INSM)",
	"compliant": cip_015_compliant,
	"score": cip_015_score,
	"requirements": {
		"R1_supporting_insm_scope": r1_compliant,
		"R1_insm_implementation": r2_compliant,
		"R1_documentation_management": r3_compliant,
	},
	"sub_requirements": {
		"R1_2_network_baseline": r2_1_compliant,
		"R1_2_anomaly_detection": r2_2_compliant,
		"R1_2_malicious_comm_detection": r2_3_compliant,
		"R1_3_response_process": r2_4_compliant,
	},
	"not_implemented": ["R1.1 network data feeds", "R2 retention of INSM data", "R3 protection of INSM data"],
	"violations": cip_015_violations,
	"violation_count": count(cip_015_violations),
	"systems_assessed": count(object.get(input, ["insm", "systems"], [])),
	"applicable_systems": count([s | s := input.insm.systems[_]; s.impact_categorization in ["high", "medium"]; s.has_external_routable_connectivity == true]),
	"metadata": {
		"standard": "NERC CIP-015-1",
		"full_title": "Internal Network Security Monitoring",
		"approved": "FERC order issued 2025-06-26 (Docket No. RM24-7-000)",
		"us_status": "subject to future enforcement",
		"us_effective_date": "2028-10-01",
		"regulatory_authority": "NERC / FERC",
		"penalties": "Up to $1M per day per violation",
	},
}
