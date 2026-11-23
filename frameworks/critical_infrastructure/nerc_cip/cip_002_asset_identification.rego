# METADATA
# title: "CIP-002-5.1a: BES Cyber System Categorization"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 22
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package nerc_cip.cip_002

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default all_bes_cyber_systems_categorized := false

default all_bes_cyber_systems_identified := false

default annual_review_performed := false

default categorization_criteria_documented := false

default cip_senior_manager_approval := false

default high_impact_criteria_documented := false

default medium_impact_criteria_documented := false

default review_triggered_by_changes := false

default eacms_classified := false

default pacs_classified := false

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

# CIP-002-5.1a: BES Cyber System Categorization
# Requirement: Identify and categorize BES Cyber Systems and their associated
# BES Cyber Assets according to the impact they could have on the reliability
# of the Bulk Electric System.
#
# Applicability: High Impact, Medium Impact, Low Impact BES Cyber Systems
# NERC Standards Reference: CIP-002-5.1a

# =============================================================================
# R1: BES Cyber System Identification and Categorization
# =============================================================================

# R1 - Each BES Cyber System must be identified (Parts 1.1 high impact, 1.2 medium
# impact, 1.3 assets containing low impact BES Cyber Systems)
all_bes_cyber_systems_identified if {
	count(object.get(input, ["bes_cyber_systems"], [])) > 0
	every system in input.bes_cyber_systems {
		system.system_id
		system.system_name
		system.functional_obligations
		system.cyber_assets
	}
}

# R1 - Each BES Cyber System must be categorized per Attachment 1
all_bes_cyber_systems_categorized if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		not valid_impact_categorization(system.impact_categorization)
	]
	count(violations) == 0
}

valid_impact_categorization(cat) if cat == "high"
valid_impact_categorization(cat) if cat == "medium"
valid_impact_categorization(cat) if cat == "low"

# R1.1 - High Impact BES Cyber Systems — Attachment 1, Section 1 (the fact keys
# under attachment1.high_impact_criteria keep their historical criterion_2_* names)
high_impact_criteria_documented if {
	every system in input.bes_cyber_systems {
		system.impact_categorization != "high"
	}
} else if {
	high_systems := [s | s := input.bes_cyber_systems[_]; s.impact_categorization == "high"]
	count(high_systems) > 0
	input.attachment1.high_impact_criteria.criterion_2_1_control_centers.evaluated == true
	input.attachment1.high_impact_criteria.criterion_2_2_transmission_facilities.evaluated == true
	input.attachment1.high_impact_criteria.criterion_2_3_generation.evaluated == true
	input.attachment1.high_impact_criteria.criterion_2_4_systems.evaluated == true
	input.attachment1.high_impact_criteria.criterion_2_5_fca.evaluated == true
	input.attachment1.high_impact_criteria.criterion_2_6_eacms.evaluated == true
	input.attachment1.high_impact_criteria.rationale_documented == true
}

# R1.2 - Medium Impact BES Cyber Systems — Attachment 1, Section 2 (the fact keys
# under attachment1.medium_impact_criteria keep their historical criterion_3_* names)
medium_impact_criteria_documented if {
	every system in input.bes_cyber_systems {
		system.impact_categorization != "medium"
	}
} else if {
	medium_systems := [s | s := input.bes_cyber_systems[_]; s.impact_categorization == "medium"]
	count(medium_systems) > 0
	input.attachment1.medium_impact_criteria.criterion_3_1_control_centers.evaluated == true
	input.attachment1.medium_impact_criteria.criterion_3_2_transmission.evaluated == true
	input.attachment1.medium_impact_criteria.criterion_3_3_generation.evaluated == true
	input.attachment1.medium_impact_criteria.criterion_3_4_eacms.evaluated == true
	input.attachment1.medium_impact_criteria.rationale_documented == true
}

# Categorization documentation and rationale
categorization_criteria_documented if {
	input.categorization_documentation.criteria_defined == true
	input.categorization_documentation.methodology_documented == true
	input.categorization_documentation.rationale_provided == true
	input.categorization_documentation.attachment1_used == true
}

# =============================================================================
# R2: Review and Approval (Parts 2.1 and 2.2)
# =============================================================================

# R2.1 - Review the identifications in R1 (and update them if there are changes)
# at least once every 15 calendar months
annual_review_performed if {
	age_days(input.categorization_documentation.last_review_date) <= 455 # 15 calendar months
}

# Applicability must be declared (decisions 2026-10-19): an explicit
# bes_environment_changes == false (or an empty list) means no change occurred;
# an absent key is "applicability not determined" and fails closed.
review_triggered_by_changes if {
	input.bes_environment_changes == false
}

review_triggered_by_changes if {
	every change in input.bes_environment_changes {
		change.categorization_impact_assessed == true
		change.categorization_updated_if_needed == true
	}
}

# R2.2 - Have the CIP Senior Manager or delegate approve the identifications
# required by R1 at least once every 15 calendar months. (CIP-002-5.1a has two
# requirements; there is no R3.)
cip_senior_manager_approval if {
	input.categorization_documentation.cip_senior_manager_approved == true
	age_days(input.categorization_documentation.approval_date) <= 455 # 15 calendar months
}

dated_evidence contains {
	"requirement": "R2.1",
	"path": "categorization_documentation.last_review_date",
	"value": object.get(input, ["categorization_documentation", "last_review_date"], null),
}

dated_evidence contains {
	"requirement": "R2.2",
	"path": "categorization_documentation.approval_date",
	"value": object.get(input, ["categorization_documentation", "approval_date"], null),
}

# =============================================================================
# EACMS and PACS Classification
# =============================================================================

# Electronic Access Control or Monitoring Systems (EACMS) and
# Physical Access Control Systems (PACS) must also be classified
# Applicability must be declared (decisions 2026-10-19): an explicit
# `false` means the entity has none (not applicable); an absent key fails closed.
eacms_classified if {
	input.electronic_access_control_systems == false
}

eacms_classified if {
	every eacm in input.electronic_access_control_systems {
		eacm.associated_bes_system_id
		eacm.impact_categorization
		valid_impact_categorization(eacm.impact_categorization)
		eacm.classification_rationale
	}
}

pacs_classified if {
	input.physical_access_control_systems == false
}

pacs_classified if {
	every pac in input.physical_access_control_systems {
		pac.associated_bes_system_id
		pac.impact_categorization
		valid_impact_categorization(pac.impact_categorization)
	}
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not all_bes_cyber_systems_identified
	v := {
		"standard": "CIP-002",
		"requirement": "R1",
		"severity": "high",
		"description": "BES Cyber Systems not fully identified with required attributes",
		"remediation": "Identify all BES Cyber Systems with system_id, name, functional obligations, and cyber assets",
	}
}

violations contains v if {
	not all_bes_cyber_systems_categorized
	v := {
		"standard": "CIP-002",
		"requirement": "R1",
		"severity": "critical",
		"description": "One or more BES Cyber Systems lack valid impact categorization (high/medium/low)",
		"remediation": "Categorize all BES Cyber Systems per Attachment 1 criteria",
	}
}

violations contains v if {
	not categorization_criteria_documented
	v := {
		"standard": "CIP-002",
		"requirement": "R1",
		"severity": "high",
		"description": "Categorization methodology or rationale not documented",
		"remediation": "Document categorization criteria, methodology, and rationale using Attachment 1",
	}
}

violations contains v if {
	not annual_review_performed
	v := {
		"standard": "CIP-002",
		"requirement": "R2.1",
		"severity": "high",
		"description": "BES Cyber System categorization not reviewed within 15 calendar months",
		"remediation": "Review and update categorization at least every 15 calendar months",
	}
}

violations contains v if {
	not high_impact_criteria_documented
	v := {
		"standard": "CIP-002",
		"requirement": "R1.1",
		"severity": "high",
		"description": "High impact (Attachment 1, Section 1) criteria not evaluated for the identified high impact BES Cyber Systems",
		"remediation": "Evaluate every Attachment 1 Section 1 criterion and document the rationale",
	}
}

violations contains v if {
	not medium_impact_criteria_documented
	v := {
		"standard": "CIP-002",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Medium impact (Attachment 1, Section 2) criteria not evaluated for the identified medium impact BES Cyber Systems",
		"remediation": "Evaluate every Attachment 1 Section 2 criterion and document the rationale",
	}
}

violations contains v if {
	not eacms_classified
	object.get(input, "electronic_access_control_systems", null) != null
	v := {
		"standard": "CIP-002",
		"requirement": "R1",
		"severity": "medium",
		"description": "One or more EACMS are not associated with a BES Cyber System and classified",
		"remediation": "Classify each EACMS with an associated system, impact categorization and rationale",
	}
}

violations contains v if {
	not pacs_classified
	object.get(input, "physical_access_control_systems", null) != null
	v := {
		"standard": "CIP-002",
		"requirement": "R1",
		"severity": "medium",
		"description": "One or more PACS are not associated with a BES Cyber System and classified",
		"remediation": "Classify each PACS with an associated system and impact categorization",
	}
}

violations contains v if {
	not review_triggered_by_changes
	object.get(input, "bes_environment_changes", null) != null
	v := {
		"standard": "CIP-002",
		"requirement": "R2.1",
		"severity": "medium",
		"description": "Changes to the BES environment were not assessed for categorization impact",
		"remediation": "Assess every environment change for categorization impact and update the categorization where needed",
	}
}

violations contains v if {
	not cip_senior_manager_approval
	v := {
		"standard": "CIP-002",
		"requirement": "R2.2",
		"severity": "medium",
		"description": "CIP Senior Manager or delegate has not approved the identifications within 15 calendar months",
		"remediation": "Obtain CIP Senior Manager or delegate approval of the R1 identifications at least once every 15 calendar months",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-002",
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
		"standard": "CIP-002",
		"requirement": e.requirement,
		"severity": "high",
		"description": sprintf("input.%s (%v) is later than the evaluation time — a future date is not evidence of a completed activity", [e.path, e.value]),
		"remediation": sprintf("Record in input.%s the date the activity was actually completed", [e.path]),
	}
}

undeclared := {
	"electronic_access_control_systems": "R1",
	"physical_access_control_systems": "R1",
	"bes_environment_changes": "R2.1",
}

violations contains v if {
	some fact, req in undeclared
	object.get(input, fact, null) == null
	v := {
		"standard": "CIP-002",
		"requirement": req,
		"severity": "medium",
		"description": sprintf("CIP-002 %s: applicability not determined — %s not declared", [req, fact]),
		"remediation": sprintf("Declare %s as a list of items, or set it to false when not applicable", [fact]),
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	all_bes_cyber_systems_identified
	all_bes_cyber_systems_categorized
	categorization_criteria_documented
	annual_review_performed
	cip_senior_manager_approval
	high_impact_criteria_documented
	medium_impact_criteria_documented
	eacms_classified
	pacs_classified
	review_triggered_by_changes
}

report := {
	"standard": "CIP-002-5.1a",
	"title": "BES Cyber System Categorization",
	"compliant": compliant,
	"requirements": {
		"R1_identification": all_bes_cyber_systems_identified,
		"R1_categorization": all_bes_cyber_systems_categorized,
		"R1_criteria_documented": categorization_criteria_documented,
		"R2_1_review_current": annual_review_performed,
		"R2_2_senior_manager_approval": cip_senior_manager_approval,
		"R1_1_high_impact_criteria": high_impact_criteria_documented,
		"R1_2_medium_impact_criteria": medium_impact_criteria_documented,
		"R1_eacms_classified": eacms_classified,
		"R1_pacs_classified": pacs_classified,
		"R2_1_changes_assessed": review_triggered_by_changes,
	},
	"systems": {
		"total": count(object.get(input, ["bes_cyber_systems"], [])),
		"high_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "high"]),
		"medium_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "medium"]),
		"low_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "low"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
