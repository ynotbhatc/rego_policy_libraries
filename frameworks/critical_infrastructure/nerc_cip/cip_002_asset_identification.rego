package nerc_cip.cip_002

import rego.v1

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

# R1.1 - Each BES Cyber System must be identified
all_bes_cyber_systems_identified if {
	count(input.bes_cyber_systems) > 0
	every system in input.bes_cyber_systems {
		system.system_id
		system.system_name
		system.functional_obligations
		system.cyber_assets
	}
}

# R1.2 - Each BES Cyber System must be categorized per Attachment 1
all_bes_cyber_systems_categorized if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		not valid_impact_categorization(system.impact_categorization)
	]
	count(violations) == 0
}

valid_impact_categorization(cat) if { cat == "high" }
valid_impact_categorization(cat) if { cat == "medium" }
valid_impact_categorization(cat) if { cat == "low" }

# High Impact BES Cyber Systems — Attachment 1, Criterion 2
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

# Medium Impact BES Cyber Systems — Attachment 1, Criterion 3
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
# R2: Annual Review
# =============================================================================

# R2 - Review and update the identification and categorization of BES Cyber Systems
# at least every 15 calendar months
annual_review_performed if {
	last_review_ns := time.parse_rfc3339_ns(input.categorization_documentation.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455 # 15 calendar months
}

review_triggered_by_changes if {
	every change in input.bes_environment_changes {
		change.categorization_impact_assessed == true
		change.categorization_updated_if_needed == true
	}
}

# =============================================================================
# R3: CIP Senior Manager Approval
# =============================================================================

# R3 - Have the CIP Senior Manager or delegate approve the identifications
# and categorizations in Requirement R1 at least once each calendar year
cip_senior_manager_approval if {
	input.categorization_documentation.cip_senior_manager_approved == true
	approval_ns := time.parse_rfc3339_ns(input.categorization_documentation.approval_date)
	approval_age_days := (time.now_ns() - approval_ns) / (24 * 60 * 60 * 1000000000)
	approval_age_days <= 365
}

# =============================================================================
# EACMS and PACS Classification
# =============================================================================

# Electronic Access Control or Monitoring Systems (EACMS) and
# Physical Access Control Systems (PACS) must also be classified
eacms_classified if {
	every eacm in input.electronic_access_control_systems {
		eacm.associated_bes_system_id
		eacm.impact_categorization
		valid_impact_categorization(eacm.impact_categorization)
		eacm.classification_rationale
	}
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
		"requirement": "R2",
		"severity": "high",
		"description": "BES Cyber System categorization not reviewed within 15 calendar months",
		"remediation": "Review and update categorization at least every 15 calendar months",
	}
}

violations contains v if {
	not cip_senior_manager_approval
	v := {
		"standard": "CIP-002",
		"requirement": "R3",
		"severity": "medium",
		"description": "CIP Senior Manager has not approved categorizations within the past calendar year",
		"remediation": "Obtain CIP Senior Manager or delegate approval of categorizations annually",
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
}

report := {
	"standard": "CIP-002-5.1a",
	"title": "BES Cyber System Categorization",
	"compliant": compliant,
	"requirements": {
		"R1_identification": all_bes_cyber_systems_identified,
		"R1_categorization": all_bes_cyber_systems_categorized,
		"R1_criteria_documented": categorization_criteria_documented,
		"R2_annual_review": annual_review_performed,
		"R3_senior_manager_approval": cip_senior_manager_approval,
	},
	"systems": {
		"total": count(input.bes_cyber_systems),
		"high_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "high"]),
		"medium_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "medium"]),
		"low_impact": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "low"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
