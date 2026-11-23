# METADATA
# title: "CIP-003-9: Security Management Controls"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 30
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package nerc_cip.cip_003

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default cip_senior_manager_designated := false

default cybersecurity_policies_established := false

default delegation_documented := false

default information_sharing_plan_exists := false

default low_impact_plan_implemented := false

default low_impact_plan_reviewed := false

default low_impact_policy_areas_covered := false

default low_impact_vendor_remote_access_controlled := false

default policy_review_current := false

default removable_media_controls := false

default required_policy_areas_covered := false

default transient_asset_security_controls := false

default transient_cyber_asset_policy := false

# CIP-003-9: Security Management Controls
# Requirement: Specify consistent and sustainable security management controls
# that establish responsibility and accountability for the protection of
# BES Cyber Systems.
#
# NERC Standards Reference: CIP-003-9 (FERC Docket No. RD23-3-000; mandatory and
# enforceable in the United States from 2026-04-01, replacing CIP-003-8).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-003-9.pdf
#
# The standard has four requirements:
#   R1  cyber security policies, reviewed and approved by the CIP Senior Manager
#       at least once every 15 calendar months (Part 1.1 high/medium impact
#       topics 1.1.1-1.1.9, Part 1.2 low impact topics 1.2.1-1.2.7)
#   R2  cyber security plan(s) for low impact BES Cyber Systems that include the
#       sections of Attachment 1 (Sections 1-6)
#   R3  identify a CIP Senior Manager by name
#   R4  documented delegation of authority, unless no delegations are used
#
# New in version 9 (vendor electronic remote access for low impact):
#   R1 Part 1.2.6           policy topic "Vendor electronic remote access security controls"
#   Attachment 1 Section 6  methods to determine (6.1) and disable (6.2) vendor
#                           electronic remote access, and to detect known or
#                           suspected malicious communications over it (6.3)
#
# Not implemented: R3 "document any change [of CIP Senior Manager] within 30
# calendar days"; Attachment 1 Section 3.2 (Dial-up Connectivity authentication)
# and Sections 4.1-4.6 as separate checks (Section 4 is one boolean).

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

# -----------------------------------------------------------------------------
# Applicability
# -----------------------------------------------------------------------------

# R1 Part 1.1 applies to high and medium impact BES Cyber Systems "if any", R1
# Part 1.2 and R2 to assets containing low impact BES Cyber Systems "if any".
# Only a collected inventory can show that a class is absent: without one, every
# part applies.
inventory_present if {
	is_array(input.bes_cyber_systems)
	count(input.bes_cyber_systems) > 0
}

low_impact_systems_absent if {
	inventory_present
	count([s | some s in input.bes_cyber_systems; s.impact_categorization == "low"]) == 0
}

high_medium_systems_absent if {
	inventory_present
	count([s | some s in input.bes_cyber_systems; s.impact_categorization in {"high", "medium"}]) == 0
}

# =============================================================================
# R1: Cyber Security Policies
# =============================================================================

# R1 - Review and obtain CIP Senior Manager approval at least once every 15
# calendar months for one or more documented cyber security policies

cybersecurity_policies_established if {
	input.cybersecurity_policies.documented == true
	input.cybersecurity_policies.approved == true
	input.cybersecurity_policies.cip_senior_manager_approved == true
}

# R1.1 - Topics for high impact and medium impact BES Cyber Systems, if any
high_medium_policy_areas := {
	"personnel_and_training": "1.1.1",
	"electronic_security_perimeters": "1.1.2",
	"physical_security": "1.1.3",
	"systems_security_management": "1.1.4",
	"incident_response": "1.1.5",
	"recovery_plans": "1.1.6",
	"configuration_management": "1.1.7",
	"information_protection": "1.1.8",
	"cip_exceptional_circumstances": "1.1.9",
}

missing_high_medium_policy_areas contains area if {
	not high_medium_systems_absent
	some area, _ in high_medium_policy_areas
	not input.cybersecurity_policies.areas[area] == true
}

required_policy_areas_covered if count(missing_high_medium_policy_areas) == 0

# R1.2 - Topics for assets containing low impact BES Cyber Systems, if any.
# 1.2.6 (vendor electronic remote access security controls) is new in CIP-003-9.
low_impact_policy_areas := {
	"cyber_security_awareness": "1.2.1",
	"physical_security_controls": "1.2.2",
	"electronic_access_controls": "1.2.3",
	"cyber_security_incident_response": "1.2.4",
	"transient_cyber_assets_and_removable_media": "1.2.5",
	"vendor_electronic_remote_access": "1.2.6",
	"cip_exceptional_circumstances": "1.2.7",
}

missing_low_impact_policy_areas contains area if {
	not low_impact_systems_absent
	some area, _ in low_impact_policy_areas
	not input.cybersecurity_policies.low_impact_areas[area] == true
}

low_impact_policy_areas_covered if count(missing_low_impact_policy_areas) == 0

# R1 - Policies reviewed (and approved) within 15 calendar months
policy_review_current if {
	age_days(input.cybersecurity_policies.last_review_date) <= 455
}

# =============================================================================
# R2: Cyber Security Plan(s) for Low Impact BES Cyber Systems (Attachment 1)
# =============================================================================

# R2 - Implement one or more documented cyber security plan(s) that include the
# sections in Attachment 1. Required only when at least one asset contains a low
# impact BES Cyber System; no inventory is not "no low impact systems".

low_impact_plan_implemented if {
	low_impact_systems_absent
} else if {
	input.low_impact_plan.documented == true
	input.low_impact_plan.approved == true
	input.low_impact_plan.cyber_security_awareness == true # Attachment 1 Section 1
	input.low_impact_plan.physical_security_controls == true # Section 2
	input.low_impact_plan.electronic_access_controls == true # Section 3
	input.low_impact_plan.cyber_security_incident_response == true # Section 4
	input.low_impact_plan.transient_cyber_asset_controls == true # Section 5
}

# CIP-003-9 sets no review interval for the R2 plan itself (the 15 calendar month
# cycle is R1, for the policies). This is kept as a supporting check under R2: a
# plan that nobody has looked at for 15 months is weak evidence of implementation.
low_impact_plan_reviewed if {
	low_impact_systems_absent
} else if {
	age_days(input.low_impact_plan.last_review_date) <= 455
}

# Attachment 1 Section 5 - Transient Cyber Asset and Removable Media malicious
# code risk mitigation for low impact BES Cyber Systems. (Transient Cyber Assets
# used with high and medium impact systems are CIP-010 R4, not CIP-003.)

transient_cyber_asset_policy if {
	low_impact_systems_absent
} else if {
	input.transient_cyber_assets.policy_documented == true
	input.transient_cyber_assets.asset_management.inventory_maintained == true
	input.transient_cyber_assets.asset_management.authorization_required == true
}

# Section 5.1 / 5.2 - methods to mitigate the introduction of malicious code
transient_asset_security_controls if {
	low_impact_systems_absent
} else if {
	input.transient_cyber_assets.controls.malicious_code_prevention == true
	input.transient_cyber_assets.controls.security_patches.applied == true
	input.transient_cyber_assets.controls.security_patches.documented == true
}

# Section 5.3 - Removable Media: detect malicious code and mitigate before use
removable_media_controls if {
	low_impact_systems_absent
} else if {
	input.removable_media.policy_documented == true
	input.removable_media.authorization_required == true
	input.removable_media.scanning_before_use == true
	input.removable_media.encryption_when_applicable == true
}

# Attachment 1 Section 6 - Vendor Electronic Remote Access Security Controls
# (new in CIP-003-9). Applies to assets containing low impact BES Cyber Systems
# that allow vendor electronic remote access. Not allowing it must be stated:
# `allowed: false`. An absent statement is evidence missing, not an exemption.
vendor_remote_access_methods := {
	"determine_method": "6.1",
	"disable_method": "6.2",
	"malicious_communications_detection": "6.3",
}

low_impact_vendor_remote_access_controlled if {
	low_impact_systems_absent
} else if {
	input.low_impact_plan.vendor_electronic_remote_access.allowed == false
} else if {
	input.low_impact_plan.vendor_electronic_remote_access.allowed == true
	count(missing_vendor_remote_access_methods) == 0
}

missing_vendor_remote_access_methods contains method if {
	some method, _ in vendor_remote_access_methods
	not input.low_impact_plan.vendor_electronic_remote_access[method] == true
}

vendor_remote_access_undeclared if {
	not low_impact_systems_absent
	not is_boolean(object.get(input, ["low_impact_plan", "vendor_electronic_remote_access", "allowed"], null))
}

# =============================================================================
# R3: CIP Senior Manager
# =============================================================================

# R3 - Identify a CIP Senior Manager by name

cip_senior_manager_designated if {
	input.cybersecurity_organization.senior_manager.designated == true
	input.cybersecurity_organization.senior_manager.name
	input.cybersecurity_organization.senior_manager.title
	input.cybersecurity_organization.senior_manager.authority_documented == true
	input.cybersecurity_organization.senior_manager.responsibilities_defined == true
	input.cybersecurity_organization.senior_manager.accountability_documented == true
}

# =============================================================================
# R4: Delegation of Authority
# =============================================================================

# R4 - Implement a documented process to delegate authority, unless no
# delegations are used. "No delegations" must be stated: delegated_authority
# false, or delegated_authority.exists false. An absent key is evidence missing.

delegation_documented if {
	input.cybersecurity_organization.delegated_authority == false
}

delegation_documented if {
	input.cybersecurity_organization.delegated_authority.exists == false
}

delegation_documented if {
	input.cybersecurity_organization.delegated_authority.exists == true
	input.cybersecurity_organization.delegated_authority.documented == true
	input.cybersecurity_organization.delegated_authority.current == true
	input.cybersecurity_organization.delegated_authority.delegate_name
	input.cybersecurity_organization.delegated_authority.scope_defined == true
}

delegation_undeclared if {
	object.get(input, ["cybersecurity_organization", "delegated_authority"], null) == null
}

# =============================================================================
# Advisory (not a CIP-003-9 requirement)
# =============================================================================

# Information sharing plan with NERC and Regional Entity contacts. CIP-003-9 has
# no such requirement (earlier releases of this module labelled it "R5", which
# does not exist). It is reported under `advisory` and does not gate `compliant`
# or produce a violation.
information_sharing_plan_exists if {
	input.information_sharing_plan.documented == true
	input.information_sharing_plan.nerc_contact_included == true
	input.information_sharing_plan.regional_entity_contact_included == true
	input.information_sharing_plan.contacts_current == true
	age_days(input.information_sharing_plan.last_review_date) <= 455
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not cybersecurity_policies_established
	v := {
		"standard": "CIP-003",
		"requirement": "R1",
		"severity": "high",
		"description": "Cybersecurity policies not established or not approved by CIP Senior Manager",
		"remediation": "Document cybersecurity policies and obtain CIP Senior Manager approval",
	}
}

violations contains v if {
	some area in missing_high_medium_policy_areas
	part := high_medium_policy_areas[area]
	v := {
		"standard": "CIP-003",
		"requirement": sprintf("R%s", [part]),
		"severity": "high",
		"description": sprintf("Cyber security policies for high and medium impact BES Cyber Systems do not address %s (Part %s)", [area, part]),
		"remediation": sprintf("Address the topic in a documented policy and set cybersecurity_policies.areas.%s", [area]),
	}
}

violations contains v if {
	some area in missing_low_impact_policy_areas
	part := low_impact_policy_areas[area]
	v := {
		"standard": "CIP-003",
		"requirement": sprintf("R%s", [part]),
		"severity": "high",
		"description": sprintf("Cyber security policies for assets containing low impact BES Cyber Systems do not address %s (Part %s)", [area, part]),
		"remediation": sprintf("Address the topic in a documented policy and set cybersecurity_policies.low_impact_areas.%s", [area]),
	}
}

violations contains v if {
	not policy_review_current
	v := {
		"standard": "CIP-003",
		"requirement": "R1",
		"severity": "medium",
		"description": "Cybersecurity policies not reviewed within 15 calendar months",
		"remediation": "Review and obtain CIP Senior Manager re-approval within 15 calendar months",
	}
}

violations contains v if {
	not low_impact_plan_implemented
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Low impact cyber security plan not documented, approved and implemented with the Attachment 1 sections (R2)",
		"remediation": "Document and implement a low impact plan covering Attachment 1 Sections 1-5: awareness, physical security, electronic access, incident response, transient cyber assets",
	}
}

violations contains v if {
	not low_impact_plan_reviewed
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "medium",
		"description": "Low impact cybersecurity plan not reviewed within 15 calendar months (R2 supporting check)",
		"remediation": "Review the low impact plan within 15 calendar months",
	}
}

violations contains v if {
	not transient_cyber_asset_policy
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Transient Cyber Asset policy or asset management not in place (R2, Attachment 1 Section 5)",
		"remediation": "Document the TCA policy, keep an inventory and require authorization",
	}
}

violations contains v if {
	not transient_asset_security_controls
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Transient Cyber Asset security controls (malicious code prevention, patching) not in place (R2, Attachment 1 Sections 5.1-5.2)",
		"remediation": "Apply and document malicious code prevention and security patching for TCAs",
	}
}

violations contains v if {
	not removable_media_controls
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Removable media controls (authorization, scanning before use, encryption) not in place (R2, Attachment 1 Section 5.3)",
		"remediation": "Document and enforce removable media authorization, scanning before use and encryption",
	}
}

violations contains v if {
	vendor_remote_access_undeclared
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "evidence missing — input.low_impact_plan.vendor_electronic_remote_access.allowed not declared (R2, Attachment 1 Section 6)",
		"remediation": "Declare whether assets containing low impact BES Cyber Systems allow vendor electronic remote access (true or false)",
	}
}

violations contains v if {
	not low_impact_systems_absent
	input.low_impact_plan.vendor_electronic_remote_access.allowed == true
	some method in missing_vendor_remote_access_methods
	section := vendor_remote_access_methods[method]
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": sprintf("Vendor electronic remote access to low impact BES Cyber Systems is allowed but %s is not in place (R2, Attachment 1 Section %s)", [method, section]),
		"remediation": "Implement methods to determine and to disable vendor electronic remote access, and to detect known or suspected inbound and outbound malicious communications over it",
	}
}

violations contains v if {
	not cip_senior_manager_designated
	v := {
		"standard": "CIP-003",
		"requirement": "R3",
		"severity": "critical",
		"description": "CIP Senior Manager not identified by name with documented authority",
		"remediation": "Identify the CIP Senior Manager by name with documented authority and defined responsibilities",
	}
}

violations contains v if {
	delegation_undeclared
	v := {
		"standard": "CIP-003",
		"requirement": "R4",
		"severity": "medium",
		"description": "evidence missing — input.cybersecurity_organization.delegated_authority not declared (R4)",
		"remediation": "Describe the delegation of authority, or set delegated_authority to false when no delegations are used",
	}
}

violations contains v if {
	not delegation_undeclared
	not delegation_documented
	v := {
		"standard": "CIP-003",
		"requirement": "R4",
		"severity": "medium",
		"description": "Delegation of CIP Senior Manager authority not documented, not current or without a named delegate and scope (R4)",
		"remediation": "Document each delegation with the name or title of the delegate, the actions delegated and the date, approved by the CIP Senior Manager",
	}
}

# Dated evidence the recency checks read.
dated_evidence contains {
	"requirement": "R1",
	"path": "cybersecurity_policies.last_review_date",
	"value": object.get(input, ["cybersecurity_policies", "last_review_date"], null),
}

dated_evidence contains {
	"requirement": "R2",
	"path": "low_impact_plan.last_review_date",
	"value": object.get(input, ["low_impact_plan", "last_review_date"], null),
} if {
	not low_impact_systems_absent
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-003",
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
		"standard": "CIP-003",
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
	cybersecurity_policies_established
	required_policy_areas_covered
	low_impact_policy_areas_covered
	policy_review_current
	low_impact_plan_implemented
	low_impact_plan_reviewed
	transient_cyber_asset_policy
	transient_asset_security_controls
	removable_media_controls
	low_impact_vendor_remote_access_controlled
	cip_senior_manager_designated
	delegation_documented
}

report := {
	"standard": "CIP-003-9",
	"title": "Security Management Controls",
	"compliant": compliant,
	"requirements": {
		"R1_policies_established": cybersecurity_policies_established,
		"R1_1_high_medium_policy_areas_covered": required_policy_areas_covered,
		"R1_2_low_impact_policy_areas_covered": low_impact_policy_areas_covered,
		"R1_policy_review_current": policy_review_current,
		"R2_low_impact_plan": low_impact_plan_implemented,
		"R2_low_impact_plan_reviewed": low_impact_plan_reviewed,
		"R2_s5_transient_asset_policy": transient_cyber_asset_policy,
		"R2_s5_transient_asset_controls": transient_asset_security_controls,
		"R2_s5_removable_media_controls": removable_media_controls,
		"R2_s6_vendor_remote_access": low_impact_vendor_remote_access_controlled,
		"R3_cip_senior_manager": cip_senior_manager_designated,
		"R4_delegation_documented": delegation_documented,
	},
	"advisory": {"information_sharing_plan": information_sharing_plan_exists},
	"violations": violations,
	"violation_count": count(violations),
}
