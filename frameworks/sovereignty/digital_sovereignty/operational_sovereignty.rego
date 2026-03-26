package digital_sovereignty.operational_sovereignty

import rego.v1

# Digital Sovereignty — Operational Sovereignty
# Ensures that people operating the environment are trusted, that vendor access
# is controlled, and that sensitive operations cannot be compelled by foreign actors.
#
# Input schema:
#   input.approved_jurisdictions[]
#   input.personnel[]
#     .person_id, .role
#     .location_country                  — where the person works
#     .nationality_screened              — bool
#     .security_clearance_level          — none | baseline | nv1 | nv2 | ts
#     .access_level                      — admin | privileged | standard | read_only
#     .vetting_current                   — bool
#     .foreign_government_connection     — bool
#   input.vendor_access[]
#     .vendor_id, .vendor_name
#     .vendor_hq_country
#     .access_type                       — remote | on_site | emergency
#     .sessions_monitored                — bool
#     .sessions_logged                   — bool
#     .sessions_recorded                 — bool
#     .access_requires_approval          — bool
#     .just_in_time_access               — bool
#     .data_classification_accessed
#   input.support_contracts[]
#     .vendor_id, .vendor_name
#     .support_personnel_location        — country where support staff are located
#     .right_to_refuse_foreign_access    — bool
#     .data_handling_agreement           — bool
#     .foreign_government_disclosure_clause — bool
#   input.privileged_access_management
#     .pam_solution_deployed             — bool
#     .session_recording_enabled         — bool
#     .credential_vaulting_enabled       — bool
#     .just_in_time_provisioning         — bool
#     .privileged_access_review_current  — bool
#     .review_frequency_days
#   input.foreign_access_requests
#     .policy_documented                 — bool
#     .legal_review_required             — bool
#     .notification_to_data_owner        — bool
#     .right_to_challenge                — bool
#   input.remote_operations
#     .vpn_in_jurisdiction               — bool
#     .jump_host_in_jurisdiction         — bool
#     .remote_from_approved_countries_only — bool

# =============================================================================
# PERSONNEL VETTING
# =============================================================================

# Privileged/admin personnel must be vetted
privileged_personnel_vetted if {
	violations := [p |
		p := input.personnel[_]
		p.access_level in ["admin", "privileged"]
		not p.vetting_current == true
	]
	count(violations) == 0
}

# Privileged personnel should work from approved jurisdictions
privileged_personnel_in_jurisdiction if {
	violations := [p |
		p := input.personnel[_]
		p.access_level in ["admin", "privileged"]
		not p.location_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# Personnel with foreign government connections must not have privileged access
no_foreign_connected_privileged_access if {
	violations := [p |
		p := input.personnel[_]
		p.access_level in ["admin", "privileged"]
		p.foreign_government_connection == true
	]
	count(violations) == 0
}

# =============================================================================
# VENDOR ACCESS CONTROLS
# =============================================================================

# All vendor remote access must be monitored, logged, and recorded
vendor_access_monitored if {
	violations := [va |
		va := input.vendor_access[_]
		va.data_classification_accessed in ["sensitive", "restricted", "sovereign"]
		not va.sessions_monitored == true
	]
	count(violations) == 0
}

vendor_access_logged if {
	violations := [va |
		va := input.vendor_access[_]
		not va.sessions_logged == true
	]
	count(violations) == 0
}

# Vendor access to sensitive data must require explicit approval
vendor_access_requires_approval if {
	violations := [va |
		va := input.vendor_access[_]
		va.data_classification_accessed in ["sensitive", "restricted", "sovereign"]
		not va.access_requires_approval == true
	]
	count(violations) == 0
}

# Just-in-time access preferred for vendor sessions
vendor_jit_access_implemented if {
	violations := [va |
		va := input.vendor_access[_]
		va.data_classification_accessed in ["sensitive", "restricted", "sovereign"]
		not va.just_in_time_access == true
	]
	count(violations) == 0
}

# Vendors from foreign-jurisdiction companies accessing sovereign data must be restricted
foreign_vendor_sovereign_access_controlled if {
	violations := [va |
		va := input.vendor_access[_]
		va.data_classification_accessed in ["sovereign", "restricted"]
		not va.vendor_hq_country in input.approved_jurisdictions
		not va.access_requires_approval == true
	]
	count(violations) == 0
}

# =============================================================================
# SUPPORT CONTRACTS
# =============================================================================

# Support personnel location should be in approved jurisdiction for sensitive systems
support_personnel_in_jurisdiction if {
	violations := [sc |
		sc := input.support_contracts[_]
		not sc.support_personnel_location in input.approved_jurisdictions
		not sc.data_handling_agreement == true
	]
	count(violations) == 0
}

# Contracts must include right to refuse foreign government access
right_to_refuse_foreign_access if {
	violations := [sc |
		sc := input.support_contracts[_]
		not sc.right_to_refuse_foreign_access == true
	]
	count(violations) == 0
}

# Contracts must specify how foreign government disclosure requests are handled
foreign_disclosure_clause_in_contracts if {
	violations := [sc |
		sc := input.support_contracts[_]
		not sc.foreign_government_disclosure_clause == true
	]
	count(violations) == 0
}

# =============================================================================
# PRIVILEGED ACCESS MANAGEMENT
# =============================================================================

# PAM solution must be deployed
pam_deployed if {
	input.privileged_access_management.pam_solution_deployed == true
	input.privileged_access_management.credential_vaulting_enabled == true
	input.privileged_access_management.session_recording_enabled == true
}

# Just-in-time provisioning reduces standing privileges
jit_provisioning_enabled if {
	input.privileged_access_management.just_in_time_provisioning == true
}

# Privileged access must be reviewed regularly
privileged_access_review_current if {
	input.privileged_access_management.privileged_access_review_current == true
	input.privileged_access_management.review_frequency_days <= 90
}

# =============================================================================
# FOREIGN ACCESS REQUEST HANDLING
# =============================================================================

# Organisation must have a policy for handling foreign government access requests
foreign_access_request_policy if {
	input.foreign_access_requests.policy_documented == true
	input.foreign_access_requests.legal_review_required == true
	input.foreign_access_requests.notification_to_data_owner == true
	input.foreign_access_requests.right_to_challenge == true
}

# =============================================================================
# REMOTE OPERATIONS CONTROLS
# =============================================================================

# Remote management must go through in-jurisdiction VPN/jump host
remote_operations_controlled if {
	input.remote_operations.vpn_in_jurisdiction == true
	input.remote_operations.jump_host_in_jurisdiction == true
	input.remote_operations.remote_from_approved_countries_only == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not privileged_personnel_vetted
	p := input.personnel[_]
	p.access_level in ["admin", "privileged"]
	not p.vetting_current == true
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-001",
		"severity": "critical",
		"person_id": p.person_id,
		"description": concat("", ["Privileged personnel not currently vetted: ", p.person_id, " (", p.role, ")"]),
		"remediation": "Complete background vetting for all privileged/admin personnel",
	}
}

violations contains v if {
	not privileged_personnel_in_jurisdiction
	p := input.personnel[_]
	p.access_level in ["admin", "privileged"]
	not p.location_country in input.approved_jurisdictions
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-002",
		"severity": "high",
		"person_id": p.person_id,
		"description": concat("", ["Privileged personnel located outside approved jurisdiction: ", p.person_id, " in ", p.location_country]),
		"remediation": "Restrict privileged access to personnel located in approved jurisdictions or implement compensating controls",
	}
}

violations contains v if {
	not no_foreign_connected_privileged_access
	p := input.personnel[_]
	p.access_level in ["admin", "privileged"]
	p.foreign_government_connection == true
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-003",
		"severity": "critical",
		"person_id": p.person_id,
		"description": concat("", ["Privileged access held by person with foreign government connection: ", p.person_id]),
		"remediation": "Revoke privileged access pending review; implement compensating controls",
	}
}

violations contains v if {
	not vendor_access_monitored
	va := input.vendor_access[_]
	va.data_classification_accessed in ["sensitive", "restricted", "sovereign"]
	not va.sessions_monitored == true
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-004",
		"severity": "critical",
		"vendor_id": va.vendor_id,
		"description": concat("", ["Vendor access to sensitive data is not monitored: ", va.vendor_name]),
		"remediation": "Implement session monitoring and recording for all vendor access to sensitive systems",
	}
}

violations contains v if {
	not vendor_access_requires_approval
	va := input.vendor_access[_]
	va.data_classification_accessed in ["sensitive", "restricted", "sovereign"]
	not va.access_requires_approval == true
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-005",
		"severity": "high",
		"vendor_id": va.vendor_id,
		"description": concat("", ["Vendor can access sensitive data without explicit approval: ", va.vendor_name]),
		"remediation": "Implement just-in-time access with approval workflow for all vendor access",
	}
}

violations contains v if {
	not right_to_refuse_foreign_access
	sc := input.support_contracts[_]
	not sc.right_to_refuse_foreign_access == true
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-006",
		"severity": "high",
		"vendor_id": sc.vendor_id,
		"description": concat("", ["Support contract does not include right to refuse foreign government access: ", sc.vendor_name]),
		"remediation": "Renegotiate contract to include explicit right to refuse or challenge foreign government access requests",
	}
}

violations contains v if {
	not pam_deployed
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-007",
		"severity": "high",
		"description": "Privileged Access Management (PAM) solution not deployed or lacking credential vaulting/recording",
		"remediation": "Deploy PAM solution with credential vaulting, session recording, and JIT provisioning",
	}
}

violations contains v if {
	not foreign_access_request_policy
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-008",
		"severity": "high",
		"description": "No documented policy for handling foreign government data access requests",
		"remediation": "Document policy requiring legal review, data owner notification, and right to challenge all foreign access requests",
	}
}

violations contains v if {
	not remote_operations_controlled
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-009",
		"severity": "high",
		"description": "Remote operations not routed through in-jurisdiction VPN/jump host or accessible from unapproved countries",
		"remediation": "Route all remote management through VPN and jump hosts located in approved jurisdictions",
	}
}

violations contains v if {
	not privileged_access_review_current
	v := {
		"domain": "operational_sovereignty",
		"control": "OS-010",
		"severity": "medium",
		"description": "Privileged access not reviewed within 90 days",
		"remediation": "Conduct quarterly privileged access reviews; revoke unused or excessive access",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	privileged_personnel_vetted
	privileged_personnel_in_jurisdiction
	no_foreign_connected_privileged_access
	vendor_access_monitored
	vendor_access_logged
	vendor_access_requires_approval
	vendor_jit_access_implemented
	foreign_vendor_sovereign_access_controlled
	support_personnel_in_jurisdiction
	right_to_refuse_foreign_access
	foreign_disclosure_clause_in_contracts
	pam_deployed
	jit_provisioning_enabled
	privileged_access_review_current
	foreign_access_request_policy
	remote_operations_controlled
}

report := {
	"domain": "Operational Sovereignty",
	"compliant": compliant,
	"controls": {
		"OS-001_privileged_personnel_vetted": privileged_personnel_vetted,
		"OS-002_privileged_personnel_in_jurisdiction": privileged_personnel_in_jurisdiction,
		"OS-003_no_foreign_connected_access": no_foreign_connected_privileged_access,
		"OS-004_vendor_access_monitored": vendor_access_monitored,
		"OS-005_vendor_access_approval": vendor_access_requires_approval,
		"OS-006_right_to_refuse_foreign_access": right_to_refuse_foreign_access,
		"OS-007_pam_deployed": pam_deployed,
		"OS-008_foreign_access_request_policy": foreign_access_request_policy,
		"OS-009_remote_ops_controlled": remote_operations_controlled,
		"OS-010_privileged_access_review": privileged_access_review_current,
	},
	"personnel_summary": {
		"total_privileged": count([p | p := input.personnel[_]; p.access_level in ["admin", "privileged"]]),
		"in_jurisdiction": count([p | p := input.personnel[_]; p.access_level in ["admin", "privileged"]; p.location_country in input.approved_jurisdictions]),
		"vetted": count([p | p := input.personnel[_]; p.vetting_current == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
