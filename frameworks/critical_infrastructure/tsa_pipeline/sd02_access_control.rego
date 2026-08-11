package tsa_pipeline.sd02_access_control

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.C — Access Control Measures
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.C.1.a–b, III.C.2, III.C.3, III.C.4.a–b,
#                         III.C.5 (8 subparagraphs)
#
# III.C requires access control measures, "including for local and remote
# access, to secure and prevent unauthorized access to Critical Cyber Systems."
#
# Two carve-outs in the directive text are modeled as conditional compensating
# control requirements rather than hard failures:
#   - III.C.2: an Owner/Operator that does not apply MFA to industrial control
#     workstations in control rooms regulated under 49 CFR parts 192 or 195
#     "shall specify what compensating controls are used to manage access."
#   - III.C.3: where least privilege and separation of duties are not
#     technically feasible, the policies must describe the compensating controls.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.access_control: {
#   "policy_documented":       boolean,
#   "covers_local_and_remote": boolean,
#   "identification_authentication": {
#       "policy_documented":            boolean,
#       "password_reset_schedule_defined": boolean,   # III.C.1.a
#       "components_exempt_from_reset": [ {           # III.C.1.b
#           "name":                  string,
#           "mitigations_documented": boolean,
#           "mitigation_timeframe_defined": boolean
#       } ]
#   },
#   "multi_factor_authentication": {                   # III.C.2
#       "implemented":                    boolean,
#       "control_room_workstations_exempt": boolean,   # 49 CFR parts 192/195
#       "compensating_controls_specified": boolean
#   },
#   "least_privilege": {                               # III.C.3
#       "implemented":                    boolean,
#       "separation_of_duties":           boolean,
#       "not_technically_feasible":       boolean,
#       "compensating_controls_described": boolean
#   },
#   "shared_accounts": {                               # III.C.4
#       "policy_documented":              boolean,
#       "limited_to_operations_critical": boolean,
#       "accounts": [ {
#           "name":                        string,
#           "operations_critical":         boolean,
#           "least_privilege_managed":     boolean,   # III.C.4.a
#           "credential_rotated_on_departure": boolean # III.C.4.b
#       } ]
#   },
#   "domain_trusts": {                                 # III.C.5
#       "review_schedule_defined":  boolean,
#       "management_policy_defined": boolean
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_access_control
# =============================================================================

# `input` is UNDEFINED (not {}) when OPA receives an empty request body. Routing
# every lookup through this defaulted alias makes an absent fact evaluate to the
# fail-closed default instead of silently skipping the violation rule entirely.
default facts := {}

facts := input

default compliant := false

compliant if {
	count(violations) == 0
}

exempt_components := [c |
	some c in object.get(facts, ["access_control", "identification_authentication", "components_exempt_from_reset"], [])
	is_object(c)
]

shared_accounts := [a |
	some a in object.get(facts, ["access_control", "shared_accounts", "accounts"], [])
	is_object(a)
]

# ── III.C — Access control measures exist ────────────────────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "policy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C: No documented access control measures to secure and prevent unauthorized access to Critical Cyber Systems"
}

violations contains msg if {
	object.get(facts, ["access_control", "covers_local_and_remote"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C: Access control measures do not cover both local and remote access to Critical Cyber Systems"
}

# ── III.C.1 — Identification and authentication ──────────────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "identification_authentication", "policy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.1: No identification and authentication policies and procedures designed to prevent unauthorized access to Critical Cyber Systems"
}

violations contains msg if {
	object.get(facts, ["access_control", "identification_authentication", "password_reset_schedule_defined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.1.a: No schedule defined for memorized secret authenticator resets"
}

violations contains msg if {
	some c in exempt_components
	object.get(c, "mitigations_documented", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.C.1.b: Critical Cyber System component '%s' is exempt from the password reset schedule but has no documented and defined mitigation measures", [object.get(c, "name", "unnamed")])
}

violations contains msg if {
	some c in exempt_components
	object.get(c, "mitigation_timeframe_defined", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.C.1.b: Critical Cyber System component '%s' is exempt from the password reset schedule but has no timeframe to complete its mitigations", [object.get(c, "name", "unnamed")])
}

# ── III.C.2 — Multi-factor authentication ────────────────────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "multi_factor_authentication", "implemented"], false) == false
	object.get(facts, ["access_control", "multi_factor_authentication", "control_room_workstations_exempt"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.2: Multi-factor authentication — or other logical and physical security controls supplementing password authentication to provide commensurate risk mitigation — is not implemented"
}

violations contains msg if {
	object.get(facts, ["access_control", "multi_factor_authentication", "control_room_workstations_exempt"], false) == true
	object.get(facts, ["access_control", "multi_factor_authentication", "compensating_controls_specified"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.2: Multi-factor authentication is not applied to industrial control workstations in control rooms regulated under 49 CFR parts 192 or 195, and the compensating controls used to manage access are not specified"
}

# ── III.C.3 — Least privilege and separation of duties ───────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "least_privilege", "implemented"], false) == false
	object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.3: No policies and procedures to manage access rights based on the principle of least privilege"
}

violations contains msg if {
	object.get(facts, ["access_control", "least_privilege", "separation_of_duties"], false) == false
	object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.3: No policies and procedures to manage access rights based on the principle of separation of duties"
}

violations contains msg if {
	object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], false) == true
	object.get(facts, ["access_control", "least_privilege", "compensating_controls_described"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.3: Least privilege and separation of duties are declared not technically feasible, but the policies and procedures do not describe the compensating controls the Owner/Operator will apply"
}

# ── III.C.4 — Shared accounts ────────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "shared_accounts", "policy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.4: No enforced standards limiting the availability and use of shared accounts"
}

violations contains msg if {
	some a in shared_accounts
	object.get(a, "operations_critical", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.C.4: Shared account '%s' is not critical for operations — shared accounts must be limited to those critical for operations, and then only if absolutely necessary", [object.get(a, "name", "unnamed")])
}

violations contains msg if {
	some a in shared_accounts
	object.get(a, "least_privilege_managed", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.C.4.a: Access to shared account '%s' is not limited through account management that uses the principles of least privilege and separation of duties", [object.get(a, "name", "unnamed")])
}

violations contains msg if {
	some a in shared_accounts
	object.get(a, "credential_rotated_on_departure", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.C.4.b: Shared account '%s' has no process ensuring individuals who no longer need access do not retain knowledge of the password", [object.get(a, "name", "unnamed")])
}

# ── III.C.5 — Domain trust relationships ─────────────────────────────────────

violations contains msg if {
	object.get(facts, ["access_control", "domain_trusts", "review_schedule_defined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.5: No schedule for review of existing domain trust relationships to ensure their necessity"
}

violations contains msg if {
	object.get(facts, ["access_control", "domain_trusts", "management_policy_defined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.C.5: No policies to manage domain trusts"
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.C",
	"name": "Access Control Measures",
	"requirements_evaluated": 8,
	"shared_accounts_assessed": count(shared_accounts),
	"reset_exempt_components_assessed": count(exempt_components),
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
