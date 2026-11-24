# METADATA
# title: "TSA Security Directive Pipeline-2021-02G"
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 18
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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
	not object.get(facts, ["access_control", "policy_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C: No documented access control measures to secure and prevent unauthorized access to Critical Cyber Systems"
	msg := concat("", [finding, _ev_input("access_control.policy_documented")])
}

violations contains msg if {
	not object.get(facts, ["access_control", "covers_local_and_remote"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C: Access control measures do not cover both local and remote access to Critical Cyber Systems"
	msg := concat("", [finding, _ev_input("access_control.covers_local_and_remote")])
}

# ── III.C.1 — Identification and authentication ──────────────────────────────

violations contains msg if {
	not object.get(facts, ["access_control", "identification_authentication", "policy_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.1: No identification and authentication policies and procedures designed to prevent unauthorized access to Critical Cyber Systems"
	msg := concat("", [finding, _ev_input("access_control.identification_authentication.policy_documented")])
}

violations contains msg if {
	not object.get(facts, ["access_control", "identification_authentication", "password_reset_schedule_defined"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.1.a: No schedule defined for memorized secret authenticator resets"
	msg := concat("", [finding, _ev_input("access_control.identification_authentication.password_reset_schedule_defined")])
}

violations contains msg if {
	some c in exempt_components
	not object.get(c, "mitigations_documented", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.C.1.b: Critical Cyber System component '%s' is exempt from the password reset schedule but has no documented and defined mitigation measures", [object.get(c, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(c, "mitigations_documented")])
}

violations contains msg if {
	some c in exempt_components
	not object.get(c, "mitigation_timeframe_defined", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.C.1.b: Critical Cyber System component '%s' is exempt from the password reset schedule but has no timeframe to complete its mitigations", [object.get(c, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(c, "mitigation_timeframe_defined")])
}

# ── III.C.2 — Multi-factor authentication ────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["access_control", "multi_factor_authentication", "implemented"], null) == true
	not object.get(facts, ["access_control", "multi_factor_authentication", "control_room_workstations_exempt"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.2: Multi-factor authentication — or other logical and physical security controls supplementing password authentication to provide commensurate risk mitigation — is not implemented"
	msg := concat("", [finding, _ev_input("access_control.multi_factor_authentication.implemented"), _ev_input("access_control.multi_factor_authentication.control_room_workstations_exempt")])
}

violations contains msg if {
	object.get(facts, ["access_control", "multi_factor_authentication", "control_room_workstations_exempt"], false) == true
	not object.get(facts, ["access_control", "multi_factor_authentication", "compensating_controls_specified"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.2: Multi-factor authentication is not applied to industrial control workstations in control rooms regulated under 49 CFR parts 192 or 195, and the compensating controls used to manage access are not specified"
	msg := concat("", [finding, _ev_input("access_control.multi_factor_authentication.compensating_controls_specified")])
}

# ── III.C.3 — Least privilege and separation of duties ───────────────────────

violations contains msg if {
	not object.get(facts, ["access_control", "least_privilege", "implemented"], null) == true
	not object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.3: No policies and procedures to manage access rights based on the principle of least privilege"
	msg := concat("", [finding, _ev_input("access_control.least_privilege.implemented"), _ev_input("access_control.least_privilege.not_technically_feasible")])
}

violations contains msg if {
	not object.get(facts, ["access_control", "least_privilege", "separation_of_duties"], null) == true
	not object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.3: No policies and procedures to manage access rights based on the principle of separation of duties"
	msg := concat("", [finding, _ev_input("access_control.least_privilege.separation_of_duties"), _ev_input("access_control.least_privilege.not_technically_feasible")])
}

violations contains msg if {
	object.get(facts, ["access_control", "least_privilege", "not_technically_feasible"], false) == true
	not object.get(facts, ["access_control", "least_privilege", "compensating_controls_described"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.3: Least privilege and separation of duties are declared not technically feasible, but the policies and procedures do not describe the compensating controls the Owner/Operator will apply"
	msg := concat("", [finding, _ev_input("access_control.least_privilege.compensating_controls_described")])
}

# ── III.C.4 — Shared accounts ────────────────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["access_control", "shared_accounts", "policy_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.4: No enforced standards limiting the availability and use of shared accounts"
	msg := concat("", [finding, _ev_input("access_control.shared_accounts.policy_documented")])
}

violations contains msg if {
	some a in shared_accounts
	not object.get(a, "operations_critical", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.C.4: Shared account '%s' is not critical for operations — shared accounts must be limited to those critical for operations, and then only if absolutely necessary", [object.get(a, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(a, "operations_critical")])
}

violations contains msg if {
	some a in shared_accounts
	not object.get(a, "least_privilege_managed", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.C.4.a: Access to shared account '%s' is not limited through account management that uses the principles of least privilege and separation of duties", [object.get(a, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(a, "least_privilege_managed")])
}

violations contains msg if {
	some a in shared_accounts
	not object.get(a, "credential_rotated_on_departure", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.C.4.b: Shared account '%s' has no process ensuring individuals who no longer need access do not retain knowledge of the password", [object.get(a, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(a, "credential_rotated_on_departure")])
}

# ── III.C.5 — Domain trust relationships ─────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["access_control", "domain_trusts", "review_schedule_defined"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.5: No schedule for review of existing domain trust relationships to ensure their necessity"
	msg := concat("", [finding, _ev_input("access_control.domain_trusts.review_schedule_defined")])
}

violations contains msg if {
	not object.get(facts, ["access_control", "domain_trusts", "management_policy_defined"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.C.5: No policies to manage domain trusts"
	msg := concat("", [finding, _ev_input("access_control.domain_trusts.management_policy_defined")])
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

# ---------------------------------------------------------------------------
# Stated facts. A fact that decides whether a requirement applies must be the
# boolean true or false, and a measured value must be a number: an absent fact,
# null or a string is an evidence problem and a finding, never a silent pass.
# Rows: [path under input, directive paragraph].
# ---------------------------------------------------------------------------

_stated_booleans := [
	[["access_control", "multi_factor_authentication", "implemented"], "III.C.2"],
	[["access_control", "multi_factor_authentication", "control_room_workstations_exempt"], "III.C.2"],
	[["access_control", "least_privilege", "not_technically_feasible"], "III.C.3"],
]

violations contains msg if {
	some [path, paragraph] in _stated_booleans
	not is_boolean(object.get(facts, path, null))
	msg := sprintf("TSA SD Pipeline-2021-02G %s: input.%s is not stated as true or false, so the requirement cannot be decided%s", [paragraph, concat(".", path), _ev_input(concat(".", path))])
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
