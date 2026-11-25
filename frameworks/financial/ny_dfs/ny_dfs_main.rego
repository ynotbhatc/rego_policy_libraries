# METADATA
# title: "New York Department of Financial Services — 23 NYCRR Part 500"
# custom:
#   class: compliance
#   framework: ny_dfs
#   source: ny-dfs
#   domains: [financial, us-state]
#   coverage:
#     checks: 46
#     cited: 33
#     expected: 45
#     found: 46
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package ny_dfs.main

import rego.v1

# New York Department of Financial Services — 23 NYCRR Part 500
# Cybersecurity Requirements for Financial Services Companies
# Version 2 (November 2023) — significant updates from original 2017 rule.
# The second amendment's phased effective dates ran through 2025-11-01;
# the FINAL tranche is now fully enforceable (DFS examines against it):
#   500.12   MFA for ANY individual accessing ANY information system
#            (exceptions only via documented CISO-approved compensating
#            controls)
#   500.13(a) complete asset inventory tracking owner, location,
#            classification, support expiration and recovery-time
#            objectives
#
# Applies to: all DFS-licensed/registered entities including banks, insurance companies,
#             money transmitters, mortgage servicers, and virtual currency businesses
#
# Key sections:
#   500.2   Cybersecurity Program
#   500.3   Cybersecurity Policy
#   500.4   Chief Information Security Officer (CISO)
#   500.5   Penetration Testing and Vulnerability Assessments
#   500.6   Audit Trail
#   500.7   Access Privileges and Management
#   500.9   Risk Assessment
#   500.10  Cybersecurity Personnel and Intelligence
#   500.11  Third-Party Service Provider Security Policy
#   500.12  Multi-Factor Authentication
#   500.13  Data Retention Limitations
#   500.14  Training and Monitoring
#   500.15  Encryption of Non-Public Information
#   500.16  Incident Response and Business Continuity Plan
#   500.17  Notices to Superintendent
#
# OPA endpoint: POST http://<host>:8182/v1/data/ny_dfs/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

# ── 500.2 — Cybersecurity Program ────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["cybersecurity_program", "exists"])
	text := "23 NYCRR 500.2: Cybersecurity program not established to protect information systems and nonpublic information"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["cybersecurity_program", "risk_based", "design"])
	text := "23 NYCRR 500.2(b): Cybersecurity program not designed based on covered entity's risk assessment"
	msg := concat("", [text, note])
}

# ── 500.3 — Cybersecurity Policy ─────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["cybersecurity_policy", "documented"])
	text := "23 NYCRR 500.3: Written cybersecurity policy not implemented and maintained"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["cybersecurity_policy", "board_approved"])
	text := "23 NYCRR 500.3: Cybersecurity policy not approved by senior officer or board"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["cybersecurity_policy", "annual_review"])
	text := "23 NYCRR 500.3: Cybersecurity policy not reviewed at least annually"
	msg := concat("", [text, note])
}

# ── 500.4 — CISO ─────────────────────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["ciso", "designated"])
	text := "23 NYCRR 500.4(a): Qualified CISO not designated to oversee cybersecurity program"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ciso", "annual_report", "to_board"])
	text := "23 NYCRR 500.4(b): CISO has not provided annual report to board on cybersecurity program"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ciso", "annual_report", "includes_material_issues"])
	text := "23 NYCRR 500.4(b): CISO annual report does not address material cybersecurity issues"
	msg := concat("", [text, note])
}

# ── 500.5 — Penetration Testing & Vulnerability Assessments ──────────────────

violations contains msg if {
	note := _unmet(_root, ["testing", "penetration_test", "annual"])
	text := "23 NYCRR 500.5(a)(1): Annual penetration testing of information systems not performed"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["testing", "vulnerability_assessment", "semi_annual"])
	text := "23 NYCRR 500.5(a)(2): Bi-annual automated vulnerability scans not conducted"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["testing", "findings", "remediation_tracked"])
	text := "23 NYCRR 500.5: Penetration test and vulnerability assessment findings not tracked to remediation"
	msg := concat("", [text, note])
}

# ── 500.6 — Audit Trail ──────────────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["audit_trail", "systems", "tamper_resistant"])
	text := "23 NYCRR 500.6(a): Audit trail systems not designed to protect against tampering and alteration"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["audit_trail", "retention", "minimum_3_years_financial"])
	text := "23 NYCRR 500.6(b): Financial records audit trail not retained for minimum 3 years"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["audit_trail", "retention", "minimum_5_years_security"])
	text := "23 NYCRR 500.6(b): Cybersecurity event audit trail not retained for minimum 5 years"
	msg := concat("", [text, note])
}

# ── 500.7 — Access Privileges ────────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["access_control", "least_privilege", "enforced"])
	text := "23 NYCRR 500.7: Least privilege not enforced — access limited to what is necessary for job function"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "privileged_accounts", "regular_review"])
	text := "23 NYCRR 500.7(b): Privileged account access not reviewed at least annually"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "terminated_users", "prompt_revocation"])
	text := "23 NYCRR 500.7(c): Access not promptly revoked for terminated employees"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "password_policy", "strong"])
	text := "23 NYCRR 500.7(d): Strong password policy not enforced for system access"
	msg := concat("", [text, note])
}

# ── 500.9 — Risk Assessment ───────────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["risk_assessment", "conducted"])
	text := "23 NYCRR 500.9: Cybersecurity risk assessment not conducted"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["risk_assessment", "periodic_review"])
	text := "23 NYCRR 500.9(a): Risk assessment not reviewed and updated periodically"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["risk_assessment", "covers_nonpublic_information"])
	text := "23 NYCRR 500.9(a)(2): Risk assessment does not address risks to nonpublic information"
	msg := concat("", [text, note])
}

# ── 500.10 — Cybersecurity Personnel ─────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["personnel", "qualified_staff", "available"])
	text := "23 NYCRR 500.10(a): Qualified cybersecurity personnel not employed or engaged"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["personnel", "training", "cybersecurity", "annual"])
	text := "23 NYCRR 500.10(b): Annual cybersecurity training not provided to all relevant personnel"
	msg := concat("", [text, note])
}

# ── 500.11 — Third-Party Service Provider Security ────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["third_party", "policy", "documented"])
	text := "23 NYCRR 500.11: Written third-party service provider security policy not implemented"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["third_party", "contracts", "security_controls_required"])
	text := "23 NYCRR 500.11(a)(1): Third-party contracts do not require implementation of security controls"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["third_party", "contracts", "prompt_notification_required"])
	text := "23 NYCRR 500.11(a)(2): Third-party contracts do not require prompt notification of cybersecurity events"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["third_party", "assessment", "periodic_due_diligence"])
	text := "23 NYCRR 500.11(a)(3): Periodic due diligence of third-party service providers not conducted"
	msg := concat("", [text, note])
}

# ── 500.12 — Multi-Factor Authentication ─────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["mfa", "remote_access", "enforced"])
	text := "23 NYCRR 500.12: MFA not implemented for remote access to information systems"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["mfa", "third_party_access", "enforced"])
	text := "23 NYCRR 500.12: MFA not implemented for third-party access to internal networks"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["mfa", "privileged_accounts", "enforced"])
	text := "23 NYCRR 500.12: MFA not implemented for privileged account access"
	msg := concat("", [text, note])
}

# Final-tranche obligation (enforceable since 2025-11-01): MFA for ANY
# individual accessing ANY information system — the narrow remote/
# third-party/privileged scoping above is no longer sufficient on its
# own. Exceptions only via documented, CISO-approved compensating
# controls (500.12(c)).
violations contains msg if {
	not input.mfa.all_individuals_all_systems.enforced == true
	not input.mfa.ciso_approved_compensating_controls.documented == true
	msg := "23 NYCRR 500.12 (second amendment, enforceable 2025-11-01): MFA not enforced for all individuals accessing any information system, and no CISO-approved compensating controls are documented"
}

# ── 500.13 — Asset Inventory and Data Retention ──────────────────────────────

# 500.13(a) (second amendment, enforceable 2025-11-01): written policies
# and procedures for a complete, accurate asset inventory.
violations contains msg if {
	note := _unmet(_root, ["asset_inventory", "maintained"])
	text := "23 NYCRR 500.13(a) (second amendment, enforceable 2025-11-01): complete asset inventory of information systems not maintained"
	msg := concat("", [text, note])
}

violations contains msg if {
	input.asset_inventory.maintained == true
	note := _unmet(_root, ["asset_inventory", "tracks_required_fields"])
	text := "23 NYCRR 500.13(a): asset inventory does not track the required fields — owner, location, classification/sensitivity, support expiration date, recovery time objectives"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["data_retention", "policy", "documented"])
	text := "23 NYCRR 500.13: Data retention and disposal policy not documented"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["data_retention", "nonpublic_info", "disposed_when_no_longer_needed"])
	text := "23 NYCRR 500.13: Nonpublic information not securely disposed when no longer needed"
	msg := concat("", [text, note])
}

# ── 500.14 — Training and Monitoring ─────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["training", "security_awareness", "annual"])
	text := "23 NYCRR 500.14(a): Annual cybersecurity awareness training not provided to all personnel"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["monitoring", "anomalous_activity", "systems_in_place"])
	text := "23 NYCRR 500.14(b): Monitoring systems not in place to detect anomalous activity"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["monitoring", "user_activity", "privileged_users_monitored"])
	text := "23 NYCRR 500.14(b): Authorized user activity not monitored to detect unauthorized access"
	msg := concat("", [text, note])
}

# ── 500.15 — Encryption ───────────────────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["encryption", "nonpublic_info", "in_transit"])
	text := "23 NYCRR 500.15: Nonpublic information not encrypted in transit over external networks"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["encryption", "nonpublic_info", "at_rest"])
	text := "23 NYCRR 500.15: Nonpublic information not encrypted at rest"
	msg := concat("", [text, note])
}

# ── 500.16 — Incident Response Plan ──────────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["incident_response", "plan", "documented"])
	text := "23 NYCRR 500.16: Written incident response plan not established and maintained"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["incident_response", "plan", "tested_annually"])
	text := "23 NYCRR 500.16: Incident response plan not tested at least annually"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["incident_response", "plan", "roles_defined"])
	text := "23 NYCRR 500.16(b)(1): Roles and responsibilities not defined in incident response plan"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["business_continuity", "plan", "documented"])
	text := "23 NYCRR 500.16: Business continuity plan not established for material cybersecurity events"
	msg := concat("", [text, note])
}

# ── 500.17 — Notices to Superintendent ───────────────────────────────────────

violations contains msg if {
	note := _unmet(_root, ["superintendent_notice", "process", "within_72_hours"])
	text := "23 NYCRR 500.17(a): Process not established to notify DFS Superintendent within 72 hours of material cybersecurity event"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["superintendent_notice", "annual_certification", "filed"])
	text := "23 NYCRR 500.17(b): Annual certification of compliance not filed with DFS Superintendent"
	msg := concat("", [text, note])
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default dfs_license_number := "unknown"

dfs_license_number := input.dfs_license_number

default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

compliance_report := {
	"framework": "NY DFS Cybersecurity Regulation",
	"regulation": "23 NYCRR Part 500 (second amendment, Nov 2023; final tranche enforceable 2025-11-01)",
	"entity_name": entity_name,
	"entity_type": entity_type,
	"dfs_license": dfs_license_number,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": total_controls,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": count(violations),
	"passed_controls": total_controls - count(violations),
	"not_applicable_controls": 0,
}

# ── Counting ─────────────────────────────────────────────────────────────────
# 45 controls, one finding each. By section of 23 NYCRR 500:
#   .2: 2 · .3: 3 · .4: 3 · .5: 3 · .6: 3 · .7: 4 · .9: 3 · .10: 2 · .11: 4 · .12: 4 · .13: 3
#   .14: 3 · .15: 2 · .16: 4 · .17: 2  = 45
# The module has 46 check rules: the two 500.13(a) rules are one control (the asset inventory is
# maintained and tracks the required fields). The field rule fires only when the inventory is stated as
# maintained and the other fires only when it is not, so they never report together and a failed
# control is one finding. The total was declared as 44, from before the 2025-11-01 tranche added the
# 500.12 all-individuals check: 45 findings sat beside 44 and failed_controls was capped (audit
# 2026-11-24). No check is ever out of scope, so not_applicable_controls is 0.
total_controls := 45

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
