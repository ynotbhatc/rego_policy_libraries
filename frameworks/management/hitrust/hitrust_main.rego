# METADATA
# title: "HITRUST Common Security Framework (CSF) v11.3.0"
# custom:
#   class: compliance
#   framework: hitrust
#   source: hitrust
#   domains: [healthcare]
#   coverage:
#     checks: 63
#     cited: 0
#     expected: 63
#     found: 63
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package hitrust.main

import rego.v1

# HITRUST Common Security Framework (CSF) v11.3.0
# Released: 2024-04-16 (HITRUST Advisory HAA 2024-002)
#
# UPSTREAM STATUS (checked 2026-11-21, public HITRUST advisories only):
#   - Not current. Upstream is CSF v11.9.0 (HAA 2026-005, 2026-09-24); v11.4.0
#     through v11.8.0 (HAA 2026-002, 2026-05-07) came between.
#   - v11.0-v11.3 are DECOMMISSIONED (HAA 2026-007, 2026-09-24): maintenance
#     ended 2026-09-24; new r2 assessment objects created from 2026-12-23 must
#     use v11.4 or later (the advisory also names 2026-12-31 for disabling
#     v11.0-v11.3 creation); no v11.0-v11.3 submissions for report processing
#     after 2027-03-31; libraries removed from MyCSF 2028-06-30.
#   - The module is a set of HIPAA-oriented healthcare checks written from
#     public knowledge. It carries no CSF requirement text, and its ids are the
#     module's own numbering in CSF reference style, not CSF control references:
#     the CSF has 14 control categories (00-13, per public summaries), so
#     14.a-18.c do not exist and 11-13 carry different topics upstream
#     (11 Incident Management, 12 Business Continuity, 13 Privacy Practices).
#   - The CSF itself is licensed by HITRUST (free, but only to Qualified
#     Organizations; derivative software needs HITRUST's prior written consent).
#     A rebuild against v11.9.0 waits on that permission. See
#     STANDARDS_UPDATE_REGISTRY.md.
#
# Applies to: Healthcare organizations, business associates, and
#             technology vendors handling protected health information (PHI)
#             or requiring HITRUST certification for healthcare customers.
#
# Module check groups (module numbering, see above):
#   00 Security management program   01 Access control
#   02 HR security                   03 Risk management
#   04 Security policy               06 Compliance (HIPAA rules)
#   07 Asset management              08 Physical security
#   09 Operations                    10 Acquisition and development
#   11 Information access            12 Audit logging
#   13 Training                      14 Third parties
#   15 Incident management           16 Business continuity
#   17 Encryption                    18 Privacy practices
#
# OPA endpoint: POST http://<host>:8182/v1/data/hitrust/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Category 00 — Information Security Management Program ───────────────────

_base := []

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("HITRUST CSF 00.a: Information Security Management System (ISMS) not formally established", ["security_program", "isms", "established"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 00.b: Information security policies not approved by senior management", ["security_program", "policies", "approved_by_management"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 00.c: Information security policies not reviewed at least annually", ["security_program", "policies", "annual_review"])
}

# ── Category 01 — Access Control ────────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 01.a: Access control policy not established, documented, and implemented", ["access_control", "policy", "documented"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.b: Formal user access registration and de-registration process not established", ["access_control", "user_access", "formal_registration"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.c: Privileged access rights not managed through formal authorization process", ["access_control", "privileged_access", "controlled"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.d: Strong password/authentication policy not enforced", ["access_control", "password_policy", "strong"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.e: Multi-factor authentication not enforced for critical system access", ["access_control", "mfa", "critical_systems"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.f: Periodic review of user access rights not conducted (at minimum annually)", ["access_control", "access_review", "periodic"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 01.g: Access rights not promptly revoked upon termination or role change", ["access_control", "termination", "prompt_revocation"])
}

# ── Category 02 — Human Resources Security ──────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 02.a: Pre-employment background checks not performed for personnel with PHI access", ["hr_security", "background_checks", "performed"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 02.b: Confidentiality/non-disclosure agreements not signed by employees with PHI access", ["hr_security", "confidentiality", "agreements_signed"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 02.c: Sanction policy for workforce members who fail to comply with security policies not documented", ["hr_security", "sanctions", "policy_documented"])
}

# ── Category 03 — Risk Management ────────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 03.a: Formal risk assessment not conducted", ["risk_management", "assessment", "conducted"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 03.b: Risk assessment does not include PHI confidentiality, integrity, and availability", ["risk_management", "assessment", "phi_scope"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 03.c: Risk treatment plan not documented with accepted residual risks", ["risk_management", "treatment", "plan_documented"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 03.d: Risk assessment not reviewed and updated periodically or after significant changes", ["risk_management", "assessment", "periodic_review"])
}

# ── Category 04 — Security Policy ────────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 04.a: PHI-specific security policies and procedures not documented", ["security_policy", "phi_specific", "documented"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 04.b: Security policies not disseminated to all relevant workforce members", ["security_policy", "dissemination", "to_workforce"])
}

# ── Category 06 — Compliance ─────────────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 06.a: HIPAA Privacy Rule compliance policies not implemented", ["compliance", "hipaa", "privacy_rule", "policies"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 06.b: HIPAA Security Rule compliance policies not implemented", ["compliance", "hipaa", "security_rule", "policies"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 06.c: HIPAA Breach Notification Rule compliance plan not established", ["compliance", "hipaa", "breach_notification", "plan"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 06.d: Periodic compliance review not conducted to identify legal/regulatory changes", ["compliance", "legal", "periodic_review"])
}

# ── Category 07 — Asset Management ────────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 07.a: Asset inventory not maintained for systems and media containing PHI", ["asset_management", "inventory", "maintained"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 07.b: PHI assets not classified and labeled according to sensitivity", ["asset_management", "classification", "phi_labeled"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 07.c: Secure media sanitization procedures not established for PHI disposal", ["asset_management", "disposal", "secure_media_sanitization"])
}

# ── Category 08 — Physical and Environmental Security ───────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 08.a: Physical access to facilities containing PHI systems not controlled", ["physical_security", "perimeter", "controlled_access"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 08.b: Equipment containing PHI not secured against physical threats", ["physical_security", "equipment", "secured"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 08.c: Visitor access to secure areas not logged and controlled", ["physical_security", "visitor_access", "logged"])
}

# ── Category 09 — Communications and Operations Management ──────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 09.a: Formal change management process not established for PHI systems", ["operations", "change_management", "formal_process"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 09.b: Malware protection not deployed on all systems processing PHI", ["operations", "malware", "protection_deployed"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 09.c: PHI not backed up with tested recovery procedures", ["operations", "backup", "phi_backed_up"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 09.d: Regular vulnerability scanning not performed on systems processing PHI", ["operations", "vulnerability_management", "scanning"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 09.e: Timely patch management process not established for PHI systems", ["operations", "patch_management", "timely"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 09.f: Network monitoring not implemented to detect anomalous activity involving PHI", ["operations", "network_monitoring", "enabled"])
}

# ── Category 10 — Information Systems Acquisition, Development ──────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 10.a: Security requirements not included in information system development/acquisition", ["secure_development", "requirements", "security_included"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 10.b: Security testing not performed before PHI systems are placed into production", ["secure_development", "testing", "security_testing"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 10.c: PHI used in development or test environments — must use de-identified data", ["secure_development", "phi", "no_phi_in_test"])
}

# ── Category 11 — Information Access Management ──────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 11.a: Access to PHI not restricted to minimum necessary for job function", ["access_management", "phi", "minimum_necessary"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 11.b: Remote access to PHI systems not controlled and monitored", ["access_management", "remote_access", "controlled"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 11.c: Wireless access transmitting PHI not properly secured and encrypted", ["access_management", "wireless", "secured"])
}

# ── Category 12 — Audit Logging and Monitoring ──────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 12.a: All access to PHI (create, read, update, delete) not logged", ["audit", "phi_access", "logged"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 12.b: Audit logs not protected from unauthorized modification or deletion", ["audit", "logs", "protected_from_tampering"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 12.c: Audit logs for PHI not retained for minimum 6 years (HIPAA requirement)", ["audit", "logs", "retention_6_years"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 12.d: Audit logs not reviewed regularly for suspicious activity", ["audit", "review", "regular"])
}

# ── Category 13 — Education, Training and Awareness ─────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 13.a: Annual HIPAA security and privacy training not provided to all workforce members", ["training", "hipaa", "all_workforce_annual"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 13.b: PHI handling procedures not included in security awareness training", ["training", "phi_handling", "included"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 13.c: Security training completion not tracked for all workforce members", ["training", "completion", "tracked"])
}

# ── Category 14 — Third Party Assurance ─────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 14.a: Business Associate Agreements (BAA) not executed with all vendors accessing PHI", ["third_party", "baa", "executed"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 14.b: Security evaluation of third parties with PHI access not performed", ["third_party", "assessment", "security_evaluation"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 14.c: Contracts with PHI-handling vendors do not include security requirements", ["third_party", "contracts", "security_requirements"])
}

# ── Category 15 — Incident Management ────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 15.a: Security incident response plan not documented", ["incident_response", "plan", "documented"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 15.b: PHI breach response procedures not established (including HIPAA notification timelines)", ["incident_response", "phi_breach", "procedures"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 15.c: Incident response plan not tested at least annually", ["incident_response", "plan", "tested_annually"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 15.d: Process not established to report breaches affecting 500+ individuals to HHS within 60 days", ["incident_response", "reporting", "hhs_60_days"])
}

# ── Category 16 — Business Continuity Management ─────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 16.a: Business continuity plan not documented for critical PHI systems", ["business_continuity", "bcp", "documented"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 16.b: Disaster recovery plan not established for PHI system restoration", ["business_continuity", "drp", "phi_systems"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 16.c: Business continuity/disaster recovery plan not tested periodically", ["business_continuity", "bcp", "tested"])
}

# ── Category 17 — Risk Management Specific ────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 17.a: PHI not encrypted at rest on storage systems", ["risk_management", "encryption", "phi_at_rest"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 17.b: PHI not encrypted in transit over networks (TLS 1.2+ required)", ["risk_management", "encryption", "phi_in_transit"])
}

# ── Category 18 — Privacy Practices ──────────────────────────────────────────

violations contains msg if {
	msg := _finding("HITRUST CSF 18.a: Notice of Privacy Practices not provided to patients", ["privacy", "notice", "provided_to_patients"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 18.b: Minimum necessary standard not enforced for PHI access and disclosure", ["privacy", "minimum_necessary", "enforced"])
}

violations contains msg if {
	msg := _finding("HITRUST CSF 18.c: Process not established to honor patient rights (access, amendment, accounting of disclosures)", ["privacy", "patient_rights", "process_exists"])
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

compliance_report := {
	"framework": "HITRUST Common Security Framework (CSF)",
	"version": "v11.3.0",
	"published": "2024-04-16",
	"entity_name": entity_name,
	"entity_type": entity_type,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": total_controls,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": count(violations),
	"passed_controls": total_controls - count(violations),
	"not_applicable_controls": 0,
	# total_checks and failed_checks date from when the declared total (59) was below the check count;
	# they now equal total_controls and failed_controls and are kept for report consumers.
	"total_checks": total_controls,
	"failed_checks": count(violations),
	"category_summary": {
		"security_mgmt_program": [v | some v in violations; contains(v, "CSF 00.")],
		"access_control": [v | some v in violations; contains(v, "CSF 01.")],
		"hr_security": [v | some v in violations; contains(v, "CSF 02.")],
		"risk_management": array.concat([v | some v in violations; contains(v, "CSF 03.")], [v | some v in violations; contains(v, "CSF 17.")]),
		"security_policy": [v | some v in violations; contains(v, "CSF 04.")],
		"compliance": [v | some v in violations; contains(v, "CSF 06.")],
		"asset_management": [v | some v in violations; contains(v, "CSF 07.")],
		"physical_security": [v | some v in violations; contains(v, "CSF 08.")],
		"operations": [v | some v in violations; contains(v, "CSF 09.")],
		"system_acquisition_development": [v | some v in violations; contains(v, "CSF 10.")],
		"information_access": [v | some v in violations; contains(v, "CSF 11.")],
		"audit_logging": [v | some v in violations; contains(v, "CSF 12.")],
		"training": [v | some v in violations; contains(v, "CSF 13.")],
		"third_party": [v | some v in violations; contains(v, "CSF 14.")],
		"incident_management": [v | some v in violations; contains(v, "CSF 15.")],
		"business_continuity": [v | some v in violations; contains(v, "CSF 16.")],
		"privacy": [v | some v in violations; contains(v, "CSF 18.")],
	},
}

# ── Counting ─────────────────────────────────────────────────────────────────
# One control per check rule, one finding per control, each under its own id in the module's numbering
# (see the header: these are not CSF control references). By group:
#   00: 3 · 01: 7 · 02: 3 · 03: 4 · 04: 2 · 06: 4 · 07: 3 · 08: 3 · 09: 6 · 10: 3 · 11: 3 · 12: 4
#   13: 3 · 14: 3 · 15: 4 · 16: 3 · 17: 2 · 18: 3  = 63
# The total was declared as 59 while 63 ids reported, so 63 findings sat beside a total of 59 and
# failed_controls was capped. No id is repeated and no two rules read the same fact, so the rule set
# is the catalogue and the declared figure was four short (audit 2026-11-24). No check is ever out of
# scope, so not_applicable_controls is 0 and passed + failed = 63 on every input.
total_controls := 63
