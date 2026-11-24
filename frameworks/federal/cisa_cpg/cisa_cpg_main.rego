# METADATA
# title: "CISA Cross-Sector Cybersecurity Performance Goals (CPG) 2.0"
# custom:
#   class: compliance
#   framework: cisa_cpg
#   source: cisa
#   domains: [us-federal, critical-infrastructure]
#   coverage:
#     checks: 35
#     cited: 25
#     expected: 34
#     found: 35
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cisa_cpg.main

import rego.v1

# CISA Cross-Sector Cybersecurity Performance Goals (CPG) 2.0
# (official publication 2025-12-11; aligned to NIST CSF 2.0's six functions,
# GOVERN added; CISA's stated revision cycle is 24-36 months)
#
# 34 goals across six functions:
#   1 Govern (1.A-1.E)    4 Detect (4.A-4.B)
#   2 Identify (2.A-2.E)  5 Respond (5.A-5.B)
#   3 Protect (3.A-3.S)   6 Recover (6.A)
#
# The CPGs are a prioritized floor, not a full program — every goal
# maps to NIST CSF subcategories by design. Where a goal's concept is
# already collected for the CSF 2.0 modules, this module reads the
# SAME input fields so one fact collection feeds both frameworks:
#
#   2.A Manage Organizational Assets → input.identify.asset_management.*
#       (shared with nist.csf.identify)
#   3.F Multi-factor Authentication  → input.access_control.remote_access.
#       multi_factor_authentication (shared with nist.csf.protect)
#
# Everything else reads from the input.cpg.* namespace. See tests for
# the full expected shape.
#
# v1.0.1 → 2.0 renumbering is captured in the report's
# "version_mapping_note" so historical assessments remain traceable.

# ── Evidence rule ────────────────────────────────────────────────────────────
# Only the boolean true passes a yes/no fact. A fact that is missing, null, or any
# other type ("true", "false", "no", 0, 1) is an evidence problem: the control fails
# and the finding names the problem. A boolean false keeps the plain finding.

default _input := {}

_input := input if is_object(input)

_fact(path) := object.get(_input, path, null)

_not_true(path) if _fact(path) != true

_finding(msg, path) := msg if _fact(path) == false

_finding(msg, path) := sprintf("%s [evidence missing — input.%s not collected]", [msg, concat(".", path)]) if {
	_fact(path) == null
}

_finding(msg, path) := sprintf("%s [evidence invalid — input.%s is not a boolean (got %s)]", [msg, concat(".", path), type_name(_fact(path))]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Function 1 — GOVERN ──────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["cpg", "governance", "responsibilities_established"])
	finding := "CISA CPG 1.A (Establish Cybersecurity Responsibilities): Leadership responsibility and accountability for cybersecurity not established for IT and OT"
	msg := _finding(finding, ["cpg", "governance", "responsibilities_established"])
}

violations contains msg if {
	_not_true(["cpg", "governance", "oversight_managed"])
	finding := "CISA CPG 1.B (Manage Cybersecurity Oversight): Leadership does not regularly review and adapt the cybersecurity program against evolving threats"
	msg := _finding(finding, ["cpg", "governance", "oversight_managed"])
}

violations contains msg if {
	_not_true(["cpg", "governance", "incident_response_plans_managed"])
	finding := "CISA CPG 1.C (Maintain Incident Response Plans): IT and OT incident response plans not established, maintained, and exercised"
	msg := _finding(finding, ["cpg", "governance", "incident_response_plans_managed"])
}

violations contains msg if {
	_not_true(["cpg", "governance", "supply_chain_reporting_required"])
	finding := "CISA CPG 1.D (Supply Chain Incident Reporting & Vulnerability Disclosure): Supplier contracts do not require incident reporting and vulnerability disclosure"
	msg := _finding(finding, ["cpg", "governance", "supply_chain_reporting_required"])
}

violations contains msg if {
	_not_true(["cpg", "governance", "msp_risk_managed"])
	finding := "CISA CPG 1.E (Manage Risks from Managed Service Providers): Risks from MSPs with privileged system access not identified and managed"
	msg := _finding(finding, ["cpg", "governance", "msp_risk_managed"])
}

# ── Function 2 — IDENTIFY ────────────────────────────────────────────────────

# 2.A shares the CSF Identify fact namespace (one collection, two frameworks).
violations contains msg if {
	_not_true(["identify", "asset_management", "physical_devices_inventoried"])
	finding := "CISA CPG 2.A (Manage Organizational Assets): Physical device/hardware asset inventory not maintained"
	msg := _finding(finding, ["identify", "asset_management", "physical_devices_inventoried"])
}

violations contains msg if {
	_not_true(["identify", "asset_management", "software_platforms_inventoried"])
	finding := "CISA CPG 2.A (Manage Organizational Assets): Software and platform inventory not maintained"
	msg := _finding(finding, ["identify", "asset_management", "software_platforms_inventoried"])
}

violations contains msg if {
	_not_true(["cpg", "identify", "kev_mitigated"])
	finding := "CISA CPG 2.B (Mitigate Known Vulnerabilities): Known exploited vulnerabilities (CISA KEV) not mitigated on internet-facing systems within risk-informed timelines"
	msg := _finding(finding, ["cpg", "identify", "kev_mitigated"])
}

violations contains msg if {
	_not_true(["cpg", "identify", "independent_validation"])
	finding := "CISA CPG 2.C (Obtain Independent Validation of Cybersecurity Controls): Controls not independently validated (assessment, audit, or pen test by parties outside the implementing team)"
	msg := _finding(finding, ["cpg", "identify", "independent_validation"])
}

violations contains msg if {
	_not_true(["cpg", "identify", "vulnerability_disclosure_process"])
	finding := "CISA CPG 2.D (Maintain Vulnerability Disclosure/Reporting Process): Public process for external parties to report vulnerabilities not maintained"
	msg := _finding(finding, ["cpg", "identify", "vulnerability_disclosure_process"])
}

violations contains msg if {
	_not_true(["cpg", "identify", "network_topology_documented"])
	finding := "CISA CPG 2.E (Document Network Topology): Current network topology documentation (IT and OT) not maintained"
	msg := _finding(finding, ["cpg", "identify", "network_topology_documented"])
}

# ── Function 3 — PROTECT ─────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["cpg", "protect", "default_passwords_changed"])
	finding := "CISA CPG 3.A (Changing Default Passwords): Default manufacturer passwords not changed before deployment"
	msg := _finding(finding, ["cpg", "protect", "default_passwords_changed"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "minimum_password_strength"])
	finding := "CISA CPG 3.B (Establish Minimum Password Strength): Minimum password strength not enforced organization-wide"
	msg := _finding(finding, ["cpg", "protect", "minimum_password_strength"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "unique_credentials"])
	finding := "CISA CPG 3.C (Create Unique Credentials): Unique credentials per user/service not enforced (shared accounts in use)"
	msg := _finding(finding, ["cpg", "protect", "unique_credentials"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "departing_credentials_revoked"])
	finding := "CISA CPG 3.D (Revoking Credentials for Departing Staff): Credentials of departing employees/contractors not promptly revoked"
	msg := _finding(finding, ["cpg", "protect", "departing_credentials_revoked"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "unsuccessful_logins_monitored"])
	finding := "CISA CPG 3.E (Monitor Unsuccessful Login Attempts): Unsuccessful (automated) login attempts not detected and alerted (brute-force indicator)"
	msg := _finding(finding, ["cpg", "protect", "unsuccessful_logins_monitored"])
}

# 3.F shares the CSF Protect fact for remote-access MFA.
violations contains msg if {
	_not_true(["access_control", "remote_access", "multi_factor_authentication"])
	finding := "CISA CPG 3.F (Implement Multi-factor Authentication): MFA not implemented — at minimum for remote access and privileged accounts, phishing-resistant preferred"
	msg := _finding(finding, ["access_control", "remote_access", "multi_factor_authentication"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "separate_privileged_accounts"])
	finding := "CISA CPG 3.G (Administrators Maintain Separate User and Privileged Accounts): Administrators do not use separate accounts for user vs privileged activity"
	msg := _finding(finding, ["cpg", "protect", "separate_privileged_accounts"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "least_privilege"])
	finding := "CISA CPG 3.H (Implement the Principles of Least Privilege): Access rights not limited to those required for role/function"
	msg := _finding(finding, ["cpg", "protect", "least_privilege"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "network_segmentation"])
	finding := "CISA CPG 3.I (Implement Logical/Physical Network Segmentation): Networks (including IT/OT boundary) not segmented"
	msg := _finding(finding, ["cpg", "protect", "network_segmentation"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "cybersecurity_training"])
	finding := "CISA CPG 3.J (Implement Cybersecurity Training): Cybersecurity training (including OT-specific where applicable) not provided"
	msg := _finding(finding, ["cpg", "protect", "cybersecurity_training"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "strong_encryption"])
	finding := "CISA CPG 3.K (Utilize Strong Encryption): Strong, agile encryption not used for data in transit and sensitive data (including credentials/secrets) at rest"
	msg := _finding(finding, ["cpg", "protect", "strong_encryption"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "email_security"])
	finding := "CISA CPG 3.L (Enable Email Security): Email security controls (SPF/DKIM/DMARC, STARTTLS) not enabled"
	msg := _finding(finding, ["cpg", "protect", "email_security"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "macros_disabled"])
	finding := "CISA CPG 3.M (Disable Autorun & Macros By Default): Autorun and Office macros not disabled by default"
	msg := _finding(finding, ["cpg", "protect", "macros_disabled"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "change_management"])
	finding := "CISA CPG 3.N (Establish Change Management Processes): Documented change management for systems and configurations not established"
	msg := _finding(finding, ["cpg", "protect", "change_management"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "backups_maintained"])
	finding := "CISA CPG 3.O (Maintain System Backups & Restoration Ability): System backups not maintained, isolated, and restoration-tested"
	msg := _finding(finding, ["cpg", "protect", "backups_maintained"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "hw_sw_approval_process"])
	finding := "CISA CPG 3.P (Maintain Hardware & Software Approval Process): Administrative approval process for new hardware/software not maintained"
	msg := _finding(finding, ["cpg", "protect", "hw_sw_approval_process"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "log_collection_storage"])
	finding := "CISA CPG 3.Q (Maintain Log Collection & Storage): Security logs not collected and stored securely (tamper-resistant, adequate retention)"
	msg := _finding(finding, ["cpg", "protect", "log_collection_storage"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "unauthorized_devices_prohibited"])
	finding := "CISA CPG 3.R (Prohibit Connection of Unauthorized Devices): Connection of unauthorized devices (including removable media) not prevented"
	msg := _finding(finding, ["cpg", "protect", "unauthorized_devices_prohibited"])
}

violations contains msg if {
	_not_true(["cpg", "protect", "internet_facing_secured"])
	finding := "CISA CPG 3.S (Secure Internet Facing Devices): Unnecessary exploitable services on internet-facing assets (and unprotected OT exposure) not eliminated"
	msg := _finding(finding, ["cpg", "protect", "internet_facing_secured"])
}

# ── Function 4 — DETECT ──────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["cpg", "detect", "malicious_code_detection"])
	finding := "CISA CPG 4.A (Establish Malicious Code Detection): Malicious code detection (endpoint/network) not established"
	msg := _finding(finding, ["cpg", "detect", "malicious_code_detection"])
}

violations contains msg if {
	_not_true(["cpg", "detect", "adverse_events_identified"])
	finding := "CISA CPG 4.B (Identify Adverse Events): Capability to identify adverse events and relevant threat TTPs not established"
	msg := _finding(finding, ["cpg", "detect", "adverse_events_identified"])
}

# ── Function 5 — RESPOND ─────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["cpg", "respond", "incident_communications"])
	finding := "CISA CPG 5.A (Establish Incident Communication Procedures): Incident communication procedures (internal, partners, suppliers) not established"
	msg := _finding(finding, ["cpg", "respond", "incident_communications"])
}

violations contains msg if {
	_not_true(["cpg", "respond", "incident_reporting"])
	finding := "CISA CPG 5.B (Establish Incident Reporting Procedures): Procedures to report incidents (including to CISA/authorities as applicable) not established"
	msg := _finding(finding, ["cpg", "respond", "incident_reporting"])
}

# ── Function 6 — RECOVER ─────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["cpg", "recover", "incident_planning_preparedness"])
	finding := "CISA CPG 6.A (Execute Incident Recovery Plan): capability to execute recovery plans (restoration exercises, degraded-operations readiness, lessons learned) not established"
	msg := _finding(finding, ["cpg", "recover", "incident_planning_preparedness"])
}

# ── Per-function rollup ──────────────────────────────────────────────────────

function_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

function_summary := {
	"govern": count(function_violations("CISA CPG 1.")),
	"identify": count(function_violations("CISA CPG 2.")),
	"protect": count(function_violations("CISA CPG 3.")),
	"detect": count(function_violations("CISA CPG 4.")),
	"respond": count(function_violations("CISA CPG 5.")),
	"recover": count(function_violations("CISA CPG 6.")),
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

compliance_report := {
	"framework": "CISA Cross-Sector Cybersecurity Performance Goals",
	"version": "2.0 (published 2025-12-11)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 34,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([34, count(violations)]),
	"function_summary": function_summary,
	"version_mapping_note": "Goal IDs follow CPG 2.0. For assessments recorded against v1.0.1 IDs, consult the v1.0.1-to-2.0 mapping table in the CPG 2.0 report (e.g. old 1.A Asset Inventory = new 2.A; old 2.H MFA = new 3.F).",
}
