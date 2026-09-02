package cisa_cpg.main

import rego.v1

# CISA Cross-Sector Cybersecurity Performance Goals (CPG) 2.0
# (October 2025 update; aligned to NIST CSF 2.0's six functions,
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

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Function 1 — GOVERN ──────────────────────────────────────────────────────

violations contains msg if {
	not input.cpg.governance.responsibilities_established
	msg := "CISA CPG 1.A (Establish Cybersecurity Responsibilities): Leadership responsibility and accountability for cybersecurity not established for IT and OT"
}

violations contains msg if {
	not input.cpg.governance.oversight_managed
	msg := "CISA CPG 1.B (Manage Cybersecurity Oversight): Leadership does not regularly review and adapt the cybersecurity program against evolving threats"
}

violations contains msg if {
	not input.cpg.governance.incident_response_plans_managed
	msg := "CISA CPG 1.C (Manage Incident Response Plans): IT and OT incident response plans not established, maintained, and exercised"
}

violations contains msg if {
	not input.cpg.governance.supply_chain_reporting_required
	msg := "CISA CPG 1.D (Supply Chain Incident Reporting & Vulnerability Disclosure): Supplier contracts do not require incident reporting and vulnerability disclosure"
}

violations contains msg if {
	not input.cpg.governance.msp_risk_managed
	msg := "CISA CPG 1.E (Manage Risks from Managed Service Providers): Risks from MSPs with privileged system access not identified and managed"
}

# ── Function 2 — IDENTIFY ────────────────────────────────────────────────────

# 2.A shares the CSF Identify fact namespace (one collection, two frameworks).
violations contains msg if {
	not input.identify.asset_management.physical_devices_inventoried
	msg := "CISA CPG 2.A (Manage Organizational Assets): Physical device/hardware asset inventory not maintained"
}

violations contains msg if {
	not input.identify.asset_management.software_platforms_inventoried
	msg := "CISA CPG 2.A (Manage Organizational Assets): Software and platform inventory not maintained"
}

violations contains msg if {
	not input.cpg.identify.kev_mitigated
	msg := "CISA CPG 2.B (Mitigate Known Vulnerabilities): Known exploited vulnerabilities (CISA KEV) not mitigated on internet-facing systems within risk-informed timelines"
}

violations contains msg if {
	not input.cpg.identify.independent_validation
	msg := "CISA CPG 2.C (Obtain Independent Validation of Cybersecurity Controls): Controls not independently validated (assessment, audit, or pen test by parties outside the implementing team)"
}

violations contains msg if {
	not input.cpg.identify.vulnerability_disclosure_process
	msg := "CISA CPG 2.D (Maintain Vulnerability Disclosure/Reporting Process): Public process for external parties to report vulnerabilities not maintained"
}

violations contains msg if {
	not input.cpg.identify.network_topology_documented
	msg := "CISA CPG 2.E (Document Network Topology): Current network topology documentation (IT and OT) not maintained"
}

# ── Function 3 — PROTECT ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cpg.protect.default_passwords_changed
	msg := "CISA CPG 3.A (Changing Default Passwords): Default manufacturer passwords not changed before deployment"
}

violations contains msg if {
	not input.cpg.protect.minimum_password_strength
	msg := "CISA CPG 3.B (Establish Minimum Password Strength): Minimum password strength not enforced organization-wide"
}

violations contains msg if {
	not input.cpg.protect.unique_credentials
	msg := "CISA CPG 3.C (Create Unique Credentials): Unique credentials per user/service not enforced (shared accounts in use)"
}

violations contains msg if {
	not input.cpg.protect.departing_credentials_revoked
	msg := "CISA CPG 3.D (Revoking Credentials for Departing Staff): Credentials of departing employees/contractors not promptly revoked"
}

violations contains msg if {
	not input.cpg.protect.unsuccessful_logins_monitored
	msg := "CISA CPG 3.E (Monitor Unsuccessful Login Attempts): Unsuccessful (automated) login attempts not detected and alerted (brute-force indicator)"
}

# 3.F shares the CSF Protect fact for remote-access MFA.
violations contains msg if {
	not input.access_control.remote_access.multi_factor_authentication
	msg := "CISA CPG 3.F (Implement Multi-factor Authentication): MFA not implemented — at minimum for remote access and privileged accounts, phishing-resistant preferred"
}

violations contains msg if {
	not input.cpg.protect.separate_privileged_accounts
	msg := "CISA CPG 3.G (Administrators Maintain Separate User and Privileged Accounts): Administrators do not use separate accounts for user vs privileged activity"
}

violations contains msg if {
	not input.cpg.protect.least_privilege
	msg := "CISA CPG 3.H (Implement the Principles of Least Privilege): Access rights not limited to those required for role/function"
}

violations contains msg if {
	not input.cpg.protect.network_segmentation
	msg := "CISA CPG 3.I (Implement Logical/Physical Network Segmentation): Networks (including IT/OT boundary) not segmented"
}

violations contains msg if {
	not input.cpg.protect.cybersecurity_training
	msg := "CISA CPG 3.J (Implement Cybersecurity Training): Cybersecurity training (including OT-specific where applicable) not provided"
}

violations contains msg if {
	not input.cpg.protect.strong_encryption
	msg := "CISA CPG 3.K (Utilize Strong Encryption): Strong, agile encryption not used for data in transit and sensitive data (including credentials/secrets) at rest"
}

violations contains msg if {
	not input.cpg.protect.email_security
	msg := "CISA CPG 3.L (Enable Email Security): Email security controls (SPF/DKIM/DMARC, STARTTLS) not enabled"
}

violations contains msg if {
	not input.cpg.protect.macros_disabled
	msg := "CISA CPG 3.M (Disable Autorun & Macros By Default): Autorun and Office macros not disabled by default"
}

violations contains msg if {
	not input.cpg.protect.change_management
	msg := "CISA CPG 3.N (Establish Change Management Processes): Documented change management for systems and configurations not established"
}

violations contains msg if {
	not input.cpg.protect.backups_maintained
	msg := "CISA CPG 3.O (Maintain System Backups & Restoration Ability): System backups not maintained, isolated, and restoration-tested"
}

violations contains msg if {
	not input.cpg.protect.hw_sw_approval_process
	msg := "CISA CPG 3.P (Maintain Hardware & Software Approval Process): Administrative approval process for new hardware/software not maintained"
}

violations contains msg if {
	not input.cpg.protect.log_collection_storage
	msg := "CISA CPG 3.Q (Maintain Log Collection & Storage): Security logs not collected and stored securely (tamper-resistant, adequate retention)"
}

violations contains msg if {
	not input.cpg.protect.unauthorized_devices_prohibited
	msg := "CISA CPG 3.R (Prohibit Connection of Unauthorized Devices): Connection of unauthorized devices (including removable media) not prevented"
}

violations contains msg if {
	not input.cpg.protect.internet_facing_secured
	msg := "CISA CPG 3.S (Secure Internet Facing Devices): Unnecessary exploitable services on internet-facing assets (and unprotected OT exposure) not eliminated"
}

# ── Function 4 — DETECT ──────────────────────────────────────────────────────

violations contains msg if {
	not input.cpg.detect.malicious_code_detection
	msg := "CISA CPG 4.A (Establish Malicious Code Detection): Malicious code detection (endpoint/network) not established"
}

violations contains msg if {
	not input.cpg.detect.adverse_events_identified
	msg := "CISA CPG 4.B (Identify Adverse Events): Capability to identify adverse events and relevant threat TTPs not established"
}

# ── Function 5 — RESPOND ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cpg.respond.incident_communications
	msg := "CISA CPG 5.A (Establish Incident Communication Procedures): Incident communication procedures (internal, partners, suppliers) not established"
}

violations contains msg if {
	not input.cpg.respond.incident_reporting
	msg := "CISA CPG 5.B (Establish Incident Reporting Procedures): Procedures to report incidents (including to CISA/authorities as applicable) not established"
}

# ── Function 6 — RECOVER ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cpg.recover.incident_planning_preparedness
	msg := "CISA CPG 6.A (Incident Planning and Preparedness): Recovery planning and preparedness (restoration exercises, lessons learned) not established"
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
	"version": "2.0 (October 2025)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 34,
	"violations": violations,
	"violation_count": count(violations),
	"function_summary": function_summary,
	"version_mapping_note": "Goal IDs follow CPG 2.0. For assessments recorded against v1.0.1 IDs, consult the v1.0.1-to-2.0 mapping table in the CPG 2.0 report (e.g. old 1.A Asset Inventory = new 2.A; old 2.H MFA = new 3.F).",
}
