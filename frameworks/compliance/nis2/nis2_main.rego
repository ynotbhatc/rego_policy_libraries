# METADATA
# title: "EU Network and Information Security Directive 2 (NIS2) — Directive (EU) 2022/2555"
# custom:
#   class: compliance
#   framework: nis2
#   source: eu
#   domains: [eu, critical-infrastructure]
#   coverage:
#     checks: 37
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nis2.main

import rego.v1

# EU Network and Information Security Directive 2 (NIS2) — Directive (EU) 2022/2555
# Text: https://eur-lex.europa.eu/eli/dir/2022/2555/oj (OJ L 333, 27.12.2022). Member States had to adopt and
# publish their transposition measures by 17 October 2024 (Article 41(1)).
#
# Sectors (18): Annex I, sectors of high criticality — energy, transport, banking, financial market
# infrastructures, health, drinking water, waste water, digital infrastructure, ICT service management
# (business-to-business), public administration, space. Annex II, other critical sectors — postal and courier
# services, waste management, chemicals, food, manufacturing, digital providers, research. Whether an entity is
# essential or important follows from Article 3 (annex and size), not from the sector alone.
#
# What is checked, and against which provision:
#   Article 20(1)   management body approves the Article 21 measures and oversees their implementation
#   Article 20(2)   members of the management body follow cybersecurity training
#   Article 21(2)   the ten minimum measures:
#     (a) policies on risk analysis and information system security
#     (b) incident handling
#     (c) business continuity, such as backup management and disaster recovery, and crisis management
#     (d) supply chain security
#     (e) security in network and information systems acquisition, development and maintenance,
#         including vulnerability handling and disclosure
#     (f) policies and procedures to assess the effectiveness of cybersecurity risk-management measures
#     (g) basic cyber hygiene practices and cybersecurity training
#     (h) policies and procedures regarding the use of cryptography and, where appropriate, encryption
#     (i) human resources security, access control policies and asset management
#     (j) the use of multi-factor authentication or continuous authentication solutions, secured voice, video
#         and text communications and secured emergency communication systems within the entity, where appropriate
#   Article 23(4)   significant-incident reporting: (a) early warning within 24 hours, (b) incident notification
#                   within 72 hours, (d) final report not later than one month after the notification
#
# Library criteria that go beyond the Directive's wording. The Directive names the measures; it sets no test or
# review interval and does not mention logs. Where a check below uses a frequency or a logging criterion, the
# message says "library criterion". Commission Implementing Regulation (EU) 2024/2690
# (https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj) is binding only on the entity types listed in its Article 1
# (DNS, TLD, cloud, data centre, CDN, managed service, managed security service, online marketplace, search
# engine, social network and trust service providers). For those it requires: review of the risk assessment at
# least annually (Annex 2.1.4), business continuity and disaster recovery plans tested at planned intervals
# (4.1.4), awareness raising at planned intervals (8.1.3), and logs maintained for a predefined period (3.2.5,
# under its section 3 on Article 21(2)(b)). Neither text sets a one-year log retention period.
#
# Evidence rules:
#   - A check passes only on the boolean true. An absent, null or non-boolean value (for example the string
#     "yes") is missing evidence and is reported as a finding.
#   - Article 21(2)(h) (encryption) and Article 21(2)(j) apply "where appropriate". A measure that is not in
#     place is a finding unless the input states that it is not appropriate:
#       input.applicability.<measure> = {"appropriate": false, "justification": "<non-empty text>"}
#     Measures: strong_authentication_remote_access, strong_authentication_privileged_accounts,
#     strong_authentication_critical_systems, secured_voice_video_text_communications,
#     secured_emergency_communications, encryption_at_rest, encryption_in_transit.
#     Leaving the statement out is never an exemption. Accepted statements are listed in the report under
#     measures_not_appropriate so a reviewer can read the justifications.
#   - Strong authentication (Article 21(2)(j)) is met per access scope by multi-factor authentication
#     (input.mfa.<scope>.enforced) or by continuous authentication
#     (input.continuous_authentication.<scope>.enforced).
#
# OPA endpoint: POST http://<host>:8182/v1/data/nis2/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

# Defaults — without these, an empty input makes compliance_report undefined
# and the OPA endpoint returns null.
default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

default sector := "unknown"

sector := input.sector

default entity_category := "unknown"

entity_category := input.entity_category

default assessed_at := "unknown"

assessed_at := input.assessment_date

# ── Evidence helpers ────────────────────────────────────────────────────────

# Evidence is the boolean true: every check reads `input.<path> == true`, so an absent, null or wrong-typed
# value is not evidence.

# Measures the Directive requires "where appropriate".
_where_appropriate := {
	"strong_authentication_remote_access",
	"strong_authentication_privileged_accounts",
	"strong_authentication_critical_systems",
	"secured_voice_video_text_communications",
	"secured_emergency_communications",
	"encryption_at_rest",
	"encryption_in_transit",
}

# What shows each measure is in place. Strong authentication has two alternatives.
_in_place("strong_authentication_remote_access") if input.mfa.remote_access.enforced == true

_in_place("strong_authentication_remote_access") if input.continuous_authentication.remote_access.enforced == true

_in_place("strong_authentication_privileged_accounts") if input.mfa.privileged_accounts.enforced == true

_in_place("strong_authentication_privileged_accounts") if {
	input.continuous_authentication.privileged_accounts.enforced == true
}

_in_place("strong_authentication_critical_systems") if input.mfa.critical_systems.enforced == true

_in_place("strong_authentication_critical_systems") if {
	input.continuous_authentication.critical_systems.enforced == true
}

_in_place("secured_voice_video_text_communications") if input.secure_communications.voice_video_text.secured == true

_in_place("secured_emergency_communications") if input.secure_communications.emergency_systems.secured == true

_in_place("encryption_at_rest") if input.cryptography.encryption.sensitive_data_at_rest == true

_in_place("encryption_in_transit") if input.cryptography.encryption.data_in_transit == true

# An explicit, typed statement: appropriate is the boolean false and a justification is given.
_stated_not_appropriate(measure) if {
	statement := input.applicability[measure]
	statement.appropriate == false
	is_string(statement.justification)
	trim_space(statement.justification) != ""
}

# Not in place and no valid statement: a finding.
_gap(measure) if {
	not _in_place(measure)
	not _stated_not_appropriate(measure)
}

# Not in place, with a valid statement: reported, not a finding.
measures_not_appropriate[measure] := justification if {
	some measure in _where_appropriate
	not _in_place(measure)
	_stated_not_appropriate(measure)
	justification := trim_space(input.applicability[measure].justification)
}

# Logging. The Directive itself does not mention logs and neither text sets a one-year period. Implementing Regulation
# (EU) 2024/2690 Annex 3.2.5 (section 3, incident handling, Article 21(2)(b)) requires the entities it covers to
# "maintain and back up logs for a predefined period". The check is therefore a defined retention period;
# the earlier field minimum_1_year still counts, because a one-year minimum is a defined period.
_log_retention_defined if input.incident_handling.log_retention.period_defined == true

_log_retention_defined if input.incident_handling.log_retention.minimum_1_year == true

# ── Article 21(2)(a) — Risk Analysis & Security Policies ────────────────────

violations contains msg if {
	not input.risk_management.risk_analysis.documented == true
	msg := "NIS2 Art.21(2)(a): Risk analysis for network and information systems not documented"
}

violations contains msg if {
	not input.risk_management.security_policies.approved_by_management == true
	msg := "NIS2 Art.21(2)(a): Information security policies not approved by management body"
}

violations contains msg if {
	not input.risk_management.risk_review.frequency_annual == true
	msg := "NIS2 Art.21(2)(a): Risk analysis not reviewed at least annually or after significant changes (library criterion; the Directive sets no interval)"
}

# ── Article 21(2)(b) — Incident Handling ────────────────────────────────────

violations contains msg if {
	not input.incident_handling.plan.documented == true
	msg := "NIS2 Art.21(2)(b): Incident handling plan not documented and tested"
}

violations contains msg if {
	not input.incident_handling.significant_incident.early_warning_24h == true
	msg := "NIS2 Art.23(4)(a): Early warning to CSIRT/authority not issued within 24 hours of significant incident"
}

violations contains msg if {
	not input.incident_handling.significant_incident.notification_72h == true
	msg := "NIS2 Art.23(4)(b): Incident notification to authority not issued within 72 hours"
}

violations contains msg if {
	not input.incident_handling.significant_incident.final_report_1month == true
	msg := "NIS2 Art.23(4)(d): Final incident report not submitted within 1 month"
}

violations contains msg if {
	not _log_retention_defined
	msg := "NIS2 Art.21(2)(b): No defined retention period for security logs (library criterion: Directive (EU) 2022/2555 itself does not mention logs; Implementing Regulation (EU) 2024/2690 Annex 3.2.5 requires the entities it covers to maintain and back up logs for a predefined period)"
}

# ── Article 21(2)(c) — Business Continuity ──────────────────────────────────

violations contains msg if {
	not input.business_continuity.bcp.documented == true
	msg := "NIS2 Art.21(2)(c): Business continuity plan not documented"
}

violations contains msg if {
	not input.business_continuity.bcp.tested_annually == true
	msg := "NIS2 Art.21(2)(c): Business continuity plan not tested at least annually (library criterion; the Directive sets no test interval)"
}

violations contains msg if {
	not input.business_continuity.drp.documented == true
	msg := "NIS2 Art.21(2)(c): Disaster recovery plan not documented"
}

violations contains msg if {
	not input.business_continuity.crisis_management.plan_exists == true
	msg := "NIS2 Art.21(2)(c): Crisis management plan not established"
}

# ── Article 21(2)(d) — Supply Chain Security ────────────────────────────────

violations contains msg if {
	not input.supply_chain.vendor_assessment.process_exists == true
	msg := "NIS2 Art.21(2)(d): Supplier and third-party security assessment process not established"
}

violations contains msg if {
	not input.supply_chain.critical_suppliers.identified == true
	msg := "NIS2 Art.21(2)(d): Critical ICT suppliers not identified and risk-assessed"
}

violations contains msg if {
	not input.supply_chain.contractual_requirements.security_clauses == true
	msg := "NIS2 Art.21(2)(d): Security requirements not included in supplier contracts"
}

# ── Article 21(2)(e) — Secure Acquisition / Development ─────────────────────

violations contains msg if {
	not input.secure_development.sdlc_policy.documented == true
	msg := "NIS2 Art.21(2)(e): Secure software development lifecycle policy not documented"
}

violations contains msg if {
	not input.secure_development.vulnerability_management.process_exists == true
	msg := "NIS2 Art.21(2)(e): Vulnerability management process not established"
}

violations contains msg if {
	not input.secure_development.patch_management.timely == true
	msg := "NIS2 Art.21(2)(e): Timely patch management process not in place"
}

# ── Article 21(2)(f) — Effectiveness Assessment ─────────────────────────────

violations contains msg if {
	not input.effectiveness_assessment.penetration_testing.annual == true
	msg := "NIS2 Art.21(2)(f): Penetration testing not conducted at least annually (library criterion; the Directive names no test or interval)"
}

violations contains msg if {
	not input.effectiveness_assessment.audit.regular == true
	msg := "NIS2 Art.21(2)(f): Regular security audits of cybersecurity measures not performed"
}

# ── Article 21(2)(g) — Cyber Hygiene & Training ─────────────────────────────

violations contains msg if {
	not input.training.cybersecurity_awareness.conducted_annually == true
	msg := "NIS2 Art.21(2)(g): Cybersecurity awareness training not conducted annually for all staff (library criterion; the Directive sets no interval)"
}

violations contains msg if {
	not input.cyber_hygiene.patch_policy.exists == true
	msg := "NIS2 Art.21(2)(g): Cyber hygiene policy (patching, updates, configurations) not established"
}

# ── Article 21(2)(h) — Cryptography ─────────────────────────────────────────

violations contains msg if {
	not input.cryptography.policy.documented == true
	msg := "NIS2 Art.21(2)(h): Cryptography and encryption policy not documented"
}

# Encryption is required "where appropriate" (see the evidence rules in the header).
violations contains msg if {
	_gap("encryption_at_rest")
	msg := "NIS2 Art.21(2)(h): Sensitive data at rest not encrypted, and not stated as not appropriate (input.applicability.encryption_at_rest)"
}

violations contains msg if {
	_gap("encryption_in_transit")
	msg := "NIS2 Art.21(2)(h): Data in transit not encrypted with strong protocols, and not stated as not appropriate (input.applicability.encryption_in_transit)"
}

# ── Article 21(2)(i) — HR Security, Access Control & Asset Management ────────

violations contains msg if {
	not input.access_control.principle_of_least_privilege.enforced == true
	msg := "NIS2 Art.21(2)(i): Principle of least privilege not enforced for system access"
}

violations contains msg if {
	not input.access_control.privileged_accounts.managed == true
	msg := "NIS2 Art.21(2)(i): Privileged accounts not managed through formal process"
}

violations contains msg if {
	not input.asset_management.inventory.maintained == true
	msg := "NIS2 Art.21(2)(i): Asset inventory not maintained for network and information systems"
}

violations contains msg if {
	not input.hr_security.joiners_movers_leavers.process_exists == true
	msg := "NIS2 Art.21(2)(i): HR security process for joiners/movers/leavers not established"
}

# ── Article 21(2)(j) — Authentication and Secured Communications ─────────────
# "the use of multi-factor authentication or continuous authentication solutions, secured voice, video and text
# communications and secured emergency communication systems within the entity, where appropriate."
# Three limbs: strong authentication (either alternative, checked for three access scopes, which are the
# library's breakdown), secured voice, video and text communications, secured emergency communication systems.

violations contains msg if {
	_gap("strong_authentication_remote_access")
	msg := "NIS2 Art.21(2)(j): No multi-factor or continuous authentication for remote access, and not stated as not appropriate (input.applicability.strong_authentication_remote_access)"
}

violations contains msg if {
	_gap("strong_authentication_privileged_accounts")
	msg := "NIS2 Art.21(2)(j): No multi-factor or continuous authentication for privileged accounts, and not stated as not appropriate (input.applicability.strong_authentication_privileged_accounts)"
}

violations contains msg if {
	_gap("strong_authentication_critical_systems")
	msg := "NIS2 Art.21(2)(j): No multi-factor or continuous authentication for access to critical systems, and not stated as not appropriate (input.applicability.strong_authentication_critical_systems)"
}

violations contains msg if {
	_gap("secured_voice_video_text_communications")
	msg := "NIS2 Art.21(2)(j): Voice, video and text communications within the entity not secured, and not stated as not appropriate (input.applicability.secured_voice_video_text_communications)"
}

violations contains msg if {
	_gap("secured_emergency_communications")
	msg := "NIS2 Art.21(2)(j): No secured emergency communication system within the entity, and not stated as not appropriate (input.applicability.secured_emergency_communications)"
}

# ── Governance (Article 20) ──────────────────────────────────────────────────

violations contains msg if {
	not input.governance.management_body.approved_measures == true
	msg := "NIS2 Art.20(1): Management body has not approved the cybersecurity risk-management measures"
}

violations contains msg if {
	not input.governance.management_body.oversight_accountability == true
	msg := "NIS2 Art.20(1): Management body does not oversee, and is not held accountable for, implementation of the cybersecurity risk-management measures"
}

violations contains msg if {
	not input.training.management_body.cybersecurity_training == true
	msg := "NIS2 Art.20(2): Members of the management body have not followed cybersecurity training"
}

# ── Compliance Report ────────────────────────────────────────────────────────

# One violation rule per control and one message per rule, so the number of violations is the number of failed
# controls. tests/test_nis2_main.rego pins that every control fails on empty input, which keeps this total equal
# to the rules above. passed + failed + not appropriate = total on every input.
total_controls := 37

failed_controls := count(violations)

passed_controls := (total_controls - failed_controls) - count(measures_not_appropriate)

compliance_report := {
	"framework": "EU Network and Information Security Directive 2 (NIS2)",
	"directive": "Directive (EU) 2022/2555",
	"transposition": "October 2024",
	"entity_name": entity_name,
	"entity_type": entity_type,
	"sector": sector,
	"entity_category": entity_category,
	"assessed_at": assessed_at,
	"compliant": compliant,
	"total_controls": total_controls,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": failed_controls,
	"passed_controls": passed_controls,
	"not_appropriate_controls": count(measures_not_appropriate),
	"measures_not_appropriate": measures_not_appropriate,
	"article_summary": {
		"art_20_governance": [v | some v in violations; contains(v, "Art.20")],
		"art_21a_risk_policies": [v | some v in violations; contains(v, "Art.21(2)(a)")],
		"art_21b_incident_handling": [v | some v in violations; contains(v, "Art.21(2)(b)")],
		"art_21c_continuity": [v | some v in violations; contains(v, "Art.21(2)(c)")],
		"art_21d_supply_chain": [v | some v in violations; contains(v, "Art.21(2)(d)")],
		"art_21e_secure_dev": [v | some v in violations; contains(v, "Art.21(2)(e)")],
		"art_21f_effectiveness": [v | some v in violations; contains(v, "Art.21(2)(f)")],
		"art_21g_hygiene_training": [v | some v in violations; contains(v, "Art.21(2)(g)")],
		"art_21h_cryptography": [v | some v in violations; contains(v, "Art.21(2)(h)")],
		"art_21i_access_assets": [v | some v in violations; contains(v, "Art.21(2)(i)")],
		"art_21j_authentication_communications": [v | some v in violations; contains(v, "Art.21(2)(j)")],
		"art_23_reporting": [v | some v in violations; contains(v, "Art.23")],
	},
}
