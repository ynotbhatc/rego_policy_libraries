# ISO/IEC 27001:2022 — Information security management systems. Main entry point for the framework:
# the 93 Annex A controls, one row per control, under the 2022 numbering, plus the five technical
# fact modules in the sub-directories of this directory.
#
# Numbering. ISO/IEC 27001:2022 Annex A lists the same 93 controls, in the same order and under the same
# numbers, as ISO/IEC 27002:2022 clauses 5 to 8: Annex A control A.5.1 is ISO/IEC 27002:2022 control 5.1. This module keys every control by its Annex A id (`A.5.1` … `A.8.34`) and exposes the same
# rows under the 27002 number (`5.1` … `8.34`) as the `iso27002` view (iso27002_controls / the report's
# "iso27002" block). Ids from ISO/IEC 27001:2013 (A.5.1.1 … A.18.2.3, 114 controls in 14 groups) are not
# controls of this module; an attestation that names one is a violation.
#
# Themes (27002:2022 clauses 5–8):  5 Organizational 37 · 6 People 8 · 7 Physical 14 · 8 Technological 34.
#
# What is reproduced. ISO/IEC 27001 and 27002 are copyrighted; this repository does not carry their text.
# Each row holds only the control number, its title, its theme and the values of the five ISO/IEC
# 27002:2022 attributes (control type, information security properties, cybersecurity concepts,
# operational capabilities, security domains), as lists of the attribute values (hashtags without '#').
# Every row is title-only: no control, purpose or guidance text, and none paraphrased.
#
# Sources (public listings, retrieved 2026-10-13):
#   titles      intuitem CISO Assistant library iso27001-2022.yaml (urn:intuitem:risk:library:iso27001-2022,
#               version 18), github.com/intuitem/ciso-assistant-community at commit
#               afd672c6cf8ab6f67d331ac2f7a6a3b911a5ac15, backend/library/libraries/iso27001-2022.yaml,
#               sha256 443903f8c658cb83003104f8e9d689393be0fc1d5602ce004feb501512f34cf5. 93 A.x.y ref_ids,
#               names copied as published (27001 Annex A spelling: "Clock synchronization",
#               "User end point devices", "Privacy and protection of PII").
#   attributes  github.com/edison-enriquez/ISO27001 src/datos/atributos.ts at commit
#               5f27740702d91f889e120d17de4d3c14962b229c (sha256 c365e9c0…b195e5), cross-checked cell by
#               cell against an independent listing, the Deming ISMS tool's measures.en.csv
#               (github.com/sourcentis/deming at f5fbc2dd62f02519ed54c20738d5edfffb8a3d3a, sha256
#               e4dfba39…2f7107, a French-origin translation whose machine-translated value names were
#               normalised to the 27002 vocabulary). The two agree on all 465 cells (93 controls x 5
#               attributes) except one truncated token in Deming's 8.18 row. Both are secondary listings of
#               27002:2022 Annex A, not ISO's own publication; treat the attribute values as informative.
#
# How a control is evaluated (fail-closed); `basis` in the report says which applies:
#   facts         35 controls are decided by the fact checks of the five sub-modules
#                 (data.iso27001.<module>, facts at the top level of input: input.access_control,
#                 input.cryptography, ...). Those modules were written against the 2013 Annex A; each check
#                 is keyed here to the 2022 control that ISO/IEC 27002:2022 Annex B (correspondence with
#                 27002:2013) maps its 2013 control to, and the 2013 id is kept as `iso2013`. Checks the
#                 modules hold with no 2013 number are keyed to the 2022 control whose subject they test
#                 (iso2013 ""). Every mapped check must pass. An attestation for one of these ids is
#                 accepted but does not decide it.
#     A.5.8   system_acquisition_maintenance.security_requirements_defined (A.14.1.1)
#     A.5.14  communications_security.transfer_policies (A.13.2.1), communications_security.transfer_agreements (A.13.2.2), communications_security.electronic_messaging_secure (A.13.2.3)
#     A.5.15  access_control.business_requirements_met (A.9.1)
#     A.5.16  access_control.user_registration_process (A.9.2.1)
#     A.5.17  access_control.secret_authentication_management (A.9.2.4), access_control.user_responsibilities (A.9.3.1), access_control.password_management_system (A.9.4.3)
#     A.5.18  access_control.user_access_provisioning (A.9.2.2), access_control.access_rights_review (A.9.2.5), access_control.access_rights_removal (A.9.2.6)
#     A.5.37  operations_security.operating_procedures_documented (A.12.1.1)
#     A.6.6   communications_security.nda_requirements (A.13.2.4)
#     A.6.7   communications_security.remote_access_secure
#     A.8.2   access_control.privileged_access_management (A.9.2.3)
#     A.8.3   access_control.information_access_restriction (A.9.4.1)
#     A.8.4   access_control.source_code_access_control (A.9.4.5)
#     A.8.5   access_control.secure_logon_procedures (A.9.4.2)
#     A.8.6   operations_security.capacity_management (A.12.1.3)
#     A.8.7   operations_security.malware_protection (A.12.2.1)
#     A.8.8   operations_security.vulnerability_management (A.12.6.1)
#     A.8.13  operations_security.backup_management (A.12.3.1)
#     A.8.15  operations_security.event_logging (A.12.4.1), operations_security.log_protection (A.12.4.2), operations_security.admin_logs (A.12.4.3)
#     A.8.16  communications_security.network_monitoring
#     A.8.17  operations_security.clock_synchronization (A.12.4.4)
#     A.8.18  access_control.privileged_utility_control (A.9.4.4)
#     A.8.19  operations_security.software_installation_control (A.12.5.1), operations_security.software_restriction (A.12.6.2)
#     A.8.20  communications_security.network_controls (A.13.1.1), communications_security.network_management_secure
#     A.8.21  communications_security.network_services_secure (A.13.1.2)
#     A.8.22  communications_security.network_segregation (A.13.1.3)
#     A.8.24  cryptography.cryptographic_policy (A.10.1.1), cryptography.key_management (A.10.1.2), cryptography.data_encryption, cryptography.digital_signatures, cryptography.algorithm_compliance
#     A.8.25  system_acquisition_maintenance.secure_development_policy (A.14.2.1)
#     A.8.26  system_acquisition_maintenance.public_network_services_secure (A.14.1.2), system_acquisition_maintenance.transaction_protection (A.14.1.3)
#     A.8.27  system_acquisition_maintenance.secure_engineering_principles (A.14.2.5)
#     A.8.29  system_acquisition_maintenance.security_testing (A.14.2.8), system_acquisition_maintenance.acceptance_testing (A.14.2.9)
#     A.8.30  system_acquisition_maintenance.outsourced_development (A.14.2.7)
#     A.8.31  operations_security.environment_separation (A.12.1.4), system_acquisition_maintenance.secure_development_environment (A.14.2.6)
#     A.8.32  operations_security.change_management (A.12.1.2), system_acquisition_maintenance.change_control_procedures (A.14.2.2), system_acquisition_maintenance.os_change_review (A.14.2.3), system_acquisition_maintenance.software_package_control (A.14.2.4)
#     A.8.33  system_acquisition_maintenance.data_protection_control (A.14.3.1)
#     A.8.34  operations_security.audit_controls (A.12.7.1)
#   attestation   58 controls have no fact check and are attested:
#                 input.iso27001.annex_a["A.5.1"] == true. They are:
#                A.5.1, A.5.2, A.5.3, A.5.4, A.5.5, A.5.6, A.5.7, A.5.9, A.5.10, A.5.11, A.5.12, A.5.13,
#                A.5.19, A.5.20, A.5.21, A.5.22, A.5.23, A.5.24, A.5.25, A.5.26, A.5.27, A.5.28, A.5.29,
#                A.5.30, A.5.31, A.5.32, A.5.33, A.5.34, A.5.35, A.5.36, A.6.1, A.6.2, A.6.3, A.6.4, A.6.5,
#                A.6.8, A.7.1, A.7.2, A.7.3, A.7.4, A.7.5, A.7.6, A.7.7, A.7.8, A.7.9, A.7.10, A.7.11, A.7.12,
#                A.7.13, A.7.14, A.8.1, A.8.9, A.8.10, A.8.11, A.8.12, A.8.14, A.8.23, A.8.28
#   unmapped      module checks that gate neither their own module nor a control here (listed in
#                 unmapped_fact_rules; they still appear in each module's compliance_details).
# Missing or non-object input.iso27001.annex_a is a FAIL-CLOSED violation; a failed fact check, a
# non-true attestation, an unknown id or a 2013-era id is a violation.
#
# ISMS clauses 4–10 are not evaluated by this module (it carried no clause checks before the 2022
# re-key either); iso27001_assessment keeps its five domain rollups (the 2013 groups A.9, A.10, A.12,
# A.13, A.14 the sub-modules are named after).
#
# Query: POST /v1/data/iso27001/compliance_report   (Annex A, per-theme rollups, iso27002 view)
#        POST /v1/data/iso27001/iso27001_assessment  (consumer endpoint, unchanged keys + annex_a_controls)

# METADATA
# title: "ISO/IEC 27001:2022 — Annex A (93 controls = ISO/IEC 27002:2022 clauses 5–8), fact-evaluated or attested"
# custom:
#   class: compliance
#   framework: iso27001
#   source: iso
#   domains: [isms]
#   coverage:
#     checks: 109
#     cited: 100
#     expected: 93
#     found: 100
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package iso27001

import rego.v1

import data.iso27001.access_control
import data.iso27001.communications_security
import data.iso27001.cryptography
import data.iso27001.operations_security
import data.iso27001.system_acquisition_maintenance

# Defaults so report/details never collapse to {} on empty input
default access_control_compliant := false

default cryptography_compliant := false

default operations_security_compliant := false

default communications_security_compliant := false

default system_acquisition_maintenance_compliant := false

# Technical fact modules (written against the 2013 Annex A groups; re-keyed to 2022 in fact_checks)
default allow := false

allow if {
	access_control.compliant
	cryptography.compliant
	operations_security.compliant
	communications_security.compliant
	system_acquisition_maintenance.compliant
}

# Individual category compliance checks
access_control_compliant if {
	access_control.compliant
}

cryptography_compliant if {
	cryptography.compliant
}

operations_security_compliant if {
	operations_security.compliant
}

communications_security_compliant if {
	communications_security.compliant
}

system_acquisition_maintenance_compliant if {
	system_acquisition_maintenance.compliant
}

# Consumer endpoint — /v1/data/iso27001/iso27001_assessment
# The compliance-repo iso27001_compliance role reads .compliant, .score,
# .isms_results and .annex_a_controls.<theme>_controls. Score = % of the 5 technical domains passing;
# annex_a_controls = Annex A controls satisfied per theme (see compliance_report for the full Annex A view).
iso27001_domains_passing := count([c |
	some c in [
		access_control_compliant,
		cryptography_compliant,
		operations_security_compliant,
		communications_security_compliant,
		system_acquisition_maintenance_compliant,
	]
	c == true
])

iso27001_assessment := {
	"framework": "ISO/IEC 27001:2022",
	"compliant": allow,
	"score": round((100 * iso27001_domains_passing) / 5),
	"domains_evaluated": 5,
	"domains_passing": iso27001_domains_passing,
	"isms_results": {
		"access_control": access_control_compliant,
		"cryptography": cryptography_compliant,
		"operations_security": operations_security_compliant,
		"communications_security": communications_security_compliant,
		"system_acquisition_maintenance": system_acquisition_maintenance_compliant,
	},
	"annex_a_controls": annex_a_controls,
}

# Annex A controls satisfied per theme, under the keys the consumer reads (organizational_controls, ...)
annex_a_controls := {concat("", [lower(name), "_controls"]): r.satisfied | some name, r in theme_reports}

# Comprehensive ISO 27001 compliance report (technical fact modules)
iso27001_compliance_report := {
	"overall_compliant": allow,
	"access_control": {
		"compliant": access_control.compliant,
		"details": access_control.compliance_details,
	},
	"cryptography": {
		"compliant": cryptography.compliant,
		"details": cryptography.compliance_details,
	},
	"operations_security": {
		"compliant": operations_security.compliant,
		"details": operations_security.compliance_details,
	},
	"communications_security": {
		"compliant": communications_security.compliant,
		"details": communications_security.compliance_details,
	},
	"system_acquisition_maintenance": {
		"compliant": system_acquisition_maintenance.compliant,
		"details": system_acquisition_maintenance.compliance_details,
	},
}

# =============================================================================
# Annex A (ISO/IEC 27001:2022) = ISO/IEC 27002:2022 clauses 5–8
# =============================================================================

source := {
	"standard": "ISO/IEC 27001:2022 Annex A; ISO/IEC 27002:2022 clauses 5-8 and attributes",
	"website_27001": "https://www.iso.org/standard/27001",
	"website_27002": "https://www.iso.org/standard/75652.html",
	"titles": "intuitem CISO Assistant iso27001-2022.yaml v18, github.com/intuitem/ciso-assistant-community@afd672c6cf8ab6f67d331ac2f7a6a3b911a5ac15",
	"titles_sha256": "443903f8c658cb83003104f8e9d689393be0fc1d5602ce004feb501512f34cf5",
	"attributes": "github.com/edison-enriquez/ISO27001@5f27740702d91f889e120d17de4d3c14962b229c src/datos/atributos.ts",
	"attributes_sha256": "c365e9c07d1d30795eca937cc79608be8b981cdb9e6a54d23283aa03b7b195e5",
	"attributes_crosscheck": "github.com/sourcentis/deming@f5fbc2dd62f02519ed54c20738d5edfffb8a3d3a database/data/measures.en.csv",
	"retrieved": "2026-10-13",
}

# theme by 27002:2022 clause
themes := {
	"5": "Organizational",
	"6": "People",
	"7": "Physical",
	"8": "Technological",
}

# the value set of each ISO/IEC 27002:2022 attribute (hashtags without '#')
attribute_values := {
	"control_type": ["Preventive", "Detective", "Corrective"],
	"properties": ["Confidentiality", "Integrity", "Availability"],
	"concepts": ["Identify", "Protect", "Detect", "Respond", "Recover"],
	"capabilities": [
		"Governance", "Asset_management", "Information_protection", "Human_resource_security",
		"Physical_security", "System_and_network_security", "Application_security", "Secure_configuration",
		"Identity_and_access_management", "Threat_and_vulnerability_management", "Continuity",
		"Supplier_relationships_security", "Legal_and_compliance", "Information_security_event_management",
		"Information_security_assurance",
	],
	"domains": ["Governance_and_Ecosystem", "Protection", "Defence", "Resilience"],
}

# One row per Annex A control: theme, title (title only, no control text) and the five 27002 attributes.
annex_a := {
	"A.5.1": {
		"theme": "Organizational",
		"title": "Policies for information security",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Governance"],
		"domains": ["Governance_and_Ecosystem", "Resilience"],
	},
	"A.5.2": {
		"theme": "Organizational",
		"title": "Information security roles and responsibilities",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Governance"],
		"domains": ["Governance_and_Ecosystem", "Protection", "Resilience"],
	},
	"A.5.3": {
		"theme": "Organizational",
		"title": "Segregation of duties",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Governance", "Identity_and_access_management"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.5.4": {
		"theme": "Organizational",
		"title": "Management responsibilities",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Governance"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.5.5": {
		"theme": "Organizational",
		"title": "Contact with authorities",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect", "Respond", "Recover"],
		"capabilities": ["Governance"],
		"domains": ["Defence", "Resilience"],
	},
	"A.5.6": {
		"theme": "Organizational",
		"title": "Contact with special interest groups",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Respond", "Recover"],
		"capabilities": ["Governance"],
		"domains": ["Defence"],
	},
	"A.5.7": {
		"theme": "Organizational",
		"title": "Threat intelligence",
		"control_type": ["Preventive", "Detective", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Detect", "Respond"],
		"capabilities": ["Threat_and_vulnerability_management"],
		"domains": ["Defence", "Resilience"],
	},
	"A.5.8": {
		"theme": "Organizational",
		"title": "Information security in project management",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Governance"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.9": {
		"theme": "Organizational",
		"title": "Inventory of information and other associated assets",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Asset_management"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.10": {
		"theme": "Organizational",
		"title": "Acceptable use of information and other associated assets",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Information_protection"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.11": {
		"theme": "Organizational",
		"title": "Return of assets",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management"],
		"domains": ["Protection"],
	},
	"A.5.12": {
		"theme": "Organizational",
		"title": "Classification of information",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Information_protection"],
		"domains": ["Protection", "Defence"],
	},
	"A.5.13": {
		"theme": "Organizational",
		"title": "Labelling of information",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection"],
		"domains": ["Protection", "Defence"],
	},
	"A.5.14": {
		"theme": "Organizational",
		"title": "Information transfer",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Information_protection"],
		"domains": ["Protection"],
	},
	"A.5.15": {
		"theme": "Organizational",
		"title": "Access control",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.5.16": {
		"theme": "Organizational",
		"title": "Identity management",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.5.17": {
		"theme": "Organizational",
		"title": "Authentication information",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.5.18": {
		"theme": "Organizational",
		"title": "Access rights",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.5.19": {
		"theme": "Organizational",
		"title": "Information security in supplier relationships",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.20": {
		"theme": "Organizational",
		"title": "Addressing information security within supplier agreements",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.21": {
		"theme": "Organizational",
		"title": "Managing information security in the ICT supply chain",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.22": {
		"theme": "Organizational",
		"title": "Monitoring, review and change management of supplier services",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Supplier_relationships_security", "Information_security_assurance"],
		"domains": ["Governance_and_Ecosystem", "Protection", "Defence"],
	},
	"A.5.23": {
		"theme": "Organizational",
		"title": "Information security for use of cloud services",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.24": {
		"theme": "Organizational",
		"title": "Information security incident management planning and preparation",
		"control_type": ["Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Respond", "Recover"],
		"capabilities": ["Governance", "Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.5.25": {
		"theme": "Organizational",
		"title": "Assessment and decision on information security events",
		"control_type": ["Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Detect", "Respond"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.5.26": {
		"theme": "Organizational",
		"title": "Response to information security incidents",
		"control_type": ["Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Respond", "Recover"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.5.27": {
		"theme": "Organizational",
		"title": "Learning from information security incidents",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.5.28": {
		"theme": "Organizational",
		"title": "Collection of evidence",
		"control_type": ["Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Detect", "Respond"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.5.29": {
		"theme": "Organizational",
		"title": "Information security during disruption",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Respond"],
		"capabilities": ["Continuity"],
		"domains": ["Protection", "Resilience"],
	},
	"A.5.30": {
		"theme": "Organizational",
		"title": "ICT readiness for business continuity",
		"control_type": ["Corrective"],
		"properties": ["Availability"],
		"concepts": ["Respond"],
		"capabilities": ["Continuity"],
		"domains": ["Resilience"],
	},
	"A.5.31": {
		"theme": "Organizational",
		"title": "Legal, statutory, regulatory and contractual requirements",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Legal_and_compliance"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.5.32": {
		"theme": "Organizational",
		"title": "Intellectual property rights",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["Legal_and_compliance"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.5.33": {
		"theme": "Organizational",
		"title": "Protection of records",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Asset_management", "Information_protection", "Legal_and_compliance"],
		"domains": ["Defence"],
	},
	"A.5.34": {
		"theme": "Organizational",
		"title": "Privacy and protection of PII",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Information_protection", "Legal_and_compliance"],
		"domains": ["Protection"],
	},
	"A.5.35": {
		"theme": "Organizational",
		"title": "Independent review of information security",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Information_security_assurance"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.5.36": {
		"theme": "Organizational",
		"title": "Compliance with policies, rules and standards for information security",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Legal_and_compliance", "Information_security_assurance"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.5.37": {
		"theme": "Organizational",
		"title": "Documented operating procedures",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Recover"],
		"capabilities": ["Asset_management", "Physical_security", "System_and_network_security", "Application_security", "Secure_configuration", "Identity_and_access_management", "Threat_and_vulnerability_management", "Continuity", "Information_security_event_management"],
		"domains": ["Governance_and_Ecosystem", "Protection", "Defence"],
	},
	"A.6.1": {
		"theme": "People",
		"title": "Screening",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Human_resource_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.2": {
		"theme": "People",
		"title": "Terms and conditions of employment",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Human_resource_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.3": {
		"theme": "People",
		"title": "Information security awareness, education and training",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Human_resource_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.4": {
		"theme": "People",
		"title": "Disciplinary process",
		"control_type": ["Preventive", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Respond"],
		"capabilities": ["Human_resource_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.5": {
		"theme": "People",
		"title": "Responsibilities after termination or change of employment",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Human_resource_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.6": {
		"theme": "People",
		"title": "Confidentiality or non-disclosure agreements",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection", "Human_resource_security", "Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem"],
	},
	"A.6.7": {
		"theme": "People",
		"title": "Remote working",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Information_protection", "Physical_security", "System_and_network_security"],
		"domains": ["Protection"],
	},
	"A.6.8": {
		"theme": "People",
		"title": "Information security event reporting",
		"control_type": ["Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Detect"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.7.1": {
		"theme": "Physical",
		"title": "Physical security perimeters",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.2": {
		"theme": "Physical",
		"title": "Physical entry",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security", "Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.7.3": {
		"theme": "Physical",
		"title": "Securing offices, rooms and facilities",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.4": {
		"theme": "Physical",
		"title": "Physical security monitoring",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection", "Defence"],
	},
	"A.7.5": {
		"theme": "Physical",
		"title": "Protecting against physical and environmental threats",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.6": {
		"theme": "Physical",
		"title": "Working In secure areas",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.7": {
		"theme": "Physical",
		"title": "Clear desk and clear screen",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.8": {
		"theme": "Physical",
		"title": "Equipment siting and protection",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.9": {
		"theme": "Physical",
		"title": "Security of assets off-premises",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.10": {
		"theme": "Physical",
		"title": "Storage media",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.11": {
		"theme": "Physical",
		"title": "Supporting utilities",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Integrity", "Availability"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.12": {
		"theme": "Physical",
		"title": "Cabling security",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Physical_security"],
		"domains": ["Protection"],
	},
	"A.7.13": {
		"theme": "Physical",
		"title": "Equipment maintenance",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection", "Resilience"],
	},
	"A.7.14": {
		"theme": "Physical",
		"title": "Secure disposal or re-use of equipment",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Physical_security"],
		"domains": ["Protection"],
	},
	"A.8.1": {
		"theme": "Technological",
		"title": "User end point devices",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Information_protection"],
		"domains": ["Protection"],
	},
	"A.8.2": {
		"theme": "Technological",
		"title": "Privileged access rights",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.8.3": {
		"theme": "Technological",
		"title": "Information access restriction",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.8.4": {
		"theme": "Technological",
		"title": "Access to source code",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Application_security", "Secure_configuration", "Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.8.5": {
		"theme": "Technological",
		"title": "Secure authentication",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Identity_and_access_management"],
		"domains": ["Protection"],
	},
	"A.8.6": {
		"theme": "Technological",
		"title": "Capacity management",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Integrity", "Availability"],
		"concepts": ["Identify", "Protect", "Detect"],
		"capabilities": ["Continuity"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.8.7": {
		"theme": "Technological",
		"title": "Protection against malware",
		"control_type": ["Preventive", "Detective", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["Information_protection", "System_and_network_security"],
		"domains": ["Protection", "Defence"],
	},
	"A.8.8": {
		"theme": "Technological",
		"title": "Management of technical vulnerabilities",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect"],
		"capabilities": ["Threat_and_vulnerability_management"],
		"domains": ["Governance_and_Ecosystem", "Protection", "Defence"],
	},
	"A.8.9": {
		"theme": "Technological",
		"title": "Configuration management",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Secure_configuration"],
		"domains": ["Protection"],
	},
	"A.8.10": {
		"theme": "Technological",
		"title": "Information deletion",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection", "Legal_and_compliance"],
		"domains": ["Protection"],
	},
	"A.8.11": {
		"theme": "Technological",
		"title": "Data masking",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection"],
		"domains": ["Protection"],
	},
	"A.8.12": {
		"theme": "Technological",
		"title": "Data leakage prevention",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Confidentiality"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["Information_protection"],
		"domains": ["Protection", "Defence"],
	},
	"A.8.13": {
		"theme": "Technological",
		"title": "Information backup",
		"control_type": ["Corrective"],
		"properties": ["Integrity", "Availability"],
		"concepts": ["Recover"],
		"capabilities": ["Continuity"],
		"domains": ["Protection"],
	},
	"A.8.14": {
		"theme": "Technological",
		"title": "Redundancy of information processing facilities",
		"control_type": ["Preventive"],
		"properties": ["Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Asset_management", "Continuity"],
		"domains": ["Protection", "Resilience"],
	},
	"A.8.15": {
		"theme": "Technological",
		"title": "Logging",
		"control_type": ["Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Detect"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Protection", "Defence"],
	},
	"A.8.16": {
		"theme": "Technological",
		"title": "Monitoring activities",
		"control_type": ["Detective", "Corrective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Detect", "Respond"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Defence"],
	},
	"A.8.17": {
		"theme": "Technological",
		"title": "Clock synchronization",
		"control_type": ["Detective"],
		"properties": ["Integrity"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["Information_security_event_management"],
		"domains": ["Protection", "Defence"],
	},
	"A.8.18": {
		"theme": "Technological",
		"title": "Use of privileged utility programs",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security", "Secure_configuration"],
		"domains": ["Protection"],
	},
	"A.8.19": {
		"theme": "Technological",
		"title": "Installation of software on operational systems",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Application_security", "Secure_configuration"],
		"domains": ["Protection"],
	},
	"A.8.20": {
		"theme": "Technological",
		"title": "Networks security",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect", "Detect"],
		"capabilities": ["System_and_network_security"],
		"domains": ["Protection"],
	},
	"A.8.21": {
		"theme": "Technological",
		"title": "Security of network services",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security"],
		"domains": ["Protection"],
	},
	"A.8.22": {
		"theme": "Technological",
		"title": "Segregation of networks",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security"],
		"domains": ["Protection"],
	},
	"A.8.23": {
		"theme": "Technological",
		"title": "Web filtering",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security"],
		"domains": ["Protection"],
	},
	"A.8.24": {
		"theme": "Technological",
		"title": "Use of cryptography",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Secure_configuration"],
		"domains": ["Protection"],
	},
	"A.8.25": {
		"theme": "Technological",
		"title": "Secure development life cycle",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection"],
	},
	"A.8.26": {
		"theme": "Technological",
		"title": "Application security requirements",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection", "Defence"],
	},
	"A.8.27": {
		"theme": "Technological",
		"title": "Secure system architecture and engineering principles",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection"],
	},
	"A.8.28": {
		"theme": "Technological",
		"title": "Secure coding",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection"],
	},
	"A.8.29": {
		"theme": "Technological",
		"title": "Security testing in development and acceptance",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify"],
		"capabilities": ["System_and_network_security", "Application_security", "Information_security_assurance"],
		"domains": ["Protection"],
	},
	"A.8.30": {
		"theme": "Technological",
		"title": "Outsourced development",
		"control_type": ["Preventive", "Detective"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Identify", "Protect", "Detect"],
		"capabilities": ["System_and_network_security", "Application_security", "Supplier_relationships_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
	"A.8.31": {
		"theme": "Technological",
		"title": "Separation of development, test and production environments",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection"],
	},
	"A.8.32": {
		"theme": "Technological",
		"title": "Change management",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["System_and_network_security", "Application_security"],
		"domains": ["Protection"],
	},
	"A.8.33": {
		"theme": "Technological",
		"title": "Test information",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection"],
		"domains": ["Protection"],
	},
	"A.8.34": {
		"theme": "Technological",
		"title": "Protection of information systems during audit testing",
		"control_type": ["Preventive"],
		"properties": ["Confidentiality", "Integrity", "Availability"],
		"concepts": ["Protect"],
		"capabilities": ["Information_protection", "System_and_network_security"],
		"domains": ["Governance_and_Ecosystem", "Protection"],
	},
}

fact_checks := {
	"A.5.8": [{"pkg": "system_acquisition_maintenance", "rule": "security_requirements_defined", "iso2013": "A.14.1.1"}],
	"A.5.14": [
		{"pkg": "communications_security", "rule": "transfer_policies", "iso2013": "A.13.2.1"},
		{"pkg": "communications_security", "rule": "transfer_agreements", "iso2013": "A.13.2.2"},
		{"pkg": "communications_security", "rule": "electronic_messaging_secure", "iso2013": "A.13.2.3"},
	],
	"A.5.15": [{"pkg": "access_control", "rule": "business_requirements_met", "iso2013": "A.9.1"}],
	"A.5.16": [{"pkg": "access_control", "rule": "user_registration_process", "iso2013": "A.9.2.1"}],
	"A.5.17": [
		{"pkg": "access_control", "rule": "secret_authentication_management", "iso2013": "A.9.2.4"},
		{"pkg": "access_control", "rule": "user_responsibilities", "iso2013": "A.9.3.1"},
		{"pkg": "access_control", "rule": "password_management_system", "iso2013": "A.9.4.3"},
	],
	"A.5.18": [
		{"pkg": "access_control", "rule": "user_access_provisioning", "iso2013": "A.9.2.2"},
		{"pkg": "access_control", "rule": "access_rights_review", "iso2013": "A.9.2.5"},
		{"pkg": "access_control", "rule": "access_rights_removal", "iso2013": "A.9.2.6"},
	],
	"A.5.37": [{"pkg": "operations_security", "rule": "operating_procedures_documented", "iso2013": "A.12.1.1"}],
	"A.6.6": [{"pkg": "communications_security", "rule": "nda_requirements", "iso2013": "A.13.2.4"}],
	"A.6.7": [{"pkg": "communications_security", "rule": "remote_access_secure", "iso2013": ""}],
	"A.8.2": [{"pkg": "access_control", "rule": "privileged_access_management", "iso2013": "A.9.2.3"}],
	"A.8.3": [{"pkg": "access_control", "rule": "information_access_restriction", "iso2013": "A.9.4.1"}],
	"A.8.4": [{"pkg": "access_control", "rule": "source_code_access_control", "iso2013": "A.9.4.5"}],
	"A.8.5": [{"pkg": "access_control", "rule": "secure_logon_procedures", "iso2013": "A.9.4.2"}],
	"A.8.6": [{"pkg": "operations_security", "rule": "capacity_management", "iso2013": "A.12.1.3"}],
	"A.8.7": [{"pkg": "operations_security", "rule": "malware_protection", "iso2013": "A.12.2.1"}],
	"A.8.8": [{"pkg": "operations_security", "rule": "vulnerability_management", "iso2013": "A.12.6.1"}],
	"A.8.13": [{"pkg": "operations_security", "rule": "backup_management", "iso2013": "A.12.3.1"}],
	"A.8.15": [
		{"pkg": "operations_security", "rule": "event_logging", "iso2013": "A.12.4.1"},
		{"pkg": "operations_security", "rule": "log_protection", "iso2013": "A.12.4.2"},
		{"pkg": "operations_security", "rule": "admin_logs", "iso2013": "A.12.4.3"},
	],
	"A.8.16": [{"pkg": "communications_security", "rule": "network_monitoring", "iso2013": ""}],
	"A.8.17": [{"pkg": "operations_security", "rule": "clock_synchronization", "iso2013": "A.12.4.4"}],
	"A.8.18": [{"pkg": "access_control", "rule": "privileged_utility_control", "iso2013": "A.9.4.4"}],
	"A.8.19": [
		{"pkg": "operations_security", "rule": "software_installation_control", "iso2013": "A.12.5.1"},
		{"pkg": "operations_security", "rule": "software_restriction", "iso2013": "A.12.6.2"},
	],
	"A.8.20": [
		{"pkg": "communications_security", "rule": "network_controls", "iso2013": "A.13.1.1"},
		{"pkg": "communications_security", "rule": "network_management_secure", "iso2013": ""},
	],
	"A.8.21": [{"pkg": "communications_security", "rule": "network_services_secure", "iso2013": "A.13.1.2"}],
	"A.8.22": [{"pkg": "communications_security", "rule": "network_segregation", "iso2013": "A.13.1.3"}],
	"A.8.24": [
		{"pkg": "cryptography", "rule": "cryptographic_policy", "iso2013": "A.10.1.1"},
		{"pkg": "cryptography", "rule": "key_management", "iso2013": "A.10.1.2"},
		{"pkg": "cryptography", "rule": "data_encryption", "iso2013": ""},
		{"pkg": "cryptography", "rule": "digital_signatures", "iso2013": ""},
		{"pkg": "cryptography", "rule": "algorithm_compliance", "iso2013": ""},
	],
	"A.8.25": [{"pkg": "system_acquisition_maintenance", "rule": "secure_development_policy", "iso2013": "A.14.2.1"}],
	"A.8.26": [
		{"pkg": "system_acquisition_maintenance", "rule": "public_network_services_secure", "iso2013": "A.14.1.2"},
		{"pkg": "system_acquisition_maintenance", "rule": "transaction_protection", "iso2013": "A.14.1.3"},
	],
	"A.8.27": [{"pkg": "system_acquisition_maintenance", "rule": "secure_engineering_principles", "iso2013": "A.14.2.5"}],
	"A.8.29": [
		{"pkg": "system_acquisition_maintenance", "rule": "security_testing", "iso2013": "A.14.2.8"},
		{"pkg": "system_acquisition_maintenance", "rule": "acceptance_testing", "iso2013": "A.14.2.9"},
	],
	"A.8.30": [{"pkg": "system_acquisition_maintenance", "rule": "outsourced_development", "iso2013": "A.14.2.7"}],
	"A.8.31": [
		{"pkg": "operations_security", "rule": "environment_separation", "iso2013": "A.12.1.4"},
		{"pkg": "system_acquisition_maintenance", "rule": "secure_development_environment", "iso2013": "A.14.2.6"},
	],
	"A.8.32": [
		{"pkg": "operations_security", "rule": "change_management", "iso2013": "A.12.1.2"},
		{"pkg": "system_acquisition_maintenance", "rule": "change_control_procedures", "iso2013": "A.14.2.2"},
		{"pkg": "system_acquisition_maintenance", "rule": "os_change_review", "iso2013": "A.14.2.3"},
		{"pkg": "system_acquisition_maintenance", "rule": "software_package_control", "iso2013": "A.14.2.4"},
	],
	"A.8.33": [{"pkg": "system_acquisition_maintenance", "rule": "data_protection_control", "iso2013": "A.14.3.1"}],
	"A.8.34": [{"pkg": "operations_security", "rule": "audit_controls", "iso2013": "A.12.7.1"}],
}

# module checks that gate no Annex A control (no 2013 number and not required by their own module)
unmapped_fact_rules := [
	"communications_security.dns_security",
	"cryptography.hsm_usage",
	"system_acquisition_maintenance.data_generation_control",
	"system_acquisition_maintenance.cicd_security",
	"system_acquisition_maintenance.sca_controls",
]

# The ISO/IEC 27002:2022 view: the same rows keyed by the 27002 clause number ("5.1"), with the Annex A id.
iso27002_controls[cid] := object.union(row, {"annex_a": id}) if {
	some id, row in annex_a
	cid := substring(id, 2, -1)
}

# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "iso27001", {})

_attestations := a if {
	a := _in.annex_a
	is_object(a)
}

_supplied if _attestations

_attested(id) if _attestations[id] == true

_fact_ok(c) if {
	c.pkg == "access_control"
	access_control[c.rule] == true
}

_fact_ok(c) if {
	c.pkg == "cryptography"
	cryptography[c.rule] == true
}

_fact_ok(c) if {
	c.pkg == "operations_security"
	operations_security[c.rule] == true
}

_fact_ok(c) if {
	c.pkg == "communications_security"
	communications_security[c.rule] == true
}

_fact_ok(c) if {
	c.pkg == "system_acquisition_maintenance"
	system_acquisition_maintenance[c.rule] == true
}

_failed_facts[id] := [c | some c in checks; not _fact_ok(c)] if {
	some id, checks in fact_checks
}

_fact_evaluated(id) if fact_checks[id]

_satisfied(id) if {
	annex_a[id]
	_fact_evaluated(id)
	count(_failed_facts[id]) == 0
}

_satisfied(id) if {
	annex_a[id]
	not _fact_evaluated(id)
	_attested(id)
}

# 2013-era ids: three-level (A.5.1.1 … A.18.2.3) or a 2013 group number above 8 (A.9.1, A.12)
_iso2013_id(id) if regex.match(`^A\.\d+\.\d+\.\d+$`, id)

_iso2013_id(id) if {
	regex.match(`^A\.\d+(\.\d+)?$`, id)
	to_number(split(id, ".")[1]) > 8
}

violations contains "ISO/IEC 27001:2022 Annex A: FAIL-CLOSED - attestations 'input.iso27001.annex_a' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, r in annex_a
	not _fact_evaluated(id)
	not _attested(id)
	msg := sprintf("ISO/IEC 27001:2022 %v %v (%v): not attested — input.iso27001.annex_a[\"%v\"] must be true", [id, r.title, r.theme, id])
}

violations contains msg if {
	some id, failed in _failed_facts
	some c in failed
	msg := sprintf("ISO/IEC 27001:2022 %v %v: fact check failed — data.iso27001.%v.%v%v", [id, annex_a[id].title, c.pkg, c.rule, _iso2013_note(c)])
}

_iso2013_note(c) := sprintf(" (2013 %v)", [c.iso2013]) if c.iso2013 != ""

else := ""

violations contains msg if {
	some id, _ in _attestations
	not annex_a[id]
	_iso2013_id(id)
	msg := sprintf("ISO/IEC 27001 Input Contract: %v is an ISO/IEC 27001:2013 Annex A id — the 2022 edition renumbered Annex A (A.5.1 … A.8.34); attest the 2022 control", [id])
}

violations contains msg if {
	some id, _ in _attestations
	not annex_a[id]
	not _iso2013_id(id)
	msg := sprintf("ISO/IEC 27001 Input Contract: attestation for unknown Annex A control id %v — ids are ISO/IEC 27001:2022 Annex A numbers such as A.5.1 (the ISO/IEC 27002:2022 number with an \"A.\" prefix)", [id])
}

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------

control_status[id] := s if {
	some id, r in annex_a
	s := {
		"theme": r.theme,
		"title": r.title,
		"iso27002": substring(id, 2, -1),
		"basis": _basis(id),
		"attested": _attested_bool(id),
		"fact_checks_failed": [concat(".", [c.pkg, c.rule]) | some c in object.get(_failed_facts, id, [])],
		"satisfied": _satisfied_bool(id),
	}
}

iso27002_status[cid] := object.union(s, {"annex_a": id}) if {
	some id, s in control_status
	cid := substring(id, 2, -1)
}

_basis(id) := "facts" if _fact_evaluated(id)

else := "attestation"

_attested_bool(id) if _attested(id)

else := false

_satisfied_bool(id) if _satisfied(id)

else := false

theme_reports[name] := r if {
	some clause, name in themes
	ids := {id | some id; q := annex_a[id]; q.theme == name}
	ok := {id | some id in ids; _satisfied(id)}
	r := {
		"clause": clause,
		"controls": count(ids),
		"satisfied": count(ok),
		"fact_evaluated": count({id | some id in ids; _fact_evaluated(id)}),
		"attested_basis": count({id | some id in ids; not _fact_evaluated(id)}),
		"gaps": _in_order({id | some id in ids; not id in ok}),
	}
}

# Annex A ids in numeric order (A.5.2 before A.5.10)
_in_order(s) := [k[2] | some k in sort([[to_number(p[1]), to_number(p[2]), id] | some id in s; p := split(id, ".")])]

_n_satisfied := count({id | some id; _ = annex_a[id]; _satisfied(id)})

compliance_report := {
	"framework": "ISO/IEC 27001:2022",
	"standard": "ISO/IEC 27001:2022 Annex A — information security controls (= ISO/IEC 27002:2022 clauses 5-8)",
	"source": source,
	"compliant": compliant,
	"overall_compliant": compliant,
	"total_controls": count(annex_a),
	"standard_total": 93, # ISO/IEC 27001:2022 Annex A: 93 controls (37 organizational, 8 people, 14 physical, 34 technological)
	"controls_satisfied": _n_satisfied,
	"controls_fact_evaluated": count(fact_checks),
	"controls_attested": count(annex_a) - count(fact_checks),
	"themes_total": count(themes),
	"themes_passing": count([t | some t; r := theme_reports[t]; count(r.gaps) == 0]),
	"themes": theme_reports,
	"annex_a": control_status,
	"iso27002": iso27002_status,
	"isms_domains": iso27001_assessment.isms_results,
	"unmapped_fact_rules": unmapped_fact_rules,
	"violation_count": count(violations),
	"violations": violations,
}
