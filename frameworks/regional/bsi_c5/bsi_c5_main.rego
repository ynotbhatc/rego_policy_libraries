# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — master orchestrator
#
# Aggregates the 17 C5 criteria domains into one compliance report with a
# per-domain rollup. C5 distinguishes basic and additional criteria and is
# attested via Type 1 / Type 2 reports; this module models the domain
# requirements as a straight fail-closed pass/fail (an unattested requirement
# is a gap) and does not model the attestation route. Requirement ids are
# AAC's operationalization, not the official C5 criterion numbering.
#
# Entry point: data.bsi_c5.main.compliance_report

package bsi_c5.main

import rego.v1

import data.bsi_c5.asset_management
import data.bsi_c5.business_continuity
import data.bsi_c5.communication_security
import data.bsi_c5.compliance_audit
import data.bsi_c5.cryptography
import data.bsi_c5.government_inquiries
import data.bsi_c5.identity_access_management
import data.bsi_c5.incident_management
import data.bsi_c5.operations
import data.bsi_c5.organisation_information_security
import data.bsi_c5.personnel
import data.bsi_c5.physical_security
import data.bsi_c5.portability_interoperability
import data.bsi_c5.product_security
import data.bsi_c5.security_policies
import data.bsi_c5.supplier_control
import data.bsi_c5.system_development

# Per-domain reports, in C5 catalogue order.
domain_reports := [
	organisation_information_security.compliance_report,
	security_policies.compliance_report,
	personnel.compliance_report,
	asset_management.compliance_report,
	physical_security.compliance_report,
	operations.compliance_report,
	identity_access_management.compliance_report,
	cryptography.compliance_report,
	communication_security.compliance_report,
	portability_interoperability.compliance_report,
	system_development.compliance_report,
	supplier_control.compliance_report,
	incident_management.compliance_report,
	business_continuity.compliance_report,
	compliance_audit.compliance_report,
	government_inquiries.compliance_report,
	product_security.compliance_report,
]

all_violations := [v | some r in domain_reports; some v in r.violations]

# Attestation object for a domain, defaulted to {} so the report is robust
# to entirely-absent input (the standard bare `opa eval` verify command) and
# to a malformed non-object `requirements` value, which would otherwise make
# object.get undefined and silently drop the domain's ids from _all.
default _attest(_) := {}

_attest(domain) := req if {
	req := input.bsi_c5[domain].requirements
	is_object(req)
}

_specs := [
	{"key": "organisation_information_security", "req": organisation_information_security.requirements},
	{"key": "security_policies", "req": security_policies.requirements},
	{"key": "personnel", "req": personnel.requirements},
	{"key": "asset_management", "req": asset_management.requirements},
	{"key": "physical_security", "req": physical_security.requirements},
	{"key": "operations", "req": operations.requirements},
	{"key": "identity_access_management", "req": identity_access_management.requirements},
	{"key": "cryptography", "req": cryptography.requirements},
	{"key": "communication_security", "req": communication_security.requirements},
	{"key": "portability_interoperability", "req": portability_interoperability.requirements},
	{"key": "system_development", "req": system_development.requirements},
	{"key": "supplier_control", "req": supplier_control.requirements},
	{"key": "incident_management", "req": incident_management.requirements},
	{"key": "business_continuity", "req": business_continuity.requirements},
	{"key": "compliance_audit", "req": compliance_audit.requirements},
	{"key": "government_inquiries", "req": government_inquiries.requirements},
	{"key": "product_security", "req": product_security.requirements},
]

# id -> {domain, met}. Requirement ids are unique across domains (distinct prefixes).
_all[id] := {"domain": m.domain, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Per-domain rollup, keyed by domain name.
criteria_domains[name] := {
	"domain": r.domain,
	"requirements": r.requirements_evaluated,
	"gaps": r.violation_count,
	"compliant": r.compliant,
} if {
	some r in domain_reports
	name := r.area_name
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "BSI C5:2020",
	"reference": "BSI Cloud Computing Compliance Criteria Catalogue (C5:2020)",
	"domains_evaluated": count(domain_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"criteria_domains": criteria_domains,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
