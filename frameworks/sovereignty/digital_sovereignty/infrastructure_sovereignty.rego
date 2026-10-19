# METADATA
# title: "Digital Sovereignty — Infrastructure Sovereignty"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 38
#     cited: 21
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package digital_sovereignty.infrastructure_sovereignty

import rego.v1

# Digital Sovereignty — Infrastructure Sovereignty
# Ensures the organisation controls its infrastructure, understands cloud provider
# legal exposure, and avoids unacceptable concentration risk.
#
# Input schema:
#   input.approved_jurisdictions[]
#   input.infrastructure_components[]
#     .component_id, .component_type      — server | network | storage | cloud_service | saas
#     .deployment_type                    — on_prem | sovereign_cloud | private_cloud | public_cloud
#     .provider, .provider_hq_country     — HQ country of vendor (legal jurisdiction exposure)
#     .physical_location_country
#     .data_classification
#     .subject_to_foreign_surveillance_law — bool (CLOUD Act, FISA 702, etc.)
#     .foreign_government_access_risk     — none | low | medium | high
#   input.cloud_providers[]
#     .provider_id, .provider_name
#     .hq_country
#     .subject_to_cloud_act               — bool
#     .sovereign_cloud_offering.available — bool
#     .sovereign_cloud_offering.jurisdiction
#     .data_processed_pct                 — % of total data handled by this provider
#   input.hardware_components[]
#     .component_id, .component_type
#     .manufacturer_country
#     .firmware_origin_country
#     .supply_chain_audited               — bool
#     .known_vulnerabilities.hardware_backdoor — bool
#   input.network_infrastructure
#     .dns_provider.location_country
#     .dns_provider.under_foreign_jurisdiction — bool
#     .cdn.provider_hq_country
#     .cdn.content_cached_in_approved_regions — bool
#   input.concentration_limits
#     .max_single_provider_pct            — e.g. 70
#     .max_foreign_provider_pct           — e.g. 50
#   input.exit_strategy
#     .documented                         — bool
#     .portability_tested                 — bool
#     .estimated_migration_days
#     .data_portability_format_open       — bool

# =============================================================================
# CLOUD PROVIDER LEGAL EXPOSURE
# =============================================================================

# Critical workloads must not run on providers subject to CLOUD Act
# (or equivalent foreign surveillance laws) without mitigating controls
# Fail closed: a component handling regulated data is exposed unless the
# surveillance-law flag is explicitly false; an unrecorded flag is not "no exposure".
cloud_act_offenders contains c if {
	some c in object.get(input, "infrastructure_components", [])
	c.data_classification in ["sensitive", "restricted", "sovereign"]
	not c.subject_to_foreign_surveillance_law == false
	not c.mitigation.encryption_before_upload == true
	not c.mitigation.sovereign_cloud_used == true
}

default cloud_act_risk_mitigated := false

cloud_act_risk_mitigated if count(cloud_act_offenders) == 0

# Sovereign/restricted workloads must not use providers with high foreign access risk
# Fail closed: the risk rating must be recorded as none/low. (`not x.f in list`
# is undefined when f is absent, so the rating is read with object.get.)
foreign_access_offenders contains c if {
	some c in object.get(input, "infrastructure_components", [])
	c.data_classification in ["sovereign", "restricted"]
	not object.get(c, "foreign_government_access_risk", "") in ["none", "low"]
}

default sovereign_workloads_not_at_risk := false

sovereign_workloads_not_at_risk if count(foreign_access_offenders) == 0

# =============================================================================
# PROVIDER CONCENTRATION RISK
# =============================================================================

# No single foreign provider should handle more than allowed percentage of data
default provider_concentration_within_limits := false

provider_concentration_within_limits if {
	violations := [p |
		p := input.cloud_providers[_]
		not p.hq_country in input.approved_jurisdictions
		p.data_processed_pct > input.concentration_limits.max_single_provider_pct
	]
	count(violations) == 0
}

# Total percentage of data processed by foreign providers must be within limit
foreign_provider_concentration_within_limits if {
	total_foreign_pct := sum([p.data_processed_pct |
		p := input.cloud_providers[_]
		not p.hq_country in input.approved_jurisdictions
	])
	total_foreign_pct <= input.concentration_limits.max_foreign_provider_pct
}

# =============================================================================
# HARDWARE SUPPLY CHAIN
# =============================================================================

# Critical hardware must not come from high-risk manufacturer countries
default hardware_supply_chain_acceptable := false

hardware_supply_chain_acceptable if {
	violations := [h |
		h := input.hardware_components[_]
		h.component_type in ["server", "network_device", "storage_controller", "hsm"]
		not h.manufacturer_country in input.approved_jurisdictions
		not h.supply_chain_audited == true
	]
	count(violations) == 0
}

# No hardware with known backdoors in critical infrastructure
default no_hardware_backdoors := false

no_hardware_backdoors if {
	violations := [h |
		h := input.hardware_components[_]
		h.known_vulnerabilities.hardware_backdoor == true
	]
	count(violations) == 0
}

# Firmware must originate from approved or audited sources
default firmware_origin_acceptable := false

firmware_origin_acceptable if {
	violations := [h |
		h := input.hardware_components[_]
		h.component_type in ["server", "network_device", "storage_controller"]
		not h.firmware_origin_country in input.approved_jurisdictions
		not h.supply_chain_audited == true
	]
	count(violations) == 0
}

# =============================================================================
# NETWORK INFRASTRUCTURE SOVEREIGNTY
# =============================================================================

# DNS resolution must not depend on foreign-controlled providers
dns_sovereignty if {
	input.network_infrastructure.dns_provider.under_foreign_jurisdiction == false
}

default dns_in_jurisdiction := false

dns_in_jurisdiction if {
	input.network_infrastructure.dns_provider.location_country in input.approved_jurisdictions
}

# CDN caches must only be in approved regions for regulated data
default cdn_in_approved_regions := false

cdn_in_approved_regions if {
	not input.network_infrastructure.cdn
} else if {
	input.network_infrastructure.cdn.content_cached_in_approved_regions == true
}

# =============================================================================
# DEPLOYMENT TYPE CLASSIFICATION
# =============================================================================

# Sovereign data must only be on on-premises or sovereign cloud
default sovereign_data_on_sovereign_infra := false

sovereign_data_on_sovereign_infra if {
	violations := [c |
		c := input.infrastructure_components[_]
		c.data_classification in ["sovereign", "restricted"]
		not c.deployment_type in ["on_prem", "sovereign_cloud", "private_cloud"]
	]
	count(violations) == 0
}

# All components classified as to sovereignty impact
default all_components_classified := false

all_components_classified if {
	violations := [c |
		c := input.infrastructure_components[_]
		not c.data_classification
	]
	count(violations) == 0
}

# =============================================================================
# EXIT STRATEGY AND PORTABILITY
# =============================================================================

# An exit strategy from each provider must be documented and tested
exit_strategy_documented if {
	input.exit_strategy.documented == true
	input.exit_strategy.portability_tested == true
}

# Data must be exportable in open formats (no proprietary lock-in)
data_portability_in_open_formats if {
	input.exit_strategy.data_portability_format_open == true
}

# Migration must be achievable within the acceptable timeframe (90 days).
# decisions 2026-10-19: wired into compliant/violations as IS-019; an undeclared
# estimate fails closed.
default migration_timeline_acceptable := false

migration_timeline_acceptable if {
	input.exit_strategy.estimated_migration_days <= 90
}

# =============================================================================
# SURVEILLANCE LAW RESPONSE (IS-011, IS-012)
# =============================================================================
#   input.surveillance_law_response
#     .procedure_documented               — bool
#     .legal_counsel_on_retainer          — bool
#     .notification_to_data_owner_required — bool
#     .challenge_mechanism_available      — bool
#     .cloud_act_specific_procedure       — bool
#     .fisa_702_specific_procedure        — bool

# CLOUD Act response: documented procedure + legal counsel + specific procedure
cloud_act_response_procedure_documented if {
	input.surveillance_law_response.procedure_documented == true
	input.surveillance_law_response.legal_counsel_on_retainer == true
	input.surveillance_law_response.cloud_act_specific_procedure == true
}

# FISA 702 response: specific procedure + challenge mechanism + data owner notification
fisa_702_response_procedure_documented if {
	input.surveillance_law_response.fisa_702_specific_procedure == true
	input.surveillance_law_response.challenge_mechanism_available == true
	input.surveillance_law_response.notification_to_data_owner_required == true
}

# =============================================================================
# VENDOR LOCK-IN COST ASSESSMENT (IS-013)
# =============================================================================
#   input.vendor_lock_in_assessment
#     .conducted                          — bool
#     .exit_cost_acceptable               — bool
#     .cost_reduction_plan_documented     — bool
#     .proprietary_api_dependencies[]
#       .service_id                       — string
#       .mitigation_documented            — bool

# Vendor lock-in cost must be assessed and either acceptable or under active mitigation
vendor_lockin_cost_assessed if {
	input.vendor_lock_in_assessment.conducted == true
	input.vendor_lock_in_assessment.exit_cost_acceptable == true
}

# All proprietary API dependencies must have documented mitigations
default proprietary_apis_have_mitigations := false

proprietary_apis_have_mitigations if {
	unmitigated := [dep |
		dep := input.vendor_lock_in_assessment.proprietary_api_dependencies[_]
		not dep.mitigation_documented == true
	]
	count(unmitigated) == 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	some c in cloud_act_offenders
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-001",
		"severity": "critical",
		"component_id": object.get(c, "component_id", "unknown"),
		"description": concat("", ["Component subject to (or not recorded as free of) foreign surveillance law, without mitigation: ", object.get(c, "component_id", "unknown"), " (", object.get(c, "provider", "unknown"), ")"]),
		"remediation": "Implement client-side encryption before upload, or migrate to sovereign cloud offering",
	}
}

violations contains v if {
	some c in foreign_access_offenders
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-002",
		"severity": "critical",
		"component_id": object.get(c, "component_id", "unknown"),
		"description": concat("", ["Sovereign data on infrastructure with medium/high (or unrecorded) foreign access risk: ", object.get(c, "component_id", "unknown")]),
		"remediation": "Move sovereign/restricted workloads to on-premises or approved sovereign cloud",
	}
}

violations contains v if {
	not provider_concentration_within_limits
	p := input.cloud_providers[_]
	not p.hq_country in input.approved_jurisdictions
	p.data_processed_pct > input.concentration_limits.max_single_provider_pct
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-003",
		"severity": "high",
		"provider": p.provider_name,
		"description": concat("", ["Single foreign provider concentration exceeds limit: ", p.provider_name, " processes ", format_int(p.data_processed_pct, 10), "% of data"]),
		"remediation": concat("", ["Reduce dependency on ", p.provider_name, " to below ", format_int(input.concentration_limits.max_single_provider_pct, 10), "%"]),
	}
}

violations contains v if {
	not foreign_provider_concentration_within_limits
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-004",
		"severity": "high",
		"description": "Total foreign provider data processing concentration exceeds acceptable limit",
		"remediation": "Rebalance workloads to increase domestic/in-jurisdiction infrastructure share",
	}
}

violations contains v if {
	not hardware_supply_chain_acceptable
	h := input.hardware_components[_]
	h.component_type in ["server", "network_device", "storage_controller", "hsm"]
	not h.manufacturer_country in input.approved_jurisdictions
	not h.supply_chain_audited == true
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-005",
		"severity": "high",
		"component_id": h.component_id,
		"description": concat("", ["Critical hardware from unapproved country without supply chain audit: ", h.component_id, " (", h.manufacturer_country, ")"]),
		"remediation": "Conduct supply chain audit or replace with hardware from approved manufacturers",
	}
}

violations contains v if {
	not no_hardware_backdoors
	h := input.hardware_components[_]
	h.known_vulnerabilities.hardware_backdoor == true
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-006",
		"severity": "critical",
		"component_id": h.component_id,
		"description": concat("", ["Hardware with known backdoor vulnerability in use: ", h.component_id]),
		"remediation": "Immediately replace hardware with known backdoor vulnerabilities",
	}
}

violations contains v if {
	not sovereign_data_on_sovereign_infra
	c := input.infrastructure_components[_]
	c.data_classification in ["sovereign", "restricted"]
	not c.deployment_type in ["on_prem", "sovereign_cloud", "private_cloud"]
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-007",
		"severity": "critical",
		"component_id": c.component_id,
		"description": concat("", ["Sovereign/restricted data on non-sovereign infrastructure: ", c.component_id, " (", c.deployment_type, ")"]),
		"remediation": "Migrate sovereign data to on-premises, private cloud, or certified sovereign cloud",
	}
}

violations contains v if {
	not dns_sovereignty
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-008",
		"severity": "high",
		"description": "DNS resolver is under foreign jurisdiction — traffic metadata exposed",
		"remediation": "Deploy DNS resolver within approved jurisdiction or use DNSSEC with in-jurisdiction resolver",
	}
}

violations contains v if {
	not exit_strategy_documented
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-009",
		"severity": "medium",
		"description": "No documented and tested exit strategy from cloud providers",
		"remediation": "Document exit strategy for each cloud provider and perform annual portability test",
	}
}

violations contains v if {
	not data_portability_in_open_formats
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-010",
		"severity": "medium",
		"description": "Data not exportable in open formats — vendor lock-in risk",
		"remediation": "Ensure all regulated data can be exported in open, non-proprietary formats",
	}
}

violations contains v if {
	not cloud_act_response_procedure_documented
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-011",
		"severity": "high",
		"description": "No documented CLOUD Act response procedure with legal counsel and specific handling steps (FedRAMP, NIST SP 800-171C)",
		"remediation": "Document CLOUD Act response procedure covering receipt of legal process, challenge rights, and data owner notification; retain legal counsel familiar with CLOUD Act",
	}
}

violations contains v if {
	not fisa_702_response_procedure_documented
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-012",
		"severity": "high",
		"description": "No documented FISA Section 702 response procedure with challenge mechanism and data owner notification (NIST SP 800-171C)",
		"remediation": "Document FISA 702 response procedure; ensure challenge mechanism is available and data owners are notified when legally permitted",
	}
}

violations contains v if {
	not vendor_lockin_cost_assessed
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-013",
		"severity": "medium",
		"description": "Vendor lock-in exit cost not assessed or not within acceptable threshold (EU Data Act Art. 5(6))",
		"remediation": "Conduct vendor lock-in cost assessment; document exit costs; if unacceptable, create cost reduction plan targeting open APIs and portable formats",
	}
}

violations contains v if {
	not migration_timeline_acceptable
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-019",
		"severity": "medium",
		"description": "Estimated migration/exit time not declared or exceeds the acceptable 90 days",
		"remediation": "Document an exit plan with an estimated migration time of 90 days or less",
	}
}

violations contains v if {
	not proprietary_apis_have_mitigations
	dep := input.vendor_lock_in_assessment.proprietary_api_dependencies[_]
	not dep.mitigation_documented == true
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-018", # decisions 2026-10-19: was IS-013 (shared with vendor lock-in cost)
		"severity": "medium",
		"service_id": dep.service_id,
		"description": concat("", ["Proprietary API dependency with no documented migration mitigation: ", dep.service_id]),
		"remediation": "Document abstraction layer or migration path for each proprietary API dependency",
	}
}

# Controls that gate `compliant` and previously had no violation entry
# (compliant could be false with violation_count 0).
violations contains v if {
	not firmware_origin_acceptable
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-014",
		"severity": "high",
		"description": "Firmware originates outside approved jurisdictions without a supply-chain audit",
		"remediation": "Source firmware from approved jurisdictions or complete a supply-chain audit for the affected components",
	}
}

violations contains v if {
	not dns_in_jurisdiction
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-015",
		"severity": "high",
		"description": "DNS provider is not located in an approved jurisdiction (or its location is not recorded)",
		"remediation": "Use a DNS provider located in an approved jurisdiction and record network_infrastructure.dns_provider.location_country",
	}
}

violations contains v if {
	not cdn_in_approved_regions
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-016",
		"severity": "high",
		"description": "CDN content is cached outside approved regions",
		"remediation": "Restrict CDN caching to approved regions for regulated data",
	}
}

violations contains v if {
	not all_components_classified
	v := {
		"domain": "infrastructure_sovereignty",
		"control": "IS-017",
		"severity": "medium",
		"description": "One or more infrastructure components have no data classification recorded",
		"remediation": "Classify every infrastructure component by data classification",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	cloud_act_risk_mitigated
	sovereign_workloads_not_at_risk
	provider_concentration_within_limits
	foreign_provider_concentration_within_limits
	hardware_supply_chain_acceptable
	no_hardware_backdoors
	firmware_origin_acceptable
	dns_sovereignty
	dns_in_jurisdiction
	cdn_in_approved_regions
	sovereign_data_on_sovereign_infra
	all_components_classified
	exit_strategy_documented
	data_portability_in_open_formats
	cloud_act_response_procedure_documented
	fisa_702_response_procedure_documented
	vendor_lockin_cost_assessed
	proprietary_apis_have_mitigations
	migration_timeline_acceptable
}

report := {
	"domain": "Infrastructure Sovereignty",
	"compliant": compliant,
	"controls": {
		"IS-001_cloud_act_risk_mitigated": cloud_act_risk_mitigated,
		"IS-002_sovereign_workloads_protected": sovereign_workloads_not_at_risk,
		"IS-003_provider_concentration": provider_concentration_within_limits,
		"IS-004_foreign_concentration": foreign_provider_concentration_within_limits,
		"IS-005_hardware_supply_chain": hardware_supply_chain_acceptable,
		"IS-006_no_hardware_backdoors": no_hardware_backdoors,
		"IS-007_sovereign_infra": sovereign_data_on_sovereign_infra,
		"IS-008_dns_sovereignty": dns_sovereignty,
		"IS-009_exit_strategy": exit_strategy_documented,
		"IS-010_data_portability": data_portability_in_open_formats,
		"IS-011_cloud_act_response": cloud_act_response_procedure_documented,
		"IS-012_fisa_702_response": fisa_702_response_procedure_documented,
		"IS-013_vendor_lockin_assessed": vendor_lockin_cost_assessed,
		"IS-014_firmware_origin": firmware_origin_acceptable,
		"IS-015_dns_in_jurisdiction": dns_in_jurisdiction,
		"IS-016_cdn_in_approved_regions": cdn_in_approved_regions,
		"IS-017_components_classified": all_components_classified,
		"IS-018_proprietary_api_mitigations": proprietary_apis_have_mitigations,
		"IS-019_migration_timeline": migration_timeline_acceptable,
	},
	"provider_summary": {
		"total_providers": count(object.get(input, ["cloud_providers"], [])),
		"foreign_providers": count([p | p := input.cloud_providers[_]; not p.hq_country in input.approved_jurisdictions]),
		"cloud_act_exposed": count([p | p := input.cloud_providers[_]; p.subject_to_cloud_act == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default cloud_act_response_procedure_documented := false
default data_portability_in_open_formats := false
default dns_sovereignty := false
default exit_strategy_documented := false
default fisa_702_response_procedure_documented := false
default foreign_provider_concentration_within_limits := false
default vendor_lockin_cost_assessed := false
