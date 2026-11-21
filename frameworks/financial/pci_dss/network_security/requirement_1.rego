# PCI DSS Requirement 1 - Install and Maintain Network Security Controls
# Network security controls for cardholder data environment (CDE)

# METADATA
# title: "PCI DSS Requirement 1 - Install and Maintain Network Security Controls"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 22
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.network_security.requirement_1

import rego.v1

# =================================================================
# 1.1 - Processes and mechanisms for installing and maintaining network security controls
# =================================================================

# Network security policies and procedures are established
# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
network_security_policies_established if {
	input.pci.network_security.policies.documented == true
	input.pci.network_security.policies.approved == true
	input.pci.network_security.policies.current == true
}

# Network security roles and responsibilities are defined
network_security_roles_defined if {
	input.pci.network_security.roles.defined == true
	input.pci.network_security.roles.documented == true
	input.pci.network_security.responsibilities.assigned == true
	input.pci.network_security.accountability.established == true
}

# Network security controls are maintained
network_security_controls_maintained if {
	input.pci.network_security.maintenance.scheduled == true
	input.pci.network_security.maintenance.documented == true
	input.pci.network_security.change_management.implemented == true
	input.pci.network_security.review_process.established == true
}

# =================================================================
# 1.2 - Network security controls (NSCs) are configured and maintained
# =================================================================

# Firewall and router configuration standards are established
firewall_configuration_standards if {
	input.pci.firewalls.configuration_standards.documented == true
	input.pci.firewalls.configuration_standards.approved == true
	input.pci.firewalls.configuration_standards.implemented == true
	input.pci.firewalls.default_deny.configured == true
}

# Firewall rules are documented and justified
firewall_rules_documented if {
	input.pci.firewalls.rules.documented == true
	input.pci.firewalls.rules.business_justification == true
	input.pci.firewalls.rules.reviewed_regularly == true
	input.pci.firewalls.rules.approved_before_implementation == true
}

# Network connections between trusted and untrusted networks are controlled
network_connections_controlled if {
	input.pci.network.trusted_untrusted.identified == true
	input.pci.network.trusted_untrusted.controlled == true
	input.pci.network.connections.documented == true
	input.pci.network.connections.justified == true
}

# =================================================================
# 1.3 - Network access to and from the cardholder data environment is restricted
# =================================================================

# Inbound traffic to CDE is restricted
inbound_traffic_restricted if {
	input.pci.cde.inbound_traffic.restricted == true
	input.pci.cde.inbound_traffic.necessary_only == true
	input.pci.cde.inbound_traffic.documented == true
	input.pci.cde.inbound_traffic.authorized == true
}

# Outbound traffic from CDE is restricted
outbound_traffic_restricted if {
	input.pci.cde.outbound_traffic.restricted == true
	input.pci.cde.outbound_traffic.necessary_only == true
	input.pci.cde.outbound_traffic.documented == true
	input.pci.cde.outbound_traffic.authorized == true
}

# Direct public access between Internet and CDE is prohibited
direct_internet_access_prohibited if {
	input.pci.cde.direct_internet_access.prohibited == true
	input.pci.cde.dmz.implemented == true
	input.pci.cde.proxy_services.configured == true
	input.pci.cde.internet_isolation.enforced == true
}

# =================================================================
# 1.4 - Network connections between trusted and untrusted networks are controlled
# =================================================================

# Network segmentation is implemented to isolate CDE
network_segmentation_implemented if {
	input.pci.network_segmentation.implemented == true
	input.pci.network_segmentation.cde_isolated == true
	input.pci.network_segmentation.documented == true
	input.pci.network_segmentation.validated == true
}

# DMZ is properly configured
dmz_properly_configured if {
	input.pci.dmz.implemented == true
	input.pci.dmz.separates_untrusted_from_cde == true
	input.pci.dmz.controls_traffic_flow == true
	input.pci.dmz.monitored == true
}

# Network address translation (NAT) is implemented
nat_implemented if {
	input.pci.network.nat.implemented == true
	input.pci.network.nat.hides_internal_addresses == true
	input.pci.network.nat.documented == true
	input.pci.network.nat.configured_securely == true
}

# =================================================================
# 1.5 - The multi-tenant service provider protects each entity's CDE
# =================================================================

# Multi-tenant environment isolation (if applicable)
# Not applicable (explicitly declared), or applicable with isolation evidence
multi_tenant_isolation if {
	input.pci.multi_tenant.applicable == false
} else if {
	input.pci.multi_tenant.applicable == true
	input.pci.multi_tenant.each_entity_isolated == true
	input.pci.multi_tenant.cannot_access_others == true
	input.pci.multi_tenant.documented == true
}

# =================================================================
# OpenShift/Kubernetes Network Security Controls
# =================================================================

# OpenShift network policies for CDE isolation
openshift_network_policies_cde if {
	input.openshift.network_policies.cde_isolation.enabled == true
	input.openshift.network_policies.default_deny.configured == true
	input.openshift.network_policies.ingress_rules.restrictive == true
	input.openshift.network_policies.egress_rules.restrictive == true
}

# Service mesh security for PCI environments
service_mesh_pci_security if {
	input.openshift.service_mesh.enabled == true
	input.openshift.service_mesh.mutual_tls.enforced == true
	input.openshift.service_mesh.traffic_policies.pci_compliant == true
	input.openshift.service_mesh.access_control.implemented == true
}

# Container network isolation
container_network_isolation if {
	input.openshift.containers.network_isolation.enabled == true
	input.openshift.containers.pod_security.network_restricted == true
	input.openshift.containers.namespace_isolation.cde_separated == true
}

# OpenShift SDN security
openshift_sdn_security if {
	input.openshift.sdn.network_policy.enabled == true
	input.openshift.sdn.multitenant.configured == true
	input.openshift.sdn.subnet_isolation.enabled == true
	input.openshift.sdn.ingress_controllers.secured == true
}

# =================================================================
# Cloud Environment Network Security
# =================================================================

# Cloud network security groups
cloud_security_groups_configured if {
	input.cloud.security_groups.cde_specific == true
	input.cloud.security_groups.least_privilege == true
	input.cloud.security_groups.regularly_reviewed == true
	input.cloud.security_groups.documented == true
}

# Virtual private cloud (VPC) configuration
vpc_configuration_secure if {
	input.cloud.vpc.cde_dedicated == true
	input.cloud.vpc.private_subnets.cde_isolated == true
	input.cloud.vpc.nat_gateways.configured == true
	input.cloud.vpc.flow_logs.enabled == true
}

# Cloud web application firewall (WAF)
cloud_waf_implemented if {
	input.cloud.waf.enabled == true
	input.cloud.waf.rules.pci_specific == true
	input.cloud.waf.logging.comprehensive == true
	input.cloud.waf.monitoring.real_time == true
}

# =================================================================
# Network Monitoring and Logging
# =================================================================

# Network traffic monitoring
network_traffic_monitoring if {
	input.pci.network_monitoring.traffic_analysis.enabled == true
	input.pci.network_monitoring.intrusion_detection.deployed == true
	input.pci.network_monitoring.anomaly_detection.configured == true
	input.pci.network_monitoring.real_time_alerts.enabled == true
}

# Network access logging
network_access_logging if {
	input.pci.network_logging.firewall_logs.comprehensive == true
	input.pci.network_logging.access_attempts.logged == true
	input.pci.network_logging.denied_connections.logged == true
	input.pci.network_logging.centralized.implemented == true
}

# Network security event correlation
network_security_correlation if {
	input.pci.network_security.event_correlation.enabled == true
	input.pci.network_security.siem_integration.configured == true
	input.pci.network_security.threat_detection.automated == true
	input.pci.network_security.incident_response.integrated == true
}

# =================================================================
# PCI Requirement 1 Overall Assessment
# =================================================================

requirement_1_1_compliant if {
	network_security_policies_established
	network_security_roles_defined
	network_security_controls_maintained
}

requirement_1_2_compliant if {
	firewall_configuration_standards
	firewall_rules_documented
	network_connections_controlled
}

requirement_1_3_compliant if {
	inbound_traffic_restricted
	outbound_traffic_restricted
	direct_internet_access_prohibited
}

requirement_1_4_compliant if {
	network_segmentation_implemented
	dmz_properly_configured
	nat_implemented
}

requirement_1_5_compliant if {
	multi_tenant_isolation
}

openshift_network_security_compliant if {
	openshift_network_policies_cde
	service_mesh_pci_security
	container_network_isolation
	openshift_sdn_security
}

cloud_network_security_compliant if {
	cloud_security_groups_configured
	vpc_configuration_secure
	cloud_waf_implemented
}

network_monitoring_compliant if {
	network_traffic_monitoring
	network_access_logging
	network_security_correlation
}

pci_requirement_1_compliant if {
	requirement_1_1_compliant
	requirement_1_2_compliant
	requirement_1_3_compliant
	requirement_1_4_compliant
	requirement_1_5_compliant
	openshift_network_security_compliant
	cloud_network_security_compliant
	network_monitoring_compliant
}

# =================================================================
# PCI Requirement 1 Score Calculation
# =================================================================

# Every control referenced by the score, findings and roll-ups has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default network_security_policies_established := false

default network_security_roles_defined := false

default network_security_controls_maintained := false

default firewall_configuration_standards := false

default firewall_rules_documented := false

default network_connections_controlled := false

default inbound_traffic_restricted := false

default outbound_traffic_restricted := false

default direct_internet_access_prohibited := false

default network_segmentation_implemented := false

default dmz_properly_configured := false

default nat_implemented := false

default multi_tenant_isolation := false

default openshift_network_policies_cde := false

default service_mesh_pci_security := false

default container_network_isolation := false

default openshift_sdn_security := false

default cloud_security_groups_configured := false

default vpc_configuration_secure := false

default cloud_waf_implemented := false

default network_traffic_monitoring := false

default network_access_logging := false

default network_security_correlation := false

default requirement_1_1_compliant := false

default requirement_1_2_compliant := false

default requirement_1_3_compliant := false

default requirement_1_4_compliant := false

default requirement_1_5_compliant := false

default openshift_network_security_compliant := false

default cloud_network_security_compliant := false

default network_monitoring_compliant := false

default pci_requirement_1_compliant := false

default pci_requirement_1_score := 0

default pci_requirement_1_findings := {}

pci_requirement_1_score := score if {
	controls := [
		network_security_policies_established,
		network_security_roles_defined,
		network_security_controls_maintained,
		firewall_configuration_standards,
		firewall_rules_documented,
		network_connections_controlled,
		inbound_traffic_restricted,
		outbound_traffic_restricted,
		direct_internet_access_prohibited,
		network_segmentation_implemented,
		dmz_properly_configured,
		nat_implemented,
		multi_tenant_isolation,
		openshift_network_policies_cde,
		service_mesh_pci_security,
		container_network_isolation,
		openshift_sdn_security,
		cloud_security_groups_configured,
		vpc_configuration_secure,
		cloud_waf_implemented,
		network_traffic_monitoring,
		network_access_logging,
		network_security_correlation,
	]

	passed := count([control | control := controls[_]; control == true])
	total := count(controls)
	score := (passed / total) * 100
}

# =================================================================
# PCI Requirement 1 Detailed Findings
# =================================================================

pci_requirement_1_findings := findings if {
	findings := {
		"requirement_1_1": {
			"network_security_policies_established": network_security_policies_established,
			"network_security_roles_defined": network_security_roles_defined,
			"network_security_controls_maintained": network_security_controls_maintained,
		},
		"requirement_1_2": {
			"firewall_configuration_standards": firewall_configuration_standards,
			"firewall_rules_documented": firewall_rules_documented,
			"network_connections_controlled": network_connections_controlled,
		},
		"requirement_1_3": {
			"inbound_traffic_restricted": inbound_traffic_restricted,
			"outbound_traffic_restricted": outbound_traffic_restricted,
			"direct_internet_access_prohibited": direct_internet_access_prohibited,
		},
		"requirement_1_4": {
			"network_segmentation_implemented": network_segmentation_implemented,
			"dmz_properly_configured": dmz_properly_configured,
			"nat_implemented": nat_implemented,
		},
		"requirement_1_5": {"multi_tenant_isolation": multi_tenant_isolation},
		"openshift_controls": {
			"openshift_network_policies_cde": openshift_network_policies_cde,
			"service_mesh_pci_security": service_mesh_pci_security,
			"container_network_isolation": container_network_isolation,
			"openshift_sdn_security": openshift_sdn_security,
		},
		"cloud_controls": {
			"cloud_security_groups_configured": cloud_security_groups_configured,
			"vpc_configuration_secure": vpc_configuration_secure,
			"cloud_waf_implemented": cloud_waf_implemented,
		},
		"monitoring": {
			"network_traffic_monitoring": network_traffic_monitoring,
			"network_access_logging": network_access_logging,
			"network_security_correlation": network_security_correlation,
		},
		"overall_score": pci_requirement_1_score,
		"overall_compliant": pci_requirement_1_compliant,
	}
}

# BEGIN evidence_spec (generated by scripts/gen_pci_dss_evidence_spec.py; do not edit by hand)
# The facts each check that gates pci_requirement_1_compliant reads, for pci_dss.main: a failing check is
# "evidence missing" when no alternative holds a present, non-compliant fact and some fact is absent or of
# the wrong type. Term tests are described in the generator's docstring.
evidence_spec := {
	"network_security_policies_established": {
		"passed": network_security_policies_established,
		"alternatives": [
			[["pci.network_security.policies.documented", "true"], ["pci.network_security.policies.approved", "true"], ["pci.network_security.policies.current", "true"]],
		],
	},
	"network_security_roles_defined": {
		"passed": network_security_roles_defined,
		"alternatives": [
			[["pci.network_security.roles.defined", "true"], ["pci.network_security.roles.documented", "true"], ["pci.network_security.responsibilities.assigned", "true"], ["pci.network_security.accountability.established", "true"]],
		],
	},
	"network_security_controls_maintained": {
		"passed": network_security_controls_maintained,
		"alternatives": [
			[["pci.network_security.maintenance.scheduled", "true"], ["pci.network_security.maintenance.documented", "true"], ["pci.network_security.change_management.implemented", "true"], ["pci.network_security.review_process.established", "true"]],
		],
	},
	"firewall_configuration_standards": {
		"passed": firewall_configuration_standards,
		"alternatives": [
			[["pci.firewalls.configuration_standards.documented", "true"], ["pci.firewalls.configuration_standards.approved", "true"], ["pci.firewalls.configuration_standards.implemented", "true"], ["pci.firewalls.default_deny.configured", "true"]],
		],
	},
	"firewall_rules_documented": {
		"passed": firewall_rules_documented,
		"alternatives": [
			[["pci.firewalls.rules.documented", "true"], ["pci.firewalls.rules.business_justification", "true"], ["pci.firewalls.rules.reviewed_regularly", "true"], ["pci.firewalls.rules.approved_before_implementation", "true"]],
		],
	},
	"network_connections_controlled": {
		"passed": network_connections_controlled,
		"alternatives": [
			[["pci.network.trusted_untrusted.identified", "true"], ["pci.network.trusted_untrusted.controlled", "true"], ["pci.network.connections.documented", "true"], ["pci.network.connections.justified", "true"]],
		],
	},
	"inbound_traffic_restricted": {
		"passed": inbound_traffic_restricted,
		"alternatives": [
			[["pci.cde.inbound_traffic.restricted", "true"], ["pci.cde.inbound_traffic.necessary_only", "true"], ["pci.cde.inbound_traffic.documented", "true"], ["pci.cde.inbound_traffic.authorized", "true"]],
		],
	},
	"outbound_traffic_restricted": {
		"passed": outbound_traffic_restricted,
		"alternatives": [
			[["pci.cde.outbound_traffic.restricted", "true"], ["pci.cde.outbound_traffic.necessary_only", "true"], ["pci.cde.outbound_traffic.documented", "true"], ["pci.cde.outbound_traffic.authorized", "true"]],
		],
	},
	"direct_internet_access_prohibited": {
		"passed": direct_internet_access_prohibited,
		"alternatives": [
			[["pci.cde.direct_internet_access.prohibited", "true"], ["pci.cde.dmz.implemented", "true"], ["pci.cde.proxy_services.configured", "true"], ["pci.cde.internet_isolation.enforced", "true"]],
		],
	},
	"network_segmentation_implemented": {
		"passed": network_segmentation_implemented,
		"alternatives": [
			[["pci.network_segmentation.implemented", "true"], ["pci.network_segmentation.cde_isolated", "true"], ["pci.network_segmentation.documented", "true"], ["pci.network_segmentation.validated", "true"]],
		],
	},
	"dmz_properly_configured": {
		"passed": dmz_properly_configured,
		"alternatives": [
			[["pci.dmz.implemented", "true"], ["pci.dmz.separates_untrusted_from_cde", "true"], ["pci.dmz.controls_traffic_flow", "true"], ["pci.dmz.monitored", "true"]],
		],
	},
	"nat_implemented": {
		"passed": nat_implemented,
		"alternatives": [
			[["pci.network.nat.implemented", "true"], ["pci.network.nat.hides_internal_addresses", "true"], ["pci.network.nat.documented", "true"], ["pci.network.nat.configured_securely", "true"]],
		],
	},
	"multi_tenant_isolation": {
		"passed": multi_tenant_isolation,
		"alternatives": [
			[["pci.multi_tenant.applicable", "false"]],
			[["pci.multi_tenant.applicable", "true"], ["pci.multi_tenant.each_entity_isolated", "true"], ["pci.multi_tenant.cannot_access_others", "true"], ["pci.multi_tenant.documented", "true"]],
		],
	},
	"openshift_network_policies_cde": {
		"passed": openshift_network_policies_cde,
		"alternatives": [
			[["openshift.network_policies.cde_isolation.enabled", "true"], ["openshift.network_policies.default_deny.configured", "true"], ["openshift.network_policies.ingress_rules.restrictive", "true"], ["openshift.network_policies.egress_rules.restrictive", "true"]],
		],
	},
	"service_mesh_pci_security": {
		"passed": service_mesh_pci_security,
		"alternatives": [
			[["openshift.service_mesh.enabled", "true"], ["openshift.service_mesh.mutual_tls.enforced", "true"], ["openshift.service_mesh.traffic_policies.pci_compliant", "true"], ["openshift.service_mesh.access_control.implemented", "true"]],
		],
	},
	"container_network_isolation": {
		"passed": container_network_isolation,
		"alternatives": [
			[["openshift.containers.network_isolation.enabled", "true"], ["openshift.containers.pod_security.network_restricted", "true"], ["openshift.containers.namespace_isolation.cde_separated", "true"]],
		],
	},
	"openshift_sdn_security": {
		"passed": openshift_sdn_security,
		"alternatives": [
			[["openshift.sdn.network_policy.enabled", "true"], ["openshift.sdn.multitenant.configured", "true"], ["openshift.sdn.subnet_isolation.enabled", "true"], ["openshift.sdn.ingress_controllers.secured", "true"]],
		],
	},
	"cloud_security_groups_configured": {
		"passed": cloud_security_groups_configured,
		"alternatives": [
			[["cloud.security_groups.cde_specific", "true"], ["cloud.security_groups.least_privilege", "true"], ["cloud.security_groups.regularly_reviewed", "true"], ["cloud.security_groups.documented", "true"]],
		],
	},
	"vpc_configuration_secure": {
		"passed": vpc_configuration_secure,
		"alternatives": [
			[["cloud.vpc.cde_dedicated", "true"], ["cloud.vpc.private_subnets.cde_isolated", "true"], ["cloud.vpc.nat_gateways.configured", "true"], ["cloud.vpc.flow_logs.enabled", "true"]],
		],
	},
	"cloud_waf_implemented": {
		"passed": cloud_waf_implemented,
		"alternatives": [
			[["cloud.waf.enabled", "true"], ["cloud.waf.rules.pci_specific", "true"], ["cloud.waf.logging.comprehensive", "true"], ["cloud.waf.monitoring.real_time", "true"]],
		],
	},
	"network_traffic_monitoring": {
		"passed": network_traffic_monitoring,
		"alternatives": [
			[["pci.network_monitoring.traffic_analysis.enabled", "true"], ["pci.network_monitoring.intrusion_detection.deployed", "true"], ["pci.network_monitoring.anomaly_detection.configured", "true"], ["pci.network_monitoring.real_time_alerts.enabled", "true"]],
		],
	},
	"network_access_logging": {
		"passed": network_access_logging,
		"alternatives": [
			[["pci.network_logging.firewall_logs.comprehensive", "true"], ["pci.network_logging.access_attempts.logged", "true"], ["pci.network_logging.denied_connections.logged", "true"], ["pci.network_logging.centralized.implemented", "true"]],
		],
	},
	"network_security_correlation": {
		"passed": network_security_correlation,
		"alternatives": [
			[["pci.network_security.event_correlation.enabled", "true"], ["pci.network_security.siem_integration.configured", "true"], ["pci.network_security.threat_detection.automated", "true"], ["pci.network_security.incident_response.integrated", "true"]],
		],
	},
}

# END evidence_spec
