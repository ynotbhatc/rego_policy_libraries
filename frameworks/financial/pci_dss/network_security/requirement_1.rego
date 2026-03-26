# PCI DSS Requirement 1 - Install and Maintain Network Security Controls
# Network security controls for cardholder data environment (CDE)

package pci_dss.network_security.requirement_1

import rego.v1

# =================================================================
# 1.1 - Processes and mechanisms for installing and maintaining network security controls
# =================================================================

# Network security policies and procedures are established
network_security_policies_established if {
    input.pci.network_security.policies.documented == true
    input.pci.network_security.policies.approved == true
    input.pci.network_security.policies.current == true
    input.pci.network_security.policies.reviewed_annually == true
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
multi_tenant_isolation if {
    input.pci.multi_tenant.applicable == false
    # OR if applicable:
    # input.pci.multi_tenant.each_entity_isolated == true
    # input.pci.multi_tenant.cannot_access_others == true
    # input.pci.multi_tenant.documented == true
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
        network_security_correlation
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
            "network_security_controls_maintained": network_security_controls_maintained
        },
        "requirement_1_2": {
            "firewall_configuration_standards": firewall_configuration_standards,
            "firewall_rules_documented": firewall_rules_documented,
            "network_connections_controlled": network_connections_controlled
        },
        "requirement_1_3": {
            "inbound_traffic_restricted": inbound_traffic_restricted,
            "outbound_traffic_restricted": outbound_traffic_restricted,
            "direct_internet_access_prohibited": direct_internet_access_prohibited
        },
        "requirement_1_4": {
            "network_segmentation_implemented": network_segmentation_implemented,
            "dmz_properly_configured": dmz_properly_configured,
            "nat_implemented": nat_implemented
        },
        "requirement_1_5": {
            "multi_tenant_isolation": multi_tenant_isolation
        },
        "openshift_controls": {
            "openshift_network_policies_cde": openshift_network_policies_cde,
            "service_mesh_pci_security": service_mesh_pci_security,
            "container_network_isolation": container_network_isolation,
            "openshift_sdn_security": openshift_sdn_security
        },
        "cloud_controls": {
            "cloud_security_groups_configured": cloud_security_groups_configured,
            "vpc_configuration_secure": vpc_configuration_secure,
            "cloud_waf_implemented": cloud_waf_implemented
        },
        "monitoring": {
            "network_traffic_monitoring": network_traffic_monitoring,
            "network_access_logging": network_access_logging,
            "network_security_correlation": network_security_correlation
        },
        "overall_score": pci_requirement_1_score,
        "overall_compliant": pci_requirement_1_compliant
    }
}