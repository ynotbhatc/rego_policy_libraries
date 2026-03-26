# SOC 2 Infrastructure - Network Security and Architecture
# Comprehensive network infrastructure controls for SOC 2 compliance

package soc2.infrastructure.network

import rego.v1

# =================================================================
# NETWORK ARCHITECTURE AND DESIGN
# =================================================================

# Network segmentation is properly implemented
network_segmentation_compliant if {
    input.network.architecture.segmentation.enabled == true
    input.network.architecture.segmentation.dmz.configured == true
    input.network.architecture.segmentation.internal_zones.count >= 3
    input.network.architecture.segmentation.zero_trust.enabled == true
}

# Network topology is documented and managed
network_topology_managed if {
    input.network.topology.documentation.current == true
    input.network.topology.documentation.detailed == true
    input.network.topology.change_management.required == true
    input.network.topology.reviews.periodic == true
}

# Redundancy and high availability
network_redundancy_implemented if {
    input.network.redundancy.multiple_paths.enabled == true
    input.network.redundancy.failover.automatic == true
    input.network.redundancy.load_balancing.configured == true
    input.network.redundancy.geographic_distribution.enabled == true
}

# =================================================================
# FIREWALL AND PERIMETER SECURITY
# =================================================================

# Firewall configuration and management
firewall_controls_compliant if {
    input.network.firewalls.perimeter.configured == true
    input.network.firewalls.internal.configured == true
    input.network.firewalls.rules.default_deny == true
    input.network.firewalls.rules.regular_review == true
    input.network.firewalls.logging.enabled == true
}

# Next-generation firewall capabilities
ngfw_capabilities_enabled if {
    input.network.firewalls.ngfw.deep_packet_inspection == true
    input.network.firewalls.ngfw.application_control == true
    input.network.firewalls.ngfw.intrusion_prevention == true
    input.network.firewalls.ngfw.threat_intelligence == true
}

# Web application firewall (WAF)
waf_protection_implemented if {
    input.network.waf.enabled == true
    input.network.waf.rules.owasp_top10 == true
    input.network.waf.rules.custom_rules.configured == true
    input.network.waf.monitoring.real_time == true
    input.network.waf.false_positive_tuning == true
}

# =================================================================
# NETWORK ACCESS CONTROL
# =================================================================

# Network access control (NAC)
network_access_control_implemented if {
    input.network.access_control.nac.enabled == true
    input.network.access_control.device_authentication.required == true
    input.network.access_control.posture_assessment.enabled == true
    input.network.access_control.quarantine.automated == true
}

# 802.1X authentication
dot1x_authentication_enabled if {
    input.network.access_control.dot1x.enabled == true
    input.network.access_control.dot1x.certificate_based == true
    input.network.access_control.dot1x.radius_integration == true
    input.network.access_control.dot1x.dynamic_vlan_assignment == true
}

# Wireless network security
wireless_security_compliant if {
    input.network.wireless.encryption.wpa3_enabled == true
    input.network.wireless.guest_isolation.enabled == true
    input.network.wireless.rogue_ap_detection.enabled == true
    input.network.wireless.certificate_authentication == true
}

# =================================================================
# NETWORK MONITORING AND DETECTION
# =================================================================

# Network monitoring infrastructure
network_monitoring_comprehensive if {
    input.network.monitoring.traffic_analysis.enabled == true
    input.network.monitoring.flow_monitoring.netflow_enabled == true
    input.network.monitoring.packet_capture.strategic_points == true
    input.network.monitoring.performance.continuous == true
}

# Intrusion detection and prevention
network_ids_ips_deployed if {
    input.network.security.ids.network_based.enabled == true
    input.network.security.ids.host_based.enabled == true
    input.network.security.ips.inline_deployment == true
    input.network.security.ips.signature_updates.automatic == true
    input.network.security.ips.custom_rules.configured == true
}

# Security information and event management (SIEM)
network_siem_integration if {
    input.network.monitoring.siem.integration.enabled == true
    input.network.monitoring.siem.log_correlation == true
    input.network.monitoring.siem.real_time_alerting == true
    input.network.monitoring.siem.threat_hunting == true
}

# =================================================================
# NETWORK ENCRYPTION AND VPN
# =================================================================

# Network encryption standards
network_encryption_compliant if {
    input.network.encryption.in_transit.tls_minimum_version >= 1.2
    input.network.encryption.in_transit.perfect_forward_secrecy == true
    input.network.encryption.ipsec.configured == true
    input.network.encryption.macsec.enabled == true
}

# VPN infrastructure and management
vpn_infrastructure_secure if {
    input.network.vpn.multi_factor_authentication.required == true
    input.network.vpn.split_tunneling.disabled == true
    input.network.vpn.encryption.strong_ciphers == true
    input.network.vpn.session_management.timeout_configured == true
    input.network.vpn.logging.detailed == true
}

# Remote access security
remote_access_controls if {
    input.network.remote_access.zero_trust.implemented == true
    input.network.remote_access.conditional_access.enabled == true
    input.network.remote_access.device_compliance.required == true
    input.network.remote_access.session_recording.enabled == true
}

# =================================================================
# CLOUD NETWORK SECURITY
# =================================================================

# Software-defined networking (SDN)
sdn_security_controls if {
    input.network.sdn.controller_security.hardened == true
    input.network.sdn.flow_rules.validated == true
    input.network.sdn.network_policies.enforced == true
    input.network.sdn.micro_segmentation.enabled == true
}

# Container networking security
container_network_security if {
    input.network.containers.network_policies.enabled == true
    input.network.containers.service_mesh.security.enabled == true
    input.network.containers.ingress_controls.configured == true
    input.network.containers.egress_filtering.enabled == true
}

# Multi-cloud networking
multi_cloud_network_security if {
    input.network.multi_cloud.consistent_policies == true
    input.network.multi_cloud.encrypted_interconnects == true
    input.network.multi_cloud.centralized_management == true
    input.network.multi_cloud.security_orchestration == true
}

# =================================================================
# NETWORK INCIDENT RESPONSE
# =================================================================

# Network incident detection and response
network_incident_response if {
    input.network.incident_response.detection.automated == true
    input.network.incident_response.isolation.automated == true
    input.network.incident_response.forensics.packet_capture == true
    input.network.incident_response.communication.defined == true
}

# Distributed Denial of Service (DDoS) protection
ddos_protection_implemented if {
    input.network.ddos_protection.detection.enabled == true
    input.network.ddos_protection.mitigation.automatic == true
    input.network.ddos_protection.cloud_based.enabled == true
    input.network.ddos_protection.capacity.sufficient == true
}

# Network forensics capabilities
network_forensics_ready if {
    input.network.forensics.packet_capture.continuous == true
    input.network.forensics.flow_analysis.retained == true
    input.network.forensics.timeline_reconstruction == true
    input.network.forensics.legal_compliance == true
}

# =================================================================
# OPENSHIFT/KUBERNETES NETWORK SECURITY
# =================================================================

# OpenShift networking security
openshift_network_security if {
    input.openshift.networking.sdn.security_enabled == true
    input.openshift.networking.network_policies.default_deny == true
    input.openshift.networking.service_mesh.istio.enabled == true
    input.openshift.networking.ingress.rate_limiting == true
}

# Kubernetes network policies
k8s_network_policies_comprehensive if {
    input.kubernetes.network_policies.ingress_rules.restrictive == true
    input.kubernetes.network_policies.egress_rules.defined == true
    input.kubernetes.network_policies.namespace_isolation == true
    input.kubernetes.network_policies.pod_to_pod.controlled == true
}

# Service mesh security
service_mesh_security_controls if {
    input.service_mesh.mutual_tls.enforced == true
    input.service_mesh.traffic_policies.encryption_required == true
    input.service_mesh.access_control.rbac_enabled == true
    input.service_mesh.observability.traffic_monitoring == true
}

# =================================================================
# OVERALL NETWORK INFRASTRUCTURE ASSESSMENT
# =================================================================

network_architecture_compliant if {
    network_segmentation_compliant
    network_topology_managed
    network_redundancy_implemented
}

network_security_compliant if {
    firewall_controls_compliant
    ngfw_capabilities_enabled
    waf_protection_implemented
    network_access_control_implemented
    dot1x_authentication_enabled
    wireless_security_compliant
}

network_monitoring_compliant if {
    network_monitoring_comprehensive
    network_ids_ips_deployed
    network_siem_integration
}

network_encryption_compliant_overall if {
    network_encryption_compliant
    vpn_infrastructure_secure
    remote_access_controls
}

cloud_network_compliant if {
    sdn_security_controls
    container_network_security
    multi_cloud_network_security
}

network_resilience_compliant if {
    network_incident_response
    ddos_protection_implemented
    network_forensics_ready
}

openshift_network_compliant if {
    openshift_network_security
    k8s_network_policies_comprehensive
    service_mesh_security_controls
}

overall_network_infrastructure_compliant if {
    network_architecture_compliant
    network_security_compliant
    network_monitoring_compliant
    network_encryption_compliant_overall
    cloud_network_compliant
    network_resilience_compliant
    openshift_network_compliant
}

# =================================================================
# NETWORK INFRASTRUCTURE SCORE CALCULATION
# =================================================================

network_infrastructure_score := score if {
    controls := [
        network_segmentation_compliant,
        network_topology_managed,
        network_redundancy_implemented,
        firewall_controls_compliant,
        ngfw_capabilities_enabled,
        waf_protection_implemented,
        network_access_control_implemented,
        dot1x_authentication_enabled,
        wireless_security_compliant,
        network_monitoring_comprehensive,
        network_ids_ips_deployed,
        network_siem_integration,
        network_encryption_compliant,
        vpn_infrastructure_secure,
        remote_access_controls,
        sdn_security_controls,
        container_network_security,
        multi_cloud_network_security,
        network_incident_response,
        ddos_protection_implemented,
        network_forensics_ready,
        openshift_network_security,
        k8s_network_policies_comprehensive,
        service_mesh_security_controls
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# DETAILED NETWORK INFRASTRUCTURE FINDINGS
# =================================================================

network_infrastructure_findings := findings if {
    findings := {
        "architecture": {
            "network_segmentation_compliant": network_segmentation_compliant,
            "network_topology_managed": network_topology_managed,
            "network_redundancy_implemented": network_redundancy_implemented
        },
        "security": {
            "firewall_controls_compliant": firewall_controls_compliant,
            "ngfw_capabilities_enabled": ngfw_capabilities_enabled,
            "waf_protection_implemented": waf_protection_implemented,
            "network_access_control_implemented": network_access_control_implemented,
            "dot1x_authentication_enabled": dot1x_authentication_enabled,
            "wireless_security_compliant": wireless_security_compliant
        },
        "monitoring": {
            "network_monitoring_comprehensive": network_monitoring_comprehensive,
            "network_ids_ips_deployed": network_ids_ips_deployed,
            "network_siem_integration": network_siem_integration
        },
        "encryption": {
            "network_encryption_compliant": network_encryption_compliant,
            "vpn_infrastructure_secure": vpn_infrastructure_secure,
            "remote_access_controls": remote_access_controls
        },
        "cloud_native": {
            "sdn_security_controls": sdn_security_controls,
            "container_network_security": container_network_security,
            "multi_cloud_network_security": multi_cloud_network_security
        },
        "resilience": {
            "network_incident_response": network_incident_response,
            "ddos_protection_implemented": ddos_protection_implemented,
            "network_forensics_ready": network_forensics_ready
        },
        "openshift": {
            "openshift_network_security": openshift_network_security,
            "k8s_network_policies_comprehensive": k8s_network_policies_comprehensive,
            "service_mesh_security_controls": service_mesh_security_controls
        },
        "overall_score": network_infrastructure_score
    }
}