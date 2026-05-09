package csa_ccm.infrastructure

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.infrastructure.network_segmentation.segmentation_implemented
    msg := "IVS-01: Network segmentation not implemented — production, development, and sensitive workloads must be isolated"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_segmentation.micro_segmentation_applied
    msg := "IVS-01: Micro-segmentation not applied to cloud virtual networks — workloads must be isolated at the subnet or security group level"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_segmentation.dmz_implemented
    msg := "IVS-01: DMZ or equivalent perimeter isolation not implemented for internet-facing cloud services"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_segmentation.segmentation_validated
    msg := "IVS-01: Network segmentation effectiveness not validated through testing or verification"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.hypervisor.hypervisor_hardened
    msg := "IVS-02: Hypervisor not hardened — virtualization layer must be configured per security hardening standards"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.hypervisor.hypervisor_patched_regularly
    msg := "IVS-02: Hypervisor and virtualization platform not patched on defined schedule to address known vulnerabilities"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.hypervisor.hypervisor_access_restricted
    msg := "IVS-02: Administrative access to hypervisor not restricted to authorized personnel only"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vm_isolation.vm_isolation_enforced
    msg := "IVS-03: Virtual machine isolation not enforced — guest VMs must be prevented from accessing other VMs or host resources"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vm_isolation.vm_breakout_controls_implemented
    msg := "IVS-03: VM escape/breakout controls not implemented — hypervisor-level protections must prevent VM escapes"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vm_isolation.multi_tenant_isolation_verified
    msg := "IVS-03: Multi-tenant isolation not verified — cloud provider tenant isolation controls must be validated"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_security_groups.security_groups_configured
    msg := "IVS-04: Cloud network security groups not configured — all cloud resources must have explicit ingress and egress rules"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_security_groups.default_deny_implemented
    msg := "IVS-04: Default-deny posture not implemented — network security groups must deny all traffic not explicitly permitted"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_security_groups.overly_permissive_rules_detected
    msg := "IVS-04: Overly permissive security group rules (0.0.0.0/0 on sensitive ports) not detected and remediated"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_security_groups.security_group_review_conducted
    msg := "IVS-04: Security group rules not reviewed regularly for necessity and least-privilege compliance"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.container_security.container_images_scanned
    msg := "IVS-05: Container images not scanned for vulnerabilities before deployment"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.container_security.trusted_registries_enforced
    msg := "IVS-05: Container images not restricted to trusted registries — image pull from public untrusted sources must be blocked"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.container_security.containers_run_as_non_root
    msg := "IVS-05: Containers not enforced to run as non-root user — privileged container execution must be prevented"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.container_security.runtime_security_monitoring
    msg := "IVS-05: Container runtime security monitoring not implemented — anomalous container behavior must be detected"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.container_security.image_signing_enforced
    msg := "IVS-05: Container image signing not enforced — only signed images from authorized sources should be deployed"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.workload_protection.workload_protection_deployed
    msg := "IVS-06: Workload protection solution not deployed — cloud workloads must be protected against malware and threats"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.workload_protection.cloud_security_posture_managed
    msg := "IVS-06: Cloud security posture management (CSPM) not implemented to detect cloud misconfiguration"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.workload_protection.cloud_workload_protection_active
    msg := "IVS-06: Cloud workload protection platform (CWPP) not active on production cloud workloads"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vulnerability_scanning.infrastructure_scanned
    msg := "IVS-07: Infrastructure vulnerability scanning not performed on cloud hosts and network components"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vulnerability_scanning.scan_frequency_defined
    msg := "IVS-07: Infrastructure scanning frequency not defined — scan cadence must be documented and enforced"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vulnerability_scanning.findings_tracked_to_remediation
    msg := "IVS-07: Infrastructure vulnerability scan findings not tracked to remediation with defined SLAs"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.vulnerability_scanning.authenticated_scans_used
    msg := "IVS-07: Authenticated vulnerability scans not used — unauthenticated scans miss significant vulnerability classes"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.host_hardening.hardening_standards_applied
    msg := "IVS-08: Host hardening standards not applied to cloud virtual machine instances"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.host_hardening.cis_benchmark_or_stig_followed
    msg := "IVS-08: CIS Benchmark or DISA STIG not followed for cloud host hardening configuration"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.host_hardening.hardening_compliance_verified
    msg := "IVS-08: Hardening compliance not verified after provisioning — drift from baseline must be detected"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_monitoring.network_traffic_monitored
    msg := "IVS-09: Cloud network traffic not monitored for anomalous or malicious activity"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_monitoring.flow_logs_enabled
    msg := "IVS-09: Cloud network flow logs not enabled — VPC/VNet flow logs must be collected for security analysis"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.network_monitoring.ids_ips_deployed
    msg := "IVS-09: Intrusion detection or prevention system not deployed to monitor cloud network traffic"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.patch_management.infrastructure_patches_applied
    msg := "IVS-10: Infrastructure patching not enforced — cloud hosts and network components must be patched on defined schedule"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.patch_management.critical_patches_applied_timely
    msg := "IVS-10: Critical infrastructure patches not applied within required timeframe (≤15 days for critical severity)"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.patch_management.patch_compliance_monitored
    msg := "IVS-10: Infrastructure patch compliance not monitored — unpatched systems must be identified and reported"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.resource_management.unused_resources_identified
    msg := "IVS-11: Unused cloud resources not identified — orphaned instances, storage, and access keys create unnecessary attack surface"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.resource_management.resource_inventory_maintained
    msg := "IVS-11: Cloud resource inventory not maintained — all provisioned cloud assets must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.infrastructure.resource_management.resource_tagging_enforced
    msg := "IVS-11: Resource tagging not enforced — cloud resources must be tagged with owner, environment, and classification"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "IVS — Infrastructure & Virtualization Security",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
