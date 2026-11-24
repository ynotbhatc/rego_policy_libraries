# METADATA
# title: "Csa Ccm Infrastructure"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 38
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.infrastructure

import rego.v1

default compliant := false

_base := ["csa_ccm", "infrastructure"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("IVS-01: Network segmentation not implemented — production, development, and sensitive workloads must be isolated", ["network_segmentation", "segmentation_implemented"])
}

violations contains msg if {
	msg := _finding("IVS-01: Micro-segmentation not applied to cloud virtual networks — workloads must be isolated at the subnet or security group level", ["network_segmentation", "micro_segmentation_applied"])
}

violations contains msg if {
	msg := _finding("IVS-01: DMZ or equivalent perimeter isolation not implemented for internet-facing cloud services", ["network_segmentation", "dmz_implemented"])
}

violations contains msg if {
	msg := _finding("IVS-01: Network segmentation effectiveness not validated through testing or verification", ["network_segmentation", "segmentation_validated"])
}

violations contains msg if {
	msg := _finding("IVS-02: Hypervisor not hardened — virtualization layer must be configured per security hardening standards", ["hypervisor", "hypervisor_hardened"])
}

violations contains msg if {
	msg := _finding("IVS-02: Hypervisor and virtualization platform not patched on defined schedule to address known vulnerabilities", ["hypervisor", "hypervisor_patched_regularly"])
}

violations contains msg if {
	msg := _finding("IVS-02: Administrative access to hypervisor not restricted to authorized personnel only", ["hypervisor", "hypervisor_access_restricted"])
}

violations contains msg if {
	msg := _finding("IVS-03: Virtual machine isolation not enforced — guest VMs must be prevented from accessing other VMs or host resources", ["vm_isolation", "vm_isolation_enforced"])
}

violations contains msg if {
	msg := _finding("IVS-03: VM escape/breakout controls not implemented — hypervisor-level protections must prevent VM escapes", ["vm_isolation", "vm_breakout_controls_implemented"])
}

violations contains msg if {
	msg := _finding("IVS-03: Multi-tenant isolation not verified — cloud provider tenant isolation controls must be validated", ["vm_isolation", "multi_tenant_isolation_verified"])
}

violations contains msg if {
	msg := _finding("IVS-04: Cloud network security groups not configured — all cloud resources must have explicit ingress and egress rules", ["network_security_groups", "security_groups_configured"])
}

violations contains msg if {
	msg := _finding("IVS-04: Default-deny posture not implemented — network security groups must deny all traffic not explicitly permitted", ["network_security_groups", "default_deny_implemented"])
}

violations contains msg if {
	msg := _finding("IVS-04: Overly permissive security group rules (0.0.0.0/0 on sensitive ports) not detected and remediated", ["network_security_groups", "overly_permissive_rules_detected"])
}

violations contains msg if {
	msg := _finding("IVS-04: Security group rules not reviewed regularly for necessity and least-privilege compliance", ["network_security_groups", "security_group_review_conducted"])
}

violations contains msg if {
	msg := _finding("IVS-05: Container images not scanned for vulnerabilities before deployment", ["container_security", "container_images_scanned"])
}

violations contains msg if {
	msg := _finding("IVS-05: Container images not restricted to trusted registries — image pull from public untrusted sources must be blocked", ["container_security", "trusted_registries_enforced"])
}

violations contains msg if {
	msg := _finding("IVS-05: Containers not enforced to run as non-root user — privileged container execution must be prevented", ["container_security", "containers_run_as_non_root"])
}

violations contains msg if {
	msg := _finding("IVS-05: Container runtime security monitoring not implemented — anomalous container behavior must be detected", ["container_security", "runtime_security_monitoring"])
}

violations contains msg if {
	msg := _finding("IVS-05: Container image signing not enforced — only signed images from authorized sources should be deployed", ["container_security", "image_signing_enforced"])
}

violations contains msg if {
	msg := _finding("IVS-06: Workload protection solution not deployed — cloud workloads must be protected against malware and threats", ["workload_protection", "workload_protection_deployed"])
}

violations contains msg if {
	msg := _finding("IVS-06: Cloud security posture management (CSPM) not implemented to detect cloud misconfiguration", ["workload_protection", "cloud_security_posture_managed"])
}

violations contains msg if {
	msg := _finding("IVS-06: Cloud workload protection platform (CWPP) not active on production cloud workloads", ["workload_protection", "cloud_workload_protection_active"])
}

violations contains msg if {
	msg := _finding("IVS-07: Infrastructure vulnerability scanning not performed on cloud hosts and network components", ["vulnerability_scanning", "infrastructure_scanned"])
}

violations contains msg if {
	msg := _finding("IVS-07: Infrastructure scanning frequency not defined — scan cadence must be documented and enforced", ["vulnerability_scanning", "scan_frequency_defined"])
}

violations contains msg if {
	msg := _finding("IVS-07: Infrastructure vulnerability scan findings not tracked to remediation with defined SLAs", ["vulnerability_scanning", "findings_tracked_to_remediation"])
}

violations contains msg if {
	msg := _finding("IVS-07: Authenticated vulnerability scans not used — unauthenticated scans miss significant vulnerability classes", ["vulnerability_scanning", "authenticated_scans_used"])
}

violations contains msg if {
	msg := _finding("IVS-08: Host hardening standards not applied to cloud virtual machine instances", ["host_hardening", "hardening_standards_applied"])
}

violations contains msg if {
	msg := _finding("IVS-08: CIS Benchmark or DISA STIG not followed for cloud host hardening configuration", ["host_hardening", "cis_benchmark_or_stig_followed"])
}

violations contains msg if {
	msg := _finding("IVS-08: Hardening compliance not verified after provisioning — drift from baseline must be detected", ["host_hardening", "hardening_compliance_verified"])
}

violations contains msg if {
	msg := _finding("IVS-09: Cloud network traffic not monitored for anomalous or malicious activity", ["network_monitoring", "network_traffic_monitored"])
}

violations contains msg if {
	msg := _finding("IVS-09: Cloud network flow logs not enabled — VPC/VNet flow logs must be collected for security analysis", ["network_monitoring", "flow_logs_enabled"])
}

violations contains msg if {
	msg := _finding("IVS-09: Intrusion detection or prevention system not deployed to monitor cloud network traffic", ["network_monitoring", "ids_ips_deployed"])
}

violations contains msg if {
	msg := _finding("IVS-10: Infrastructure patching not enforced — cloud hosts and network components must be patched on defined schedule", ["patch_management", "infrastructure_patches_applied"])
}

violations contains msg if {
	msg := _finding("IVS-10: Critical infrastructure patches not applied within required timeframe (≤15 days for critical severity)", ["patch_management", "critical_patches_applied_timely"])
}

violations contains msg if {
	msg := _finding("IVS-10: Infrastructure patch compliance not monitored — unpatched systems must be identified and reported", ["patch_management", "patch_compliance_monitored"])
}

violations contains msg if {
	msg := _finding("IVS-11: Unused cloud resources not identified — orphaned instances, storage, and access keys create unnecessary attack surface", ["resource_management", "unused_resources_identified"])
}

violations contains msg if {
	msg := _finding("IVS-11: Cloud resource inventory not maintained — all provisioned cloud assets must be catalogued", ["resource_management", "resource_inventory_maintained"])
}

violations contains msg if {
	msg := _finding("IVS-11: Resource tagging not enforced — cloud resources must be tagged with owner, environment, and classification", ["resource_management", "resource_tagging_enforced"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["IVS-01", "IVS-02", "IVS-03", "IVS-04", "IVS-05", "IVS-06", "IVS-07", "IVS-08", "IVS-09", "IVS-10", "IVS-11"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "IVS — Infrastructure & Virtualization Security",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 38,
	"violation_count": count(violations),
	"violations": violations,
}
