package stig.kubernetes.core

# DISA STIG — Kubernetes Security Technical Implementation Guide
# V2R6 | Release: 6 Benchmark Date: 01 Apr 2026
# 23 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Input contract: see gen_k8s.py header / tests fixture.

import rego.v1

# CNTR-K8-000160 | V-242377 | CAT II
default r_cntr_k8_000160 := false
r_cntr_k8_000160 if {
	input.scheduler.flags["tls-min-version"] in {"VersionTLS12", "VersionTLS13"}
}

finding_r_cntr_k8_000160 := {
	"vuln_id": "V-242377",
	"stig_id": "CNTR-K8-000160",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
	"status": status_r_cntr_k8_000160,
}
status_r_cntr_k8_000160 := "Not_a_Finding" if r_cntr_k8_000160
status_r_cntr_k8_000160 := "Open" if not r_cntr_k8_000160

# CNTR-K8-000170 | V-242378 | CAT II
default r_cntr_k8_000170 := false
r_cntr_k8_000170 if {
	input.api_server.flags["tls-min-version"] in {"VersionTLS12", "VersionTLS13"}
}

finding_r_cntr_k8_000170 := {
	"vuln_id": "V-242378",
	"stig_id": "CNTR-K8-000170",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
	"status": status_r_cntr_k8_000170,
}
status_r_cntr_k8_000170 := "Not_a_Finding" if r_cntr_k8_000170
status_r_cntr_k8_000170 := "Open" if not r_cntr_k8_000170

# CNTR-K8-000220 | V-242381 | CAT I
default r_cntr_k8_000220 := false
r_cntr_k8_000220 if {
	input.controller_manager.flags["use-service-account-credentials"] == "true"
}

finding_r_cntr_k8_000220 := {
	"vuln_id": "V-242381",
	"stig_id": "CNTR-K8-000220",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Controller Manager must create unique service accounts for each work payload.",
	"status": status_r_cntr_k8_000220,
}
status_r_cntr_k8_000220 := "Not_a_Finding" if r_cntr_k8_000220
status_r_cntr_k8_000220 := "Open" if not r_cntr_k8_000220

# CNTR-K8-000290 | V-242383 | CAT I
default r_cntr_k8_000290 := false
r_cntr_k8_000290 if {
	input.namespaces.user_resources_in_dedicated == true
}

finding_r_cntr_k8_000290 := {
	"vuln_id": "V-242383",
	"stig_id": "CNTR-K8-000290",
	"severity": "CAT I",
	"rule_title": "User-managed resources must be created in dedicated namespaces.",
	"status": status_r_cntr_k8_000290,
}
status_r_cntr_k8_000290 := "Not_a_Finding" if r_cntr_k8_000290
status_r_cntr_k8_000290 := "Open" if not r_cntr_k8_000290

# CNTR-K8-000330 | V-242387 | CAT I
default r_cntr_k8_000330 := false
r_cntr_k8_000330 if {
	input.kubelet.config.readOnlyPort == 0
}

finding_r_cntr_k8_000330 := {
	"vuln_id": "V-242387",
	"stig_id": "CNTR-K8-000330",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Kubelet must have the \"readOnlyPort\" flag disabled.",
	"status": status_r_cntr_k8_000330,
}
status_r_cntr_k8_000330 := "Not_a_Finding" if r_cntr_k8_000330
status_r_cntr_k8_000330 := "Open" if not r_cntr_k8_000330

# CNTR-K8-000360 | V-242390 | CAT I
default r_cntr_k8_000360 := false
r_cntr_k8_000360 if {
	input.api_server.flags["anonymous-auth"] == "false"
}

finding_r_cntr_k8_000360 := {
	"vuln_id": "V-242390",
	"stig_id": "CNTR-K8-000360",
	"severity": "CAT I",
	"rule_title": "The Kubernetes API server must have anonymous authentication disabled.",
	"status": status_r_cntr_k8_000360,
}
status_r_cntr_k8_000360 := "Not_a_Finding" if r_cntr_k8_000360
status_r_cntr_k8_000360 := "Open" if not r_cntr_k8_000360

# CNTR-K8-000370 | V-242391 | CAT I
default r_cntr_k8_000370 := false
r_cntr_k8_000370 if {
	input.kubelet.config.authentication_anonymous_enabled == false
}

finding_r_cntr_k8_000370 := {
	"vuln_id": "V-242391",
	"stig_id": "CNTR-K8-000370",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Kubelet must have anonymous authentication disabled.",
	"status": status_r_cntr_k8_000370,
}
status_r_cntr_k8_000370 := "Not_a_Finding" if r_cntr_k8_000370
status_r_cntr_k8_000370 := "Open" if not r_cntr_k8_000370

# CNTR-K8-000380 | V-242392 | CAT I
default r_cntr_k8_000380 := false
r_cntr_k8_000380 if {
	input.kubelet.config.authorization_mode == "Webhook"
}

finding_r_cntr_k8_000380 := {
	"vuln_id": "V-242392",
	"stig_id": "CNTR-K8-000380",
	"severity": "CAT I",
	"rule_title": "The Kubernetes kubelet must enable explicit authorization.",
	"status": status_r_cntr_k8_000380,
}
status_r_cntr_k8_000380 := "Not_a_Finding" if r_cntr_k8_000380
status_r_cntr_k8_000380 := "Open" if not r_cntr_k8_000380

# CNTR-K8-000440 | V-242397 | CAT I
default r_cntr_k8_000440 := false
r_cntr_k8_000440 if {
	not input.kubelet.config.staticPodPath
}

finding_r_cntr_k8_000440 := {
	"vuln_id": "V-242397",
	"stig_id": "CNTR-K8-000440",
	"severity": "CAT I",
	"rule_title": "The Kubernetes kubelet staticPodPath must not enable static pods.",
	"status": status_r_cntr_k8_000440,
}
status_r_cntr_k8_000440 := "Not_a_Finding" if r_cntr_k8_000440
status_r_cntr_k8_000440 := "Open" if not r_cntr_k8_000440

# CNTR-K8-000850 | V-242404 | CAT II
default r_cntr_k8_000850 := false
r_cntr_k8_000850 if {
	not input.kubelet.flags["hostname-override"]
}

finding_r_cntr_k8_000850 := {
	"vuln_id": "V-242404",
	"stig_id": "CNTR-K8-000850",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must deny hostname override.",
	"status": status_r_cntr_k8_000850,
}
status_r_cntr_k8_000850 := "Not_a_Finding" if r_cntr_k8_000850
status_r_cntr_k8_000850 := "Open" if not r_cntr_k8_000850

# CNTR-K8-001160 | V-242415 | CAT I
default r_cntr_k8_001160 := false
r_cntr_k8_001160 if {
	input.secrets.env_var_usage_count == 0
}

finding_r_cntr_k8_001160 := {
	"vuln_id": "V-242415",
	"stig_id": "CNTR-K8-001160",
	"severity": "CAT I",
	"rule_title": "Secrets in Kubernetes must not be stored as environment variables.",
	"status": status_r_cntr_k8_001160,
}
status_r_cntr_k8_001160 := "Not_a_Finding" if r_cntr_k8_001160
status_r_cntr_k8_001160 := "Open" if not r_cntr_k8_001160

# CNTR-K8-001161 | V-274883 | CAT I
default r_cntr_k8_001161 := false
r_cntr_k8_001161 if {
	input.secrets.sensitive_data_in_secrets_only == true
}

finding_r_cntr_k8_001161 := {
	"vuln_id": "V-274883",
	"stig_id": "CNTR-K8-001161",
	"severity": "CAT I",
	"rule_title": "Sensitive information must be stored using Kubernetes Secrets or an external Secret store provider.",
	"status": status_r_cntr_k8_001161,
}
status_r_cntr_k8_001161 := "Not_a_Finding" if r_cntr_k8_001161
status_r_cntr_k8_001161 := "Open" if not r_cntr_k8_001161

# CNTR-K8-001162 | V-274882 | CAT I
default r_cntr_k8_001162 := false
r_cntr_k8_001162 if {
	input.etcd.encryption_provider_configured == true
}

finding_r_cntr_k8_001162 := {
	"vuln_id": "V-274882",
	"stig_id": "CNTR-K8-001162",
	"severity": "CAT I",
	"rule_title": "Kubernetes Secrets must be encrypted at rest.",
	"status": status_r_cntr_k8_001162,
}
status_r_cntr_k8_001162 := "Not_a_Finding" if r_cntr_k8_001162
status_r_cntr_k8_001162 := "Open" if not r_cntr_k8_001162

# CNTR-K8-001480 | V-242426 | CAT II
default r_cntr_k8_001480 := false
r_cntr_k8_001480 if {
	input.etcd.flags["peer-client-cert-auth"] == "true"
}

finding_r_cntr_k8_001480 := {
	"vuln_id": "V-242426",
	"stig_id": "CNTR-K8-001480",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must enable client authentication to secure service.",
	"status": status_r_cntr_k8_001480,
}
status_r_cntr_k8_001480 := "Not_a_Finding" if r_cntr_k8_001480
status_r_cntr_k8_001480 := "Open" if not r_cntr_k8_001480

# CNTR-K8-001620 | V-242434 | CAT I
default r_cntr_k8_001620 := false
r_cntr_k8_001620 if {
	input.kubelet.config.protectKernelDefaults == true
}

finding_r_cntr_k8_001620 := {
	"vuln_id": "V-242434",
	"stig_id": "CNTR-K8-001620",
	"severity": "CAT I",
	"rule_title": "Kubernetes Kubelet must enable kernel protection.",
	"status": status_r_cntr_k8_001620,
}
status_r_cntr_k8_001620 := "Not_a_Finding" if r_cntr_k8_001620
status_r_cntr_k8_001620 := "Open" if not r_cntr_k8_001620

# CNTR-K8-002000 | V-242436 | CAT I
default r_cntr_k8_002000 := false
r_cntr_k8_002000 if {
	"ValidatingAdmissionWebhook" in input.api_server.admission_plugins
}

finding_r_cntr_k8_002000 := {
	"vuln_id": "V-242436",
	"stig_id": "CNTR-K8-002000",
	"severity": "CAT I",
	"rule_title": "The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.",
	"status": status_r_cntr_k8_002000,
}
status_r_cntr_k8_002000 := "Not_a_Finding" if r_cntr_k8_002000
status_r_cntr_k8_002000 := "Open" if not r_cntr_k8_002000

# CNTR-K8-002001 | V-254801 | CAT I
default r_cntr_k8_002001 := false
r_cntr_k8_002001 if {
	"PodSecurity" in input.api_server.admission_plugins
}

finding_r_cntr_k8_002001 := {
	"vuln_id": "V-254801",
	"stig_id": "CNTR-K8-002001",
	"severity": "CAT I",
	"rule_title": "Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.",
	"status": status_r_cntr_k8_002001,
}
status_r_cntr_k8_002001 := "Not_a_Finding" if r_cntr_k8_002001
status_r_cntr_k8_002001 := "Open" if not r_cntr_k8_002001

# CNTR-K8-002010 | V-242437 | CAT I
default r_cntr_k8_002010 := false
r_cntr_k8_002010 if {
	input.pod_security.policy_enforced == true
}

finding_r_cntr_k8_002010 := {
	"vuln_id": "V-242437",
	"stig_id": "CNTR-K8-002010",
	"severity": "CAT I",
	"rule_title": "Kubernetes must have a pod security policy set.",
	"status": status_r_cntr_k8_002010,
}
status_r_cntr_k8_002010 := "Not_a_Finding" if r_cntr_k8_002010
status_r_cntr_k8_002010 := "Open" if not r_cntr_k8_002010

# CNTR-K8-002011 | V-254800 | CAT I
default r_cntr_k8_002011 := false
r_cntr_k8_002011 if {
	input.pod_security.admission_config_file_set == true
}

finding_r_cntr_k8_002011 := {
	"vuln_id": "V-254800",
	"stig_id": "CNTR-K8-002011",
	"severity": "CAT I",
	"rule_title": "Kubernetes must have a Pod Security Admission control file configured.",
	"status": status_r_cntr_k8_002011,
}
status_r_cntr_k8_002011 := "Not_a_Finding" if r_cntr_k8_002011
status_r_cntr_k8_002011 := "Open" if not r_cntr_k8_002011

# CNTR-K8-002620 | V-245542 | CAT I
default r_cntr_k8_002620 := false
r_cntr_k8_002620 if {
	not input.api_server.flags["basic-auth-file"]
}

finding_r_cntr_k8_002620 := {
	"vuln_id": "V-245542",
	"stig_id": "CNTR-K8-002620",
	"severity": "CAT I",
	"rule_title": "Kubernetes API Server must disable basic authentication to protect information in transit.",
	"status": status_r_cntr_k8_002620,
}
status_r_cntr_k8_002620 := "Not_a_Finding" if r_cntr_k8_002620
status_r_cntr_k8_002620 := "Open" if not r_cntr_k8_002620

# CNTR-K8-002630 | V-245543 | CAT I
default r_cntr_k8_002630 := false
r_cntr_k8_002630 if {
	not input.api_server.flags["token-auth-file"]
}

finding_r_cntr_k8_002630 := {
	"vuln_id": "V-245543",
	"stig_id": "CNTR-K8-002630",
	"severity": "CAT I",
	"rule_title": "Kubernetes API Server must disable token authentication to protect information in transit.",
	"status": status_r_cntr_k8_002630,
}
status_r_cntr_k8_002630 := "Not_a_Finding" if r_cntr_k8_002630
status_r_cntr_k8_002630 := "Open" if not r_cntr_k8_002630

# CNTR-K8-002640 | V-245544 | CAT I
default r_cntr_k8_002640 := false
r_cntr_k8_002640 if {
	input.api_server.flags["tls-cert-file"] != ""
	input.api_server.flags["tls-private-key-file"] != ""
}

finding_r_cntr_k8_002640 := {
	"vuln_id": "V-245544",
	"stig_id": "CNTR-K8-002640",
	"severity": "CAT I",
	"rule_title": "Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.",
	"status": status_r_cntr_k8_002640,
}
status_r_cntr_k8_002640 := "Not_a_Finding" if r_cntr_k8_002640
status_r_cntr_k8_002640 := "Open" if not r_cntr_k8_002640

# CNTR-K8-003110 | V-242444 | CAT II
default r_cntr_k8_003110 := false
r_cntr_k8_003110 if {
	input.manifests.owned_by_root == true
}

finding_r_cntr_k8_003110 := {
	"vuln_id": "V-242444",
	"stig_id": "CNTR-K8-003110",
	"severity": "CAT II",
	"rule_title": "The Kubernetes component manifests must be owned by root.",
	"status": status_r_cntr_k8_003110,
}
status_r_cntr_k8_003110 := "Not_a_Finding" if r_cntr_k8_003110
status_r_cntr_k8_003110 := "Open" if not r_cntr_k8_003110

findings := [
	finding_r_cntr_k8_000160,
	finding_r_cntr_k8_000170,
	finding_r_cntr_k8_000220,
	finding_r_cntr_k8_000290,
	finding_r_cntr_k8_000330,
	finding_r_cntr_k8_000360,
	finding_r_cntr_k8_000370,
	finding_r_cntr_k8_000380,
	finding_r_cntr_k8_000440,
	finding_r_cntr_k8_000850,
	finding_r_cntr_k8_001160,
	finding_r_cntr_k8_001161,
	finding_r_cntr_k8_001162,
	finding_r_cntr_k8_001480,
	finding_r_cntr_k8_001620,
	finding_r_cntr_k8_002000,
	finding_r_cntr_k8_002001,
	finding_r_cntr_k8_002010,
	finding_r_cntr_k8_002011,
	finding_r_cntr_k8_002620,
	finding_r_cntr_k8_002630,
	finding_r_cntr_k8_002640,
	finding_r_cntr_k8_003110,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
