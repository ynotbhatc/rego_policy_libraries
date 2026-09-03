package stig.openshift_4.core

# DISA STIG — Red Hat OpenShift Container Platform 4.x Security Technical Implementation Guide
# V2R6 | Release: 6 Benchmark Date: 01 Jul 2026
# 14 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Input contract: see gen_k8s.py header / tests fixture.

import rego.v1

# CNTR-OS-000010 | V-257505 | CAT II
default r_cntr_os_000010 := false
r_cntr_os_000010 if {
	input.openshift.oauth_idle_timeout_configured == true
}

finding_r_cntr_os_000010 := {
	"vuln_id": "V-257505",
	"stig_id": "CNTR-OS-000010",
	"severity": "CAT II",
	"rule_title": "OpenShift must use TLS 1.2 or greater for secure container image transport from trusted sources.",
	"status": status_r_cntr_os_000010,
}
status_r_cntr_os_000010 := "Not_a_Finding" if r_cntr_os_000010
status_r_cntr_os_000010 := "Open" if not r_cntr_os_000010

# CNTR-OS-000030 | V-257507 | CAT II
default r_cntr_os_000030 := false
r_cntr_os_000030 if {
	input.openshift.cluster_logging_forwarding_configured == true
}

finding_r_cntr_os_000030 := {
	"vuln_id": "V-257507",
	"stig_id": "CNTR-OS-000030",
	"severity": "CAT II",
	"rule_title": "OpenShift must use a centralized user management solution to support account management functions.",
	"status": status_r_cntr_os_000030,
}
status_r_cntr_os_000030 := "Not_a_Finding" if r_cntr_os_000030
status_r_cntr_os_000030 := "Open" if not r_cntr_os_000030

# CNTR-OS-000090 | V-257513 | CAT I
default r_cntr_os_000090 := false
r_cntr_os_000090 if {
	input.openshift.rbac_enforced == true
}

finding_r_cntr_os_000090 := {
	"vuln_id": "V-257513",
	"stig_id": "CNTR-OS-000090",
	"severity": "CAT I",
	"rule_title": "OpenShift role-based access controls (RBAC) must be enforced.",
	"status": status_r_cntr_os_000090,
}
status_r_cntr_os_000090 := "Not_a_Finding" if r_cntr_os_000090
status_r_cntr_os_000090 := "Open" if not r_cntr_os_000090

# CNTR-OS-000170 | V-257519 | CAT I
default r_cntr_os_000170 := false
r_cntr_os_000170 if {
	input.rhcos.audit_at_startup == true
}

finding_r_cntr_os_000170 := {
	"vuln_id": "V-257519",
	"stig_id": "CNTR-OS-000170",
	"severity": "CAT I",
	"rule_title": "Red Hat Enterprise Linux CoreOS (RHCOS) must initiate session audits at system startup.",
	"status": status_r_cntr_os_000170,
}
status_r_cntr_os_000170 := "Not_a_Finding" if r_cntr_os_000170
status_r_cntr_os_000170 := "Open" if not r_cntr_os_000170

# CNTR-OS-000320 | V-257534 | CAT II
default r_cntr_os_000320 := false
r_cntr_os_000320 if {
	input.openshift.api_server_audit_profile_set == true
}

finding_r_cntr_os_000320 := {
	"vuln_id": "V-257534",
	"stig_id": "CNTR-OS-000320",
	"severity": "CAT II",
	"rule_title": "OpenShift must prevent unauthorized changes to logon UIDs.",
	"status": status_r_cntr_os_000320,
}
status_r_cntr_os_000320 := "Not_a_Finding" if r_cntr_os_000320
status_r_cntr_os_000320 := "Open" if not r_cntr_os_000320

# CNTR-OS-000400 | V-257540 | CAT I
default r_cntr_os_000400 := false
r_cntr_os_000400 if {
	input.openshift.root_sessions_disabled == true
}

finding_r_cntr_os_000400 := {
	"vuln_id": "V-257540",
	"stig_id": "CNTR-OS-000400",
	"severity": "CAT I",
	"rule_title": "OpenShift must disable root and terminate network connections.",
	"status": status_r_cntr_os_000400,
}
status_r_cntr_os_000400 := "Not_a_Finding" if r_cntr_os_000400
status_r_cntr_os_000400 := "Open" if not r_cntr_os_000400

# CNTR-OS-000460 | V-257543 | CAT I
default r_cntr_os_000460 := false
r_cntr_os_000460 if {
	input.openshift.identity_provider_fips_validated == true
}

finding_r_cntr_os_000460 := {
	"vuln_id": "V-257543",
	"stig_id": "CNTR-OS-000460",
	"severity": "CAT I",
	"rule_title": "OpenShift must use FIPS validated LDAP or OpenIDConnect.",
	"status": status_r_cntr_os_000460,
}
status_r_cntr_os_000460 := "Not_a_Finding" if r_cntr_os_000460
status_r_cntr_os_000460 := "Open" if not r_cntr_os_000460

# CNTR-OS-000510 | V-257546 | CAT I
default r_cntr_os_000510 := false
r_cntr_os_000510 if {
	input.openshift.fips_mode_enabled == true
}

finding_r_cntr_os_000510 := {
	"vuln_id": "V-257546",
	"stig_id": "CNTR-OS-000510",
	"severity": "CAT I",
	"rule_title": "OpenShift must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 validated cryptography.",
	"status": status_r_cntr_os_000510,
}
status_r_cntr_os_000510 := "Not_a_Finding" if r_cntr_os_000510
status_r_cntr_os_000510 := "Open" if not r_cntr_os_000510

# CNTR-OS-000560 | V-257548 | CAT II
default r_cntr_os_000560 := false
r_cntr_os_000560 if {
	input.openshift.etcd_encryption_enabled == true
}

finding_r_cntr_os_000560 := {
	"vuln_id": "V-257548",
	"stig_id": "CNTR-OS-000560",
	"severity": "CAT II",
	"rule_title": "OpenShift must prevent unauthorized and unintended information transfer via shared system resources and enable page poisoning.",
	"status": status_r_cntr_os_000560,
}
status_r_cntr_os_000560 := "Not_a_Finding" if r_cntr_os_000560
status_r_cntr_os_000560 := "Open" if not r_cntr_os_000560

# CNTR-OS-000660 | V-257557 | CAT I
default r_cntr_os_000660 := false
r_cntr_os_000660 if {
	input.openshift.default_scc_least_privilege == true
}

finding_r_cntr_os_000660 := {
	"vuln_id": "V-257557",
	"stig_id": "CNTR-OS-000660",
	"severity": "CAT I",
	"rule_title": "Container images instantiated by OpenShift must execute using least privileges.",
	"status": status_r_cntr_os_000660,
}
status_r_cntr_os_000660 := "Not_a_Finding" if r_cntr_os_000660
status_r_cntr_os_000660 := "Open" if not r_cntr_os_000660

# CNTR-OS-000720 | V-257560 | CAT II
default r_cntr_os_000720 := false
r_cntr_os_000720 if {
	input.rhcos.chrony_configured == true
}

finding_r_cntr_os_000720 := {
	"vuln_id": "V-257560",
	"stig_id": "CNTR-OS-000720",
	"severity": "CAT II",
	"rule_title": "OpenShift must enforce access restrictions and support auditing of the enforcement actions.",
	"status": status_r_cntr_os_000720,
}
status_r_cntr_os_000720 := "Not_a_Finding" if r_cntr_os_000720
status_r_cntr_os_000720 := "Open" if not r_cntr_os_000720

# CNTR-OS-000860 | V-257568 | CAT II
default r_cntr_os_000860 := false
r_cntr_os_000860 if {
	input.openshift.image_source_policy_configured == true
}

finding_r_cntr_os_000860 := {
	"vuln_id": "V-257568",
	"stig_id": "CNTR-OS-000860",
	"severity": "CAT II",
	"rule_title": "Red Hat Enterprise Linux CoreOS (RHCOS) must implement nonexecutable data to protect its memory from unauthorized code execution.",
	"status": status_r_cntr_os_000860,
}
status_r_cntr_os_000860 := "Not_a_Finding" if r_cntr_os_000860
status_r_cntr_os_000860 := "Open" if not r_cntr_os_000860

# CNTR-OS-000930 | V-257575 | CAT II
default r_cntr_os_000930 := false
r_cntr_os_000930 if {
	input.openshift.network_policy_default_deny == true
}

finding_r_cntr_os_000930 := {
	"vuln_id": "V-257575",
	"stig_id": "CNTR-OS-000930",
	"severity": "CAT II",
	"rule_title": "OpenShift must generate audit records when successful/unsuccessful attempts to modify privileges occur.",
	"status": status_r_cntr_os_000930,
}
status_r_cntr_os_000930 := "Not_a_Finding" if r_cntr_os_000930
status_r_cntr_os_000930 := "Open" if not r_cntr_os_000930

# CNTR-OS-001010 | V-257583 | CAT I
default r_cntr_os_001010 := false
r_cntr_os_001010 if {
	input.rhcos.sshd_disabled == true
}

finding_r_cntr_os_001010 := {
	"vuln_id": "V-257583",
	"stig_id": "CNTR-OS-001010",
	"severity": "CAT I",
	"rule_title": "Red Hat Enterprise Linux CoreOS (RHCOS) must disable SSHD service.",
	"status": status_r_cntr_os_001010,
}
status_r_cntr_os_001010 := "Not_a_Finding" if r_cntr_os_001010
status_r_cntr_os_001010 := "Open" if not r_cntr_os_001010

findings := [
	finding_r_cntr_os_000010,
	finding_r_cntr_os_000030,
	finding_r_cntr_os_000090,
	finding_r_cntr_os_000170,
	finding_r_cntr_os_000320,
	finding_r_cntr_os_000400,
	finding_r_cntr_os_000460,
	finding_r_cntr_os_000510,
	finding_r_cntr_os_000560,
	finding_r_cntr_os_000660,
	finding_r_cntr_os_000720,
	finding_r_cntr_os_000860,
	finding_r_cntr_os_000930,
	finding_r_cntr_os_001010,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
