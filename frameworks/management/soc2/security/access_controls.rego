# SOC 2 Trust Services Criteria (AICPA TSP section 100, 2017, points of focus revised 2022) -
# Security (common criteria): logical-access checks for CC6.1, CC6.2, CC6.3 and CC6.6 and the
# access-logging check for CC7.2, plus OpenShift platform checks that decide no criterion.
#
# The criteria state objectives; they fix no idle-session limit, log-retention period, review
# interval, administrator count or vulnerability threshold. Those values are the entity's own
# commitments: they are read from input.soc2.commitments and the observed value is compared
# with them. A missing commitment or a missing observed value is a finding (fail closed).
#
#   input.soc2.commitments.max_idle_minutes             remote session idle limit       (CC6.6)
#   input.soc2.commitments.log_retention_days           access-log retention            (CC7.2)
#   input.soc2.commitments.access_review_interval_days  access-right review interval    (CC6.2)
#   input.soc2.commitments.max_cluster_admins           OpenShift cluster-admin users   (platform, advisory)
#   input.soc2.commitments.max_critical_vulnerabilities image threshold, critical       (platform, advisory)
#   input.soc2.commitments.max_high_vulnerabilities     image threshold, high           (platform, advisory)
#
# Which check decides which criterion is listed in data.soc2.main.criteria_checks.

# METADATA
# title: "SOC 2 Trust Services Criteria - Security: logical access (CC6.1, CC6.2, CC6.3, CC6.6) and access logging (CC7.2)"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 22
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package soc2.security.access_controls

import rego.v1

# Entity commitments (organization-defined values; see header)
_commitment(key) := v if {
	v := input.soc2.commitments[key]
	is_number(v)
}

_commitment_keys := {
	"max_idle_minutes": "CC6.6", "log_retention_days": "CC7.2", "access_review_interval_days": "CC6.2",
	"max_cluster_admins": "platform", "max_critical_vulnerabilities": "platform", "max_high_vulnerabilities": "platform",
}

# The observed values compared with a commitment.
_observed := {
	"max_idle_minutes": object.get(input, ["remote_access", "session_timeout", "max_idle_minutes"], null),
	"log_retention_days": object.get(input, ["access_controls", "access_logging", "retention_days"], null),
	"access_review_interval_days": object.get(input, ["access_controls", "periodic_reviews", "frequency_days"], null),
	"max_critical_vulnerabilities": object.get(input, ["openshift", "image_security", "vulnerability_threshold", "critical"], null),
	"max_high_vulnerabilities": object.get(input, ["openshift", "image_security", "vulnerability_threshold", "high"], null),
}

_observed_path := {
	"max_idle_minutes": "input.remote_access.session_timeout.max_idle_minutes",
	"log_retention_days": "input.access_controls.access_logging.retention_days",
	"access_review_interval_days": "input.access_controls.periodic_reviews.frequency_days",
	"max_critical_vulnerabilities": "input.openshift.image_security.vulnerability_threshold.critical",
	"max_high_vulnerabilities": "input.openshift.image_security.vulnerability_threshold.high",
}

# Findings for a missing commitment or a missing observed value. The criterion id is
# literal in each message (CC6.2, CC6.6, CC7.2); the platform thresholds cite none.

evidence_findings contains "CC6.6: evidence missing - input.soc2.commitments.max_idle_minutes (the entity's stated value) not supplied or not a number" if not _commitment("max_idle_minutes")

evidence_findings contains "CC6.6: evidence missing - input.remote_access.session_timeout.max_idle_minutes not collected or not a number" if not is_number(_observed.max_idle_minutes)

evidence_findings contains "CC7.2: evidence missing - input.soc2.commitments.log_retention_days (the entity's stated value) not supplied or not a number" if not _commitment("log_retention_days")

evidence_findings contains "CC7.2: evidence missing - input.access_controls.access_logging.retention_days not collected or not a number" if not is_number(_observed.log_retention_days)

evidence_findings contains "CC6.2: evidence missing - input.soc2.commitments.access_review_interval_days (the entity's stated value) not supplied or not a number" if not _commitment("access_review_interval_days")

evidence_findings contains "CC6.2: evidence missing - input.access_controls.periodic_reviews.frequency_days not collected or not a number" if not is_number(_observed.access_review_interval_days)

evidence_findings contains msg if {
	some key in {"max_cluster_admins", "max_critical_vulnerabilities", "max_high_vulnerabilities"}
	not _commitment(key)
	msg := sprintf("platform: evidence missing - input.soc2.commitments.%v (the entity's stated value) not supplied or not a number", [key])
}

evidence_findings contains msg if {
	some key in {"max_critical_vulnerabilities", "max_high_vulnerabilities"}
	not is_number(_observed[key])
	msg := sprintf("platform: evidence missing - %v not collected or not a number", [_observed_path[key]])
}

evidence_findings contains msg if {
	not is_array(object.get(input, ["openshift", "rbac", "cluster_admin_users"], null))
	msg := "platform: evidence missing - input.openshift.rbac.cluster_admin_users not collected (not an array)"
}

# is_number guards: OPA orders null below every number, so null <= 30 would be true.
_within_max(key) if {
	is_number(_observed[key])
	_observed[key] <= _commitment(key)
}

_at_least(key) if {
	is_number(_observed[key])
	_observed[key] >= _commitment(key)
}

# =================================================================
# CC6.1 - logical access security over protected information assets
#   (identification and authentication, credentials, segmentation)
# CC6.3 - access authorized, modified or removed by role, least privilege
# =================================================================

# User access is properly restricted based on job responsibilities (CC6.3)
default user_access_properly_restricted := false

user_access_properly_restricted if {
	input.access_controls.role_based_access == true
	input.access_controls.least_privilege_principle == true
	input.access_controls.regular_access_reviews == true
}

# Multi-factor authentication is implemented for privileged access (CC6.1)
default mfa_for_privileged_access := false

mfa_for_privileged_access if {
	count(input.access_controls.privileged_users) > 0
	mfa_enabled_users := [user | user := input.access_controls.privileged_users[_]; user.mfa_enabled == true]
	count(mfa_enabled_users) == count(input.access_controls.privileged_users)
}

# System access is monitored and logged (CC7.2); retention meets the entity's commitment
default system_access_monitored := false

system_access_monitored if {
	input.access_controls.access_logging.enabled == true
	input.access_controls.access_logging.includes_failed_attempts == true
	_at_least("log_retention_days")
}

# Network access is properly segmented (CC6.1; two zones is what segmentation means)
default network_segmentation_implemented := false

network_segmentation_implemented if {
	input.network_security.segmentation.enabled == true
	count(input.network_security.segmentation.zones) >= 2
	input.network_security.firewalls.configured == true
}

# =================================================================
# CC6.6 - logical access security measures against threats from outside the system boundary
# =================================================================

# Remote access is secured; the idle limit is the entity's commitment
default remote_access_secured := false

remote_access_secured if {
	input.remote_access.vpn_required == true
	input.remote_access.vpn_encryption.enabled == true
	input.remote_access.session_timeout.configured == true
	_within_max("max_idle_minutes")
}

# Database access is controlled (CC6.1)
default database_access_controlled := false

database_access_controlled if {
	input.database_security.authentication_required == true
	input.database_security.connection_encryption == true
	input.database_security.access_logging == true
	count(input.database_security.privileged_accounts) > 0
	count([account | account := input.database_security.privileged_accounts[_]; account.regular_review == true]) == count(input.database_security.privileged_accounts)
}

# =================================================================
# CC6.2 - users registered and authorized before credentials are issued; access removed
#   and reviewed
# =================================================================

# User provisioning and deprovisioning is automated (CC6.2)
default user_lifecycle_managed := false

user_lifecycle_managed if {
	input.user_management.automated_provisioning == true
	input.user_management.automated_deprovisioning == true
	input.user_management.approval_workflow == true
}

# Access rights are reviewed at the interval the entity committed to (CC6.2)
default access_rights_reviewed := false

access_rights_reviewed if {
	input.access_controls.periodic_reviews.enabled == true
	_within_max("access_review_interval_days")
	input.access_controls.periodic_reviews.documented == true
}

# Shared and service accounts are managed (CC6.1)
default shared_accounts_managed := false

shared_accounts_managed if {
	count(input.access_controls.shared_accounts) == 0
	count([account |
		account := input.access_controls.service_accounts[_]
		account.unique_identifier == true
		account.regular_password_change == true
	]) == count(input.access_controls.service_accounts)
}

# =================================================================
# OpenShift/Kubernetes platform checks — advisory: they decide no criterion in
# data.soc2.main (the criteria do not prescribe platform settings); thresholds
# are the entity's commitments.
# =================================================================

# RBAC is properly configured in OpenShift
default openshift_rbac_configured := false

openshift_rbac_configured if {
	input.openshift.rbac.enabled == true
	input.openshift.rbac.cluster_admin_users_limited == true
	count(input.openshift.rbac.cluster_admin_users) <= _commitment("max_cluster_admins")
	input.openshift.rbac.service_accounts_restricted == true
}

# Pod security standards are enforced
default pod_security_enforced := false

pod_security_enforced if {
	input.openshift.security.pod_security_standards.enabled == true
	input.openshift.security.pod_security_standards.level in ["restricted", "baseline"]
	input.openshift.security.security_context_constraints.default_restricted == true
}

# Network policies are implemented
default network_policies_implemented := false

network_policies_implemented if {
	input.openshift.network_policies.enabled == true
	input.openshift.network_policies.default_deny == true
	count(input.openshift.network_policies.policies) > 0
}

# Container image security is enforced
default container_security_enforced := false

container_security_enforced if {
	input.openshift.image_security.scanning_enabled == true
	_within_max("max_critical_vulnerabilities")
	_within_max("max_high_vulnerabilities")
	input.openshift.image_security.trusted_registries_only == true
}

# =================================================================
# Overall Security Assessment
# =================================================================

default security_controls_compliant := false

security_controls_compliant if {
	user_access_properly_restricted
	mfa_for_privileged_access
	system_access_monitored
	network_segmentation_implemented
	remote_access_secured
	database_access_controlled
	user_lifecycle_managed
	access_rights_reviewed
	shared_accounts_managed
}

default openshift_security_compliant := false

openshift_security_compliant if {
	openshift_rbac_configured
	pod_security_enforced
	network_policies_implemented
	container_security_enforced
}

default overall_security_compliant := false

overall_security_compliant if {
	security_controls_compliant
	openshift_security_compliant
}

# =================================================================
# Security Score Calculation
# =================================================================

security_score := score if {
	controls := [
		user_access_properly_restricted,
		mfa_for_privileged_access,
		system_access_monitored,
		network_segmentation_implemented,
		remote_access_secured,
		database_access_controlled,
		user_lifecycle_managed,
		access_rights_reviewed,
		shared_accounts_managed,
		openshift_rbac_configured,
		pod_security_enforced,
		network_policies_implemented,
		container_security_enforced,
	]

	passed := count([control | control := controls[_]; control == true])
	total := count(controls)
	score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

security_findings := findings if {
	findings := {
		"user_access_properly_restricted": user_access_properly_restricted,
		"mfa_for_privileged_access": mfa_for_privileged_access,
		"system_access_monitored": system_access_monitored,
		"network_segmentation_implemented": network_segmentation_implemented,
		"remote_access_secured": remote_access_secured,
		"database_access_controlled": database_access_controlled,
		"user_lifecycle_managed": user_lifecycle_managed,
		"access_rights_reviewed": access_rights_reviewed,
		"shared_accounts_managed": shared_accounts_managed,
		"openshift_rbac_configured": openshift_rbac_configured,
		"pod_security_enforced": pod_security_enforced,
		"network_policies_implemented": network_policies_implemented,
		"container_security_enforced": container_security_enforced,
		"overall_score": security_score,
	}
}
