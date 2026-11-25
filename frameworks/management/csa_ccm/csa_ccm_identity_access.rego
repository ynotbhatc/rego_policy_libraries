# METADATA
# title: "Csa Ccm Identity Access"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 48
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.identity_access

import rego.v1

default compliant := false

_base := ["csa_ccm", "identity_access"]

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
	msg := _finding("IAM-01: Identity and access management policy not formally established", ["iam_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("IAM-01: Cloud identity management not included in IAM policy scope", ["iam_policy", "cloud_identities_in_scope"])
}

violations contains msg if {
	msg := _finding("IAM-01: IAM policy not reviewed and updated at least annually", ["iam_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("IAM-01: Least-privilege access principle not formally adopted in IAM policy", ["iam_policy", "least_privilege_principle_adopted"])
}

violations contains msg if {
	msg := _finding("IAM-02: Identity provisioning process not defined — formal procedure for creating and managing accounts required", ["identity_lifecycle", "provisioning_process_defined"])
}

violations contains msg if {
	msg := _finding("IAM-02: Identity deprovisioning process not defined — accounts must be removed or disabled promptly when no longer needed", ["identity_lifecycle", "deprovisioning_process_defined"])
}

violations contains msg if {
	msg := _finding("IAM-02: Unique identities not enforced — shared accounts must be prohibited except where technically required", ["identity_lifecycle", "unique_identities_enforced"])
}

violations contains msg if {
	msg := _finding("IAM-02: Identity verification not performed before provisioning accounts with access to sensitive systems", ["identity_lifecycle", "identity_verified_before_provisioning"])
}

violations contains msg if {
	msg := _finding("IAM-03: Multi-factor authentication (MFA) not enforced for access to cloud management consoles and sensitive systems", ["mfa", "mfa_enforced"])
}

violations contains msg if {
	msg := _finding("IAM-03: MFA not enforced for all privileged accounts — administrative access requires MFA without exception", ["mfa", "mfa_on_privileged_accounts"])
}

violations contains msg if {
	msg := _finding("IAM-03: MFA not enforced for remote access connections (VPN, remote desktop, SSH with key-only insufficient)", ["mfa", "mfa_on_remote_access"])
}

violations contains msg if {
	msg := _finding("IAM-03: Phishing-resistant MFA not used for administrative accounts — FIDO2/hardware keys required for high-privilege access", ["mfa", "phishing_resistant_mfa_for_admins"])
}

violations contains msg if {
	msg := _finding("IAM-04: Privileged access management (PAM) solution not deployed to control and audit privileged account usage", ["privileged_access", "pam_solution_deployed"])
}

violations contains msg if {
	msg := _finding("IAM-04: Privileged accounts not inventoried — all accounts with elevated access must be catalogued", ["privileged_access", "privileged_accounts_inventoried"])
}

violations contains msg if {
	msg := _finding("IAM-04: Privileged sessions not recorded — administrative sessions must be captured for audit and forensic purposes", ["privileged_access", "privileged_sessions_recorded"])
}

violations contains msg if {
	msg := _finding("IAM-04: Standing privileged access not minimized — just-in-time access must be implemented where feasible", ["privileged_access", "standing_privilege_minimized"])
}

violations contains msg if {
	msg := _finding("IAM-04: Break-glass emergency access procedure not defined for privileged accounts", ["privileged_access", "break_glass_procedure_defined"])
}

violations contains msg if {
	msg := _finding("IAM-05: Single sign-on (SSO) not implemented for cloud applications to centralize access management", ["sso", "sso_implemented"])
}

violations contains msg if {
	_fact(["sso", "sso_implemented"]) == true
	msg := _finding("IAM-05: SSO not federated with enterprise identity provider — applications must authenticate through central IdP", ["sso", "sso_uses_federated_identity"])
}

violations contains msg if {
	msg := _finding("IAM-05: SSO session timeout not configured — idle sessions must expire after defined period of inactivity", ["sso", "sso_session_timeout_configured"])
}

violations contains msg if {
	msg := _finding("IAM-06: Service accounts not inventoried — all non-human identities must be catalogued with their purpose and owner", ["service_accounts", "service_accounts_inventoried"])
}

violations contains msg if {
	msg := _finding("IAM-06: Service account credentials not rotated on defined schedule — static credentials create persistent risk", ["service_accounts", "service_account_credentials_rotated"])
}

violations contains msg if {
	msg := _finding("IAM-06: Service account permissions not minimized — accounts must have only the access required for their function", ["service_accounts", "service_account_permissions_minimal"])
}

violations contains msg if {
	msg := _finding("IAM-06: Managed identities or workload identity federation not preferred over static service account credentials", ["service_accounts", "managed_identities_preferred"])
}

violations contains msg if {
	msg := _finding("IAM-07: Access reviews not conducted at defined intervals to verify access remains appropriate", ["access_reviews", "reviews_conducted"])
}

violations contains msg if {
	msg := _finding("IAM-07: Privileged access not reviewed more frequently than standard user access", ["access_reviews", "privileged_access_reviewed_frequently"])
}

violations contains msg if {
	msg := _finding("IAM-07: Inappropriate access identified during reviews not revoked within defined timeframe", ["access_reviews", "inappropriate_access_revoked"])
}

violations contains msg if {
	msg := _finding("IAM-07: Access review results not documented and retained for audit purposes", ["access_reviews", "review_results_documented"])
}

violations contains msg if {
	msg := _finding("IAM-08: Just-in-time (JIT) access not implemented for privileged cloud management access", ["jit_access", "jit_implemented_for_privileged"])
}

violations contains msg if {
	msg := _finding("IAM-08: JIT access requests not subject to approval before access is granted", ["jit_access", "access_requests_approved"])
}

violations contains msg if {
	msg := _finding("IAM-08: JIT access not time-limited — elevated access must automatically expire after defined duration", ["jit_access", "jit_access_time_limited"])
}

violations contains msg if {
	msg := _finding("IAM-09: Role-based access control (RBAC) not implemented — access must be granted based on defined roles", ["rbac", "rbac_implemented"])
}

violations contains msg if {
	msg := _finding("IAM-09: RBAC roles not defined per job function — access groups must align to business role requirements", ["rbac", "roles_defined_per_job_function"])
}

violations contains msg if {
	msg := _finding("IAM-09: Excessive role assignments not detected and remediated — personnel must not accumulate unnecessary roles", ["rbac", "excessive_role_assignments_detected"])
}

violations contains msg if {
	msg := _finding("IAM-10: Implicit network trust not eliminated — zero trust principles require verification of every access request", ["zero_trust", "network_implicit_trust_eliminated"])
}

violations contains msg if {
	msg := _finding("IAM-10: Continuous identity and device verification not implemented — trust must be continuously validated", ["zero_trust", "continuous_verification_implemented"])
}

violations contains msg if {
	msg := _finding("IAM-10: Microsegmentation not applied to limit lateral movement within cloud environments", ["zero_trust", "microsegmentation_applied"])
}

violations contains msg if {
	msg := _finding("IAM-11: Password policy not enforced for user accounts — minimum complexity and length requirements must be configured", ["password_policy", "password_policy_enforced"])
}

violations contains msg if {
	msg := _finding("IAM-11: Password minimum length not enforced — passwords must meet minimum length requirements (14+ characters)", ["password_policy", "minimum_length_enforced"])
}

violations contains msg if {
	msg := _finding("IAM-11: Breached password detection not implemented — compromised passwords must be blocked or flagged", ["password_policy", "breached_password_detection"])
}

violations contains msg if {
	msg := _finding("IAM-12: Account lockout policy not configured — repeated failed authentication attempts must lock accounts", ["account_lockout", "lockout_policy_configured"])
}

violations contains msg if {
	msg := _finding("IAM-12: Account lockout threshold too high — maximum failed attempts before lockout must be set to 10 or fewer", ["account_lockout", "lockout_threshold_appropriate"])
}

violations contains msg if {
	msg := _finding("IAM-13: Federated identity not implemented — cloud access must authenticate through enterprise directory", ["federated_identity", "federation_implemented"])
}

violations contains msg if {
	msg := _finding("IAM-13: Directory synchronization not operational — cloud identity must reflect current enterprise directory state", ["federated_identity", "directory_sync_operational"])
}

violations contains msg if {
	msg := _finding("IAM-13: Terminated users not automatically deprovisioned from cloud systems via directory synchronization", ["federated_identity", "terminated_users_deprovisioned_automatically"])
}

violations contains msg if {
	msg := _finding("IAM-14: Privileged identity governance not defined — lifecycle of privileged accounts must be formally managed", ["privileged_identity", "privileged_identity_governance_defined"])
}

violations contains msg if {
	msg := _finding("IAM-14: Administrative accounts not separate from standard user accounts — separate identities required for privileged tasks", ["privileged_identity", "admin_accounts_separate_from_user_accounts"])
}

violations contains msg if {
	msg := _finding("IAM-14: Number of global administrator accounts not minimized — highest-privilege roles must have the fewest holders", ["privileged_identity", "global_admin_accounts_minimized"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06", "IAM-07", "IAM-08", "IAM-09", "IAM-10", "IAM-11", "IAM-12", "IAM-13", "IAM-14"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "IAM — Identity & Access Management",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 48,
	"violation_count": count(violations),
	"violations": violations,
}
