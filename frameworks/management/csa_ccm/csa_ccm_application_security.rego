# METADATA
# title: "Csa Ccm Application Security"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 31
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.application_security

import rego.v1

default compliant := false

_base := ["csa_ccm", "application_security"]

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
	msg := _finding("AIS-01: Application security policies and procedures not formally established", ["appsec_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("AIS-01: Application security policy not reviewed at least annually", ["appsec_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("AIS-01: Developers have not formally acknowledged application security policies", ["appsec_policy", "developer_acknowledgement"])
}

violations contains msg if {
	msg := _finding("AIS-01: Cloud-hosted applications not explicitly included in application security policy scope", ["appsec_policy", "cloud_app_scope_included"])
}

violations contains msg if {
	msg := _finding("AIS-02: Secure development lifecycle (SDLC) not implemented — security must be integrated into all SDLC phases", ["sdlc", "lifecycle_implemented"])
}

violations contains msg if {
	msg := _finding("AIS-02: Security requirements not defined during application design phase", ["sdlc", "security_requirements_defined"])
}

violations contains msg if {
	msg := _finding("AIS-02: Threat modeling not performed for new and significantly changed applications", ["sdlc", "threat_modeling_performed"])
}

violations contains msg if {
	msg := _finding("AIS-02: Developers have not completed secure coding training", ["sdlc", "security_training_for_developers"])
}

violations contains msg if {
	msg := _finding("AIS-02: Security gates not integrated into CI/CD pipeline", ["sdlc", "security_gates_in_cicd"])
}

violations contains msg if {
	msg := _finding("AIS-03: Static application security testing (SAST) not conducted on application code", ["testing", "sast_conducted"])
}

violations contains msg if {
	msg := _finding("AIS-03: Dynamic application security testing (DAST) not conducted against running applications", ["testing", "dast_conducted"])
}

violations contains msg if {
	msg := _finding("AIS-03: Penetration testing not conducted at defined intervals for production applications", ["testing", "pentest_conducted"])
}

violations contains msg if {
	msg := _finding("AIS-03: Security testing findings not tracked to remediation with defined SLAs", ["testing", "findings_remediated"])
}

violations contains msg if {
	msg := _finding("AIS-03: Security testing not required before releasing new or significantly changed application versions", ["testing", "pre_release_testing_required"])
}

violations contains msg if {
	msg := _finding("AIS-04: Input validation not implemented — all user-supplied input must be validated", ["input_validation", "input_validation_implemented"])
}

violations contains msg if {
	msg := _finding("AIS-04: Output encoding not implemented — output to clients must be encoded to prevent injection attacks", ["input_validation", "output_encoding_implemented"])
}

violations contains msg if {
	msg := _finding("AIS-04: SQL injection prevention controls (parameterized queries or ORM) not verified as implemented", ["input_validation", "sql_injection_prevented"])
}

violations contains msg if {
	msg := _finding("AIS-04: Cross-site scripting (XSS) prevention controls not verified as implemented", ["input_validation", "xss_prevented"])
}

violations contains msg if {
	msg := _finding("AIS-05: API authentication not required — all API endpoints must enforce authentication", ["api_security", "authentication_required"])
}

violations contains msg if {
	msg := _finding("AIS-05: API authorization not enforced — access to API resources must be validated per request", ["api_security", "authorization_enforced"])
}

violations contains msg if {
	msg := _finding("AIS-05: API rate limiting not implemented — APIs must be protected against abuse and denial of service", ["api_security", "rate_limiting_implemented"])
}

violations contains msg if {
	msg := _finding("AIS-05: API inventory not maintained — all internal and external APIs must be catalogued", ["api_security", "api_inventory_maintained"])
}

violations contains msg if {
	msg := _finding("AIS-05: API transport encryption not enforced — all API communication must use TLS", ["api_security", "transport_encryption_enforced"])
}

violations contains msg if {
	msg := _finding("AIS-06: Third-party dependency inventory not maintained — all libraries and components must be tracked", ["dependencies", "inventory_maintained"])
}

violations contains msg if {
	msg := _finding("AIS-06: Third-party dependencies not scanned for known vulnerabilities", ["dependencies", "vulnerability_scanning"])
}

violations contains msg if {
	msg := _finding("AIS-06: Software composition analysis (SCA) tool not integrated into development pipeline", ["dependencies", "sca_tool_in_use"])
}

violations contains msg if {
	msg := _finding("AIS-06: Outdated or vulnerable third-party components not remediated within defined SLAs", ["dependencies", "outdated_components_remediated"])
}

violations contains msg if {
	msg := _finding("AIS-07: Application code review process not established", ["code_review", "review_process_established"])
}

violations contains msg if {
	msg := _finding("AIS-07: Peer code review not required before merging code into production branches", ["code_review", "peer_review_required"])
}

violations contains msg if {
	msg := _finding("AIS-07: Code review process does not include explicit security-focused review criteria", ["code_review", "security_focused_review"])
}

violations contains msg if {
	msg := _finding("AIS-07: Automated code analysis not integrated to supplement manual review processes", ["code_review", "automated_review_integrated"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["AIS-01", "AIS-02", "AIS-03", "AIS-04", "AIS-05", "AIS-06", "AIS-07"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "AIS — Application & Interface Security",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 31,
	"violation_count": count(violations),
	"violations": violations,
}
