package csa_ccm.application_security

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.application_security.appsec_policy.policy_established
    msg := "AIS-01: Application security policies and procedures not formally established"
}

violations contains msg if {
    not input.csa_ccm.application_security.appsec_policy.policy_reviewed_annually
    msg := "AIS-01: Application security policy not reviewed at least annually"
}

violations contains msg if {
    not input.csa_ccm.application_security.appsec_policy.developer_acknowledgement
    msg := "AIS-01: Developers have not formally acknowledged application security policies"
}

violations contains msg if {
    not input.csa_ccm.application_security.appsec_policy.cloud_app_scope_included
    msg := "AIS-01: Cloud-hosted applications not explicitly included in application security policy scope"
}

violations contains msg if {
    not input.csa_ccm.application_security.sdlc.lifecycle_implemented
    msg := "AIS-02: Secure development lifecycle (SDLC) not implemented — security must be integrated into all SDLC phases"
}

violations contains msg if {
    not input.csa_ccm.application_security.sdlc.security_requirements_defined
    msg := "AIS-02: Security requirements not defined during application design phase"
}

violations contains msg if {
    not input.csa_ccm.application_security.sdlc.threat_modeling_performed
    msg := "AIS-02: Threat modeling not performed for new and significantly changed applications"
}

violations contains msg if {
    not input.csa_ccm.application_security.sdlc.security_training_for_developers
    msg := "AIS-02: Developers have not completed secure coding training"
}

violations contains msg if {
    not input.csa_ccm.application_security.sdlc.security_gates_in_cicd
    msg := "AIS-02: Security gates not integrated into CI/CD pipeline"
}

violations contains msg if {
    not input.csa_ccm.application_security.testing.sast_conducted
    msg := "AIS-03: Static application security testing (SAST) not conducted on application code"
}

violations contains msg if {
    not input.csa_ccm.application_security.testing.dast_conducted
    msg := "AIS-03: Dynamic application security testing (DAST) not conducted against running applications"
}

violations contains msg if {
    not input.csa_ccm.application_security.testing.pentest_conducted
    msg := "AIS-03: Penetration testing not conducted at defined intervals for production applications"
}

violations contains msg if {
    not input.csa_ccm.application_security.testing.findings_remediated
    msg := "AIS-03: Security testing findings not tracked to remediation with defined SLAs"
}

violations contains msg if {
    not input.csa_ccm.application_security.testing.pre_release_testing_required
    msg := "AIS-03: Security testing not required before releasing new or significantly changed application versions"
}

violations contains msg if {
    not input.csa_ccm.application_security.input_validation.input_validation_implemented
    msg := "AIS-04: Input validation not implemented — all user-supplied input must be validated"
}

violations contains msg if {
    not input.csa_ccm.application_security.input_validation.output_encoding_implemented
    msg := "AIS-04: Output encoding not implemented — output to clients must be encoded to prevent injection attacks"
}

violations contains msg if {
    not input.csa_ccm.application_security.input_validation.sql_injection_prevented
    msg := "AIS-04: SQL injection prevention controls (parameterized queries or ORM) not verified as implemented"
}

violations contains msg if {
    not input.csa_ccm.application_security.input_validation.xss_prevented
    msg := "AIS-04: Cross-site scripting (XSS) prevention controls not verified as implemented"
}

violations contains msg if {
    not input.csa_ccm.application_security.api_security.authentication_required
    msg := "AIS-05: API authentication not required — all API endpoints must enforce authentication"
}

violations contains msg if {
    not input.csa_ccm.application_security.api_security.authorization_enforced
    msg := "AIS-05: API authorization not enforced — access to API resources must be validated per request"
}

violations contains msg if {
    not input.csa_ccm.application_security.api_security.rate_limiting_implemented
    msg := "AIS-05: API rate limiting not implemented — APIs must be protected against abuse and denial of service"
}

violations contains msg if {
    not input.csa_ccm.application_security.api_security.api_inventory_maintained
    msg := "AIS-05: API inventory not maintained — all internal and external APIs must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.application_security.api_security.transport_encryption_enforced
    msg := "AIS-05: API transport encryption not enforced — all API communication must use TLS"
}

violations contains msg if {
    not input.csa_ccm.application_security.dependencies.inventory_maintained
    msg := "AIS-06: Third-party dependency inventory not maintained — all libraries and components must be tracked"
}

violations contains msg if {
    not input.csa_ccm.application_security.dependencies.vulnerability_scanning
    msg := "AIS-06: Third-party dependencies not scanned for known vulnerabilities"
}

violations contains msg if {
    not input.csa_ccm.application_security.dependencies.sca_tool_in_use
    msg := "AIS-06: Software composition analysis (SCA) tool not integrated into development pipeline"
}

violations contains msg if {
    not input.csa_ccm.application_security.dependencies.outdated_components_remediated
    msg := "AIS-06: Outdated or vulnerable third-party components not remediated within defined SLAs"
}

violations contains msg if {
    not input.csa_ccm.application_security.code_review.review_process_established
    msg := "AIS-07: Application code review process not established"
}

violations contains msg if {
    not input.csa_ccm.application_security.code_review.peer_review_required
    msg := "AIS-07: Peer code review not required before merging code into production branches"
}

violations contains msg if {
    not input.csa_ccm.application_security.code_review.security_focused_review
    msg := "AIS-07: Code review process does not include explicit security-focused review criteria"
}

violations contains msg if {
    not input.csa_ccm.application_security.code_review.automated_review_integrated
    msg := "AIS-07: Automated code analysis not integrated to supplement manual review processes"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "AIS — Application & Interface Security",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
