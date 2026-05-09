package csa_ccm.human_resources

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.human_resources.background_checks.policy_established
    msg := "HRS-01: Background check policy for personnel with access to sensitive systems not established"
}

violations contains msg if {
    not input.csa_ccm.human_resources.background_checks.checks_conducted_pre_hire
    msg := "HRS-01: Background checks not conducted before granting access to sensitive cloud environments"
}

violations contains msg if {
    not input.csa_ccm.human_resources.background_checks.checks_commensurate_with_access
    msg := "HRS-01: Background check depth not commensurate with the sensitivity of access being granted"
}

violations contains msg if {
    not input.csa_ccm.human_resources.background_checks.contractors_included
    msg := "HRS-01: Background check requirements not applied to contractors and third-party personnel with system access"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_awareness.training_program_established
    msg := "HRS-02: Security awareness training program not established for all personnel"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_awareness.training_conducted_at_hire
    msg := "HRS-02: Security awareness training not completed by new employees before granting system access"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_awareness.annual_training_required
    msg := "HRS-02: Annual security awareness training not required for all personnel"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_awareness.cloud_security_topics_included
    msg := "HRS-02: Cloud security topics not included in security awareness training curriculum"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_awareness.completion_tracked
    msg := "HRS-02: Training completion not tracked to ensure all personnel have completed required training"
}

violations contains msg if {
    not input.csa_ccm.human_resources.acceptable_use.policy_established
    msg := "HRS-03: Acceptable use policy for information systems and cloud resources not established"
}

violations contains msg if {
    not input.csa_ccm.human_resources.acceptable_use.employees_acknowledged
    msg := "HRS-03: Employees have not formally acknowledged and signed the acceptable use policy"
}

violations contains msg if {
    not input.csa_ccm.human_resources.acceptable_use.policy_reviewed_annually
    msg := "HRS-03: Acceptable use policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.human_resources.acceptable_use.violations_enforced
    msg := "HRS-03: Disciplinary process for acceptable use policy violations not defined and communicated"
}

violations contains msg if {
    not input.csa_ccm.human_resources.nda.nda_required
    msg := "HRS-04: Non-disclosure agreements not required for personnel with access to sensitive or proprietary information"
}

violations contains msg if {
    not input.csa_ccm.human_resources.nda.nda_signed_before_access
    msg := "HRS-04: NDAs not signed before granting access to sensitive information or cloud environments"
}

violations contains msg if {
    not input.csa_ccm.human_resources.nda.nda_covers_cloud_data
    msg := "HRS-04: NDAs do not explicitly cover cloud-hosted data and third-party cloud environments"
}

violations contains msg if {
    not input.csa_ccm.human_resources.nda.nda_records_maintained
    msg := "HRS-04: NDA signing records not maintained for audit and legal purposes"
}

violations contains msg if {
    not input.csa_ccm.human_resources.termination.termination_procedure_defined
    msg := "HRS-05: Employee and contractor termination procedure not formally defined"
}

violations contains msg if {
    not input.csa_ccm.human_resources.termination.access_revoked_timely
    msg := "HRS-05: System and cloud access not revoked within defined timeframe upon termination"
}

violations contains msg if {
    not input.csa_ccm.human_resources.termination.privileged_access_revoked_immediately
    msg := "HRS-05: Privileged access not revoked immediately upon termination — elevated access must be removed without delay"
}

violations contains msg if {
    not input.csa_ccm.human_resources.termination.asset_return_verified
    msg := "HRS-05: Return of company-issued assets and credentials not verified upon termination"
}

violations contains msg if {
    not input.csa_ccm.human_resources.termination.exit_process_documented
    msg := "HRS-05: Exit process not documented with checklist of security-relevant steps to complete upon separation"
}

violations contains msg if {
    not input.csa_ccm.human_resources.role_based_access_removal.access_tied_to_role
    msg := "HRS-06: Access privileges not tied to job roles — access must be granted based on defined roles and responsibilities"
}

violations contains msg if {
    not input.csa_ccm.human_resources.role_based_access_removal.access_updated_on_role_change
    msg := "HRS-06: Access not updated when personnel change roles — access must reflect current job responsibilities"
}

violations contains msg if {
    not input.csa_ccm.human_resources.role_based_access_removal.periodic_access_reviews_conducted
    msg := "HRS-06: Periodic access reviews not conducted to verify access remains appropriate for current roles"
}

violations contains msg if {
    not input.csa_ccm.human_resources.role_based_access_removal.orphaned_accounts_removed
    msg := "HRS-06: Orphaned accounts (accounts without active owners) not identified and removed"
}

violations contains msg if {
    not input.csa_ccm.human_resources.insider_threat.program_exists
    msg := "HRS-07: Insider threat program not established — behavioral monitoring and detection controls must be implemented"
}

violations contains msg if {
    not input.csa_ccm.human_resources.insider_threat.monitoring_implemented
    msg := "HRS-07: User behavior monitoring not implemented to detect potential insider threat indicators"
}

violations contains msg if {
    not input.csa_ccm.human_resources.insider_threat.reporting_mechanism_exists
    msg := "HRS-07: Mechanism for reporting suspected insider threat activity not established and communicated to personnel"
}

violations contains msg if {
    not input.csa_ccm.human_resources.insider_threat.high_risk_personnel_controls
    msg := "HRS-07: Enhanced monitoring controls not applied to personnel with high-privilege access or elevated risk"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_roles.specialized_training_provided
    msg := "HRS-08: Specialized security training not provided to personnel in security-relevant roles (admins, developers, security team)"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_roles.certifications_encouraged
    msg := "HRS-08: Security certifications not encouraged or required for personnel in cloud security roles"
}

violations contains msg if {
    not input.csa_ccm.human_resources.security_roles.security_responsibilities_documented
    msg := "HRS-08: Security responsibilities not formally documented in job descriptions for roles with security functions"
}

violations contains msg if {
    not input.csa_ccm.human_resources.third_party_personnel.security_requirements_communicated
    msg := "HRS-09: Security requirements not formally communicated to third-party personnel before granting access"
}

violations contains msg if {
    not input.csa_ccm.human_resources.third_party_personnel.access_limited_to_required
    msg := "HRS-09: Third-party personnel access not limited to only what is required for contracted services"
}

violations contains msg if {
    not input.csa_ccm.human_resources.third_party_personnel.access_reviewed_regularly
    msg := "HRS-09: Third-party personnel access not reviewed regularly to confirm continued business need"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "HRS — Human Resources",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
