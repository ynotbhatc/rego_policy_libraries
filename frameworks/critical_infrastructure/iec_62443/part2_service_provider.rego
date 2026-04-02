package iec_62443.part2_4

import rego.v1

# =============================================================================
# IEC 62443-2-4 — Security Program Requirements for IACS Service Providers
#
# Purpose: Define security requirements for IACS service providers (integrators,
# maintenance contractors, OEMs, managed service providers) who design, install,
# commission, maintain, or operate IACS on behalf of asset owners.
#
# Key Requirement Areas (SP requirements):
#   SP.01 — Security management
#   SP.02 — Physical security
#   SP.03 — Personnel security
#   SP.04 — Customer security requirements
#   SP.05 — Remote access
#   SP.06 — Temporary connections
#   SP.07 — Security patching
#   SP.08 — Malicious code protection
#   SP.09 — Security event notification
#   SP.10 — Security documentation
#
# Input shape:
#   input.is_iacs_service_provider               - bool
#   input.service_provider
#     .security_program_documented               - bool
#     .customer_security_requirements_reviewed   - bool
#     .installation_protection_measures          - bool
#     .remote_access_security_controlled         - bool
#     .security_event_notification               - bool
#     .personnel_background_checks               - bool
#     .security_training_for_field_staff         - bool
#     .portable_tool_security_policy             - bool
#     .temporary_connection_policy               - bool
#     .security_documentation_provided           - bool
#     .vulnerability_disclosure_process          - bool
#     .incident_notification_sla_hours           - int
#     .remote_access_mfa_enforced                - bool
#     .remote_session_audit_logged               - bool
#     .malware_protection_on_tools               - bool
#     .patch_qualification_for_supplied_systems  - bool
# =============================================================================

default compliant := false

# Only evaluate if this is an IACS service provider context
# (Asset owners may include this as a vendor assessment checklist)

# ---------------------------------------------------------------------------
# SP.01 — Security Management
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.security_program_documented
    msg := "IEC 62443-2-4 SP.01: IACS service provider has no documented security program. A formal security management program addressing all IEC 62443-2-4 requirements is required."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.vulnerability_disclosure_process
    msg := "IEC 62443-2-4 SP.01: No vulnerability disclosure process. The service provider must have a defined process for disclosing and responding to vulnerabilities in supplied IACS products or services."
}

# ---------------------------------------------------------------------------
# SP.03 — Personnel Security
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.personnel_background_checks
    msg := "IEC 62443-2-4 SP.03: No background checks for IACS field personnel. Personnel with physical or logical access to customer IACS must undergo appropriate background screening."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.security_training_for_field_staff
    msg := "IEC 62443-2-4 SP.03: No security training for IACS field staff. Personnel performing IACS integration, installation, or maintenance must be trained on relevant cybersecurity practices."
}

# ---------------------------------------------------------------------------
# SP.04 — Customer Security Requirements
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.customer_security_requirements_reviewed
    msg := "IEC 62443-2-4 SP.04: Customer IACS security requirements have not been reviewed. The service provider must formally review and acknowledge customer security requirements before commencing work."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.security_documentation_provided
    msg := "IEC 62443-2-4 SP.10: Security documentation has not been provided to the customer. Service providers must deliver security documentation (hardening guides, default credentials list, known vulnerabilities) for all supplied IACS components."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.installation_protection_measures
    msg := "IEC 62443-2-4 SP.04: No security measures during installation/commissioning. The service provider must implement appropriate security controls during IACS installation to prevent introduction of vulnerabilities."
}

# ---------------------------------------------------------------------------
# SP.05 — Remote Access
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.remote_access_security_controlled
    msg := "IEC 62443-2-4 SP.05: Remote access to customer IACS is not security-controlled. All service provider remote access must go through customer-approved, auditable channels (VPN/jump host) with explicit session authorization."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.remote_access_mfa_enforced
    msg := "IEC 62443-2-4 SP.05: MFA is not enforced for service provider remote access. Multi-factor authentication is required for all remote IACS access by service providers."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.remote_session_audit_logged
    msg := "IEC 62443-2-4 SP.05: Remote service provider sessions are not audit logged. All remote access sessions must be logged and the logs made available to the asset owner."
}

# ---------------------------------------------------------------------------
# SP.06 — Temporary Connections
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.temporary_connection_policy
    msg := "IEC 62443-2-4 SP.06: No policy for temporary connections to IACS. Laptops, diagnostic tools, and temporary devices connected to IACS must be controlled by a formal policy requiring malware scanning, configuration hardening, and session logging."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.portable_tool_security_policy
    msg := "IEC 62443-2-4 SP.06: No portable tool security policy. Service provider laptops and diagnostic tools used on IACS must be hardened, maintained, and free of unauthorized software."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.malware_protection_on_tools
    msg := "IEC 62443-2-4 SP.06/SP.08: Service provider portable tools lack malware protection. All tools connected to customer IACS must have current malware protection to prevent introduction of malicious code."
}

# ---------------------------------------------------------------------------
# SP.07 — Security Patching for Supplied Systems
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.patch_qualification_for_supplied_systems
    msg := "IEC 62443-2-4 SP.07: No patch qualification process for supplied IACS systems. Service providers must qualify and communicate security patches for all IACS products they supply or maintain."
}

# ---------------------------------------------------------------------------
# SP.09 — Security Event Notification
# ---------------------------------------------------------------------------

violations contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.security_event_notification
    msg := "IEC 62443-2-4 SP.09: No security event notification capability. Service providers must notify asset owners of security events that may affect their IACS within defined timeframes."
}

violations contains msg if {
    input.is_iacs_service_provider == true
    input.service_provider.security_event_notification
    input.service_provider.incident_notification_sla_hours > 24
    msg := sprintf(
        "IEC 62443-2-4 SP.09: Security event notification SLA is %v hours. Service providers must notify asset owners of critical security events within 24 hours; immediately for active incidents.",
        [input.service_provider.incident_notification_sla_hours]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

compliance_report := {
    "part":                     "IEC 62443-2-4",
    "title":                    "Security Program Requirements for IACS Service Providers",
    "standard":                 "IEC 62443-2-4",
    "is_iacs_service_provider": input.is_iacs_service_provider,
    "compliant":                compliant,
    "violations":               violations,
}
