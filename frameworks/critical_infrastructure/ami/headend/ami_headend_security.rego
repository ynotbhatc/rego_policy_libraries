package ami.headend.security

import rego.v1

# AMI Head-End System Security Policy
# Covers: MDMS API gateway, database security, audit logging,
#         network segmentation, service account management
# OPA endpoint: /v1/data/ami/headend/security

# =============================================================================
# API GATEWAY SECURITY
# =============================================================================

# MFA required for all administrative API access
api_gateway_mfa if {
    input.mdms.api_gateway.authentication.mfa_enabled == true
    input.mdms.api_gateway.authentication.mfa_required_for_admin == true
    input.mdms.api_gateway.authentication.mfa_method in {"hardware_token", "pki_smartcard", "totp"}
}

# OAuth2/JWT-based session management with expiry
api_gateway_session_management if {
    input.mdms.api_gateway.authentication.oauth2_enabled == true
    input.mdms.api_gateway.authentication.jwt_expiry_minutes <= 60
    input.mdms.api_gateway.authentication.refresh_token_rotation == true
}

# RBAC with default-deny enforced
api_gateway_rbac if {
    input.mdms.api_gateway.authorization.rbac_enabled == true
    input.mdms.api_gateway.authorization.default_deny == true
    count(input.mdms.api_gateway.authorization.roles) > 0
}

# TLS 1.2 minimum — no legacy protocol support
api_tls_enforced if {
    input.mdms.api_gateway.transport.tls_minimum_version in {"TLS_1.2", "TLS_1.3"}
    input.mdms.api_gateway.transport.ssl_disabled == true
    input.mdms.api_gateway.transport.tls_1_0_disabled == true
    input.mdms.api_gateway.transport.tls_1_1_disabled == true
}

# Input validation and API rate limiting
api_input_validation if {
    input.mdms.api_gateway.protection.input_validation == true
    input.mdms.api_gateway.protection.rate_limiting_enabled == true
    input.mdms.api_gateway.protection.request_size_limit_enforced == true
}

# =============================================================================
# DATABASE SECURITY
# =============================================================================

# Data at rest encryption with AES-256
db_encrypted_at_rest if {
    input.mdms.database.encryption.at_rest == true
    input.mdms.database.encryption.algorithm in {"AES-256", "AES-256-GCM"}
}

# Transparent Data Encryption (TDE) enabled
db_tde_enabled if {
    input.mdms.database.encryption.tde_enabled == true
}

# Encryption keys managed by HSM or dedicated KMS
db_keys_hsm_managed if {
    input.mdms.database.encryption.key_management in {"HSM", "AWS_KMS", "Azure_Key_Vault", "HashiCorp_Vault"}
}

# Database not reachable from public-facing networks
db_network_isolated if {
    input.mdms.database.network.public_access_disabled == true
    input.mdms.database.network.isolated_to_private_subnet == true
    input.mdms.database.network.default_port_changed == true
}

# Per-application service accounts — no shared privileged accounts
db_service_accounts_scoped if {
    input.mdms.database.access.per_application_accounts == true
    input.mdms.database.access.shared_admin_account_disabled == true
    input.mdms.database.access.least_privilege_per_account == true
}

# Database connection encrypted in transit
db_connections_encrypted if {
    input.mdms.database.network.ssl_required_for_connections == true
    input.mdms.database.network.connection_tls_version in {"TLS_1.2", "TLS_1.3"}
}

# =============================================================================
# AUDIT LOGGING
# =============================================================================

# All required event categories must be captured
required_audit_events := {
    "user_login", "user_logout", "failed_authentication",
    "data_access", "data_modification", "configuration_change",
    "privilege_escalation", "api_call", "meter_command_issued",
    "firmware_update_triggered",
}

audit_events_complete if {
    logged := {e | e := input.mdms.audit_logging.events_logged[_]}
    every required_event in required_audit_events {
        required_event in logged
    }
}

# Minimum 365-day log retention
audit_log_retention if {
    input.mdms.audit_logging.retention_days >= 365
}

# Logs are encrypted and HMAC-integrity protected
audit_log_integrity if {
    input.mdms.audit_logging.encrypted == true
    input.mdms.audit_logging.integrity_protection in {"HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"}
    input.mdms.audit_logging.write_once_storage == true
}

# SIEM integration with real-time alerting
audit_siem_integrated if {
    input.mdms.audit_logging.siem_integrated == true
    input.mdms.audit_logging.real_time_alerting == true
    input.mdms.audit_logging.alert_on_critical_events == true
}

# =============================================================================
# NETWORK SEGMENTATION
# =============================================================================

# OT and IT networks are physically or logically separated
network_ot_it_segmented if {
    input.mdms.network.ot_it_separation == true
    input.mdms.network.firewall_between_zones == true
}

# AMI head-end not directly reachable from internet
headend_not_internet_facing if {
    input.mdms.network.internet_facing == false
    input.mdms.network.dmz_used == true
}

# Jump server or bastion host required for administrative access
admin_access_via_bastion if {
    input.mdms.network.bastion_host_required == true
    input.mdms.network.direct_ssh_blocked == true
}

# =============================================================================
# PATCH AND VULNERABILITY MANAGEMENT
# =============================================================================

# Critical patches applied within 30 days, high within 60 days
patch_management_current if {
    input.mdms.patching.critical_patch_max_days <= 30
    input.mdms.patching.high_patch_max_days <= 60
    input.mdms.patching.vulnerability_scanning_enabled == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

# API Gateway violations
violations contains msg if {
    not api_gateway_mfa
    msg := "HEADEND-API-1: MFA not enabled or not required for admin API access"
}

violations contains msg if {
    not api_gateway_session_management
    msg := "HEADEND-API-2: OAuth2/JWT session management not configured or JWT expiry exceeds 60 minutes"
}

violations contains msg if {
    not api_gateway_rbac
    msg := "HEADEND-API-3: RBAC with default-deny not configured on API gateway"
}

violations contains msg if {
    not api_tls_enforced
    msg := "HEADEND-API-4: API gateway allows deprecated TLS/SSL versions — TLS 1.2 minimum required"
}

violations contains msg if {
    not api_input_validation
    msg := "HEADEND-API-5: Input validation or rate limiting not enabled on API gateway"
}

# Database violations
violations contains msg if {
    not db_encrypted_at_rest
    msg := "HEADEND-DB-1: Database encryption at rest not enabled or not using AES-256"
}

violations contains msg if {
    not db_tde_enabled
    msg := "HEADEND-DB-2: Transparent Data Encryption (TDE) not enabled"
}

violations contains msg if {
    not db_keys_hsm_managed
    msg := "HEADEND-DB-3: Database encryption keys not managed by HSM or dedicated KMS"
}

violations contains msg if {
    not db_network_isolated
    msg := "HEADEND-DB-4: Database accessible from public network or default port in use"
}

violations contains msg if {
    not db_service_accounts_scoped
    msg := "HEADEND-DB-5: Shared database admin accounts in use — per-application service accounts required"
}

violations contains msg if {
    not db_connections_encrypted
    msg := "HEADEND-DB-6: Database connections do not require SSL/TLS 1.2+"
}

# Audit logging violations
violations contains msg if {
    not audit_events_complete
    missing := required_audit_events - {e | e := input.mdms.audit_logging.events_logged[_]}
    msg := sprintf("HEADEND-AUD-1: Required audit event types not logged: %v", [missing])
}

violations contains msg if {
    not audit_log_retention
    msg := sprintf("HEADEND-AUD-2: Audit log retention is %d days — minimum 365 days required",
        [input.mdms.audit_logging.retention_days])
}

violations contains msg if {
    not audit_log_integrity
    msg := "HEADEND-AUD-3: Audit logs not encrypted or HMAC-integrity protected with write-once storage"
}

violations contains msg if {
    not audit_siem_integrated
    msg := "HEADEND-AUD-4: SIEM integration or real-time alerting not configured"
}

# Network violations
violations contains msg if {
    not network_ot_it_segmented
    msg := "HEADEND-NET-1: OT and IT networks not segmented with firewall between zones"
}

violations contains msg if {
    not headend_not_internet_facing
    msg := "HEADEND-NET-2: AMI head-end is internet-facing without DMZ protection"
}

violations contains msg if {
    not admin_access_via_bastion
    msg := "HEADEND-NET-3: Direct SSH access to head-end not blocked — bastion host required"
}

# Patch management violations
violations contains msg if {
    not patch_management_current
    msg := "HEADEND-PATCH-1: Patch management SLAs exceed limits (critical: 30 days, high: 60 days)"
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "framework": "AMI Head-End Security",
    "standards_applied": ["NIST IR 7628", "NIST SP 800-82", "IEC 62443"],
    "categories_assessed": ["API Gateway", "Database Security", "Audit Logging", "Network Segmentation", "Patch Management"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
