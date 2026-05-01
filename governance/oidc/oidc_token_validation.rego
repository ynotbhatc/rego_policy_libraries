package governance.oidc

import rego.v1

# ── OIDC Token Validation Policy ─────────────────────────────────────────────
#
# Validates JWT claims from Keycloak / Red Hat SSO before allowing access to
# AAC compliance operations via the MCP server or portal API.
#
# Input schema:
#   input.token.claims       — decoded JWT payload (sub, email, realm_access, etc.)
#   input.token.issuer       — expected issuer (e.g. "https://sso.example.com/realms/aac")
#   input.resource.type      — what is being accessed: "assessment" | "report" | "remediation"
#   input.resource.framework — framework key, e.g. "cis_rhel9", "nerc_cip"
#   input.resource.hostname  — target host
#
# OPA evaluation:
#   POST http://192.168.4.62:8182/v1/data/governance/oidc
#   { "input": { "token": { "claims": {...} }, "resource": {...} } }

# ── Role definitions ──────────────────────────────────────────────────────────

# Roles defined in Keycloak realm — assigned in realm_access.roles claim
viewer_roles := {"viewer", "analyst", "auditor", "admin"}
analyst_roles := {"analyst", "auditor", "admin"}
auditor_roles := {"auditor", "admin"}
admin_roles   := {"admin"}

# ── Token validation ──────────────────────────────────────────────────────────

default token_valid := false

token_valid if {
    count(input.token.claims.sub) > 0
    count(user_roles) > 0
}

user_roles := roles if {
    roles := {r | some r in input.token.claims.realm_access.roles}
} else := set()

# ── Access decisions ──────────────────────────────────────────────────────────

default allow := false

# Viewers can read compliance results and framework summaries
allow if {
    token_valid
    input.resource.type in {"results", "frameworks", "hosts", "trend"}
    count(user_roles & viewer_roles) > 0
}

# Analysts can additionally download reports and OSCAL exports
allow if {
    token_valid
    input.resource.type in {"report", "oscal"}
    count(user_roles & analyst_roles) > 0
}

# Auditors can access remediation tracking
allow if {
    token_valid
    input.resource.type == "remediation"
    count(user_roles & auditor_roles) > 0
}

# Admins can launch assessments (triggers AAP job templates)
allow if {
    token_valid
    input.resource.type == "assessment_launch"
    count(user_roles & admin_roles) > 0
}

# ── Framework-level restrictions ──────────────────────────────────────────────
# Certain frameworks require elevated roles regardless of resource type.
# OT/critical infrastructure frameworks (NERC-CIP, AMI) require auditor+.

ot_frameworks := {"nerc_cip", "iec_62443", "ami_nist_ir7628", "nist_800_82"}

framework_access_allowed if {
    not input.resource.framework in ot_frameworks
}

framework_access_allowed if {
    input.resource.framework in ot_frameworks
    count(user_roles & auditor_roles) > 0
}

# Combined decision: allow only if base role + framework access both pass
default authorized := false

authorized if {
    allow
    framework_access_allowed
}

# ── Denial reasons ────────────────────────────────────────────────────────────

deny_reasons contains msg if {
    not token_valid
    msg := "Invalid or missing OIDC token"
}

deny_reasons contains msg if {
    token_valid
    not allow
    msg := sprintf(
        "Role insufficient for resource '%v'. User roles: %v",
        [input.resource.type, user_roles],
    )
}

deny_reasons contains msg if {
    token_valid
    allow
    not framework_access_allowed
    msg := sprintf(
        "Framework '%v' requires auditor role. User roles: %v",
        [input.resource.framework, user_roles],
    )
}

# ── Summary report ────────────────────────────────────────────────────────────

default summary := {}

summary := {
    "authorized": authorized,
    "user": input.token.claims.preferred_username,
    "roles": user_roles,
    "resource": input.resource,
    "deny_reasons": deny_reasons,
} if {
    token_valid
}
