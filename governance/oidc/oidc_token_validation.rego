# METADATA
# title: "OIDC Token Validation Policy"
# custom:
#   class: governance
#   framework: oidc
#   source: aac
#   domains: [identity]
#   coverage:
#     checks: 3
#     cited: 0
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.1
package governance.oidc

import rego.v1

# ── OIDC Token Validation Policy ─────────────────────────────────────────────
#
# Validates JWT claims from Keycloak / Red Hat SSO before allowing access to
# AAC compliance operations via the MCP server or portal API.
#
# Input schema:
#   input.token.claims       — decoded JWT payload (sub, email, realm_access, etc.)
#   input.token.issuer       — trusted issuer (e.g. "https://sso.example.com/realms/aac")
#   input.token.trusted_issuers — optional list of further trusted issuers
#   input.token.client_id    — expected audience (this client's id)
#   input.token.jwt / .jwks  — optional raw token + JWKS/PEM; when both are given
#                              the signature is verified here, otherwise a gateway must
#   input.resource.type      — what is being accessed: "assessment" | "report" | "remediation"
#   input.resource.framework — framework key, e.g. "cis_rhel9", "nerc_cip"
#   input.resource.hostname  — target host
#
# OPA evaluation:
#   POST http://localhost:8181/v1/data/governance/oidc
#   { "input": { "token": { "claims": {...} }, "resource": {...} } }

# ── Role definitions ──────────────────────────────────────────────────────────

# Roles defined in Keycloak realm — assigned in realm_access.roles claim
viewer_roles := {"viewer", "analyst", "auditor", "admin"}
analyst_roles := {"analyst", "auditor", "admin"}
auditor_roles := {"auditor", "admin"}
admin_roles   := {"admin"}

# ── Token validation ──────────────────────────────────────────────────────────

default token_valid := false

# A token is valid only when ALL of these hold (fail closed on any missing fact):
#   - sub present and at least one role
#   - iss is one of the configured trusted issuers
#   - aud contains the expected client id
#   - exp is in the future and nbf (when present) is not in the future
#   - signature verified, when verification material is supplied (see below)
token_valid if {
	count(input.token.claims.sub) > 0
	count(user_roles) > 0
	issuer_trusted
	audience_ok
	not_expired
	not_before_ok
	signature_ok
}

# Trusted issuers: input.token.issuer (single, the historical field) and/or
# input.token.trusted_issuers (list). An empty set trusts nothing.
trusted_issuers := ({i | i := input.token.issuer; is_string(i); i != ""} | {i | some i in input.token.trusted_issuers; is_string(i); i != ""})

issuer_trusted if input.token.claims.iss in trusted_issuers

# Expected client: input.token.client_id. aud may be a string or a list.
audience_ok if {
	is_string(input.token.client_id)
	input.token.client_id != ""
	aud_values[input.token.client_id]
}

aud_values[a] if {
	is_string(input.token.claims.aud)
	a := input.token.claims.aud
}

aud_values[a] if {
	some a in input.token.claims.aud
}

# JWT numeric dates are seconds; time.now_ns() is nanoseconds.
not_expired if {
	is_number(input.token.claims.exp)
	input.token.claims.exp * 1000000000 > time.now_ns()
}

not_before_ok if {
	not has_nbf
}

not_before_ok if {
	is_number(input.token.claims.nbf)
	input.token.claims.nbf * 1000000000 <= time.now_ns()
}

has_nbf if "nbf" in object.keys(input.token.claims)

# Signature. When the caller supplies the raw token (input.token.jwt) together
# with verification material (input.token.jwks, a JWKS document or PEM cert),
# the signature, issuer, audience and expiry are verified with
# io.jwt.decode_verify and the decoded claims must match the supplied claims.
# When NO verification material is supplied this policy cannot check the
# signature: an API gateway / the MCP server MUST verify it before calling OPA.
# Supplying input.token.jwt without material is not accepted as verified.
# decode_verify wants the key material as text (PEM or JSON JWKS string).
jwks_text := input.token.jwks if is_string(input.token.jwks)

jwks_text := json.marshal(input.token.jwks) if not is_string(input.token.jwks)

default signature_ok := false

signature_ok if {
	not input.token.jwt
	not input.token.jwks
}

signature_ok if {
	input.token.jwt
	input.token.jwks
	[verified, _, payload] := io.jwt.decode_verify(input.token.jwt, {
		"cert": jwks_text,
		"iss": input.token.claims.iss,
		"aud": input.token.client_id,
	})
	verified
	payload.sub == input.token.claims.sub
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

default summary := {
    "authorized": false,
    "user": null,
    "roles": [],
    "resource": {},
    "deny_reasons": ["Invalid or missing OIDC token"],
}

summary := {
    "authorized": authorized,
    "user": input.token.claims.preferred_username,
    "roles": user_roles,
    "resource": input.resource,
    "deny_reasons": deny_reasons,
} if {
    token_valid
}
