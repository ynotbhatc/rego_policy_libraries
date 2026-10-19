package governance.oidc_test

import rego.v1

# Token claim checks (decisions 2026-10-19, theme F): iss, aud, exp, nbf, signature.

now := 1800000000000000000 # ns; 2027-01-15

base := {
	"issuer": "https://sso.example.com/realms/aac",
	"client_id": "aac-portal",
	"claims": {
		"sub": "u1", "iss": "https://sso.example.com/realms/aac", "aud": "aac-portal",
		"exp": 1900000000, "realm_access": {"roles": ["viewer"]},
	},
}

valid(t) if data.governance.oidc.token_valid with input as {"token": t} with time.now_ns as now

test_valid_token_accepted if valid(base)

test_aud_list_accepted if valid(json.patch(base, [{"op": "replace", "path": "/claims/aud", "value": ["x", "aac-portal"]}]))

test_wrong_issuer_rejected if {
	not valid(json.patch(base, [{"op": "replace", "path": "/claims/iss", "value": "https://evil.example.com"}]))
}

test_missing_issuer_rejected if {
	not valid(json.remove(base, ["claims/iss"]))
}

test_extra_trusted_issuer_accepted if {
	t := json.patch(base, [
		{"op": "add", "path": "/trusted_issuers", "value": ["https://sso2.example.com"]},
		{"op": "replace", "path": "/claims/iss", "value": "https://sso2.example.com"},
	])
	valid(t)
}

test_wrong_audience_rejected if {
	not valid(json.patch(base, [{"op": "replace", "path": "/claims/aud", "value": "other-client"}]))
}

test_missing_client_config_rejected if {
	not valid(json.remove(base, ["client_id"]))
}

test_expired_rejected if {
	not valid(json.patch(base, [{"op": "replace", "path": "/claims/exp", "value": 1700000000}]))
}

test_missing_exp_rejected if {
	not valid(json.remove(base, ["claims/exp"]))
}

test_future_nbf_rejected if {
	not valid(json.patch(base, [{"op": "add", "path": "/claims/nbf", "value": 1850000000}]))
}

test_past_nbf_accepted if {
	valid(json.patch(base, [{"op": "add", "path": "/claims/nbf", "value": 1700000000}]))
}

test_jwt_without_key_material_not_accepted if {
	not valid(json.patch(base, [{"op": "add", "path": "/jwt", "value": "a.b.c"}]))
}

test_bad_signature_rejected_when_jwks_supplied if {
	t := json.patch(base, [
		{"op": "add", "path": "/jwt", "value": "eyJhbGciOiJIUzI1NiJ9.e30.bogus"},
		{"op": "add", "path": "/jwks", "value": "secret"},
	])
	not valid(t)
}

test_valid_signature_accepted_when_key_supplied if {
	key := {"kty": "oct", "k": "c2VjcmV0"} # "secret"
	jwt := io.jwt.encode_sign({"typ": "JWT", "alg": "HS256"}, {"sub": "u1", "iss": "https://sso.example.com/realms/aac", "aud": "aac-portal", "exp": 1900000000}, key)
	t := json.patch(base, [
		{"op": "add", "path": "/jwt", "value": jwt},
		{"op": "add", "path": "/jwks", "value": {"keys": [key]}},
	])
	valid(t)
}

test_denied_with_reason_when_expired if {
	i := {"token": json.patch(base, [{"op": "replace", "path": "/claims/exp", "value": 1700000000}]), "resource": {"type": "results"}}
	r := data.governance.oidc.deny_reasons with input as i with time.now_ns as now
	"Invalid or missing OIDC token" in r
}
