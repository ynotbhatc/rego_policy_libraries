package cjis.identification_authentication

import rego.v1

# FBI CJIS Security Policy — Policy Area 6: Identification and Authentication. AAC operationalization (CJIS maps to NIST 800-53 IA family).

requirements := {
	"IA-1": {"area": 6, "title": "Each user is uniquely identified before access to CJI is granted"},
	"IA-2": {"area": 6, "title": "Advanced authentication (MFA) is enforced for access to CJI"},
	"IA-3": {"area": 6, "title": "Password/authenticator standards meet CJIS complexity and length requirements"},
	"IA-4": {"area": 6, "title": "Authenticators are protected in storage and transmission (no plaintext)"},
	"IA-5": {"area": 6, "title": "Identifiers are managed: no shared accounts, and reuse is prevented"},
	"IA-6": {"area": 6, "title": "Authentication feedback (e.g. password entry) is obscured"},
	"IA-7": {"area": 6, "title": "Device identification and authentication is enforced before connection"},
}

attested(id) if input.cjis.identification_authentication.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Identification and Authentication] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 6,
	"area_name": "Identification and Authentication",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
