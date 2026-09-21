package cjis.access_control

import rego.v1

# FBI CJIS Security Policy — Policy Area 5: Access Control. AAC operationalization (CJIS maps to NIST 800-53 AC family).

requirements := {
	"AC-1": {"area": 5, "title": "Access to CJI is granted on least-privilege and need-to-know basis"},
	"AC-2": {"area": 5, "title": "Account management: accounts are created, reviewed, and disabled per authorization"},
	"AC-3": {"area": 5, "title": "Session lock is enforced after a maximum 30 minutes of inactivity"},
	"AC-4": {"area": 5, "title": "Unsuccessful login attempts are limited (lockout after no more than 5 attempts)"},
	"AC-5": {"area": 5, "title": "Remote access to CJI is controlled, encrypted, and monitored"},
	"AC-6": {"area": 5, "title": "A system-use notification (warning banner) is displayed before access is granted"},
	"AC-7": {"area": 5, "title": "Access enforcement restricts CJI to authorized users, processes, and devices"},
}

attested(id) if input.cjis.access_control.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Access Control] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 5,
	"area_name": "Access Control",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
