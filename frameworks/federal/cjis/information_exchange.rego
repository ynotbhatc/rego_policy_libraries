package cjis.information_exchange

import rego.v1

# FBI CJIS Security Policy — Policy Area 1: Information Exchange Agreements.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"IEA-1": {"area": 1, "title": "A signed information exchange agreement governs sharing of CJI between agencies"},
	"IEA-2": {"area": 1, "title": "A management control agreement is in place where another agency administers CJI systems on the agency's behalf"},
	"IEA-3": {"area": 1, "title": "A signed CJIS Security Addendum covers every private contractor with access to CJI"},
	"IEA-4": {"area": 1, "title": "Inter-agency and information exchange agreements define roles, responsibilities, and security controls in writing"},
	"IEA-5": {"area": 1, "title": "Secondary dissemination of CJI is authorized and recorded"},
	"IEA-6": {"area": 1, "title": "Agreements require CJI to be handled, stored, and destroyed in accordance with the CJIS Security Policy"},
	"IEA-7": {"area": 1, "title": "Agreements are reviewed and current, with a designated point of contact for each party"},
}

attested(id) if input.cjis.information_exchange.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Information Exchange Agreements] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 1,
	"area_name": "Information Exchange Agreements",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
