package cjis.mobile_devices

import rego.v1

# FBI CJIS Security Policy — Policy Area 13: Mobile Devices.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"MD-1": {"area": 13, "title": "Mobile devices that access, process, or store CJI are enrolled in centralized mobile device management (MDM)"},
	"MD-2": {"area": 13, "title": "Data at rest and CJI on mobile devices is protected with FIPS 140-validated encryption"},
	"MD-3": {"area": 13, "title": "Lost or stolen mobile devices can be remotely locked and remotely wiped of CJI"},
	"MD-4": {"area": 13, "title": "Wireless connectivity (cellular, Wi-Fi, Bluetooth) is secured and unapproved interfaces are disabled"},
	"MD-5": {"area": 13, "title": "Mobile devices enforce authentication, session lock, and automatic device lock after inactivity"},
	"MD-6": {"area": 13, "title": "Compensating controls are applied to limited-feature (pocket/handheld) and tablet devices that cannot meet full requirements"},
	"MD-7": {"area": 13, "title": "Mobile devices are patched and run only approved, malware-protected applications"},
	"MD-8": {"area": 13, "title": "Personally owned (BYOD) devices accessing CJI are governed by policy and technical controls before access is granted"}, # FIDELITY: unsure
}

attested(id) if input.cjis.mobile_devices.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Mobile Devices] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 13,
	"area_name": "Mobile Devices",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
