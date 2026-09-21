package cjis.systems_communications_protection

import rego.v1

# FBI CJIS Security Policy — Policy Area 10: Systems and Communications Protection and Information Integrity. AAC operationalization (maps to NIST 800-53 SC and SI families).

requirements := {
	"SC-1": {"area": 10, "title": "CJI in transit is encrypted with FIPS 140-2/140-3 validated cryptography (minimum 128-bit)"},
	"SC-2": {"area": 10, "title": "CJI at rest is encrypted with FIPS 140-2/140-3 validated cryptography when stored outside a physically secure location"},
	"SC-3": {"area": 10, "title": "Boundary protection is enforced (firewall between the CJI network and untrusted networks)"},
	"SC-4": {"area": 10, "title": "The network is segmented so that CJI systems are isolated (VLAN/subnet separation) from non-criminal-justice systems"},
	"SC-5": {"area": 10, "title": "Malicious code protection (antivirus/anti-malware) is deployed and signatures are kept current"},
	"SC-6": {"area": 10, "title": "Spam and spyware protection is deployed at gateways and workstations"},
	"SC-7": {"area": 10, "title": "A personal firewall is enabled on mobile/remote devices that access CJI outside the agency network"},
	"SC-8": {"area": 10, "title": "Security patches and critical updates are applied in a timely, documented manner (patch management)"},
	"SC-9": {"area": 10, "title": "Intrusion detection/prevention capability monitors the CJI environment for malicious activity"},
	"SC-10": {"area": 10, "title": "Information integrity: system and information flaws are identified, reported, and corrected"},
	"SC-11": {"area": 10, "title": "Voice over Internet Protocol (VoIP) transmitting CJI is protected consistent with encryption requirements"},
	"SC-12": {"area": 10, "title": "Cloud services storing or transmitting CJI meet CJIS encryption and boundary-protection requirements"},
}

attested(id) if input.cjis.systems_communications_protection.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Systems and Communications Protection and Information Integrity] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 10,
	"area_name": "Systems and Communications Protection and Information Integrity",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
