package irs_1075.computer_security

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 9: Computer System Security.
# Pub 1075 tailors NIST SP 800-53 Rev 5 for FTI; each requirement names the
# 800-53 family it operationalizes. Requirements are AAC's operationalization.
requirements := {
	"CS-1": {"section": "9", "title": "Logical access to FTI is authorized by role with least privilege (AC)"},
	"CS-2": {"section": "9", "title": "Remote access to FTI is authorized, encrypted, and monitored (AC-17)"},
	"CS-3": {"section": "9", "title": "Multi-factor authentication is enforced for access to systems that receive, process, store, or transmit FTI (IA)"},
	"CS-4": {"section": "9", "title": "Audit logging captures access to FTI with user identity; logs are protected and reviewed (AU)"},
	"CS-5": {"section": "9", "title": "FTI is encrypted in transit with FIPS 140 validated cryptography (SC-8)"},
	"CS-6": {"section": "9", "title": "FTI is encrypted at rest with FIPS 140 validated cryptography (SC-28)"},
	"CS-7": {"section": "9", "title": "FTI systems are hardened to secure configuration baselines consistent with IRS SCSEMs (CM)"},
	"CS-8": {"section": "9", "title": "A current System Security Plan covers every system that receives, processes, stores, or transmits FTI (PL-2)"},
	"CS-9": {"section": "9", "title": "Security assessments are performed on FTI systems and weaknesses tracked in a POA&M (CA)"},
	"CS-10": {"section": "9", "title": "Boundary protection isolates FTI systems; FTI is segregated or labeled in shared environments (SC-7)"},
	"CS-11": {"section": "9", "title": "Cloud environments processing FTI use FedRAMP-authorized services and keep FTI within the United States"},
	"CS-12": {"section": "9", "title": "Mobile devices and portable media containing FTI are encrypted and centrally managed (AC-19, MP)"},
	"CS-13": {"section": "9", "title": "FTI systems receive timely flaw remediation and run current malware protection (SI)"},
}

attested(id) if input.irs_1075.computer_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Computer Security] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "9",
	"area_name": "Computer Security",
	"authority": "NIST SP 800-53 Rev 5 (Pub 1075 tailoring)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
