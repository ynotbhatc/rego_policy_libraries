# FedRAMP 20x — Key Security Indicators (KSI)
#
# Source: FedRAMP Consolidated Rules for 2026, machine-readable datafile
# github.com/FedRAMP/rules (fedramp-consolidated-rules.json), KSI set
# stable since the official launch 2026-06-24. 46 indicators across 10
# families. This module is generated from that datafile — regenerate
# against it on updates rather than hand-editing the table.
#
# Certification classes (assurance classes — FedRAMP cautions they only
# loosely align with FIPS-199 impact levels):
#   Class B ("low")      — 41 KSIs required; 5 marked Optional
#   Class C ("moderate") — all 46 KSIs required
#   Class D (High)       — NOT in 20x yet (Phase 4 pilot; stays Rev5)
# The 5 class-varying KSIs: KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM.
#
# Key dates: Consolidated Rules mandatory for all stakeholders
# 2027-01-01; no new Rev5 certifications accepted after 2027-06-11.
# The existing frameworks/federal/fedramp/ module remains the Rev5
# baseline check set — valid for existing authorizations and High.
#
# Query: POST /v1/data/fedramp_20x/main/compliance_report
#
# Fail-closed:
#   - every KSI attestation must be boolean true; absent/false/non-true
#     is a violation for a required KSI
#   - absent target_class evaluates Class C (strictest available);
#     unrecognized target_class is itself a violation and evaluates C
#   - attestations for unknown KSI ids are violations (typo guard);
#     non-object ksis container is a violation
#
# Input contract — input.fedramp_20x.*
#   target_class — "b" | "c" (string, lowercase). Absent -> "c".
#   ksis         — object: {"<KSI id>": true, ...}, e.g.
#                  {"KSI-IAM-ELP": true}. Source: provider assessment
#                  records / automated KSI validation pipeline.

package fedramp_20x.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# Target certification class — absent evaluates Class C (strictest).
default _class := "c"

_class := input.fedramp_20x.target_class if input.fedramp_20x.target_class in {"b", "c"}

_attested(id) if input.fedramp_20x.ksis[id] == true

_optional_at_target(id) if {
	_class == "b"
	ksis[id].optional_at_b
}

# A KSI applies unless it is optional at the target class.
applicable contains id if {
	some id, _ in ksis
	not _optional_at_target(id)
}

violations contains msg if {
	cls := input.fedramp_20x.target_class
	not cls in {"b", "c"}
	msg := sprintf("FedRAMP 20x Input Contract: unrecognized target_class %v — must be \"b\" or \"c\" (evaluated at Class C; Class D/High is not available in 20x yet)", [cls])
}

violations contains msg if {
	ks := input.fedramp_20x.ksis
	not is_object(ks)
	msg := "FedRAMP 20x Input Contract: ksis must be an object of {\"<KSI id>\": true} attestations"
}

violations contains msg if {
	is_object(input.fedramp_20x.ksis)
	some id, _ in input.fedramp_20x.ksis
	not ksis[id]
	msg := sprintf("FedRAMP 20x Input Contract: attestation for unknown KSI id %v — not in the Consolidated Rules KSI set", [id])
}

violations contains msg if {
	some id in applicable
	not _attested(id)
	m := ksis[id]
	msg := sprintf("FedRAMP 20x %s (%s — %s): %s — not attested", [id, m.family, m.name, m.req])
}

_attested_count := count([id | some id in applicable; _attested(id)])

compliance_report := {
	"framework": "FedRAMP 20x Key Security Indicators",
	"source": "FedRAMP Consolidated Rules for 2026 (KSI set stable since 2026-06-24)",
	"target_class": _class,
	"ksis_evaluated": count(applicable),
	"ksis_attested": _attested_count,
	"rev5_sunset": "Consolidated Rules mandatory 2027-01-01; no new Rev5 certifications after 2027-06-11; Class D/High remains Rev5 pending the Phase 4 pilot",
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}

# ── KSI table — generated from fedramp-consolidated-rules.json ──────────────

ksis := {
	"KSI-CED-RAT": {
		"family": "Cybersecurity Education", "optional_at_b": false,
		"name": "Reviewing All Training",
		"req": "The effectiveness of relevant cybersecurity education and training is persistently reviewed, including at least general training for all employees, role-specific training for employees in high risk roles, training for development and engineering staff on secure software delivery, and training for staff involved with incident response or disaster recovery.",
	},
	"KSI-CMT-LMC": {
		"family": "Change Management", "optional_at_b": false,
		"name": "Logging Changes",
		"req": "Modifications to the cloud service offering are logged and monitored.",
	},
	"KSI-CMT-RMV": {
		"family": "Change Management", "optional_at_b": false,
		"name": "Redeploying vs Modifying",
		"req": "Changes to machine-based information resources are executed through the redeployment of version controlled resources rather than direct modification wherever reasonable.",
	},
	"KSI-CMT-RVP": {
		"family": "Change Management", "optional_at_b": false,
		"name": "Reviewing Change Procedures",
		"req": "The effectiveness of documented change management procedures is persistently reviewed.",
	},
	"KSI-CMT-VTD": {
		"family": "Change Management", "optional_at_b": false,
		"name": "Validating Throughout Deployment",
		"req": "Persistent testing and validation of changes throughout deployment is automated.",
	},
	"KSI-CNA-DFP": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Defining Functionality and Privileges",
		"req": "The functionality and privileges for infrastructure and services are strictly defined.",
	},
	"KSI-CNA-EIS": {
		"family": "Cloud Native Architecture", "optional_at_b": true,
		"name": "Enforcing Intended State",
		"req": "Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.",
	},
	"KSI-CNA-IBP": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Implementing Best Practices",
		"req": "The use and configuration of third-party machine-based information resources is persistently compared against the original provider's best practices and guidance.",
	},
	"KSI-CNA-MAT": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Minimizing Attack Surface",
		"req": "Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.",
	},
	"KSI-CNA-OFA": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Optimizing for Availability",
		"req": "Machine-based information resources are persistently reviewed to ensure they are appropriately optimized for high availability and rapid recovery.",
	},
	"KSI-CNA-RNT": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Restricting Network Traffic",
		"req": "Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.",
	},
	"KSI-CNA-RVP": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Reviewing Protections",
		"req": "The effectiveness of protection against denial of service attacks and other unwanted activity for machine-based information resources is persistently reviewed.",
	},
	"KSI-CNA-ULN": {
		"family": "Cloud Native Architecture", "optional_at_b": false,
		"name": "Using Logical Networking",
		"req": "Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.",
	},
	"KSI-IAM-AAM": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Automating Account Management",
		"req": "The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.",
	},
	"KSI-IAM-APM": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Adopting Passwordless Methods",
		"req": "Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.",
	},
	"KSI-IAM-ELP": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Ensuring Least Privilege",
		"req": "Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.",
	},
	"KSI-IAM-JIT": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Authorizing Just-in-Time",
		"req": "A least-privileged, role and attribute-based, and just-in-time security authorization model is used and persistently reviewed for all user and non-user accounts and services.",
	},
	"KSI-IAM-SNU": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Securing Non-User Authentication",
		"req": "Appropriately secure authentication methods are used and persistently reviewed for non-user accounts and services.",
	},
	"KSI-IAM-SUS": {
		"family": "Identity and Access Management", "optional_at_b": false,
		"name": "Responding to Suspicious Activity",
		"req": "Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.",
	},
	"KSI-INR-AAR": {
		"family": "Incident Response", "optional_at_b": false,
		"name": "Generating After Action Reports",
		"req": "Incident after action reports are generated and lessons learned are persistently incorporated.",
	},
	"KSI-INR-RIR": {
		"family": "Incident Response", "optional_at_b": false,
		"name": "Reviewing Incident Response Procedures",
		"req": "The effectiveness of documented incident response procedures is persistently reviewed.",
	},
	"KSI-INR-RPI": {
		"family": "Incident Response", "optional_at_b": false,
		"name": "Reviewing Past Incidents",
		"req": "Past incidents are persistently reviewed for patterns or vulnerabilities that were not previously apparent or identified.",
	},
	"KSI-MLA-ALA": {
		"family": "Monitoring, Logging, and Auditing", "optional_at_b": true,
		"name": "Authorizing Log Access",
		"req": "A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.",
	},
	"KSI-MLA-EVC": {
		"family": "Monitoring, Logging, and Auditing", "optional_at_b": false,
		"name": "Evaluating Configurations",
		"req": "The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.",
	},
	"KSI-MLA-LET": {
		"family": "Monitoring, Logging, and Auditing", "optional_at_b": false,
		"name": "Logging Event Types",
		"req": "A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.",
	},
	"KSI-MLA-OSM": {
		"family": "Monitoring, Logging, and Auditing", "optional_at_b": false,
		"name": "Operating SIEM Capability",
		"req": "A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.",
	},
	"KSI-MLA-RVL": {
		"family": "Monitoring, Logging, and Auditing", "optional_at_b": false,
		"name": "Reviewing Logs",
		"req": "Logs are persistently reviewed and audited.",
	},
	"KSI-PIY-GIV": {
		"family": "Policy and Inventory", "optional_at_b": false,
		"name": "Generating Inventories",
		"req": "Authoritative sources are used to automatically generate real-time inventories of all information resources when needed.",
	},
	"KSI-PIY-RES": {
		"family": "Policy and Inventory", "optional_at_b": false,
		"name": "Reviewing Executive Support",
		"req": "Executive support for achieving the provider's security goals is persistently reviewed and demonstrated.",
	},
	"KSI-PIY-RIS": {
		"family": "Policy and Inventory", "optional_at_b": false,
		"name": "Reviewing Investments in Security",
		"req": "The effectiveness of the provider's investments in achieving security goals is persistently reviewed.",
	},
	"KSI-PIY-RSD": {
		"family": "Policy and Inventory", "optional_at_b": false,
		"name": "Reviewing Security in the SDLC",
		"req": "The effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles is persistently reviewed.",
	},
	"KSI-PIY-RVD": {
		"family": "Policy and Inventory", "optional_at_b": false,
		"name": "Reviewing Vulnerability Disclosures",
		"req": "The effectiveness of the provider's vulnerability disclosure program is persistently reviewed.",
	},
	"KSI-RPL-ABO": {
		"family": "Recovery Planning", "optional_at_b": false,
		"name": "Aligning Backups with Objectives",
		"req": "The alignment of machine-based information resource backups with defined recovery objectives is persistently reviewed.",
	},
	"KSI-RPL-ARP": {
		"family": "Recovery Planning", "optional_at_b": false,
		"name": "Aligning Recovery Plan",
		"req": "The alignment of recovery plans with defined recovery objectives is persistently reviewed.",
	},
	"KSI-RPL-RRO": {
		"family": "Recovery Planning", "optional_at_b": false,
		"name": "Reviewing Recovery Objectives",
		"req": "The desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) are defined and persistently reviewed for alignment with the provider's business needs and capabilities.",
	},
	"KSI-RPL-TRC": {
		"family": "Recovery Planning", "optional_at_b": false,
		"name": "Testing Recovery Capabilities",
		"req": "The capability to recover from incidents and contingencies aligned with defined recovery objectives is persistently tested.",
	},
	"KSI-SCR-MIT": {
		"family": "Supply Chain Risk", "optional_at_b": false,
		"name": "Mitigating Supply Chain Risk",
		"req": "Persistently identify, review, and mitigate potential supply chain risks.",
	},
	"KSI-SCR-MON": {
		"family": "Supply Chain Risk", "optional_at_b": false,
		"name": "Monitoring Supply Chain Risk",
		"req": "Third party software information resources are automatically monitored for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.",
	},
	"KSI-SVC-ACM": {
		"family": "Service Configuration", "optional_at_b": false,
		"name": "Automating Configuration Management",
		"req": "The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.",
	},
	"KSI-SVC-ASM": {
		"family": "Service Configuration", "optional_at_b": false,
		"name": "Automating Secret Management",
		"req": "Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.",
	},
	"KSI-SVC-EIS": {
		"family": "Service Configuration", "optional_at_b": false,
		"name": "Evaluating and Improving Security",
		"req": "Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.",
	},
	"KSI-SVC-PRR": {
		"family": "Service Configuration", "optional_at_b": true,
		"name": "Preventing Residual Risk",
		"req": "Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.",
	},
	"KSI-SVC-RUD": {
		"family": "Service Configuration", "optional_at_b": true,
		"name": "Removing Unwanted Data",
		"req": "Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.",
	},
	"KSI-SVC-SIN": {
		"family": "Service Configuration", "optional_at_b": false,
		"name": "Securing Information",
		"req": "Information is encrypted or otherwise secured from unwanted access or modification.",
	},
	"KSI-SVC-VCM": {
		"family": "Service Configuration", "optional_at_b": true,
		"name": "Validating Communications",
		"req": "The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.",
	},
	"KSI-SVC-VRI": {
		"family": "Service Configuration", "optional_at_b": false,
		"name": "Validating Resource Integrity",
		"req": "Use cryptographic methods to validate the integrity of machine-based information resources.",
	},
}
