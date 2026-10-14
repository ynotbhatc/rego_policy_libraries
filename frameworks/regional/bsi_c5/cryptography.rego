# METADATA
# title: "BSI C5:2026 — Cryptography and Key Management (CRY), 19 criteria"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 20
#     cited: 19
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.cryptography

import rego.v1

# BSI C5:2026 (Version 1.0.1), section 5.8 Cryptography and Key Management (CRY), p. 142.
# 19 criteria, ids exactly as printed in the catalogue; 32 basic, 1 additional (sharpening) and 5
# additional (complementing) subcriteria; 4 of the 19 criteria carry an additional criterion.
# Titles are BSI's; `summary` is AAC's one-line paraphrase of the basic subcriteria, not catalogue text
# (the catalogue is CC BY-ND 4.0). Every criterion is attested, fail-closed:
#   input.bsi_c5.criteria["CRY-01"] == true
# Source, effective date, legacy lineage and input-contract checks: bsi_c5_main.rego.

area := {"code": "CRY", "section": "5.8", "name": "Cryptography and Key Management", "page": 142}

criteria := {
	"CRY-01": {
		"title": "Policy for the Use of Cryptographic Mechanisms",
		"summary": "Document policies for state-of-the-art cryptographic mechanisms, protocols and key management for the service",
		"page": 142,
		"basic": ["CRY-01.01B", "CRY-01.02B"],
		"additional_sharpening": [],
		"additional_complementing": ["CRY-01.01AC", "CRY-01.02AC", "CRY-01.03AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"CRY-02": {
		"title": "Cryptographic Change Management",
		"summary": "Assess the impact of changes to cryptographic systems, including on customer-managed keys, through change management",
		"page": 144,
		"basic": ["CRY-02.01B", "CRY-02.02B", "CRY-02.03B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-03": {
		"title": "Review of Cryptography Practices",
		"summary": "Audit encryption, authentication and key management practices at least annually and after cryptography-related incidents",
		"page": 145,
		"basic": ["CRY-03.01B", "CRY-03.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-04": {
		"title": "Protection of Data for Transmission (Transport Protection)",
		"summary": "Use state-of-the-art encryption and authentication for transmission of customer and derived data over public networks and for remote access",
		"page": 146,
		"basic": ["CRY-04.01B", "CRY-04.02B"],
		"additional_sharpening": ["CRY-04.01AS"],
		"additional_complementing": [],
		"sharpens": [["CRY-04.01AS", "CRY-04.01B"]],
		"has_additional": true,
	},
	"CRY-05": {
		"title": "Encryption of Sensitive Data at Rest",
		"summary": "Encrypt customer data at rest, with keys in general accessible only to the customer and any provider access governed by IAM-07 and agreed procedures",
		"page": 147,
		"basic": ["CRY-05.01B", "CRY-05.02B", "CRY-05.03B", "CRY-05.04B", "CRY-05.05B"],
		"additional_sharpening": [],
		"additional_complementing": ["CRY-05.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"CRY-06": {
		"title": "Secure Key Generation",
		"summary": "Generate keys securely using secure random bit generators or keys derived from them",
		"page": 148,
		"basic": ["CRY-06.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-07": {
		"title": "Rotation of Cryptographic Keys",
		"summary": "Rotate cryptographic keys on a schedule aligned with the cryptography policy, or communicate a risk-based decision not to rotate",
		"page": 148,
		"basic": ["CRY-07.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-08": {
		"title": "Public-Key Certificate Issuance",
		"summary": "Issue and obtain public-key certificates securely, including identity verification before issuance",
		"page": 149,
		"basic": ["CRY-08.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-09": {
		"title": "Secure Key Provisioning",
		"summary": "Provision and activate cryptographic keys securely, with identity and authorisation verification",
		"page": 150,
		"basic": ["CRY-09.01B", "CRY-09.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-10": {
		"title": "Secure Storage of Keys",
		"summary": "Store cryptographic keys securely, separating key management from application layers and addressing key residency",
		"page": 150,
		"basic": ["CRY-10.01B"],
		"additional_sharpening": [],
		"additional_complementing": ["CRY-10.01AC"],
		"sharpens": [],
		"has_additional": true,
	},
	"CRY-11": {
		"title": "Cryptographic Key Archival",
		"summary": "Archive cryptographic keys securely with restricted, authorised access",
		"page": 151,
		"basic": ["CRY-11.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-12": {
		"title": "Cryptographic Key Transition Management",
		"summary": "Monitor, review and approve transitions of cryptographic keys, including into and out of suspension",
		"page": 151,
		"basic": ["CRY-12.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-13": {
		"title": "Handling of Compromised Keys",
		"summary": "Restrict use of compromised keys to controlled decryption or verification and notify affected customers",
		"page": 152,
		"basic": ["CRY-13.01B", "CRY-13.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-14": {
		"title": "Secure Deactivation of Cryptographic Keys",
		"summary": "Deactivate expired cryptographic keys so they are no longer used for encryption or signing",
		"page": 153,
		"basic": ["CRY-14.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-15": {
		"title": "Requirements for Pre-Shared Keys",
		"summary": "Where pre-shared keys or wildcard certificates are used, apply dedicated procedures for their secure use and provisioning",
		"page": 153,
		"basic": ["CRY-15.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-16": {
		"title": "Operational Continuity for Key Management",
		"summary": "Assess HSM key backup versus redundancy to ensure operational continuity of key management",
		"page": 154,
		"basic": ["CRY-16.01B", "CRY-16.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-17": {
		"title": "Cryptographic Key Lifecycle Management",
		"summary": "Monitor and record the full lifecycle of cryptographic keys and materials from creation to destruction",
		"page": 155,
		"basic": ["CRY-17.01B", "CRY-17.02B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-18": {
		"title": "Usage of External Key Management Systems",
		"summary": "Where external key management systems are integrated, establish procedures and safeguards for their use",
		"page": 155,
		"basic": ["CRY-18.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
	"CRY-19": {
		"title": "Secure Handling of Customer Managed Keys",
		"summary": "Handle customer-managed keys (e.g. BYOK) securely through defined procedures and technical safeguards",
		"page": 156,
		"basic": ["CRY-19.01B"],
		"additional_sharpening": [],
		"additional_complementing": [],
		"sharpens": [],
		"has_additional": false,
	},
}

_container := c if {
	c := input.bsi_c5.criteria
	is_object(c)
}

_attested(id) if _container[id] == true

default compliant := false

compliant if count(violations) == 0

# Fail closed: an unattested criterion (absent, false, or any non-true value) is a gap.
violations contains msg if {
	some id, c in criteria
	not _attested(id)
	msg := sprintf("BSI C5:2026 %v %v (%v): not attested — input.bsi_c5.criteria[\"%v\"] must be true", [id, c.title, area.name, id])
}

criteria_status[id] := s if {
	some id, c in criteria
	s := {
		"area": area.code,
		"title": c.title,
		"basis": "attestation",
		"has_additional": c.has_additional,
		"satisfied": _satisfied_bool(id),
	}
}

_satisfied_bool(id) if _attested(id)

else := false

compliance_report := {
	"area": area.code,
	"area_name": area.name,
	"section": area.section,
	"criteria_total": count(criteria),
	"criteria_satisfied": count([id | some id, _ in criteria; _attested(id)]),
	"criteria_fact_evaluated": 0,
	"criteria_attested_basis": count(criteria),
	"criteria_with_additional": count([id | some id, c in criteria; c.has_additional]),
	"gaps": sort([id | some id, _ in criteria; not _attested(id)]),
	"criteria": criteria_status,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
