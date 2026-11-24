# METADATA
# title: "EU Cyber Resilience Act (CRA) — Annex I Part I"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 20
#     cited: 20
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cra.essential_requirements

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex I Part I
# Essential cybersecurity requirements for products with digital elements (PDE).
#
# These requirements apply to every product with digital elements placed on
# the EU market. Manufacturers must ensure compliance "by design" before
# CE marking is permitted (Articles 32-33).

default compliant := false

# Annex I Part I (1) — Security by design
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "security_by_design", "threat_modeled"])
	text := "CRA Annex I.1(a): Product not designed/developed with appropriate level of cybersecurity based on risk assessment"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "security_by_design", "documented_assessment"])
	text := "CRA Annex I.1(b): Cybersecurity risk assessment not documented"
	msg := concat("", [text, note])
}

# Annex I Part I (2) — Secure default configuration
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "default_config", "secure_out_of_box"])
	text := "CRA Annex I.2(a): Product not delivered with a secure-by-default configuration"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "default_config", "allows_reset_to_secure_defaults"])
	text := "CRA Annex I.2(b): Product does not allow reset to the original secure default configuration"
	msg := concat("", [text, note])
}

# Annex I Part I (3) — Vulnerability protection
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "vulnerability_protection", "security_updates_distinct"])
	text := "CRA Annex I.3(a): Security updates not delivered separately from feature updates"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "vulnerability_protection", "automatic_updates_default"])
	text := "CRA Annex I.3(b): Automatic security update mechanism not available or not enabled by default"
	msg := concat("", [text, note])
}

# Annex I Part I (4) — Protection from unauthorized access
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "access_protection", "authentication_state_of_the_art"])
	text := "CRA Annex I.4(a): Authentication mechanisms not state-of-the-art (e.g., MFA, hardware-backed keys for sensitive functions)"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "access_protection", "identity_access_management"])
	text := "CRA Annex I.4(b): Identity and access management controls not implemented"
	msg := concat("", [text, note])
}

# Annex I Part I (5) — Confidentiality protection
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "confidentiality", "data_at_rest_encrypted"])
	text := "CRA Annex I.5(a): Stored/personal data not protected by encryption or comparable mechanisms"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "confidentiality", "data_in_transit_encrypted"])
	text := "CRA Annex I.5(b): Transmitted data not protected via state-of-the-art encryption"
	msg := concat("", [text, note])
}

# Annex I Part I (6) — Integrity protection
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "integrity", "code_signing_enforced"])
	text := "CRA Annex I.6(a): Product does not protect integrity of stored/transmitted code and configuration (no code signing)"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "integrity", "tamper_detection"])
	text := "CRA Annex I.6(b): Tamper detection / anti-rollback mechanisms not implemented"
	msg := concat("", [text, note])
}

# Annex I Part I (7) — Data minimization
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "data_minimization", "only_necessary_data_processed"])
	text := "CRA Annex I.7: Product processes data beyond what is necessary for its intended use"
	msg := concat("", [text, note])
}

# Annex I Part I (8) — Availability protection
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "availability", "dos_protection"])
	text := "CRA Annex I.8(a): Product not protected against denial-of-service attacks affecting essential functions"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "availability", "essential_functions_preserved"])
	text := "CRA Annex I.8(b): Essential functions not preserved during/after a security incident"
	msg := concat("", [text, note])
}

# Annex I Part I (9) — Limit attack surfaces
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "attack_surface", "external_interfaces_minimized"])
	text := "CRA Annex I.9: External interfaces and attack surfaces not minimized"
	msg := concat("", [text, note])
}

# Annex I Part I (10) — Mitigate exploitation impact
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "exploitation_mitigation", "techniques_implemented"])
	text := "CRA Annex I.10: Exploitation mitigation techniques (sandboxing, ASLR, control-flow integrity) not implemented"
	msg := concat("", [text, note])
}

# Annex I Part I (11) — Security-relevant data logging
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "logging", "security_events_recorded"])
	text := "CRA Annex I.11(a): Security-relevant events not recorded/monitored"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "logging", "user_can_opt_out"])
	text := "CRA Annex I.11(b): User cannot opt out of non-essential logging (privacy violation)"
	msg := concat("", [text, note])
}

# Annex I Part I (12) — Secure data deletion
violation contains msg if {
	note := _unmet(_root, ["essential_requirements", "data_deletion", "secure_erase_available"])
	text := "CRA Annex I.12: Secure data deletion mechanism (factory reset / cryptographic erase) not provided"
	msg := concat("", [text, note])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Annex I Part I",
	"name": "Essential cybersecurity requirements",
	"controls_evaluated": 21,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
