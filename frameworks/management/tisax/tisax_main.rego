# METADATA
# title: "TISAX — VDA ISA2027.1 (Information Security, Prototype Protection, Data Protection)"
# custom:
#   class: compliance
#   framework: tisax
#   source: enx
#   domains: [automotive]
#   coverage:
#     checks: 77
#     cited: 77
#     expected: 77
#     found: 77
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package tisax.main

import rego.v1

# TISAX — Trusted Information Security Assessment Exchange
# Catalogue: VDA ISA2027.1 (Information Security Assessment), English workbook dated 2026-09-30.
# ISA2027 applies to TISAX assessments ordered from 2027-01-01 (ISA 6 serves orders placed before then).
#
# NOT APPROVED BY ENX. This module is an independent work. It is not issued, reviewed or endorsed by the
# ENX Association or the VDA, and it is not a TISAX assessment, label or result.
# VDA ISA © ENX Association, used under CC BY-ND 4.0 with the ENX additional grant; checks written
# independently. Only the catalogue's control numbers and short paraphrased labels are used here; no
# question, objective or requirement text from the catalogue is carried. Licence of the catalogue:
# https://creativecommons.org/licenses/by-nd/4.0/ plus Section 9 of the workbook's licence sheet.
# Catalogue download: https://portal.enx.com/isa2027-en.xlsx
#
# Scope: every active control number of the three catalogue parts, 77 in all.
#   Information Security   chapters 1-7   45 controls (13 evaluated from system facts, 32 attested)
#   Prototype Protection   chapter 8      20 controls (8.1.1-8.1.13, 8.2.1-8.2.7; all attested)
#   Data Protection        chapter 9      12 controls (9.1.1-9.8.1; all attested)
# 3.1.2 is marked superseded in the catalogue (its content moved to 1.6.3, 5.2.8 and 5.2.9) and is not
# assessed; it is listed under not_assessed in the report.
#
# Input contract (everything under input.tisax):
#   scope.prototype_protection / scope.data_protection
#       Information Security always applies. Prototype Protection and Data Protection are evaluated unless the
#       flag is the boolean false (absent or any other value = in scope, so missing data never shrinks scope).
#   evidence.<area>.<fact>
#       System facts for the 13 technical controls, aggregated across the hosts in scope by the collector
#       (worst value wins). The facts and limits are listed in evidence_spec below; the limits are this
#       library's defaults, not catalogue values. A fact that is absent or of the wrong type is
#       evidence_missing, never a pass. A pass covers the technical facts only: the organisational side of
#       these controls is outside what a host can show.
#   attestations["<control id>"] = {attested: true, by: "<name>", date: "<date>", maturity_level: <0-5>}
#       The only accepted evidence for an organisational control. Absent = evidence_missing; present but not
#       attested or without by/date = not_attested; maturity_level is optional, and when given it must be a
#       number of at least 3 (the target maturity level of a TISAX assessment), otherwise the control fails.
#   assessment_level, entity_name, company_scope, assessment_date (top level of input) are echoed in the report.
#
# Report contract: total_controls = controls in scope; failed_controls = controls in scope that do not pass;
# control_results lists every control in scope in catalogue order with status pass | fail | evidence_missing |
# not_attested and basis evidence | attestation. A compliant result means every control in scope passed here.
#
# Ids changed in this rebuild: the module used to cite its own numbering under an ISA 6.0.3 heading; every id
# is now an ISA2027.1 control number (see CHANGELOG).
#
# OPA endpoint: POST http://<host>:8182/v1/data/tisax/main/compliance_report

catalog := "VDA ISA2027.1 (English workbook 2026-09-30)"

# Control table: catalogue control number -> short label (paraphrased) and what this module requires, in this
# library's own words.
isa_controls := {
	# 1 IS policies and organisation
	"1.1.1": {"title": "Information security policies", "text": "Attest that a management-approved set of security policies exists, is published to the people it binds and is reviewed on a set schedule"},
	"1.2.1": {"title": "ISMS management", "text": "Attest that an information security management system with a defined scope is run, measured and improved"},
	"1.2.2": {"title": "Security responsibilities", "text": "Attest that security roles are named, staffed, free of conflicting duties and known across the organisation"},
	"1.2.3": {"title": "Security in projects", "text": "Attest that projects classify their information and plan security measures from the start"},
	"1.3.1": {"title": "Asset inventory", "text": "Attest that information assets and the systems holding them are listed with an owner"},
	"1.3.2": {"title": "Asset classification", "text": "Attest that assets carry a protection-need class and are handled according to it"},
	"1.3.3": {"title": "Approved external IT services", "text": "Attest that cloud and other external IT services are vetted and approved before they process company information"},
	"1.3.4": {"title": "Approved software", "text": "No software outside the approved list is installed, and package signature checking is on"},
	"1.4.1": {"title": "Security risk management", "text": "Attest that security risks are identified, rated, owned and treated on a repeating cycle"},
	"1.5.1": {"title": "Compliance checks in processes", "text": "Attest that adherence to the security rules is checked on a plan and deviations are followed up"},
	"1.5.2": {"title": "Independent ISMS review", "text": "Attest that a party independent of the ISMS reviews it at planned intervals"},
	"1.6.1": {"title": "Reporting security events", "text": "Attest that staff and partners have a known, low-friction way to report security events"},
	"1.6.2": {"title": "Handling reported events", "text": "Attest that reported events are triaged, handled, closed and learned from"},
	"1.6.3": {"title": "Crisis preparedness", "text": "Attest that a crisis organisation, plans and exercises exist for severe disruptions"},
	# 2 Human resources
	"2.1.1": {"title": "Staff suitability for sensitive roles", "text": "Attest that people placed in sensitive roles are checked for suitability as far as law allows"},
	"2.1.2": {"title": "Staff security obligations", "text": "Attest that every employee and contractor is bound by contract to follow the security rules"},
	"2.1.3": {"title": "Awareness and training", "text": "Attest that staff receive security awareness and training on joining and at regular intervals"},
	"2.1.4": {"title": "Mobile working", "text": "Attest that rules for working away from company premises exist and are applied"},
	# 3 Physical security
	"3.1.1": {"title": "Security zones", "text": "Attest that premises are divided into zones with physical protection matched to what they hold"},
	"3.1.3": {"title": "Supporting assets", "text": "Attest that equipment and media supporting information are handled across their life, including secure disposal"},
	"3.1.4": {"title": "Mobile devices and storage media", "text": "Full-disk encryption is on and removable storage is restricted on the devices in scope"},
	# 4 Identity and access management
	"4.1.1": {"title": "Identification means", "text": "Attest that badges, tokens and similar identification means are issued, tracked and withdrawn under control"},
	"4.1.2": {"title": "Secure user access", "text": "Privileged access needs multi-factor authentication, repeated failed logins lock out and idle sessions end within 15 minutes"},
	"4.1.3": {"title": "Accounts and credentials", "text": "Passwords are at least 12 characters, and there are no shared, password-less or default-credential accounts"},
	"4.2.1": {"title": "Access rights", "text": "No privileged account lacks approval, direct remote root login is refused and dormant accounts are disabled"},
	# 5 IT and cyber security
	"5.1.1": {"title": "Cryptography", "text": "The system-wide crypto policy is an approved one and weak algorithms are not allowed"},
	"5.1.2": {"title": "Protection in transit", "text": "TLS 1.2 or later is the minimum and no clear-text network services are enabled"},
	"5.2.1": {"title": "Change management", "text": "Attest that changes to systems are requested, assessed, approved and recorded"},
	"5.2.2": {"title": "Separated environments", "text": "Attest that development and test run apart from production"},
	"5.2.3": {"title": "Malware protection", "text": "An anti-malware agent runs with on-access scanning and signatures at most 7 days old"},
	"5.2.4": {"title": "Event logging", "text": "The audit daemon runs, logs are forwarded to central collection and the clock is synchronised"},
	"5.2.5": {"title": "Vulnerability management", "text": "A vulnerability scan ran within 30 days and no critical finding is past its fix date"},
	"5.2.6": {"title": "Technical system audits", "text": "A technical security test ran within 365 days and no high finding from it is past its fix date"},
	"5.2.7": {"title": "Network management", "text": "A host firewall is on and denies inbound traffic by default"},
	"5.2.8": {"title": "IT service continuity", "text": "Attest that continuity plans for critical IT services exist and are exercised"},
	"5.2.9": {"title": "Backup and recovery", "text": "Backups are configured, the last good backup is at most 7 days old and a restore was tested within 365 days"},
	"5.3.1": {"title": "Security in IT service development", "text": "Attest that security requirements are set and verified when IT services are built or changed"},
	"5.3.2": {"title": "Network service requirements", "text": "Attest that security requirements for network services are written down and agreed with providers"},
	"5.3.3": {"title": "Exit from external IT services", "text": "Attest that leaving an external IT service returns the data and removes it from the provider"},
	"5.3.4": {"title": "Shared external IT services", "text": "Attest that information in multi-tenant external services is protected from other tenants"},
	# 6 Supplier relationships
	"6.1.1": {"title": "Contractors and partners", "text": "Attest that contractors and partners are held to security requirements matched to the information they handle"},
	"6.1.2": {"title": "Non-disclosure agreements", "text": "Attest that confidentiality is agreed in writing before sensitive information is exchanged"},
	"6.1.3": {"title": "Provider responsibility split", "text": "Attest that the security duties of each external IT service provider and of the organisation are defined"},
	# 7 Compliance
	"7.1.1": {"title": "Legal and contractual compliance", "text": "Attest that applicable laws and contract terms are tracked and met"},
	"7.1.2": {"title": "Personal data in security measures", "text": "Attest that privacy rules are respected when security measures process personal data"},
	# 8 Prototype protection, organisational
	"8.1.1": {"title": "Prototype protection rules and roles", "text": "Attest that prototype protection rules exist and named people are responsible for them"},
	"8.1.2": {"title": "Order-specific prototype rules", "text": "Attest that each customer order's prototype handling terms are captured and applied"},
	"8.1.3": {"title": "Prototype awareness", "text": "Attest that everyone on prototype work takes part in recorded prototype awareness training"},
	"8.1.4": {"title": "Staff suitability for prototype areas", "text": "Attest that people working in prototype areas are checked for suitability"},
	"8.1.5": {"title": "Prototype confidentiality obligations", "text": "Attest that valid, enforceable confidentiality obligations cover prototype work"},
	"8.1.6": {"title": "Subcontracting prototype work", "text": "Attest that customer conditions for using subcontractors are known and met"},
	"8.1.7": {"title": "Access to security areas", "text": "Attest that admission to prototype security areas follows a defined approval process"},
	"8.1.8": {"title": "Visitor management", "text": "Attest that visitors are registered and escorted in prototype areas"},
	"8.1.9": {"title": "Camera devices in security areas", "text": "Attest that bringing and using camera-equipped devices in security areas is governed"},
	"8.1.10": {"title": "Image capture and image material", "text": "Attest that taking prototype images and storing or sharing them is governed"},
	"8.1.11": {"title": "Prototype incident handling", "text": "Attest that prototype security incidents are reported to the customer and handled as agreed"},
	"8.1.12": {"title": "Traceability of protected items", "text": "Attest that protected vehicles and parts are documented and traceable through every handling step"},
	"8.1.13": {"title": "Disposal and return of protected items", "text": "Attest that protected items no longer needed are scrapped, recycled or returned as the customer requires"},
	# 8 Prototype protection, physical and environmental
	"8.2.1": {"title": "Physical security concept", "text": "Attest that a written physical security concept for prototype sites sets the minimum measures"},
	"8.2.2": {"title": "Perimeter security", "text": "Attest that the site perimeter keeps unauthorised people away from protected property"},
	"8.2.3": {"title": "Tamper-resistant building shell", "text": "Attest that the shell of security areas resists opening or removal of parts with ordinary tools"},
	"8.2.4": {"title": "Screening from view", "text": "Attest that protected items cannot be seen from outside the security areas"},
	"8.2.5": {"title": "Entry access control", "text": "Attest that entry to security areas is enforced by access control"},
	"8.2.6": {"title": "Intrusion detection", "text": "Attest that security areas are watched by intrusion detection with a defined response"},
	"8.2.7": {"title": "Client separation on site", "text": "Attest that different customers' prototypes on one site are kept apart"},
	# 9 Data protection
	"9.1.1": {"title": "Data protection policies", "text": "Attest that data protection policies exist, are approved and are kept current"},
	"9.2.1": {"title": "Data protection responsibilities", "text": "Attest that data protection roles, including a data protection officer where required, are assigned"},
	"9.3.1": {"title": "Record of processing activities", "text": "Attest that processing activities are identified and kept in a current record"},
	"9.4.1": {"title": "Data protection impact assessment", "text": "Attest that high-risk processing is assessed before it starts and the result is acted on"},
	"9.5.1": {"title": "Data transfers", "text": "Attest that transfers of personal data are known, lawful and controlled"},
	"9.5.2": {"title": "Obligations passed to subcontractors", "text": "Attest that data protection terms flow down to subcontractors and partners and are checked"},
	"9.5.3": {"title": "Third-country transfers", "text": "Attest that transfers outside the home jurisdiction have a legal basis and safeguards"},
	"9.6.1": {"title": "Data subject requests", "text": "Attest that requests from data subjects are recognised, answered and recorded in time"},
	"9.6.2": {"title": "Data protection incidents", "text": "Attest that personal data breaches are assessed, notified where required and recorded"},
	"9.7.1": {"title": "Staff confidentiality", "text": "Attest that staff handling personal data are bound to confidentiality"},
	"9.7.2": {"title": "Data protection training", "text": "Attest that staff handling personal data are trained in data protection"},
	"9.8.1": {"title": "Processing on instruction", "text": "Attest that processing done for a customer follows that customer's documented instructions"},
}

standard_total := 77 # active control numbers in the three parts of the ISA2027.1 workbook (3.1.2 superseded)

not_assessed := [{"number": "3.1.2", "reason": "superseded in ISA2027.1 (content moved to 1.6.3, 5.2.8 and 5.2.9)"}]

chapters := {
	"1": "IS policies and organisation",
	"2": "Human resources",
	"3": "Physical security",
	"4": "Identity and access management",
	"5": "IT and cyber security",
	"6": "Supplier relationships",
	"7": "Compliance",
	"8": "Prototype protection",
	"9": "Data protection",
}

parts := {
	"information_security": "Information Security (chapters 1-7)",
	"prototype_protection": "Prototype Protection (chapter 8)",
	"data_protection": "Data Protection (chapter 9)",
}

# Facts for the 13 technical controls, read from input.tisax.evidence.<fact>. Tests: true / false (boolean),
# zero (number == 0), max / min (number <= / >= limit). Limits are this library's defaults.
evidence_spec := {
	"1.3.4": [
		{"fact": "software.unapproved_packages", "test": "zero"},
		{"fact": "software.package_signature_verification", "test": "true"},
	],
	"3.1.4": [
		{"fact": "endpoint.disk_encryption_enabled", "test": "true"},
		{"fact": "endpoint.removable_storage_restricted", "test": "true"},
	],
	"4.1.2": [
		{"fact": "authentication.mfa_privileged_access", "test": "true"},
		{"fact": "authentication.failed_login_lockout", "test": "true"},
		{"fact": "authentication.session_idle_timeout_minutes", "test": "max", "limit": 15},
	],
	"4.1.3": [
		{"fact": "accounts.password_min_length", "test": "min", "limit": 12},
		{"fact": "accounts.shared_accounts", "test": "zero"},
		{"fact": "accounts.empty_password_accounts", "test": "zero"},
		{"fact": "accounts.default_credential_accounts", "test": "zero"},
	],
	"4.2.1": [
		{"fact": "access.unapproved_privileged_accounts", "test": "zero"},
		{"fact": "access.remote_root_login_permitted", "test": "false"},
		{"fact": "access.dormant_enabled_accounts", "test": "zero"},
	],
	"5.1.1": [
		{"fact": "crypto.system_policy_approved", "test": "true"},
		{"fact": "crypto.weak_algorithms_permitted", "test": "false"},
	],
	"5.1.2": [
		{"fact": "transport.tls_min_version", "test": "min", "limit": 1.2},
		{"fact": "transport.cleartext_services_enabled", "test": "zero"},
	],
	"5.2.3": [
		{"fact": "malware.agent_running", "test": "true"},
		{"fact": "malware.on_access_scanning", "test": "true"},
		{"fact": "malware.signature_age_days", "test": "max", "limit": 7},
	],
	"5.2.4": [
		{"fact": "logging.audit_daemon_active", "test": "true"},
		{"fact": "logging.central_forwarding", "test": "true"},
		{"fact": "logging.time_synchronized", "test": "true"},
	],
	"5.2.5": [
		{"fact": "vulnerabilities.last_scan_age_days", "test": "max", "limit": 30},
		{"fact": "vulnerabilities.critical_past_due", "test": "zero"},
	],
	"5.2.6": [
		{"fact": "system_audit.last_test_age_days", "test": "max", "limit": 365},
		{"fact": "system_audit.high_findings_past_due", "test": "zero"},
	],
	"5.2.7": [
		{"fact": "network.host_firewall_enabled", "test": "true"},
		{"fact": "network.default_deny_inbound", "test": "true"},
	],
	"5.2.9": [
		{"fact": "backup.configured", "test": "true"},
		{"fact": "backup.last_success_age_days", "test": "max", "limit": 7},
		{"fact": "backup.last_restore_test_age_days", "test": "max", "limit": 365},
	],
}

target_maturity_level := 3

# ── Input ────────────────────────────────────────────────────────────────────

_in := input.tisax if is_object(input.tisax)

else := {}

_obj(x) := x if is_object(x)

else := {}

_scope := _obj(object.get(_in, "scope", {}))

_evidence := _obj(object.get(_in, "evidence", {}))

_attestations := _obj(object.get(_in, "attestations", {}))

_part_of(id) := "prototype_protection" if {
	startswith(id, "8.")
} else := "data_protection" if {
	startswith(id, "9.")
} else := "information_security"

_part_in_scope("information_security")

_part_in_scope(p) if {
	p in {"prototype_protection", "data_protection"}
	object.get(_scope, p, true) != false
}

parts_in_scope := sort([p | some p, _ in parts; _part_in_scope(p)])

parts_not_in_scope := sort([p | some p, _ in parts; not _part_in_scope(p)])

applicable := {id | some id, _ in isa_controls; _part_in_scope(_part_of(id))}

_basis(id) := "evidence" if {
	evidence_spec[id]
} else := "attestation"

# ── Technical controls ───────────────────────────────────────────────────────

_fact(f) := object.get(_evidence, split(f.fact, "."), null)

_typed(f) if {
	f.test in {"true", "false"}
	is_boolean(_fact(f))
}

_typed(f) if {
	f.test in {"zero", "max", "min"}
	is_number(_fact(f))
}

_meets(f) if {
	f.test == "true"
	_fact(f) == true
}

_meets(f) if {
	f.test == "false"
	_fact(f) == false
}

_meets(f) if {
	f.test == "zero"
	v := _fact(f)
	is_number(v)
	v == 0
}

_meets(f) if {
	f.test == "max"
	v := _fact(f)
	is_number(v)
	v <= f.limit
}

_meets(f) if {
	f.test == "min"
	v := _fact(f)
	is_number(v)
	v >= f.limit
}

_want := {"true": "true", "false": "false", "zero": "0"}

_wanted(f) := _want[f.test]

_wanted(f) := sprintf("at most %v", [f.limit]) if f.test == "max"

_wanted(f) := sprintf("at least %v", [f.limit]) if f.test == "min"

_missing_facts(id) := sort([concat("", ["input.tisax.evidence.", f.fact]) |
	some f in evidence_spec[id]
	not _typed(f)
])

_failed_facts(id) := sort([sprintf("input.tisax.evidence.%v is %v, required %v", [f.fact, _fact(f), _wanted(f)]) |
	some f in evidence_spec[id]
	_typed(f)
	not _meets(f)
])

# ── Organisational controls ──────────────────────────────────────────────────

_att(id) := object.get(_attestations, id, null)

_signed(a) if {
	is_object(a)
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_maturity_ok(a) if not "maturity_level" in object.keys(a)

_maturity_ok(a) if {
	ml := a.maturity_level
	is_number(ml)
	ml >= target_maturity_level
}

_att_path(id) := sprintf("input.tisax.attestations[%q]", [id])

# ── Status per control ───────────────────────────────────────────────────────

_status(id) := s if {
	_basis(id) == "evidence"
	s := _evidence_status(id)
}

_status(id) := s if {
	_basis(id) == "attestation"
	s := _attestation_status(id)
}

_evidence_status(id) := "fail" if {
	count(_failed_facts(id)) > 0
} else := "evidence_missing" if {
	count(_missing_facts(id)) > 0
} else := "pass"

_attestation_status(id) := "evidence_missing" if {
	_att(id) == null
} else := "not_attested" if {
	not _signed(_att(id))
} else := "fail" if {
	not _maturity_ok(_att(id))
} else := "pass"

_detail(id, "fail") := concat("", ["fail — ", concat("; ", _failed_facts(id))]) if _basis(id) == "evidence"

_detail(id, "evidence_missing") := sprintf("evidence missing — not collected or not of the expected type: %v", [concat(", ", _missing_facts(id))]) if _basis(id) == "evidence"

_detail(id, "evidence_missing") := sprintf("evidence missing — no attestation at %v; this organisational control is met only by {attested: true, by, date}", [_att_path(id)]) if _basis(id) == "attestation"

_detail(id, "not_attested") := sprintf("not attested — %v must be {attested: true, by: <name>, date: <date>}", [_att_path(id)])

_detail(id, "fail") := _maturity_detail(_att(id).maturity_level) if _basis(id) == "attestation"

_maturity_detail(ml) := sprintf("fail — attested maturity level %v is below the target level %v", [ml, target_maturity_level]) if is_number(ml)

_maturity_detail(ml) := sprintf("fail — maturity_level must be a number (target %v or higher), got %v of type %v", [target_maturity_level, ml, type_name(ml)]) if not is_number(ml)

_status_of[id] := _status(id) if some id in applicable

_finding(id) := sprintf("TISAX ISA2027 %v (%v): %v", [id, isa_controls[id].title, _detail(id, _status_of[id])])

_control_messages := {_finding(id) | some id, st in _status_of; st != "pass"}

# Input problems that are not controls but still block a compliant result.
_input_notes contains sprintf("TISAX ISA2027 input: attestation key %q is not an active ISA2027.1 control number", [k]) if {
	some k, _ in _attestations
	not isa_controls[k]
}

_input_notes contains "TISAX ISA2027 input: input.tisax is missing or not an object; no control can be evaluated" if {
	not is_object(object.get(input, "tisax", null))
}

violations := _control_messages | _input_notes

# ── Report ───────────────────────────────────────────────────────────────────

_num_key(id) := [to_number(x) | some x in split(id, ".")]

_order := [pair[1] | some pair in sort([[_num_key(id), id] | some id in applicable])]

control_results := [{
	"id": id,
	"title": isa_controls[id].title,
	"part": _part_of(id),
	"chapter": chapters[split(id, ".")[0]],
	"basis": _basis(id),
	"status": _status_of[id],
	"findings": [_finding(id) | _status_of[id] != "pass"],
} |
	some id in _order
]

control_result_counts := {s: count([id | some id, st in _status_of; st == s]) | some s in ["pass", "fail", "evidence_missing", "not_attested"]}

failed_control_ids := [id | some id in _order; _status_of[id] != "pass"]

part_results[p] := {
	"title": parts[p],
	"in_scope": p in parts_in_scope,
	"controls": count(ids),
	"evidence_based": count([id | some id in ids; _basis(id) == "evidence"]),
	"attestation_based": count([id | some id in ids; _basis(id) == "attestation"]),
	"passed": count([id | some id in ids; object.get(_status_of, id, "") == "pass"]),
	"not_passed": count([id | some id in ids; _part_in_scope(p); object.get(_status_of, id, "") != "pass"]),
} if {
	some p, _ in parts
	ids := [id | some id, _ in isa_controls; _part_of(id) == p]
}

default compliant := false

compliant if {
	count(applicable) > 0
	count(violations) == 0
}

default assessment_level := "unknown"

assessment_level := input.assessment_level

default company_scope := "unknown"

company_scope := input.company_scope

default entity_name := "unknown"

entity_name := input.entity_name

default assessment_date := "unknown"

assessment_date := input.assessment_date

compliance_report := {
	"framework": "TISAX (Trusted Information Security Assessment Exchange)",
	"framework_key": "tisax",
	"catalog": catalog,
	"applies_from": "2027-01-01",
	"approval": "Not approved by ENX: an independent check set, not a TISAX assessment or label",
	"attribution": "VDA ISA © ENX Association, used under CC BY-ND 4.0 with the ENX additional grant; checks written independently",
	"standard_total": 77, # literal so the coverage stamp reads it; equals standard_total (tested)
	"assessment_level": assessment_level,
	"entity_name": entity_name,
	"company_scope": company_scope,
	"assessed_at": assessment_date,
	"parts_in_scope": parts_in_scope,
	"parts_not_in_scope": parts_not_in_scope,
	"part_results": part_results,
	"not_assessed": not_assessed,
	"compliant": compliant,
	"total_controls": count(applicable),
	"failed_controls": count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"violations": violations,
	"violation_count": count(violations),
}
