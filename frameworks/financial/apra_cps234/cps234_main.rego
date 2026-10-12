# APRA Prudential Standard CPS 234 Information Security (Australia, July 2019,
# in force 1 July 2019; third-party-managed assets from the earlier of
# contract renewal or 1 July 2020).
#
# Source: apra.gov.au — cps_234_july_2019_for_public_release.pdf. Binding on
# every APRA-regulated entity: ADIs, general insurers, life companies,
# private health insurers and RSE licensees (paras 2–4), on a group basis
# for a Head of a group.
#
# Shape: one control per requirement paragraph (13–36), attested from the
# entity's evidence as input.apra_cps234.controls["35"] == true. Paragraphs
# that condition on related-party or third-party management of information
# assets (16, 22, 28, 34) apply when third_party_managed_assets is true; that
# flag MUST be declared true or false, because an entity that outsources and
# stays silent would otherwise pass without the assessment duties.
#
# Fail-closed: non-true attestation, unknown paragraph id, malformed container
# or undeclared flag are violations. The two notification clocks (72 hours
# for incidents, 10 business days for control weaknesses) are in the report.
#
# Query: POST /v1/data/apra_cps234/main/compliance_report

# METADATA
# title: "APRA CPS 234 Information Security (Australia, July 2019)"
# custom:
#   class: compliance
#   framework: apra_cps234
#   source: apra
#   domains: [financial, australia]
#   coverage:
#     checks: 27
#     cited: 26
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.2
package apra_cps234.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"roles": "Roles and responsibilities (paras 13–14)",
	"capability": "Information security capability (paras 15–17)",
	"policy": "Policy framework (paras 18–19)",
	"classification": "Information asset identification and classification (para 20)",
	"controls": "Implementation of controls (paras 21–22)",
	"incident": "Incident management (paras 23–26)",
	"testing": "Testing control effectiveness (paras 27–31)",
	"audit": "Internal audit (paras 32–34)",
	"notification": "APRA notification (paras 35–36)",
}

controls := {
	"13": {"s": "roles", "tp": false, "text": "The Board is ultimately responsible for information security and ensures it is maintained commensurate with the size and extent of threats, enabling continued sound operation"},
	"14": {"s": "roles", "tp": false, "text": "Information security roles and responsibilities of the Board, senior management, governing bodies and individuals (decision-making, approval, oversight, operations) are clearly defined"},
	"15": {"s": "capability", "tp": false, "text": "An information security capability commensurate with the size and extent of threats to information assets is maintained"},
	"16": {"s": "capability", "tp": true, "text": "The information security capability of each related party or third party managing information assets is assessed, commensurate with the potential consequences of an incident"},
	"17": {"s": "capability", "tp": false, "text": "The capability is actively maintained against changes in vulnerabilities and threats, including from changes to information assets or the business environment"},
	"18": {"s": "policy", "tp": false, "text": "An information security policy framework commensurate with exposures to vulnerabilities and threats is maintained"},
	"19": {"s": "policy", "tp": false, "text": "The policy framework provides direction on the responsibilities of all parties obliged to maintain information security (staff, contractors, consultants, related and third parties, customers)"},
	"20": {"s": "classification", "tp": false, "text": "Information assets, including those managed by related and third parties, are classified by criticality and sensitivity reflecting the potential financial and non-financial impact of an incident"},
	"21": {"s": "controls", "tp": false, "text": "Information security controls protect information assets, implemented in a timely manner and commensurate with vulnerabilities and threats, criticality and sensitivity, life-cycle stage, and the potential consequences of an incident"},
	"22": {"s": "controls", "tp": true, "text": "The design of each related party's or third party's information security controls protecting the entity's information assets is evaluated"},
	"23": {"s": "incident", "tp": false, "text": "Robust mechanisms detect and respond to information security incidents in a timely manner"},
	"24": {"s": "incident", "tp": false, "text": "Information security response plans are maintained for incidents that could plausibly occur"},
	"25": {"s": "incident", "tp": false, "text": "Response plans include mechanisms for managing all stages from detection to post-incident review, and for escalation and reporting to the Board, governing bodies and responsible individuals"},
	"26": {"s": "incident", "tp": false, "text": "Information security response plans are reviewed and tested annually to ensure they remain effective and fit-for-purpose"},
	"27": {"s": "testing", "tp": false, "text": "Control effectiveness is tested through a systematic testing program whose nature and frequency match the rate of change in threats, asset criticality and sensitivity, incident consequences, exposure to untrusted environments, and the materiality and frequency of change"},
	"28": {"s": "testing", "tp": true, "text": "Where reliance is placed on a related party's or third party's control testing, the nature and frequency of that testing is assessed against paragraph 27(a)–(e)"},
	"29": {"s": "testing", "tp": false, "text": "Testing results that identify control deficiencies which cannot be remediated in a timely manner are escalated and reported to the Board or senior management"},
	"30": {"s": "testing", "tp": false, "text": "Testing is conducted by appropriately skilled and functionally independent specialists"},
	"31": {"s": "testing", "tp": false, "text": "The sufficiency of the testing program is reviewed at least annually or on material change to information assets or the business environment"},
	"32": {"s": "audit", "tp": false, "text": "Internal audit reviews the design and operating effectiveness of information security controls, including those maintained by related and third parties (control assurance)"},
	"33": {"s": "audit", "tp": false, "text": "Information security control assurance is provided by appropriately skilled personnel"},
	"34": {"s": "audit", "tp": true, "text": "Internal audit assesses control assurance provided by a related or third party where an incident could materially affect the entity or its customers and audit intends to rely on that assurance"},
	"35": {"s": "notification", "tp": false, "text": "APRA is notified as soon as possible and no later than 72 hours after becoming aware of an information security incident that materially affected (or could materially affect) the entity or its customers, or that was notified to another regulator"},
	"36": {"s": "notification", "tp": false, "text": "APRA is notified as soon as possible and no later than 10 business days after becoming aware of a material control weakness the entity expects not to remediate in a timely manner"},
}

notification_clocks := {"incident_hours": 72, "control_weakness_business_days": 10}

_in := object.get(input, "apra_cps234", {})

violations contains msg if {
	not _in.third_party_managed_assets == true
	not _in.third_party_managed_assets == false
	msg := "CPS 234 para 16/22/28/34: apra_cps234.third_party_managed_assets must be declared true or false — whether related parties or third parties manage information assets cannot be assumed"
}

_tp if _in.third_party_managed_assets == true

applicable[id] := c if {
	some id, c in controls
	not c.tp
}

applicable[id] := c if {
	some id, c in controls
	c.tp
	_tp
}

_attested(id) if _in.controls[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("CPS 234 para %v (%v): %v — not attested", [id, sections[c.s], c.text])
}

violations contains msg if {
	some id, _ in _in.controls
	not controls[id]
	msg := sprintf("CPS 234 Input Contract: attestation for unknown paragraph %v — requirements are paragraphs 13–36", [id])
}

violations contains msg if {
	_in.controls
	not is_object(_in.controls)
	msg := "CPS 234 Input Contract: input.apra_cps234.controls must be an object of {\"<paragraph>\": true}"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id, c in applicable; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "controls": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

compliance_report := {
	"framework": "APRA Prudential Standard CPS 234 Information Security (July 2019)",
	"standard": "Australian Prudential Regulation Authority — CPS 234, commenced 2019-07-01",
	"source": "apra.gov.au — cps_234_july_2019_for_public_release.pdf",
	"third_party_managed_assets": object.get(_in, "third_party_managed_assets", "undeclared"),
	"notification_clocks": notification_clocks,
	"controls_total": count(controls),
	"controls_evaluated": count(applicable),
	"controls_attested": count([id | some id, _ in applicable; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
