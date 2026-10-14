# NIST SP 800-39 — Managing Information Security Risk: Organization, Mission, and Information System View
# (March 2011). The risk management process of Chapter 3: the concrete tasks it states for the four
# components (frame, assess, respond, monitor), one attested row per task.
#
# Source: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-39.pdf
#   sha256 cf680760d171fc590396c1d98eef184af96efa971ef9880830cd2912ea1a54a8, document date March 2011,
#   retrieved 2026-10-14. NIST text is public domain. Read with `pdftotext -layout`; every id, title and task
#   statement below is copied from the "Activities" of Chapter 3 (pages 34-48) by a generator; nothing is
#   paraphrased. All 12 statements were cross-checked word for word against Appendix E ("Summary of Tasks for
#   Steps in the Risk Management Process"): no differences.
#
# Ids: Chapter 3 prints "TASK 1-1:" ... "TASK 4-2:". The row key is the number ("1-1"); the printed label
# ("TASK 1-1") is kept as data.
#   Step 1: Risk Framing (§3.1 Framing Risk)         4 tasks
#   Step 2: Risk Assessment (§3.2 Assessing Risk)    2 tasks
#   Step 3: Risk Response (§3.3 Responding to Risk)  4 tasks
#   Step 4: Risk Monitoring (§3.4 Monitoring Risk)   2 tasks
#
# Tiers: SP 800-39 does not assign its tasks to individual tiers. Chapter 3 states that each step is applied
# across the three tiers of risk management (chapter introduction and Figure 4, "Risk management process
# applied across the tiers"), so every row carries all three tiers as data. No tier-qualified rows or ids
# are created (the publication prints none).
#
# Judgement calls: rows are only the 12 numbered TASKs. The Inputs and Preconditions / Outputs and Post
# Conditions narrative of each step and the Supplemental Guidance ("can", "might") are guidance, not rows.
# Could not read: nothing.
#
# Input: input.nist_sp_800_39.tasks["1-1"] == true attests the task performed. Fail-closed: a missing or
# non-object tasks container is a FAIL-CLOSED violation; a missing, false or non-true value and an unknown
# id are violations.
#
# Query: POST /v1/data/nist/sp800_39/main/compliance_report

# METADATA
# title: "NIST SP 800-39 Managing Information Security Risk — 12 risk management process tasks (frame, assess, respond, monitor), attested"
# custom:
#   class: compliance
#   framework: nist_sp_800_39
#   source: nist
#   domains: [us-federal, it-governance]
#   coverage:
#     checks: 15
#     cited: 14
#     expected: 12
#     found: 14
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_39.main

import rego.v1

source := {
	"publication": "NIST SP 800-39",
	"date": "March 2011",
	"url": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-39.pdf",
	"sha256": "cf680760d171fc590396c1d98eef184af96efa971ef9880830cd2912ea1a54a8",
	"retrieved": "2026-10-14",
}

sections := {
	"frame": "Step 1: Risk Framing (§3.1 Framing Risk)",
	"assess": "Step 2: Risk Assessment (§3.2 Assessing Risk)",
	"respond": "Step 3: Risk Response (§3.3 Responding to Risk)",
	"monitor": "Step 4: Risk Monitoring (§3.4 Monitoring Risk)",
}

tasks := {
	"1-1": {
		"label": "TASK 1-1",
		"component": "frame",
		"title": "RISK ASSUMPTIONS",
		"text": "Identify assumptions that affect how risk is assessed, responded to, and monitored within the organization.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"1-2": {
		"label": "TASK 1-2",
		"component": "frame",
		"title": "RISK CONSTRAINTS",
		"text": "Identify constraints on the conduct of risk assessment, risk response, and risk monitoring activities within the organization.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"1-3": {
		"label": "TASK 1-3",
		"component": "frame",
		"title": "RISK TOLERANCE",
		"text": "Identify the level of risk tolerance for the organization.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"1-4": {
		"label": "TASK 1-4",
		"component": "frame",
		"title": "PRIORITIES AND TRADE-OFFS",
		"text": "Identify priorities and trade-offs considered by the organization in managing risk.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"2-1": {
		"label": "TASK 2-1",
		"component": "assess",
		"title": "THREAT AND VULNERABILITY IDENTIFICATION",
		"text": "Identify threats to and vulnerabilities in organizational information systems and the environments in which the systems operate.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"2-2": {
		"label": "TASK 2-2",
		"component": "assess",
		"title": "RISK DETERMINATION",
		"text": "Determine the risk to organizational operations and assets, individuals, other organizations, and the Nation if identified threats exploit identified vulnerabilities.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"3-1": {
		"label": "TASK 3-1",
		"component": "respond",
		"title": "RISK RESPONSE IDENTIFICATION",
		"text": "Identify alternative courses of action to respond to risk determined during the risk assessment.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"3-2": {
		"label": "TASK 3-2",
		"component": "respond",
		"title": "EVALUATION OF ALTERNATIVES",
		"text": "Evaluate alternative courses of action for responding to risk.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"3-3": {
		"label": "TASK 3-3",
		"component": "respond",
		"title": "RISK RESPONSE DECISION",
		"text": "Decide on the appropriate course of action for responding to risk.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"3-4": {
		"label": "TASK 3-4",
		"component": "respond",
		"title": "RISK RESPONSE IMPLEMENTATION",
		"text": "Implement the course of action selected to respond to risk.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"4-1": {
		"label": "TASK 4-1",
		"component": "monitor",
		"title": "RISK MONITORING STRATEGY",
		"text": "Develop a risk monitoring strategy for the organization that includes the purpose, type, and frequency of monitoring activities.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
	"4-2": {
		"label": "TASK 4-2",
		"component": "monitor",
		"title": "RISK MONITORING",
		"text": "Monitor organizational information systems and environments of operation on an ongoing basis to verify compliance, determine effectiveness of risk response measures, and identify changes.",
		"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_sp_800_39", {})

_given := t if {
	t := _in.tasks
	is_object(t)
}

_supplied if _given

_true(id) if _given[id] == true

violations contains "NIST SP 800-39: FAIL-CLOSED - task attestations 'input.nist_sp_800_39.tasks' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, t in tasks
	not _true(id)
	msg := sprintf("NIST SP 800-39 %v (%v, %v): not attested performed — %v", [t.label, sections[t.component], t.title, t.text])
}

violations contains msg if {
	some id, _ in _given
	not tasks[id]
	msg := sprintf("NIST SP 800-39 Input Contract: unknown task id %v — ids are the printed task numbers such as 1-1, 4-2", [id])
}

component_reports[c] := r if {
	some c, name in sections
	ids := {id | some id, t in tasks; t.component == c}
	r := {
		"name": name,
		"tasks_total": count(ids),
		"tasks_satisfied": count({id | some id in ids; _true(id)}),
		"tasks_not_satisfied": sort([id | some id in ids; not _true(id)]),
	}
}

compliance_report := {
	"framework": "NIST SP 800-39",
	"standard": "NIST SP 800-39 — Managing Information Security Risk: Organization, Mission, and Information System View (March 2011), Chapter 3 tasks",
	"source": source,
	"compliant": compliant,
	"total_controls": count(tasks),
	"standard_total": 12, # TASK 1-1 .. TASK 4-2 printed in Chapter 3 and Appendix E
	"tasks_satisfied": count({id | some id, _ in tasks; _true(id)}),
	"tiers": ["Tier 1 - Organization", "Tier 2 - Mission / Business Processes", "Tier 3 - Information Systems"],
	"components": component_reports,
	"violation_count": count(violations),
	"violations": violations,
}
