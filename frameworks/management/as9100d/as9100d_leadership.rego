# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 5: Leadership"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 6
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.leadership

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 5: Leadership.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/leadership/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported

clause := "5"

clause_name := "Leadership"

items := {
	"5.1.1": {"title": "Leadership and commitment — top management owns QMS effectiveness, policy, objectives, resources and the promotion of risk-based thinking", "kind": "attestation"},
	"5.1.2": {"title": "Customer focus — customer and applicable statutory and regulatory requirements are met, and product conformity and on-time delivery performance are measured with action on shortfalls", "kind": "attestation"},
	"5.2.1": {"title": "Quality policy — a policy appropriate to the organization's purpose and context is established, with a framework for objectives and a commitment to improve", "kind": "attestation"},
	"5.2.2": {"title": "Quality policy communication — the policy is documented, communicated, understood, applied and available to interested parties", "kind": "attestation"},
	"5.3": {"title": "Roles and authorities — responsibilities are assigned and communicated, including a management representative with the authority and freedom to resolve quality matters", "kind": "attestation"},
}

default compliant := false

compliant if {
	count(violations) == 0
}

_attested(id) if input.as9100d.attestations[id] == true

violations contains msg if {
	some id, it in items
	it.kind == "attestation"
	not _attested(id)
	msg := sprintf("AS9100D %s: %s — not attested: input.as9100d.attestations[%q] is not true", [id, it.title, id])
}

passed contains id if {
	some id, it in items
	it.kind == "attestation"
	_attested(id)
}

fact_evaluated := 0

compliance_report := {
	"framework": "SAE AS9100D (9100:2016)",
	"clause": clause,
	"name": clause_name,
	"total": count(items),
	"attestation_items": count({id | some id, it in items; it.kind == "attestation"}),
	"fact_items": count({id | some id, it in items; it.kind == "fact"}),
	"passed": count(passed),
	"failed": count(items) - count(passed),
	"attested": count({id | some id in passed; items[id].kind == "attestation"}),
	"fact_evaluated": fact_evaluated,
	"fact_passed": count({id | some id in passed; items[id].kind == "fact"}),
	"gaps": sort([id | some id, _ in items; not id in passed]),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
