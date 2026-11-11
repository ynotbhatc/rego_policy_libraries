# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 4: Context of the organization"
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
package as9100d.context

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 4: Context of the organization.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/context/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported

clause := "4"

clause_name := "Context of the organization"

items := {
	"4.1": {"title": "Organizational context — internal and external issues relevant to the QMS are determined and reviewed", "kind": "attestation"},
	"4.2": {"title": "Interested parties — relevant parties and their requirements, including statutory, regulatory and customer, are determined", "kind": "attestation"},
	"4.3": {"title": "QMS scope — boundaries and applicability are defined, documented and justified where a requirement is not applied", "kind": "attestation"},
	"4.4.1": {"title": "QMS processes — processes, their sequence, interaction, criteria, resources, risks and ownership are established and maintained", "kind": "attestation"},
	"4.4.2": {"title": "Process documentation — documented information needed to operate the processes and to show they run as planned is maintained and retained", "kind": "attestation"},
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
