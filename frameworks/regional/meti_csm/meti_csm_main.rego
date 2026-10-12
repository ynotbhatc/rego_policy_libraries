# METI Cybersecurity Management Guidelines Ver. 3.0 (Japan; Ministry of
# Economy, Trade and Industry with IPA; March 2023, English translation
# 31 May 2023) — Appendix A check sheets.
#
# Source: meti.go.jp/policy/netsecurity/downloadfiles/CSM_Guideline_v3.0_en.pdf
#
# The Guidelines are METI's expectations of corporate management: three
# principles management must recognise and ten directions management must
# give the CISO. Appendix A turns them into check sheets — A-1 (nine items,
# self-conducted by management) and A-2 (forty items across the ten
# directions, run by practitioners and confirmed by management). This module
# is those 49 items, each with the NIST Cybersecurity Framework subcategory
# references the Guidelines print beside it.
#
# Shape: attestation from the company's evidence,
# input.meti_csm.items["D5-06"] == true. Per-principle and per-direction
# report with gaps. Fail-closed: a non-true attestation, an unknown id, or a
# malformed container is a violation. Nothing can be scoped out — the
# Guidelines apply to every company that depends on IT, scaled by size.
#
# Query: POST /v1/data/meti_csm/main/compliance_report

# METADATA
# title: "METI Cybersecurity Management Guidelines Ver. 3.0 (Japan) — Appendix A check sheets"
# custom:
#   class: compliance
#   framework: meti_csm
#   source: meti
#   domains: [japan, it-governance]
#   coverage:
#     checks: 52
#     cited: 49
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.4
package meti_csm.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

groups := {
	"P1": "Principle 1 — management recognises cybersecurity risk as a key management risk and acts on it",
	"P2": "Principle 2 — security across the entire supply chain, including bases, partners and outsourcers",
	"P3": "Principle 3 — active communication with relevant parties in normal times and emergencies",
	"D1": "Direction 1 — recognise cybersecurity risks and develop an organization-wide policy",
	"D2": "Direction 2 — build a management system for cybersecurity risk",
	"D3": "Direction 3 — secure resources (budget, workforce) for cybersecurity measures",
	"D4": "Direction 4 — identify cybersecurity risks and develop plans to address them",
	"D5": "Direction 5 — establish systems to effectively address cybersecurity risks",
	"D6": "Direction 6 — continuously improve cybersecurity measures through a PDCA cycle",
	"D7": "Direction 7 — develop a cybersecurity incident response team and procedures",
	"D8": "Direction 8 — develop a business continuity and recovery team and procedures",
	"D9": "Direction 9 — understand and drive measures across the entire supply chain",
	"D10": "Direction 10 — facilitate gathering, sharing and disclosure of cybersecurity information",
}

items := {
	# ── Appendix A-1: three principles management must recognise ─────────
	"P1-01": {"g": "P1", "csf": [], "text": "Management positions cybersecurity risk as a key risk in business decisions and recognises the need for security investment to ensure business continuity"},
	"P1-02": {"g": "P1", "csf": [], "text": "Management recognises its responsibility to reduce risks to acceptable levels through cybersecurity measures"},
	"P1-03": {"g": "P1", "csf": [], "text": "Management regularly checks that its cybersecurity instructions are implemented and urges action when they are not"},
	"P2-01": {"g": "P2", "csf": [], "text": "Management recognises that diverse supply-chain connections, not only order-receiving relationships, can significantly affect the company's and society's cybersecurity"},
	"P2-02": {"g": "P2", "csf": [], "text": "Management confirms that the scope for identifying cybersecurity risk factors includes group companies and outsourced contractors"},
	"P2-03": {"g": "P2", "csf": [], "text": "Management confirms the implementation state of comprehensive security measures across the supply chain, understanding any company can become a perpetrator"},
	"P3-01": {"g": "P3", "csf": [], "text": "Management is prepared to respond appropriately to an incident and practises communication on cybersecurity risks with relevant parties in normal times"},
	"P3-02": {"g": "P3", "csf": [], "text": "Management knows who is responsible for cybersecurity incidents within the company and is prepared to communicate appropriately in an emergency"},
	"P3-03": {"g": "P3", "csf": [], "text": "Management understands what information must be disseminated to keep external stakeholders' trust when incidents occur at the company or its contractors"},
	# ── Appendix A-2: ten important items of cybersecurity management ────
	"D1-01": {"g": "D1", "csf": [], "text": "Management recognises cybersecurity risk as one of the management risks it is responsible for"},
	"D1-02": {"g": "D1", "csf": ["ID.GV-1"], "text": "Management formulates and declares a basic cybersecurity policy that considers the cybersecurity risks of the organisation as a whole"},
	"D1-03": {"g": "D1", "csf": ["ID.GV-3", "DE.DP-2"], "text": "Management understands the requirements of laws, contracts and guidelines and has them reflected in basic policies"},
	"D2-01": {"g": "D2", "csf": ["ID.GV"], "text": "A cybersecurity risk management structure consisting of a CISO etc. is established based on the organisation's foundational policy"},
	"D2-02": {"g": "D2", "csf": ["ID.GV-2"], "text": "The roles and responsibilities of each stakeholder in managing cybersecurity risk are clear"},
	"D2-03": {"g": "D2", "csf": ["ID.GV-4"], "text": "The relationship between the governance, internal control and business continuity risk systems and the cybersecurity risk management system is clear"},
	"D3-01": {"g": "D3", "csf": ["ID.AM"], "text": "Cybersecurity measures and the resources (budget, people) to implement them are clarified through management meetings"},
	"D3-02": {"g": "D3", "csf": ["ID.BE-3", "ID.BE-4", "ID.SC-2"], "text": "There is an appropriate separation between cybersecurity measures handled in-house and those outsourced"},
	"D3-03": {"g": "D3", "csf": ["PR.AT-1", "PR.AT-2", "PR.AT-3", "PR.AT-4", "PR.AT-5"], "text": "Requirements for security personnel are clear; cybersecurity personnel are secured, developed systematically and treated satisfactorily"},
	"D3-04": {"g": "D3", "csf": ["PR.AT-1", "PR.AT-5"], "text": "Cybersecurity knowledge and skills ('Plus-Security') are acquired by personnel in non-security roles"},
	"D3-05": {"g": "D3", "csf": ["ID.BE-3", "ID.BE-4", "ID.SC-3", "ID.SC-4"], "text": "For outsourced cybersecurity, appropriate external resources are selected and used considering the company's issues, budget and location"},
	"D4-01": {"g": "D4", "csf": ["ID.AM-1", "ID.AM-2", "ID.AM-3", "ID.AM-4", "ID.AM-5"], "text": "Digital environments, services and information to be protected are identified and measures prioritised by location, business value and other aspects"},
	"D4-02": {"g": "D4", "csf": ["ID.RA-1", "ID.RA-3", "ID.RA-4", "ID.RA-5", "ID.RM-1", "ID.RM-2"], "text": "Threats and vulnerabilities (including negligence and internal impropriety) against the protected assets are identified and their business impact understood"},
	"D4-03": {"g": "D4", "csf": ["ID.RA-3", "ID.RA-6"], "text": "A risk response plan based on risk assessment results has been developed"},
	"D5-01": {"g": "D5", "csf": ["PR.IP-1", "PR.IP-2", "PR.IP-3", "PR.PT-3"], "text": "Asset, configuration and patch management of critical systems are performed"},
	"D5-02": {"g": "D5", "csf": ["PR.AC"], "text": "Measures prevent the use of shadow IT within the organisation"},
	"D5-03": {"g": "D5", "csf": ["ID.RA-6", "ID.RM-3"], "text": "Risk assessment is performed at system design and the necessary security features are implemented at development (security by design)"},
	"D5-04": {"g": "D5", "csf": ["PR.AC", "PR.DS", "PR.PT-1", "PR.PT-2", "PR.PT-3"], "text": "Multiple technical measures are implemented for terminals and servers that perform critical tasks"},
	"D5-05": {"g": "D5", "csf": ["PR.AC", "PR.DS", "PR.PT-4"], "text": "Multiple technical measures are in place for networks that perform critical tasks"},
	"D5-06": {"g": "D5", "csf": ["PR.IP-12", "DE.CM-8", "RS.MI-3"], "text": "Vulnerability countermeasures are planned and implemented: regular vulnerability checks, continuous patching and other mitigation"},
	"D5-07": {"g": "D5", "csf": ["PR.MA-1", "PR.MA-2"], "text": "Logs from terminals and networks are collected and analysed"},
	"D5-08": {"g": "D5", "csf": ["DE.AE", "DE.DP"], "text": "Incident response mechanisms such as blocking communications when a cyberattack is detected are introduced"},
	"D5-09": {"g": "D5", "csf": ["PR.IP-9"], "text": "Incident management mechanisms are in place"},
	"D5-10": {"g": "D5", "csf": ["PR.AT-1"], "text": "Cybersecurity education and exercises are conducted for employees"},
	"D6-01": {"g": "D6", "csf": ["ID.RM-1", "ID.RM-2", "ID.RM-3"], "text": "KPIs for cybersecurity operations management are defined"},
	"D6-02": {"g": "D6", "csf": ["ID.GV"], "text": "Management regularly receives reports on the implementation status of cybersecurity measures, discusses them and gives directions"},
	"D6-03": {"g": "D6", "csf": ["PR.IP-7", "RP.PT-1"], "text": "Cybersecurity audits are conducted and measures are reviewed in a timely manner based on the results"},
	"D6-04": {"g": "D6", "csf": ["ID.SC", "RS.CO-3", "RS.CO-4", "RS.CO-5"], "text": "There is communication with stakeholders about the state of action against cybersecurity risks"},
	"D7-01": {"g": "D7", "csf": ["PR.IP-9", "RS.RP-1", "RS.IM-1", "RS.IM-2", "RS.AN-4"], "text": "An incident response plan that considers the entire supply chain is developed"},
	"D7-02": {"g": "D7", "csf": ["RS.CO-1"], "text": "A dedicated incident response team (CSIRT etc.) is established and maintained"},
	"D7-03": {"g": "D7", "csf": ["RS.CO-2", "RS.CO-1"], "text": "The content and timing of what is shared, reported or published outside the organisation during an incident are specified"},
	"D7-04": {"g": "D7", "csf": ["PR.IP-10"], "text": "Emergency response exercises for incidents are conducted regularly"},
	"D7-05": {"g": "D7", "csf": ["PR.MA-1", "PR.MA-2", "PR.PT-1", "RS.AN-4"], "text": "An implementation plan enables rapid log analysis and investigation at incident time to identify the scope of impact"},
	"D8-01": {"g": "D8", "csf": ["ID.BE-5", "PR.IP-9", "RC.RP-1", "RC.IM-1", "RC.IM-2"], "text": "A business recovery plan considering the entire supply chain in the event of damage is developed"},
	"D8-02": {"g": "D8", "csf": ["PR.IP-10", "RC.CO"], "text": "Recovery exercises are conducted regularly"},
	"D9-01": {"g": "D9", "csf": ["ID.RA", "ID.BE-1"], "text": "The state of cybersecurity countermeasures in transactions and collaborations with group companies is understood"},
	"D9-02": {"g": "D9", "csf": ["ID.AM-6", "ID.BE-1", "ID.SC"], "text": "Appropriate measures are confirmed against the roles and responsibilities for cybersecurity risk agreed in contracts with business partners and contractors"},
	"D9-03": {"g": "D9", "csf": ["ID.RA-5", "ID.SC"], "text": "Cybersecurity risk is confirmed not to exceed acceptable levels across the supply chain affecting the company's business"},
	"D10-01": {"g": "D10", "csf": ["ID.RA-2", "RS.AN-5"], "text": "Warning information from related organisations and participation in the industry security community are used for the company's own countermeasures"},
	"D10-02": {"g": "D10", "csf": ["RS.CO"], "text": "Incident information (malware infection, unauthorised access) is shared and reported to related organisations and communities and published appropriately"},
}

_attested(id) if input.meti_csm.items[id] == true

violations contains msg if {
	some id, it in items
	not _attested(id)
	msg := sprintf("METI CSM %v (%v): %v — not attested", [id, groups[it.g], it.text])
}

violations contains msg if {
	some id, _ in input.meti_csm.items
	not items[id]
	msg := sprintf("METI CSM Input Contract: attestation for unknown item id %v — not an Appendix A check-sheet item", [id])
}

violations contains msg if {
	input.meti_csm.items
	not is_object(input.meti_csm.items)
	msg := "METI CSM Input Contract: input.meti_csm.items must be an object of {\"<item id>\": true}"
}

group_reports[g] := r if {
	some g, name in groups
	ids := {id | some id, it in items; it.g == g}
	passed := {id | some id in ids; _attested(id)}
	r := {
		"group": g,
		"name": name,
		"items": count(ids),
		"attested": count(passed),
		"gaps": sort([id | some id in ids; not id in passed]),
	}
}

compliance_report := {
	"framework": "METI Cybersecurity Management Guidelines Ver. 3.0 (Japan)",
	"standard": "Ministry of Economy, Trade and Industry / IPA, March 2023 (English 31 May 2023) — Appendix A-1 (3 principles, 9 items) and A-2 (10 directions, 40 items)",
	"source": "meti.go.jp — CSM_Guideline_v3.0_en.pdf",
	"items_total": count(items),
	"items_attested": count([id | some id, _ in items; _attested(id)]),
	"principles_attested": count([id | some id, it in items; startswith(it.g, "P"); _attested(id)]),
	"directions_attested": count([id | some id, it in items; startswith(it.g, "D"); _attested(id)]),
	"groups": group_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
