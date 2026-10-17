# 33 CFR Part 101 Subpart F — Cybersecurity (U.S. Coast Guard maritime cybersecurity rule, §§101.600–101.670).
# One attested row per obligation of the owner or operator of a U.S.-flagged vessel, facility or OCS facility, or
# of its Cybersecurity Officer (CySO), in §§101.620–101.665.
#
# Source of truth: U.S. Government Publishing Office, Code of Federal Regulations annual edition, bulk XML
#   https://www.govinfo.gov/bulkdata/CFR/2025/title-33/CFR-2025-title33-vol1.xml
#   sha256 0225418f8b3c7bfd18af182c0dca75367786f58c9df68119bda73c98d44c9d49, Title 33 revised as of July 1, 2025
#   (the 2026 Title 33 edition is not yet published), retrieved 2026-10-14. Public domain (17 U.S.C. 105).
#   Effective date note as printed: "By USCG-2022-0802, 90 FR 6447, Jan. 17, 2025, subpart F was added, effective
#   July 16, 2025." eCFR versioner (api/versioner/v1/versions/title-33.json?part=101, retrieved 2026-10-14) lists
#   §§101.600–101.670 only at 2025-07-16: no later amendment, so the dates below are current.
#   Federal Register API (docket USCG-2022-0802, and Coast Guard documents citing 101.650 after 2025-01-17,
#   retrieved 2026-10-14): only the final rule 2025-00708 (90 FR 6447) and the two 2024 proposals; no delay rule.
# Every id, text, stem and item below is copied verbatim from that XML by a generator; nothing is paraphrased.
# Ids are the CFR paragraph citations as printed (101.650(a)(4)); a section printed as a single undesignated
# paragraph (§§101.640, 101.655, 101.660, 101.665) is cited by its section number.
#
# Measured (designated paragraphs, plus undesignated single-paragraph sections) against emitted rows:
#   section   measured  rows  lead-ins  folded  coast-guard  not-a-row
#   §101.600         1     0         0       0            0          1
#   §101.605         2     0         0       0            0          2
#   §101.610         1     0         0       0            0          1
#   §101.615         1     0         0       0            0          1
#   §101.620         9     8         1       0            0          0
#   §101.625        32    17         1      12            0          2
#   §101.630        43    15         0      18            5          5
#   §101.635        18     8         0       0            0         10
#   §101.640         1     1         0       0            0          0
#   §101.645         2     2         0       0            0          0
#   §101.650        58    51         0       7            0          0
#   §101.655         1     1         0       0            0          0
#   §101.660         1     1         0       0            0          0
#   §101.665         1     1         0       0            0          0
#   §101.670         1     0         0       0            0          1
#   total          172   105         2      37            5         23
#
# Out of scope — Coast Guard actions: 101.630(d)(1), (d)(1)(i)–(iv) (COTP/OCMI/MSC evaluation of the plan).
# Not a row: §101.600 purpose, §101.605(a)–(b) applicability, §101.610 federalism, §101.615 definitions,
# §101.670 severability; permissions and statements: 101.625(a) (CySO may hold other duties), 101.625(c) (CySO may
# assign duties; retains responsibility), 101.630(d)(3) (plan valid 5 years: carried as data), 101.630(e)(2)(i)
# (nothing limits exigent measures), 101.630(f)(3) (re-audits may be limited), 101.635(a)(2) (a real incident may
# satisfy a drill), 101.635(c)(2), (c)(2)(i)–(iv), (c)(3) (permitted exercise forms); heading-only designators
# 101.630(e), (f), 101.635(a), (b), (c).
# Folded into their row as `items`: the CySO knowledge areas 101.625(e)(1)–(12); the fourteen plan sections
# 101.630(c)(1)–(14); 101.630(e)(1)(i); the auditor criteria 101.630(f)(4)(i)–(iii); the training topics
# 101.650(d)(1)(i)–(v) and (d)(2)(i)–(ii).
# Lead-ins carried as `stem`: 101.620(b) ("the owner or operator must—") and 101.625(d) ("the CySO must—").
#
# Judgement calls:
#   - The lead-in paragraphs of §101.650 (a)–(i) are rows of their own, because each also requires the measures to
#     be documented in a named section of the Cybersecurity Plan; their sub-paragraphs are separate rows.
#   - 101.650(e)(1) is a row (assessment by July 16, 2027 and annually) and its (i)–(v) are separate rows.
#   - 101.620(b)(7) and 101.650(g)(1) (report to the NRC unless reported under, or not subject to, 33 CFR 6.16-1)
#     and 101.635(b)(3) (a facility may not require a moored vessel to join its drill) are not gated: attest true
#     when met or not triggered.
#   - 101.625(b) is a row (a CySO for several vessels/facilities must be listed in each plan); 101.665 is a row
#     (a temporary deviation must be notified to the COTP or MSC).
# Could not read: nothing.
#
# Dates carried as data (`dated_obligations`, not evaluated against the clock): subpart effective 2025-07-16;
# training under 101.650(d)(1)(ii)–(v) and (d)(2) by 2026-01-12 and annually; Cybersecurity Assessment no later
# than 2027-07-16 and annually (101.650(e)(1)); Cybersecurity Plans submitted no later than 2027-07-16 (101.655).
# Clocks (`notification_clocks`): plan amendments 30 days before effect; owner/CySO change 96 hours; audit-driven
# amendments 30 days after the audit; plan approval valid 5 years; plan-provision training 60 days after approval;
# new personnel within 5 days of access and no later than 30 days after hiring.
#
# Input: input.maritime_33cfr101f.obligations["101.650(a)(4)"] == true means the owner's or operator's evidence
# shows that obligation met. Fail-closed: a missing or non-object `obligations` container is a FAIL-CLOSED
# violation; a missing, false or non-true value is a violation; an unknown id is a violation. Rollup per section.
#
# Query: POST /v1/data/maritime_33cfr101f/main/compliance_report

# METADATA
# title: "33 CFR 101 Subpart F — USCG maritime cybersecurity, owner/operator and CySO obligations, 105 attested"
# custom:
#   class: ot
#   framework: uscg_33cfr101_subpart_f
#   source: us-federal
#   domains: [ot, critical-infrastructure, us-federal]
#   coverage:
#     checks: 108
#     cited: 107
#     expected: 105
#     found: 108
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package maritime_33cfr101f.main

import rego.v1

framework := "33 CFR Part 101 Subpart F — Cybersecurity (U.S. Coast Guard)"

source := {
	"publication": "Code of Federal Regulations, Title 33, Part 101 Subpart F (annual edition, revised as of July 1, 2025)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-33/CFR-2025-title33-vol1.xml",
	"sha256": "0225418f8b3c7bfd18af182c0dca75367786f58c9df68119bda73c98d44c9d49",
	"edition": "2025-07-01",
	"retrieved": "2026-10-14",
}

sections := {
	"101.620": "§101.620 Owner or operator",
	"101.625": "§101.625 Cybersecurity Officer",
	"101.630": "§101.630 Cybersecurity Plan",
	"101.635": "§101.635 Drills and exercises",
	"101.640": "§101.640 Records and documentation",
	"101.645": "§101.645 Communications",
	"101.650": "§101.650 Cybersecurity measures",
	"101.655": "§101.655 Cybersecurity compliance dates",
	"101.660": "§101.660 Cybersecurity compliance documentation",
	"101.665": "§101.665 Noncompliance, waivers, and equivalents",
}

dated_obligations := {
	"subpart_f_effective": "2025-07-16",
	"101.650(d)(4)_training_(d)(1)(ii)-(v)_and_(d)(2)_completed_by": "2026-01-12",
	"101.650(e)(1)_first_cybersecurity_assessment_no_later_than": "2027-07-16",
	"101.655_cybersecurity_plans_submitted_no_later_than": "2027-07-16",
}

notification_clocks := {
	"101.630(d)(3)_plan_approval_valid_years": 5,
	"101.630(e)(1)(ii)_days_to_submit_amendments_after_coast_guard_return_at_least": 60,
	"101.630(e)(2)_days_before_amendment_effective_date": 30,
	"101.630(e)(3)_hours_to_amend_after_owner_or_operator_change": 96,
	"101.630(e)(4)_hours_to_notify_and_amend_after_cyso_change": 96,
	"101.630(f)(5)_days_after_audit_to_submit_amendments": 30,
	"101.635(c)(1)_max_months_between_exercises": 18,
	"101.650(d)(4)_days_after_plan_approval_for_(d)(1)(i)_training": 60,
	"101.650(d)(4)_days_after_system_access_for_new_personnel_training": 5,
	"101.650(d)(4)_days_after_hiring_for_new_personnel_training_at_most": 30,
}

_rows := [
	{"id": "101.620(a)", "s": "101.620", "gate": "", "stem": "", "text": "Each owner or operator of a U.S.-flagged vessel, facility, or OCS facility is responsible for compliance with the requirements of this subpart.", "items": []},
	{"id": "101.620(b)(1)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Ensure a Cybersecurity Plan is developed, approved, and maintained;", "items": []},
	{"id": "101.620(b)(2)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Define in Section 1 of the Cybersecurity Plan the cybersecurity organizational structure and identify each person exercising cybersecurity duties and responsibilities within that structure, with the support needed to fulfill those obligations;", "items": []},
	{"id": "101.620(b)(3)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Designate, in writing, by name and by title, a Cybersecurity Officer (CySO) who is accessible to the Coast Guard 24 hours a day, 7 days a week, and identify how the CySO can be contacted at any time;", "items": []},
	{"id": "101.620(b)(4)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Ensure that cybersecurity exercises, audits, and inspections, as well as the Cybersecurity Assessment, are conducted as required by this part and in accordance with the Cybersecurity Plan (see § 101.625(d)(1), (3), (6) and (7));", "items": []},
	{"id": "101.620(b)(5)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Ensure that the U.S.-flagged vessel, facility, or OCS facility operates in compliance with the approved Cybersecurity Plan;", "items": []},
	{"id": "101.620(b)(6)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "Ensure the development, approval, and execution of the Cyber Incident Response Plan; and", "items": []},
	{"id": "101.620(b)(7)", "s": "101.620", "gate": "", "stem": "For each U.S.-flagged vessel, facility, or OCS facility, the owner or operator must—", "text": "For entities that have not reported to the Coast Guard pursuant to, or are not subject to, 33 CFR 6.16-1, ensure all reportable cyber incidents are reported to the National Response Center (NRC).", "items": []},
	{"id": "101.625(b)", "s": "101.625", "gate": "", "stem": "", "text": "Serving as CySO for Multiple Vessels, Facilities, or OCS Facilities. The same person may serve as the CySO for more than one U.S.-flagged vessel, facility, or OCS facility. If a person serves as the CySO for more than one U.S.-flagged vessel, facility, or OCS facility, the name of each U.S.-flagged vessel, facility, or OCS facility for which that person is the CySO must be listed in the Cybersecurity Plan of each U.S.-flagged vessel, facility, or OCS facility for which that person is the CySO.", "items": []},
	{"id": "101.625(d)(1)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure that the Cybersecurity Assessment is conducted as required by this part;", "items": []},
	{"id": "101.625(d)(2)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure the cybersecurity measures in the Cybersecurity Plan are developed, implemented, and operating as intended;", "items": []},
	{"id": "101.625(d)(3)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure that an annual audit of the Cybersecurity Plan and its implementation is conducted and, if necessary, ensure that the Cybersecurity Plan is updated;", "items": []},
	{"id": "101.625(d)(4)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure the Cyber Incident Response Plan is executed and exercised;", "items": []},
	{"id": "101.625(d)(5)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure the Cybersecurity Plan is exercised in accordance with § 101.635(c);", "items": []},
	{"id": "101.625(d)(6)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Arrange for cybersecurity inspections, which may be conducted as their own inspections, or in conjunction with any scheduled Coast Guard inspection of a U.S.-flagged vessel, facility, or OCS facility;", "items": []},
	{"id": "101.625(d)(7)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure the prompt correction of problems identified by exercises, audits, or inspections;", "items": []},
	{"id": "101.625(d)(8)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Enhance the cybersecurity awareness and vigilance of personnel;", "items": []},
	{"id": "101.625(d)(9)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure adequate cybersecurity training of personnel;", "items": []},
	{"id": "101.625(d)(10)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure all reportable cyber incidents are recorded and reported to the owner or operator;", "items": []},
	{"id": "101.625(d)(11)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure that records required by this part are maintained in accordance with § 101.640;", "items": []},
	{"id": "101.625(d)(12)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure any reports as required by this part have been prepared and submitted;", "items": []},
	{"id": "101.625(d)(13)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure that the Cybersecurity Plan, as well as proposed amendments to cybersecurity measures included in the Plan, are submitted for approval to the cognizant COTP or the Officer in Charge, Marine Inspections (OCMI) for facilities or OCS facilities, or to the Marine Safety Center (MSC) for U.S.-flagged vessels, prior to amending the Cybersecurity Plan, in accordance with § 101.630;", "items": []},
	{"id": "101.625(d)(14)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure relevant security and management personnel are briefed regarding changes in cybersecurity conditions on board the U.S.-flagged vessel, facility, or OCS facility; and", "items": []},
	{"id": "101.625(d)(15)", "s": "101.625", "gate": "", "stem": "Responsibilities. For each U.S.-flagged vessel, facility, or OCS facility for which they are designated, the CySO must—", "text": "Ensure identification and mitigation of all KEVs in critical IT or OT systems, without delay.", "items": []},
	{"id": "101.625(e)", "s": "101.625", "gate": "", "stem": "", "text": "Qualifications. The CySO must have general knowledge, through training, education, or equivalent job experience, in the following:", "items": ["(1) General vessel, facility, or OCS facility operations and conditions;", "(2) General cybersecurity guidance and best practices;", "(3) The vessel, facility, or OCS facility's Cyber Incident Response Plan;", "(4) The vessel, facility, or OCS facility's Cybersecurity Plan;", "(5) Cybersecurity equipment and systems;", "(6) Methods of conducting cybersecurity audits, inspections, control, and monitoring techniques;", "(7) Relevant laws and regulations pertaining to cybersecurity;", "(8) Instruction techniques for cybersecurity training and education;", "(9) Handling of Sensitive Security Information and security related communications;", "(10) Current cybersecurity threat patterns and KEVs;", "(11) Recognizing characteristics and behavioral patterns of persons who are likely to threaten security; and", "(12) Conducting and assessing cybersecurity drills and exercises."]},
	{"id": "101.630(a)", "s": "101.630", "gate": "", "stem": "", "text": "General. The CySO must develop, implement, and verify a Cybersecurity Plan for U.S.-flagged vessels, facilities, or OCS facilities. The Cybersecurity Plan must reflect all cybersecurity measures required in this subpart, as appropriate, to mitigate risks identified during the Cybersecurity Assessment. The Plan must describe in detail how the requirements of subpart F will be met. The Cybersecurity Plan may be included in a VSP, FSP, or an OCS FSP; as an annex to the VSP, FSP, or OCS FSP; as part of an approved Alternative Security Program; or may be provided in a separate submission from the VSP, FSP, or OCS FSP.", "items": []},
	{"id": "101.630(b)", "s": "101.630", "gate": "", "stem": "", "text": "Protecting sensitive security information. The Cybersecurity Plan is sensitive security information and must be protected in accordance with 49 CFR part 1520.", "items": []},
	{"id": "101.630(c)", "s": "101.630", "gate": "", "stem": "", "text": "Format. The owner or operator must ensure that the Cybersecurity Plan consists of the individual sections listed in this paragraph. If the Cybersecurity Plan does not follow the order as it appears on the list, the owner or operator must ensure that the Plan contains an index identifying the location of each of the following sections:", "items": ["(1) Cybersecurity organization and identity of the CySO;", "(2) Personnel training;", "(3) Drills and exercises;", "(4) Records and documentation;", "(5) Communications;", "(6) Cybersecurity systems and equipment, with associated maintenance;", "(7) Cybersecurity measures for access control, including the computer, IT, and OT access areas;", "(8) Physical security controls for IT and OT systems;", "(9) Cybersecurity measures for monitoring;", "(10) Audits and amendments to the Cybersecurity Plan;", "(11) Reports of all cybersecurity audits and inspections, to include documentation of resolution or mitigation of all identified vulnerabilities;", "(12) Documentation of all identified, unresolved vulnerabilities, to include those that are intentionally unresolved due to owner or operator risk acceptance;", "(13) Cyber incident reporting procedures in accordance with part 101 of this subchapter; and", "(14) Cybersecurity Assessment."]},
	{"id": "101.630(d)", "s": "101.630", "gate": "", "stem": "", "text": "Submission and approval. Each owner or operator must submit one copy of their Cybersecurity Plan for review and approval to the cognizant COTP or the OCMI for a facility or OCS facility, or to the MSC for a U.S.-flagged vessel.", "items": []},
	{"id": "101.630(d)(2)", "s": "101.630", "gate": "", "stem": "", "text": "Owners or operators submitting one Cybersecurity Plan to cover two or more U.S.-flagged vessels, facilities, or OCS facilities of similar operations must ensure the Plan addresses the specific cybersecurity risks for each U.S.-flagged vessel, facility, or OCS facility.", "items": []},
	{"id": "101.630(e)(1)", "s": "101.630", "gate": "", "stem": "", "text": "Amendments to a Coast Guard-approved Cybersecurity Plan must be initiated by either—", "items": ["(i) The owner or operator or the CySO; or"]},
	{"id": "101.630(e)(1)(ii)", "s": "101.630", "gate": "", "stem": "", "text": "When the COTP, OCMI, or MSC finds that the Cybersecurity Plan no longer meets the requirements in this part, the Plan will be returned to the owner or operator with a letter explaining why the Plan no longer meets the requirements and requires amendment. The owner or operator will have at least 60 days to submit its proposed amendments. Until the amendments are approved, the owner or operator must ensure temporary cybersecurity measures are implemented to the satisfaction of the Coast Guard.", "items": []},
	{"id": "101.630(e)(2)", "s": "101.630", "gate": "", "stem": "", "text": "Proposed amendments to the Cybersecurity Plan must be sent to the Coast Guard at least 30 days before the proposed amendment's effective date. The Coast Guard will approve or disapprove the proposed amendment in accordance with this part.", "items": []},
	{"id": "101.630(e)(2)(ii)", "s": "101.630", "gate": "", "stem": "", "text": "In such cases, the owner or operator must notify the cognizant COTP for a facility or OCS facility, or the MSC for U.S.-flagged vessels, by the most rapid means practicable as to the nature of the additional measures, the circumstances that prompted these additional measures, and the period of time these additional measures are expected to be in place.", "items": []},
	{"id": "101.630(e)(3)", "s": "101.630", "gate": "", "stem": "", "text": "If the owner or operator has changed, the CySO must amend the Cybersecurity Plan as soon as reasonably practicable in light of the individual circumstances, but, in any case, not longer than 96 hours, to include the name and contact information of the new owner or operator and submit the affected portion of the Plan for review and approval in accordance with this part.", "items": []},
	{"id": "101.630(e)(4)", "s": "101.630", "gate": "", "stem": "", "text": "If the CySO has changed, the Coast Guard must be notified as soon as reasonably practicable in light of the individual circumstances, but, in any case, not longer than 96 hours, and the affected portion of the Cybersecurity Plan must be amended and submitted to the Coast Guard for review and approval in accordance with this part as soon as reasonably practicable in light of the individual circumstances, but, in any case, not longer than 96 hours.", "items": []},
	{"id": "101.630(f)(1)", "s": "101.630", "gate": "", "stem": "", "text": "The CySO must ensure that an audit of the Cybersecurity Plan and its implementation is performed annually, beginning no later than 1 year from the initial date of approval. The CySO must attach a report to the Plan certifying that the Plan meets the applicable requirements of this subpart.", "items": []},
	{"id": "101.630(f)(2)", "s": "101.630", "gate": "", "stem": "", "text": "In addition to the annual audit, the CySO must ensure that an audit of the Cybersecurity Plan occurs if there is a change in the owner or operator of the U.S.-flagged vessel, facility, or OCS facility, or if there have been modifications to the cybersecurity measures, including, but not limited to, physical access, incident response procedures, security measures, or operations.", "items": []},
	{"id": "101.630(f)(4)", "s": "101.630", "gate": "", "stem": "", "text": "Personnel conducting internal audits of the cybersecurity measures specified in the Plan or evaluating its implementation must—", "items": ["(i) Have knowledge of methods of conducting audits and inspections, as well as access control and monitoring techniques;", "(ii) Not have regularly assigned cybersecurity duties for the U.S.-flagged vessel, facility, or OCS facility being audited; and", "(iii) Be independent of any cybersecurity measures being audited."]},
	{"id": "101.630(f)(5)", "s": "101.630", "gate": "", "stem": "", "text": "If the results of an audit require amending the Cybersecurity Plan, the CySO must submit, in accordance with this part, the amendments to the Coast Guard for review and approval no later than 30 days after completion of the audit.", "items": []},
	{"id": "101.635(a)(1)", "s": "101.635", "gate": "", "stem": "", "text": "Drills and exercises must be used to test the proficiency of the U.S.-flagged vessel, facility, and OCS facility personnel in assigned cybersecurity duties and the effective implementation of the VSP, FSP, OCS FSP, and Cybersecurity Plan. The drills and exercises must enable the CySO to identify any related cybersecurity deficiencies that need to be addressed.", "items": []},
	{"id": "101.635(b)(1)", "s": "101.635", "gate": "", "stem": "", "text": "The CySO must ensure that cybersecurity drills are conducted at least twice each calendar year. Cybersecurity drills may be held in conjunction with other security or non-security drills, as required by 33 CFR 104.230, 105.220, or 106.225, where appropriate.", "items": []},
	{"id": "101.635(b)(2)", "s": "101.635", "gate": "", "stem": "", "text": "Drills must test individual elements of the Cybersecurity Plan, including responses to cybersecurity threats and incidents. Cybersecurity drills must take into account the types of operations of the U.S.-flagged vessel, facility, or OCS facility; changes to the U.S.-flagged vessel, facility, or OCS facility personnel; the type of vessel a facility is serving; and other relevant circumstances.", "items": []},
	{"id": "101.635(b)(3)", "s": "101.635", "gate": "", "stem": "", "text": "If a vessel is moored at a facility on a date a facility has planned to conduct any drills, the facility cannot require the vessel or vessel personnel to be a part of or participate in the facility's scheduled drill.", "items": []},
	{"id": "101.635(c)(1)", "s": "101.635", "gate": "", "stem": "", "text": "Exercises must be conducted at least once each calendar year, with no more than 18 months between exercises.", "items": []},
	{"id": "101.635(c)(4)", "s": "101.635", "gate": "", "stem": "", "text": "Each exercise must test communication and notification procedures and elements of coordination, resource availability, and response.", "items": []},
	{"id": "101.635(c)(5)", "s": "101.635", "gate": "", "stem": "", "text": "Exercises are a full test of the cybersecurity program and must include the substantial and active participation of the CySO(s).", "items": []},
	{"id": "101.635(c)(6)", "s": "101.635", "gate": "", "stem": "", "text": "If any corrective action identified during an exercise is needed, it must be addressed and documented as soon as possible.", "items": []},
	{"id": "101.640", "s": "101.640", "gate": "", "stem": "", "text": "All records, reports, and other documents mentioned in this subpart must be created and maintained in accordance with 33 CFR 104.235 for U.S.-flagged vessels, 105.225 for facilities, and 106.230 for OCS facilities. At a minimum, the records must be created for the following activities: training, drills, exercises, cybersecurity threats, reportable cyber incidents, and audits of the Cybersecurity Plan.", "items": []},
	{"id": "101.645(a)", "s": "101.645", "gate": "", "stem": "", "text": "The CySO must have a means to effectively notify owners or operators and personnel of a U.S.-flagged vessel, facility, or OCS facility of changes in cybersecurity conditions at the U.S.-flagged vessel, facility, and OCS facility and document these means in Section 5 of the Cybersecurity Plan.", "items": []},
	{"id": "101.645(b)", "s": "101.645", "gate": "", "stem": "", "text": "Communication systems and procedures must allow effective and continuous communications between U.S.-flagged vessel, facility, and OCS facility security personnel, vessels interfacing with a facility or an OCS facility, the cognizant COTP, and national and local authorities with security responsibilities.", "items": []},
	{"id": "101.650(a)", "s": "101.650", "gate": "", "stem": "", "text": "Account security measures. Each owner or operator of a U.S.-flagged vessel, facility, or OCS facility must ensure, at a minimum, the following account security measures are in place and documented in Section 7 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(a)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Automatic account lockout after repeated failed login attempts must be enabled on all password-protected IT systems;", "items": []},
	{"id": "101.650(a)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Default passwords must be changed before using any IT or OT systems. When changing default passwords is not feasible, appropriate compensating security controls must be implemented and documented;", "items": []},
	{"id": "101.650(a)(3)", "s": "101.650", "gate": "", "stem": "", "text": "A minimum password strength must be maintained on all IT and OT systems that are technically capable of password protection;", "items": []},
	{"id": "101.650(a)(4)", "s": "101.650", "gate": "", "stem": "", "text": "Multifactor authentication must be implemented on password-protected IT and remotely accessible OT systems. When multifactor authentication is not feasible, appropriate compensating security controls must be implemented and documented;", "items": []},
	{"id": "101.650(a)(5)", "s": "101.650", "gate": "", "stem": "", "text": "The principle of least privilege must be applied to administrator or otherwise privileged accounts on both IT and OT systems;", "items": []},
	{"id": "101.650(a)(6)", "s": "101.650", "gate": "", "stem": "", "text": "The owner or operator must ensure that users maintain separate credentials on critical IT and OT systems; and", "items": []},
	{"id": "101.650(a)(7)", "s": "101.650", "gate": "", "stem": "", "text": "The owner or operator must ensure that user credentials are removed or revoked when a user leaves the organization.", "items": []},
	{"id": "101.650(b)", "s": "101.650", "gate": "", "stem": "", "text": "Device security measures. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following device security measures are in place, addressed in Section 6 of the Cybersecurity Plan, and made available to the Coast Guard upon request:", "items": []},
	{"id": "101.650(b)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Develop and maintain a list of approved hardware, firmware, and software that may be installed on IT or OT systems. Any hardware, firmware, and software installed on IT and OT systems must be on the owner- or operator-approved list;", "items": []},
	{"id": "101.650(b)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Ensure applications running executable code are disabled by default on critical IT and OT systems;", "items": []},
	{"id": "101.650(b)(3)", "s": "101.650", "gate": "", "stem": "", "text": "Maintain an accurate inventory of network-connected systems, including designation of critical IT and OT systems; and", "items": []},
	{"id": "101.650(b)(4)", "s": "101.650", "gate": "", "stem": "", "text": "Develop and maintain accurate documentation identifying the network map and OT device configuration information.", "items": []},
	{"id": "101.650(c)", "s": "101.650", "gate": "", "stem": "", "text": "Data security measures. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following data security measures are in place and documented in Section 4 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(c)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Logs must be securely captured, stored, and protected so that they are accessible only by privileged users; and", "items": []},
	{"id": "101.650(c)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Effective encryption must be deployed to maintain confidentiality of sensitive data and integrity of IT and OT traffic, when technically feasible.", "items": []},
	{"id": "101.650(d)", "s": "101.650", "gate": "", "stem": "", "text": "Cybersecurity training for personnel. The training program to address requirements under this paragraph must be documented in Sections 2 and 4 of the Cybersecurity Plan.", "items": []},
	{"id": "101.650(d)(1)", "s": "101.650", "gate": "", "stem": "", "text": "All personnel with access to the IT or OT systems, including contractors, whether part-time, full-time, temporary, or permanent, must have cybersecurity training in the following topics:", "items": ["(i) Relevant provisions of the Cybersecurity Plan;", "(ii) Recognition and detection of cybersecurity threats and all types of cyber incidents;", "(iii) Techniques used to circumvent cybersecurity measures;", "(iv) Procedures for reporting a cyber incident to the CySO; and", "(v) OT-specific cybersecurity training for all personnel whose duties include using OT."]},
	{"id": "101.650(d)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Key personnel with access to the IT or remotely accessible OT systems, including contractors, whether part-time, full-time, temporary, or permanent, must also have cybersecurity training in the following additional topics:", "items": ["(i) Understanding their roles and responsibilities during a cyber incident and response procedure; and", "(ii) Maintaining current knowledge of changing cybersecurity threats and countermeasures."]},
	{"id": "101.650(d)(3)", "s": "101.650", "gate": "", "stem": "", "text": "When personnel must access IT or OT systems but are unable to receive cybersecurity training as specified in paragraphs (d)(1) and (2) of this section, they must be accompanied or monitored by a person who has completed the training specified in paragraphs (d)(1) and (2) of this section.", "items": []},
	{"id": "101.650(d)(4)", "s": "101.650", "gate": "", "stem": "", "text": "All personnel must complete the training specified in paragraphs (d)(1)(ii) through (v) of this section by January 12, 2026, and annually thereafter. Key personnel must complete the training specified in paragraph (d)(2) of this section by January 12, 2026, and annually thereafter, or more frequently as needed. Training for new personnel not in place at the time of the effective date of this rule must be completed within 5 days of gaining system access, but no later than within 30 days of hiring, and annually thereafter. Training for personnel on new IT or OT systems not in place at the time of the effective date of this rule must be completed within 5 days of system access, and annually thereafter. All personnel must complete the training specified in paragraph (d)(1)(i) within 60 days of receiving approval of the Cybersecurity Plan. The training must be documented and maintained in the owner's or operator's records in accordance with 33 CFR 104.235 for U.S.-flagged vessels, 105.225 for facilities, and 106.230 for OCS facilities.", "items": []},
	{"id": "101.650(e)", "s": "101.650", "gate": "", "stem": "", "text": "Risk management. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following measures for risk management are in place and documented in Sections 11 and 12 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(e)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Cybersecurity Assessment. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure completion of a Cybersecurity Assessment that addresses each covered U.S.-flagged vessel, facility, and OCS facility. A Cybersecurity Assessment must be conducted no later than July 16, 2027, and annually thereafter. However, the Cybersecurity Assessment must be conducted sooner than annually if there is a change in ownership of a U.S.-flagged vessel, facility, or OCS facility. In conducting the Cybersecurity Assessment, the owner or operator must—", "items": []},
	{"id": "101.650(e)(1)(i)", "s": "101.650", "gate": "", "stem": "", "text": "Analyze all networks to identify vulnerabilities to critical IT and OT systems and the risk posed by each digital asset;", "items": []},
	{"id": "101.650(e)(1)(ii)", "s": "101.650", "gate": "", "stem": "", "text": "Validate the Cybersecurity Plan;", "items": []},
	{"id": "101.650(e)(1)(iii)", "s": "101.650", "gate": "", "stem": "", "text": "Document recommendations and resolutions in the Vessel Security Assessment (VSA), Facility Security Assessment (FSA), or OCS FSA, in accordance with 33 CFR 104.305, 105.305, and 106.305;", "items": []},
	{"id": "101.650(e)(1)(iv)", "s": "101.650", "gate": "", "stem": "", "text": "Document and ensure patching or implementing of documented compensating controls for all KEVs in critical IT or OT systems, without delay; and", "items": []},
	{"id": "101.650(e)(1)(v)", "s": "101.650", "gate": "", "stem": "", "text": "Incorporate recommendations and resolutions from paragraph (e)(1)(iii) of this section into the Cybersecurity Plan through an amendment, in accordance with § 101.630(e).", "items": []},
	{"id": "101.650(e)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Penetration testing. In conjunction with Cybersecurity Plan renewal, the owner, operator, or designated CySO must ensure that a penetration test has been completed. Following the penetration test, a letter certifying that the test was conducted, as well as all identified vulnerabilities, must be included in the VSA, FSA, or OCS FSA, in accordance with 33 CFR 104.305, 105.305, and 106.305.", "items": []},
	{"id": "101.650(e)(3)", "s": "101.650", "gate": "", "stem": "", "text": "Routine system maintenance. Each owner or operator or a designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following measures for routine system maintenance are in place and documented in Section 6 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(e)(3)(i)", "s": "101.650", "gate": "", "stem": "", "text": "Ensure patching or implementation of documented compensating controls for all KEVs in critical IT or OT systems, without delay;", "items": []},
	{"id": "101.650(e)(3)(ii)", "s": "101.650", "gate": "", "stem": "", "text": "Maintain a method to receive and act on publicly submitted vulnerabilities;", "items": []},
	{"id": "101.650(e)(3)(iii)", "s": "101.650", "gate": "", "stem": "", "text": "Maintain a method to share threat and vulnerability information with external stakeholders;", "items": []},
	{"id": "101.650(e)(3)(iv)", "s": "101.650", "gate": "", "stem": "", "text": "Ensure there are no exploitable channels directly exposed to internet-accessible systems;", "items": []},
	{"id": "101.650(e)(3)(v)", "s": "101.650", "gate": "", "stem": "", "text": "Ensure no OT is connected to the publicly accessible internet unless explicitly required for operation, and verify that, for any remotely accessible OT system, there is a documented justification; and", "items": []},
	{"id": "101.650(e)(3)(vi)", "s": "101.650", "gate": "", "stem": "", "text": "Conduct vulnerability scans as specified in the Cybersecurity Plan.", "items": []},
	{"id": "101.650(f)", "s": "101.650", "gate": "", "stem": "", "text": "Supply chain. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following supply-chain measures are in place and documented in Section 4 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(f)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Consider cybersecurity capability as criteria for evaluation to procure IT and OT systems or services;", "items": []},
	{"id": "101.650(f)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Establish a process through which all IT and OT vendors or service providers notify the owner or operator or designated CySO of any cybersecurity vulnerabilities or reportable cyber incidents, without delay; and", "items": []},
	{"id": "101.650(f)(3)", "s": "101.650", "gate": "", "stem": "", "text": "Monitor and document all third-party remote connections to detect cyber incidents.", "items": []},
	{"id": "101.650(g)", "s": "101.650", "gate": "", "stem": "", "text": "Resilience. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following measures for resilience are in place and documented in Sections 3 and 9 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(g)(1)", "s": "101.650", "gate": "", "stem": "", "text": "For entities that have not reported to the Coast Guard pursuant to, or not subject to, 33 CFR 6.16-1, report reportable cyber incidents to the NRC without delay;", "items": []},
	{"id": "101.650(g)(2)", "s": "101.650", "gate": "", "stem": "", "text": "In addition to other plans mentioned in this subpart, develop, implement, maintain, and exercise the Cyber Incident Response Plan;", "items": []},
	{"id": "101.650(g)(3)", "s": "101.650", "gate": "", "stem": "", "text": "Periodically validate the effectiveness of the Cybersecurity Plan through annual exercises, annual reviews of incident response cases, or post-cyber incident review, as determined by the owner or operator; and", "items": []},
	{"id": "101.650(g)(4)", "s": "101.650", "gate": "", "stem": "", "text": "Perform backup of critical IT and OT systems, with those backups being sufficiently protected and tested frequently.", "items": []},
	{"id": "101.650(h)", "s": "101.650", "gate": "", "stem": "", "text": "Network segmentation. Each owner or operator or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following measures for network segmentation are in place and documented in Sections 7 and 8 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(h)(1)", "s": "101.650", "gate": "", "stem": "", "text": "Implement segmentation between IT and OT networks; and", "items": []},
	{"id": "101.650(h)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Verify that all connections between IT and OT systems are logged and monitored for suspicious activity, breaches of security, TSIs, unauthorized access, and cyber incidents.", "items": []},
	{"id": "101.650(i)", "s": "101.650", "gate": "", "stem": "", "text": "Physical security. Each owner, operator, or designated CySO of a U.S.-flagged vessel, facility, or OCS facility must ensure the following measures for physical security are in place and documented in Sections 7 and 8 of the Cybersecurity Plan:", "items": []},
	{"id": "101.650(i)(1)", "s": "101.650", "gate": "", "stem": "", "text": "In addition to any other requirements in this part, limit physical access to OT and related IT equipment to only authorized personnel, and confirm that all HMIs and other hardware are secured, monitored, and logged for personnel access; and", "items": []},
	{"id": "101.650(i)(2)", "s": "101.650", "gate": "", "stem": "", "text": "Ensure unauthorized media and hardware are not connected to IT and OT infrastructure, including blocking, disabling, or removing unused physical access ports, and establishing procedures for granting access on a by-exception basis.", "items": []},
	{"id": "101.655", "s": "101.655", "gate": "", "stem": "", "text": "All Cybersecurity Plans mentioned in this subpart must be submitted to the Coast Guard for review and approval no later than July 16, 2027, according to 33 CFR 104.410 for U.S.-flagged vessels, 33 CFR 105.410 for facilities, or 33 CFR 106.410 for OCS facilities.", "items": []},
	{"id": "101.660", "s": "101.660", "gate": "", "stem": "", "text": "Each owner or operator must ensure that the cybersecurity portion of their Plan and penetration test results are available to the Coast Guard upon request. The Alternative Security Program provisions apply to cybersecurity compliance documentation and are addressed in 33 CFR 104.140 for vessels, 33 CFR 105.140 for facilities, and 33 CFR 106.135 for OCS facilities.", "items": []},
	{"id": "101.665", "s": "101.665", "gate": "", "stem": "", "text": "An owner or operator, after completion of the required Cybersecurity Assessment, may seek a waiver or an equivalence determination for the requirements in subpart F using the standards and submission procedures applicable to a U.S.-flagged vessel, facility, or OCS facility as outlined in 33 CFR 101.130, 104.130, 104.135, 105.130, 105.135, 106.125, or 106.130. If an owner or operator must temporarily deviate from the requirements in this part, they must notify the cognizant COTP for facilities or OCS facilities, or the MSC for U.S.-flagged vessels, and may request temporary permission to continue to operate under the provisions as outlined in 33 CFR 104.125, 105.125, or 106.120.", "items": []},
]

obligations := {r.id: r | some r in _rows}

default compliant := false

compliant if count(violations) == 0

_in := input.maritime_33cfr101f if is_object(input.maritime_33cfr101f)

else := {}

_given := a if {
	a := _in.obligations
	is_object(a)
}

_supplied if _given

_attested(id) if _given[id] == true

violations contains "33 CFR 101 Subpart F: FAIL-CLOSED - attestations 'input.maritime_33cfr101f.obligations' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

_gate_open(g) if g == ""

applicable[id] := r if {
	some r in _rows
	_gate_open(r.gate)
	id := r.id
}

violations contains msg if {
	some id, r in applicable
	not _attested(id)
	msg := sprintf("33 CFR 101 Subpart F %v (%v): not attested — %v", [id, sections[r.s], r.text])
}

violations contains msg if {
	some id, _ in _given
	not obligations[id]
	msg := sprintf("33 CFR 101 Subpart F Input Contract: unknown id %v — ids are the CFR paragraph citations carried in this module, e.g. 101.650(a)(4)", [id])
}

section_reports[s] := rep if {
	some s, title in sections
	all_ids := [r.id | some r in _rows; r.s == s]
	open_ids := [r.id | some r in _rows; r.s == s; applicable[r.id]]
	rep := {
		"title": title,
		"total": count(all_ids),
		"applicable": count(open_ids),
		"attested": count([id | some id in open_ids; _attested(id)]),
		"gaps": [id | some id in open_ids; not _attested(id)],
	}
}

compliance_report := {
	"framework": framework,
	"source": source,
	"compliant": compliant,
	"total_controls": 105, # owner/operator and CySO obligation rows emitted from §§101.620–101.665 (see header)
	"dated_obligations": dated_obligations,
	"notification_clocks": notification_clocks,
	"evaluated": count(applicable),
	"attested": count([id | some id; _ = applicable[id]; _attested(id)]),
	"sections": section_reports,
	"violation_count": count(violations),
	"violations": violations,
}
