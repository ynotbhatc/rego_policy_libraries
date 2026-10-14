# OWASP Top 10:2025 (web application security risks). One attested row per category.
#
# Source (untrusted data, parsed by a generator; nothing executed):
#   https://owasp.org/Top10/2025/ (index)  sha256 1203f554f0770ae735ca70bc9621ae6769d7d159eec74dede39a342bb17bc52d
#   https://owasp.org/Top10/2025/0x00_2025-Introduction/  sha256 c77962e50792258f0061d5cb5fb6586642e528a2b130106bafe5db2959af4a20
#   A01:2025  https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
#     sha256 e51ca05866f4213489e82484f1f48ed4d779e1809e87f70449806b496a0320cd
#   A02:2025  https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
#     sha256 532fbbd67f3db734b7ed5d47e0263dd3800fce80e22da327123a88f2947017c9
#   A03:2025  https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/
#     sha256 66090225ad8f54a836e5b9e94456243baa7d38b70176f4d720668ef36f3a793d
#   A04:2025  https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/
#     sha256 5b140b4cadf334becc35334278494f98396dc9b5720df6c904688352b51dc834
#   A05:2025  https://owasp.org/Top10/2025/A05_2025-Injection/
#     sha256 69d7ec591944699c49b89c544a52cb32adccbfad56c41784ca34fde837822de6
#   A06:2025  https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
#     sha256 cf67ac90b3c088ca4566807fbc4bbd2090bccc81d61f15c0e25190032618195f
#   A07:2025  https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
#     sha256 9decccf146242740ba34b1c14df7b729ef159274a3533182c6bcefc9f52c8816
#   A08:2025  https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/
#     sha256 03082e5a3ce031d6d2425927653aca0ad47d474dafb4208862e86b4363d66d85
#   A09:2025  https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
#     sha256 e8f875d2db062bfd3eb00db65486b30dd64c417357f9346a395cf434b5055f31
#   A10:2025  https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
#     sha256 492a7444a58c06ec76af06ed4f89e656804cde6b71f61ba2ed5703a9aa343864
#   retrieved 2026-10-14; release year 2025 (the 8th installment).
# Licence: the OWASP Top 10 site states "Creative Commons Attribution 3.0 Unported" in its page footer (the
# task brief said CC BY-SA 4.0; the site footer was taken as authoritative and the discrepancy reported). Either
# way, no OWASP prose is copied here: each row carries only the category id and title, the list of CWE ids from
# the category's "List of Mapped CWEs", a one-line summary written independently, and the page URL.
# Attribution: OWASP Top 10:2025, OWASP Top 10 Team, https://owasp.org/Top10/2025/.
#
# Row counts: A01 40 CWEs, A02 16, A03 6, A04 32, A05 37, A06 39, A07 36, A08 14, A09 5, A10 24 (each equals
# the "CWEs Mapped" figure in that page's own score table; 249 mappings). The Introduction page's prose quotes
# 38 CWEs for Injection and 5 for Supply Chain; the category pages list 37 and 6. The category page lists are used.
#
# The 2021 to 2025 relationship is data (mapping_2021): only what the site states in words is recorded. The
# Introduction's mapping figure is an image and is not transcribed. Kept as string data, not rows or checks.
#
# Input: input.owasp_top10.categories["A01:2025"] == true means the organisation attests the category is
# addressed. Fail-closed: a missing or non-object categories container is a FAIL-CLOSED violation; a missing,
# false or non-true value is a violation; an unknown id is a violation.
#
# Query: POST /v1/data/owasp_top10/main/compliance_report

# METADATA
# title: "OWASP Top 10:2025 — ten web application security risk categories with mapped CWEs, attested"
# custom:
#   class: governance
#   framework: owasp_top10
#   source: owasp
#   domains: [secure-development]
#   coverage:
#     checks: 13
#     cited: 10
#     expected: 10
#     found: 10
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package owasp_top10.main

import rego.v1

source := {
	"publication": "OWASP Top 10:2025",
	"url": "https://owasp.org/Top10/2025/",
	"index_sha256": "1203f554f0770ae735ca70bc9621ae6769d7d159eec74dede39a342bb17bc52d",
	"licence": "Creative Commons Attribution 3.0 Unported (site footer)",
	"retrieved": "2026-10-14",
}

# Array of row objects: ids contain a colon, so the keyed map below is built from it.
category_rows := [
	{
		"id": "A01:2025",
		"rank": 1,
		"title": "Broken Access Control",
		"cwes": ["CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-61", "CWE-65", "CWE-200", "CWE-201", "CWE-219", "CWE-276", "CWE-281", "CWE-282", "CWE-283", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-379", "CWE-402", "CWE-424", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-615", "CWE-639", "CWE-668", "CWE-732", "CWE-749", "CWE-862", "CWE-863", "CWE-918", "CWE-922", "CWE-1275"],
		"summary": "Users can reach data or functions their role should not allow, including server-side request forgery and cross-site request forgery.",
		"url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
	},
	{
		"id": "A02:2025",
		"rank": 2,
		"title": "Security Misconfiguration",
		"cwes": ["CWE-5", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-489", "CWE-526", "CWE-547", "CWE-611", "CWE-614", "CWE-776", "CWE-942", "CWE-1004", "CWE-1174"],
		"summary": "Insecure, default or missing configuration of systems, frameworks, servers and cloud services.",
		"url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
	},
	{
		"id": "A03:2025",
		"rank": 3,
		"title": "Software Supply Chain Failures",
		"cwes": ["CWE-447", "CWE-1035", "CWE-1104", "CWE-1329", "CWE-1357", "CWE-1395"],
		"summary": "Compromise of, or vulnerabilities in, third-party dependencies, build systems and distribution channels.",
		"url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
	},
	{
		"id": "A04:2025",
		"rank": 4,
		"title": "Cryptographic Failures",
		"cwes": ["CWE-261", "CWE-296", "CWE-319", "CWE-320", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-332", "CWE-334", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-342", "CWE-347", "CWE-523", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-916", "CWE-1240", "CWE-1241"],
		"summary": "Missing or weak cryptography for data in transit and at rest, including poor key and randomness handling.",
		"url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
	},
	{
		"id": "A05:2025",
		"rank": 5,
		"title": "Injection",
		"cwes": ["CWE-20", "CWE-74", "CWE-76", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-86", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-103", "CWE-104", "CWE-112", "CWE-113", "CWE-114", "CWE-115", "CWE-116", "CWE-129", "CWE-159", "CWE-470", "CWE-493", "CWE-500", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-917"],
		"summary": "Untrusted input interpreted as commands or queries by an interpreter (SQL, OS command, script, template and similar).",
		"url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
	},
	{
		"id": "A06:2025",
		"rank": 6,
		"title": "Insecure Design",
		"cwes": ["CWE-73", "CWE-183", "CWE-256", "CWE-266", "CWE-269", "CWE-286", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-362", "CWE-382", "CWE-419", "CWE-434", "CWE-436", "CWE-444", "CWE-451", "CWE-454", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-598", "CWE-602", "CWE-628", "CWE-642", "CWE-646", "CWE-653", "CWE-656", "CWE-657", "CWE-676", "CWE-693", "CWE-799", "CWE-807", "CWE-841", "CWE-1021", "CWE-1022", "CWE-1125"],
		"summary": "Design-level flaws from missing threat modelling and security requirements, as opposed to coding defects.",
		"url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
	},
	{
		"id": "A07:2025",
		"rank": 7,
		"title": "Authentication Failures",
		"cwes": ["CWE-258", "CWE-259", "CWE-287", "CWE-288", "CWE-289", "CWE-290", "CWE-291", "CWE-293", "CWE-294", "CWE-295", "CWE-297", "CWE-298", "CWE-299", "CWE-300", "CWE-302", "CWE-303", "CWE-304", "CWE-305", "CWE-306", "CWE-307", "CWE-308", "CWE-309", "CWE-346", "CWE-350", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-941", "CWE-1390", "CWE-1391", "CWE-1392", "CWE-1393"],
		"summary": "Weak or bypassable identity proof and session handling, including default, hard-coded or guessable credentials.",
		"url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
	},
	{
		"id": "A08:2025",
		"rank": 8,
		"title": "Software or Data Integrity Failures",
		"cwes": ["CWE-345", "CWE-353", "CWE-426", "CWE-427", "CWE-494", "CWE-502", "CWE-506", "CWE-509", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-915", "CWE-926"],
		"summary": "Code, updates or data accepted without verifying origin and integrity, including unsafe deserialisation.",
		"url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
	},
	{
		"id": "A09:2025",
		"rank": 9,
		"title": "Security Logging & Alerting Failures",
		"cwes": ["CWE-117", "CWE-221", "CWE-223", "CWE-532", "CWE-778"],
		"summary": "Security-relevant events not logged, protected or alerted on, so attacks are not detected or acted on.",
		"url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
	},
	{
		"id": "A10:2025",
		"rank": 10,
		"title": "Mishandling of Exceptional Conditions",
		"cwes": ["CWE-209", "CWE-215", "CWE-234", "CWE-235", "CWE-248", "CWE-252", "CWE-274", "CWE-280", "CWE-369", "CWE-390", "CWE-391", "CWE-394", "CWE-396", "CWE-397", "CWE-460", "CWE-476", "CWE-478", "CWE-484", "CWE-550", "CWE-636", "CWE-703", "CWE-754", "CWE-755", "CWE-756"],
		"summary": "Errors and abnormal conditions handled badly: information leaks, failing open, and unchecked states.",
		"url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
	},
]

categories := {r.id: r | some r in category_rows}

# 2021 to 2025 relationship as stated on the site (strings only).
mapping_2021 := {
	"A01:2025": "stated: #1 in 2021 as well (maintains its position); SSRF (A10:2021) rolled into it",
	"A02:2025": "stated: moved up from #5 in 2021",
	"A03:2025": "stated: expansion of A06:2021 Vulnerable and Outdated Components",
	"A04:2025": "stated: fell from #2 in 2021",
	"A05:2025": "stated: fell from #3 in 2021",
	"A06:2025": "stated: slid from #4 in 2021",
	"A07:2025": "stated: kept #7 from 2021 (renamed from Identification and Authentication Failures)",
	"A08:2025": "stated: continues at #8",
	"A09:2025": "stated: retains #9 (renamed from Security Logging and Monitoring Failures)",
	"A10:2025": "stated: new category in 2025",
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "owasp_top10", {})

_given := c if {
	c := _in.categories
	is_object(c)
}

_supplied if _given

_true(id) if _given[id] == true

violations contains "OWASP Top 10:2025: FAIL-CLOSED - category attestations 'input.owasp_top10.categories' were not supplied (or are not an object); this module cannot be evaluated without them" if {
	not _supplied
}

violations contains msg if {
	some id, c in categories
	not _true(id)
	msg := sprintf("OWASP Top 10:2025 %v (%v): not attested as addressed (%v mapped CWEs)", [id, c.title, count(c.cwes)])
}

violations contains msg if {
	some id, _ in _given
	not categories[id]
	msg := sprintf("OWASP Top 10:2025 Input Contract: unknown category id %v - ids are A01:2025 to A10:2025", [id])
}

category_rollup[id] := s if {
	some id, c in categories
	s := {
		"rank": c.rank,
		"title": c.title,
		"cwes_mapped": count(c.cwes),
		"attested": _attested(id),
	}
}

_attested(id) if _true(id)

else := false

compliance_report := {
	"framework": "OWASP Top 10:2025",
	"standard": "OWASP Top 10:2025 (web application security risks)",
	"source": source,
	"compliant": compliant,
	"total_controls": count(categories),
	"standard_total": 10, # categories A01:2025 to A10:2025
	"categories_total": count(categories),
	"categories_attested": count({id | some id, _ in categories; _true(id)}),
	"cwe_mappings_total": sum([count(c.cwes) | some c in category_rows]),
	"categories": category_rollup,
	"violation_count": count(violations),
	"violations": violations,
}
