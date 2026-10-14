# NIST CSWP 39-upd1 — Considerations for Achieving Crypto Agility: Strategies
# and Practices — crypto-agility view inside the PQC readiness tree.
#
# Source (verified 2026-10-13):
#   NIST CSWP 39-upd1, "Considerations for Achieving Crypto Agility:
#   Strategies and Practices", December 19, 2025, includes updates as of
#   2026-06-29 (approved by the NIST ERB 2026-06-24).
#   https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39-upd1.pdf
#   DOI 10.6028/NIST.CSWP.39-upd1
#   sha256 e6b147d23eba193653f2abb3abe03fc25e63a9a91df918440b5445f9f58e9ac6
#   NIST text is public domain.
#
# History: upd1 supersedes the December 2025 edition (NIST CSWP 39,
# https://doi.org/10.6028/NIST.CSWP.39, withdrawn 2026-06-29; sha256
# 11c7c012423a8612a7bc42a1a7b5458437180dc47404bafc79f52ef97372c821). Appendix C of
# upd1 lists one change: the 3rd paragraph of §2.3 (SP 800-57 / IR 8547
# transition timeline, now also citing SP 800-131Ar3 [50]). §2 is
# background, so no row was added, removed or reworded; a sentence-level
# diff of chapters 3–7 between the two editions is otherwise identical
# (one layout-only change: §6.5's closing Tier 4 sentence is now a bullet).
# Section numbering is unchanged, so the ids carry over.
#
# What this is: CSWP 39 is a considerations paper, not a requirements
# standard (SCF maps it nonetheless). Each row is one sentence, verbatim,
# from chapters 3–7 that recommends or requires something an organisation
# can do or not do ("should", "must", "need(s) to", "is important to", "are
# encouraged to", or an imperative bullet of the §5 strategic plan). Ids are
# the paper's own section numbers (the unnumbered chapter intros use the
# chapter number: "3", "5"); where a section yields several rows a stable
# suffix in reading order is added ("3.4.2-e", "5-d"). Descriptive sentences
# are not rows.
#
# Not rows (data, not practices): Executive Summary, §1 Introduction
# (definitions, scope), §2 Historic Transitions (history), §6.5's maturity
# tiers (Tier 1 Partial .. Tier 4 Adaptive — descriptive characteristics of
# each tier), References, Appendices A–C.
#
# Addressee gates. The paper addresses SDOs, cryptographers, protocol
# designers, implementers, cloud providers and enterprises. Sentences
# addressed only to SDOs, algorithm designers/cryptographers, technology
# producers, cloud providers or the common-API consortium are judgement
# calls, excluded below. Sentences addressed to designers/implementers of
# protocols, systems, libraries, kernels, embedded or hardware cryptography
# apply only when the organisation declares it builds such things
# (develops_cryptographic_implementations); the §6.4 IaaS-customer sentence
# applies only when the organisation self-manages cryptography in the cloud.
# Both flags MUST be declared true or false.
#
# Rows per chapter (measured = rows in the paper under the rule above;
# emitted = rows here): ch3 23/23, ch4 12/12, ch5 19/19, ch6 10/10, ch7 3/3;
# total 67 (33 all organisations, 33 implementer-gated, 1 cloud-gated).
# Chapters 1–2 and the Executive Summary: 0 rows by design.
#
# Judgement calls — INCLUDED as rows although borderline:
#   3-c     "...the cipher suite negotiation mechanism needs to accommodate..."
#           (compound sentence, first half descriptive)
#   3.1-a   "Designers are encouraged to..." (encouraged, not should)
#   3.2.4   "...the expense ... must be considered" (in a descriptive sentence)
#   3.4     chapter-3.4 intro, restated by 3.4.1-a and 3.4.2-a
#   3.2.2-a / 3.2.2-b near-duplicates ("need to plan" / "should plan"); kept
#           as two rows because they are two sentences
#   4.2-a, 4.4-a "the crypto API must (also) be accessible ..." (design
#           requirement stated as a condition for agility)
#   5-b     "This includes understanding ... and communicating these
#           requirements to ... technology supply chain vendors" (elaborates
#           the 5-a bullet; it carries the supply-chain communication practice)
#   5-k     "These steps are continuously repeated..." (present tense, read
#           as the plan's repetition practice)
#   5.3     "...the organization implements the defined mitigation strategies
#           and begins the replacement process..." (present tense; the only
#           organisation-actionable sentence in 5.3)
#   6.3-a   "...that protocol designers and system architects and implementers
#           should take into consideration" (gated as implementer)
#   7-a..c  Conclusion sentences; 7-a/7-b restate 6 and 6.3 but are separate
#           "must"/"should" sentences
# Judgement calls — EXCLUDED (reason):
#   Exec. Summary "crypto agility is a key practice that should be adopted at
#           all levels" (summary); §2 "cryptographic transitions ... should be
#           an important part of security practices within an
#           organization-wide risk management program" (history chapter)
#   3.1.1 x3, 3.2.2 "SDOs should provide notice", 3.4.1 "SDOs should provide
#           clear guidance" (addressed to SDOs)
#   3.2   "Administrators may choose to stop using..." and "administrators can
#           change a configuration setting to prohibit..." (permissive);
#           "revoking the certificate indicates ... should not be used"
#           (certificate semantics)
#   4.2   "At minimum, designing kernel crypto libraries ... will
#           significantly improve agility" (benefit statement)
#   4.3   service mesh (descriptive throughout: "can enhance", "enables")
#   4.5   "the best and most conservative variants ... can be implemented"
#           (permissive); "A key element is the communication between
#           cryptographers and developers..." (descriptive)
#   4.6   crypto gateway "can be implemented" (permissive)
#   5     "Organizations need to transition ... multiple times" (fact);
#           "Organizations can use existing automated enterprise management
#           tools..." (permissive)
#   5.2   "Enforcing a cryptographic security policy requires communication..."
#           (descriptive; the practice is 5.2-b)
#   5.3   "Technology producers can help..." (addressed to producers)
#   5.4   "Organizations can include crypto agility characteristics as part
#           of the cryptographic architecture..." (permissive; 5.4 yields 0)
#   6.1   three sentences addressed to algorithm designers/cryptographers and
#           one research direction
#   6.2   "This requires a user interface (UI) and API..." (consequence of
#           6.2-a); "It may be beneficial to include ... Crypto Agility
#           Considerations in the standards" (standards authors, permissive)
#   6.3   "Crypto agility requires sound mechanisms..." (descriptive)
#   6.4   "Cloud providers are responsible for ensuring the agility..."
#           (addressed to providers)
#   6.6   "An effective solution must balance generality with specificity..."
#           (addressed to the common-API consortium)
#
# Input contract — input.pqc.cswp39.*
#   develops_cryptographic_implementations  bool — the organisation designs or
#       implements security protocols, applications, libraries, kernels,
#       embedded or hardware cryptography (gates the designer/implementer rows)
#   self_manages_cloud_cryptography         bool — the organisation manages
#       its own HSMs or cryptographic applications in IaaS, or integrates
#       cloud services with on-premises cryptography (gates 6.4)
#   practices                               {"<id>": true, ...}
#
# Fail-closed: absent practices (explicit FAIL-CLOSED violation), a non-true
# attestation, an unknown id, a malformed container or an undeclared flag
# are violations. Reported per chapter; wired into pqc.main's
# compliance_report as the separate `crypto_agility_cswp39` section — it
# does not change pqc.main's own violations, compliant or controls_evaluated.
#
# Query: POST /v1/data/pqc/cswp39/compliance_report

# METADATA
# title: "NIST CSWP 39-upd1 Crypto Agility (updated 2026-06-29) — strategies and practices"
# custom:
#   class: compliance
#   framework: pqc
#   source: nist
#   domains: [us-federal, cryptography]
#   coverage:
#     checks: 75
#     cited: 71
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package pqc.cswp39

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

chapters := {
	"3": "§3 Crypto Agility for Security Protocols",
	"4": "§4 Crypto Agility in System Implementations",
	"5": "§5 Crypto Agility Strategic Plan for Managing Organizations’ Crypto Risks",
	"6": "§6 Considerations for Future Works",
	"7": "§7 Conclusion",
}

_flags := {
	"develops_cryptographic_implementations": "NIST CSWP 39 §§3–4, 6.1–6.3 — whether the organisation designs or implements protocols, applications, libraries, kernels, embedded or hardware cryptography must be declared true or false",
	"self_manages_cloud_cryptography": "NIST CSWP 39 §6.4 — whether the organisation self-manages cryptography in the cloud (own HSMs or cryptographic applications in IaaS, or cloud services integrated with on-premises cryptography) must be declared true or false",
}

practices := {
	# ── Chapter 3 ──
	"3-a": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "To achieve crypto agility, security protocol implementations should be modular so they can easily accommodate the insertion of new algorithms or cipher suites."},
	"3-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Implementations should also provide a way to determine when deployed implementations have shifted from the old algorithms to more desirable ones."},
	"3-c": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "The set of mandatory-to-implement algorithms is expected to change over time, and the cipher suite negotiation mechanism needs to accommodate the identification of yet-to-be specified algorithms in the future."},
	"3.1-a": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Designers are encouraged to pick one of these approaches and use it consistently throughout the protocol or family of protocols."},
	"3.1-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "To avoid these interoperability problems in the future, any aspect of the algorithm not specified by the algorithm identifiers needs to be negotiated, including the key size and other parameters."},
	"3.2": {"ch": "3", "gate": "", "text": "When the new algorithm is widely deployed, it should be used in lieu of the old algorithm."},
	"3.2.2-a": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "As part of their crypto agility efforts in the transition to PQC, security protocol designers need to plan for public keys, signatures, and key-encapsulation ciphertext to be much larger than those currently used."},
	"3.2.2-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "To be safe, security protocol designers should plan for significant growth in the size of cryptographic data."},
	"3.2.3-a": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "The mechanism that a security protocol uses to perform cryptographic algorithm negotiation should include integrity protection."},
	"3.2.3-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "In this case, the integrity protection should be at least as strong as that provided by a future cipher suite, which can result in the need for several mandatory-to-implement algorithms to cover the various security strength requirements."},
	"3.2.4": {"ch": "3", "gate": "", "text": "The PKI root of trust must be known to all of the relying parties to validate a certificate, and the cost of deploying a PKI root of trust is significant, so the expense associated with a transition to the use of a hybrid root of trust followed by a potential second transition to using only a PQC algorithm for a root of trust must be considered."},
	"3.3-a": {"ch": "3", "gate": "", "text": "In addition, administrators need to be aware that multiple environments are being used, track the policies, and enable the algorithms or cipher suites for each of them."},
	"3.3-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Security protocol designers should perform an analysis to ensure that all security goals are achieved when each of the possible key-establishment mechanisms is used."},
	"3.4": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "When a protocol designer is specifying a cipher suite, the relative strength of each algorithm needs to be considered, and complexity in security protocols needs to be avoided."},
	"3.4.1-a": {"ch": "3", "gate": "", "text": "When selecting or negotiating a cipher suite, the relative strength of each algorithm needs to be considered."},
	"3.4.1-b": {"ch": "3", "gate": "", "text": "The security protections provided by each algorithm in a particular context need to be considered when making the selection."},
	"3.4.1-c": {"ch": "3", "gate": "", "text": "Algorithm strength needs to be considered when a security protocol is designed, implemented, deployed, and configured."},
	"3.4.1-d": {"ch": "3", "gate": "", "text": "Performance and security need to be balanced."},
	"3.4.2-a": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Security protocol designers need to balance agility with simplicity and anticipate changes to the supported set of cryptographic algorithms over time."},
	"3.4.2-b": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Security protocol implementations should be as straightforward as possible to reduce vulnerability to attacks."},
	"3.4.2-c": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "While support for multiple algorithms is necessary to achieve crypto agility, gratuitous options should be avoided to keep implementations from becoming unnecessary large."},
	"3.4.2-d": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Furthermore, once an algorithm is disallowed, it should be removed from the protocol to reduce complexity."},
	"3.4.2-e": {"ch": "3", "gate": "develops_cryptographic_implementations", "text": "Implementers should periodically review the options that are actually being used and then remove unused options to keep the attack surface as small as possible."},
	# ── Chapter 4 ──
	"4-a": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "To achieve crypto agility, system designers must introduce mechanisms that simplify the replacement of cryptographic algorithms in software, libraries, hardware, firmware, and infrastructures."},
	"4-b": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Therefore, system designers must make sure that the cryptographic interface is easy to use and well-documented to reduce the risk of errors."},
	"4-c": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Additionally, clear guidance must be provided for practitioners to follow."},
	"4.1-a": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Application developers need to consider whether the API is provided via the command line interface (CLI) or by incorporating the cryptographic algorithm’s source code into the application (i.e., “compiling in” support)."},
	"4.1-b": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "For software libraries, it is important to facilitate efficient updates."},
	"4.1-c": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Some standard mechanisms must be in place to avoid security pitfalls in library updates."},
	"4.2-a": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "To provide crypto agility in this case, the crypto API must also be accessible within the kernel."},
	"4.2-b": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Where feasible, operating system designers should consider modular or updatable cryptographic components in the kernel."},
	"4.4-a": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "To support cryptographic flexibility in this environment, the cryptographic API must be accessible to privileged code within the RTOS."},
	"4.4-b": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "Designers should consider the need to update the cryptographic implementation together or separately from the rest of the system."},
	"4.5-a": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "The crypto API needs to be designed so that all points on this spectrum are accommodated."},
	"4.5-b": {"ch": "4", "gate": "develops_cryptographic_implementations", "text": "In this case, to make sure that the platform is trustable during its lifetime, the signature schemes must be able to provide the required security during the lifetime of the device."},
	# ── Chapter 5 ──
	"5-a": {"ch": "5", "gate": "", "text": "Integrate crypto agility into the organization’s existing governance function to establish, communicate, and monitor the cybersecurity risk management strategy, expectations, and policies related to cryptography."},
	"5-b": {"ch": "5", "gate": "", "text": "This includes understanding cryptographic standards, regulations, and mandates and communicating these requirements to data owners, IT and development teams, business partners, and technology supply chain vendors prioritized by the criticality of the data for the primary use cases."},
	"5-c": {"ch": "5", "gate": "", "text": "Identify key stakeholders, including a responsible official to lead the effort and monitor the progress of the activities."},
	"5-d": {"ch": "5", "gate": "", "text": "Inventory the use of cryptography for data protection across the organization by adopting an assets-centric approach informed by the criticality of the data to identify the organization’s use cases and most valuable assets, such as application codes, libraries, software, hardware, firmware, user-generated content, communication protocols, enterprise services, and systems."},
	"5-e": {"ch": "5", "gate": "", "text": "Identify gaps in enterprise management tools for managing assets, configurations, vulnerabilities, and logs."},
	"5-f": {"ch": "5", "gate": "", "text": "These tools should support cryptographic risk management and data protection functions by automating the identification, assessment, characterization, enforcement, and monitoring of cryptography across assets."},
	"5-g": {"ch": "5", "gate": "", "text": "If necessary, enhance the tools with automated data and cryptographic discovery capabilities, including algorithms and key lengths."},
	"5-h": {"ch": "5", "gate": "", "text": "Develop a prioritized list of assets to be mitigated based on the data collected in the previous steps."},
	"5-i": {"ch": "5", "gate": "", "text": "A cryptographic policy-informed risk assessment engine should be used to analyze this data, form an implementation strategy, and recommend actions to reduce risks."},
	"5-j": {"ch": "5", "gate": "", "text": "Implement the strategy and actions based on the prioritized list of assets."},
	"5-k": {"ch": "5", "gate": "", "text": "These steps are continuously repeated to mitigate evolving cryptographic risks and progressively strengthen the crypto agility posture within organizations over time."},
	"5.1-a": {"ch": "5", "gate": "", "text": "Any crypto agility effort must consider the effects of standards, regulations, and mandates on transition requirements for cryptographic algorithms."},
	"5.1-b": {"ch": "5", "gate": "", "text": "From a practitioner’s perspective, certain policies, laws, and mechanisms must be established to enhance crypto agility practices, facilitate transitions, and provide proper security during the transition."},
	"5.1-c": {"ch": "5", "gate": "", "text": "It is very important to handle assets in a secure way during a transition."},
	"5.1-d": {"ch": "5", "gate": "", "text": "For example, for the encrypted storage of data at rest, a mechanism must be established to handle encrypted user data when the encryption algorithm is to be replaced by a stronger one."},
	"5.1-e": {"ch": "5", "gate": "", "text": "Similarly, when a digital signature algorithm must be replaced, a mechanism to handle already-signed documents using the algorithm to be replaced is required."},
	"5.2-a": {"ch": "5", "gate": "", "text": "The crypto agility assessment must consider cryptographic security policy establishment and enforcement for each protocol, system, and application."},
	"5.2-b": {"ch": "5", "gate": "", "text": "Each decision on deprecating a cryptographic algorithm must be synchronized among all of the stakeholders so that the security policy can be updated quickly and translated into a technology-specific, machine-consumable configuration profile that represents a crypto policy that can be deployed with automated tools."},
	"5.3": {"ch": "5", "gate": "", "text": "When systems reach their end-of-life stage and their cryptographic components no longer comply with organizational cryptographic policies, the organization implements the defined mitigation strategies and begins the replacement process as outlined in its policy."},
	# ── Chapter 6 ──
	"6": {"ch": "6", "gate": "", "text": "To be actionable, crypto agility requirements must be specific for each implementation and application environment."},
	"6.1": {"ch": "6", "gate": "develops_cryptographic_implementations", "text": "It is important for protocol designers to consider resource demands to plan for future transitions and to distinguish intrinsic limitations from shortsighted design decisions."},
	"6.2-a": {"ch": "6", "gate": "develops_cryptographic_implementations", "text": "To achieve cryptographic agility, a product or system must be designed to accommodate new algorithms and parameters."},
	"6.2-b": {"ch": "6", "gate": "develops_cryptographic_implementations", "text": "The design should avoid making assumptions based on specific algorithms to ensure that buffers, memory, and storage can handle diverse cryptographic data."},
	"6.2-c": {"ch": "6", "gate": "develops_cryptographic_implementations", "text": "It should be a common practice in any protocol design to facilitate secure transition and avoid inflexible implementations."},
	"6.2-d": {"ch": "6", "gate": "", "text": "It is also important to include crypto agility as an evaluation perspective for project proposals, security architects, protection profiles, protocol specifications, and application designs."},
	"6.3-a": {"ch": "6", "gate": "develops_cryptographic_implementations", "text": "Accommodating crypto agility introduces complexity into protocols and systems that protocol designers and system architects and implementers should take into consideration."},
	"6.3-b": {"ch": "6", "gate": "", "text": "For enterprise IT administrators, it is important to make sure that the configuration is updated to reflect current security requirements."},
	"6.4": {"ch": "6", "gate": "self_manages_cloud_cryptography", "text": "In the IaaS model, customers have more control, but they are responsible for the agility of their cryptographic functions when they choose to manage their own hardware (e.g., HSMs) or cryptographic applications within the cloud or when integrating cloud-based applications and services that employ on-premises cryptographic services."},
	"6.5": {"ch": "6", "gate": "", "text": "Instead, organizations should adapt their existing, mature risk management frameworks to include crypto agility."},
	# ── Chapter 7 ──
	"7-a": {"ch": "7", "gate": "", "text": "The pursuit of crypto agility capabilities involves the exploration of new technologies and management schemes, and new crypto agility requirements must be developed for each environment."},
	"7-b": {"ch": "7", "gate": "", "text": "The security analysis and evaluation of protocols, systems, and applications must include mechanisms for transitions."},
	"7-c": {"ch": "7", "gate": "", "text": "When transition mechanisms are not available, organizations should have a plan to implement compensating controls to mitigate cryptographic vulnerabilities and evolving threats."},
}

# ── Input ────────────────────────────────────────────────────────────────────

_raw := object.get(input, ["pqc", "cswp39"], {})

default _in := {}

_in := _raw if is_object(_raw)

_raw_practices := object.get(_in, "practices", null)

default _attestations := {}

_attestations := _raw_practices if is_object(_raw_practices)

violations contains msg if {
	not is_object(_raw)
	msg := "NIST CSWP 39 Input Contract: input.pqc.cswp39 must be an object"
}

violations contains msg if {
	_raw_practices == null
	msg := "NIST CSWP 39 FAIL-CLOSED: no crypto-agility practice attestations supplied (input.pqc.cswp39.practices is absent) — every applicable practice is reported unattested"
}

violations contains msg if {
	_raw_practices != null
	not is_object(_raw_practices)
	msg := "NIST CSWP 39 Input Contract: input.pqc.cswp39.practices must be an object of {\"<section id>\": true}"
}

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (pqc.cswp39.%v undeclared)", [text, key])
}

# ── Applicability and attestation ────────────────────────────────────────────

_gate_open(g) if g == ""

_gate_open(g) if _in[g] == true

applicable[id] := p if {
	some id, p in practices
	_gate_open(p.gate)
}

_attested(id) if _attestations[id] == true

violations contains msg if {
	some id, p in applicable
	not _attested(id)
	msg := sprintf("NIST CSWP 39 §%v (%v): %v — not attested", [id, chapters[p.ch], p.text])
}

violations contains msg if {
	some id, _ in _attestations
	not practices[id]
	msg := sprintf("NIST CSWP 39 Input Contract: attestation for unknown practice id %v — not a practice row of CSWP 39 chapters 3–7", [id])
}

# ── Report ───────────────────────────────────────────────────────────────────

chapter_reports[ch] := r if {
	some ch, name in chapters
	ids := {id | some id, p in applicable; p.ch == ch}
	passed := {id | some id in ids; _attested(id)}
	gaps := sort([id | some id in ids; not id in passed])
	r := {
		"chapter": name,
		"practices_total": count({id | some id, p in practices; p.ch == ch}),
		"practices_evaluated": count(ids),
		"practices_attested": count(passed),
		"gaps": gaps,
		"complete": count(gaps) == 0,
	}
}

compliance_report := {
	"framework": "NIST CSWP 39-upd1 — Considerations for Achieving Crypto Agility: Strategies and Practices",
	"document": "NIST CSWP 39-upd1, December 19, 2025, includes updates as of 2026-06-29 — recommendations of a considerations paper, not requirements",
	"source": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39-upd1.pdf (sha256 e6b147d23eba193653f2abb3abe03fc25e63a9a91df918440b5445f9f58e9ac6)",
	"supersedes": "NIST CSWP 39 (December 2025, withdrawn 2026-06-29); upd1 Appendix C changes only §2.3 (background), no practice row changed",
	"flags": {k: object.get(_in, k, "undeclared") | some k, _ in _flags},
	"practices_total": count(practices),
	"practices_evaluated": count(applicable),
	"practices_attested": count([id | some id, _ in applicable; _attested(id)]),
	"chapters": chapter_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
