# METADATA
# title: "Iso27701 Main"
# custom:
#   class: compliance
#   framework: iso27701
#   source: iso
#   domains: [privacy, isms]
#   coverage:
#     checks: 108
#     cited: 108
#     expected: 108
#     found: 108
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iso27701.main

import rego.v1

# ISO/IEC 27701:2019 (first edition, 2019-08): Privacy Information Management System, extension to
# ISO/IEC 27001 and ISO/IEC 27002. Edition used: 2019. One result for each of 108 controls.
#
# HOW THE CONTROL LIST WAS BUILT. READ BEFORE RELYING ON IT.
# - The control list was compiled from public secondary sources. It has NOT been checked against the purchased
#   standard. Nobody working on this library has bought ISO/IEC 27701 or asked ISO or anyone who charges for it.
# - It should be verified against the purchased standard when one is bought; until then treat every id and
#   grouping as the library's reading of public material, not as an audited mapping.
# - No ISO text is carried. Ids are numbers; titles and the requirement lines are this library's own short
#   paraphrases.
#
# Sources (all fetched 2026-11-22):
#   1. Publisher-distributed preview of ISO/IEC 27701:2019 (table of contents), VDE Verlag:
#      https://www.vde-verlag.de/iec-normen/preview-pdf/info_isoiec27701{ed1.0}en.pdf
#      Gives every subclause number of clauses 5 to 8 down to the third level (5.2.1, 7.3.10, 8.5.8 ...).
#   2. NQA, "ISO 27701 Annex A Controls Analysis":
#      https://www.nqa.com/medialibraries/NQA/NQA-Media-Library/PDFs/NQA-ISO-27701-Annex-A-Controls-Analysis.pdf
#      Lists the clause 5 requirements that extend ISO/IEC 27001 (incl. 5.4.1.2, 5.4.1.3), 34 clause 6 subclauses
#      that extend ISO/IEC 27002, and the Annex A (31) and Annex B (18) controls.
#   3. NQA, "ISO 27002 - ISO 27017 - ISO 27018 - ISO 27701 Mapping":
#      https://www.nqa.com/medialibraries/NQA/NQA-Media-Library/PDFs/NQA-ISO-27001-27017-27018-27701-Mapping.pdf
#      Marks, per ISO/IEC 27002:2013 control, whether 27701 adds guidance. Same publisher as source 2, so the two
#      are not independent.
#   4. NIST Privacy Framework v1.0 to ISO/IEC 27701 crosswalk (by Microsoft), NIST page
#      https://www.nist.gov/node/1625171, file https://github.com/usnistgov/PrivacyFrmwkResources (resources/
#      ISO 27701 Crosswalk Microsoft). Corroborates the clause 5, 7 and 8 ids. Not used to decide clause 6
#      membership: it cites any 27701 subclause it maps to, including ones with no added guidance.
#   5. isms.online clause 6.12 and 6.15 pages (https://www.isms.online/iso-27701/clause-6-12-supplier-relationships/,
#      https://www.isms.online/iso-27701/clause-6-15-compliance/). Consulted for the disputed clause 6 ids;
#      they do not say which subclauses carry added guidance.
#   Not usable: the ISO OBP preview (https://www.iso.org/obp/ui/#iso:std:iso-iec:27701:ed-1:v1:en) refuses
#   scripted fetches (403).
#
# Edition: 2019. The ids the module carried before this rebuild follow the 2019 clause 7 / clause 8 layout
# (several were misnumbered; see CHANGELOG). The 2019 numbering is confirmed by the publisher's own table of
# contents (source 1); the 2025 standalone edition's Annex A numbering is published only on vendor pages, so it
# is not used here.
#
# Inclusion rule (reproduces the count of 108):
#   clause 5   every requirement subclause in the table of contents (5.2.1-5.8.2), with 5.4.1 taken as its
#              two extended items 5.4.1.2 and 5.4.1.3 named by sources 2 and 4                     23
#   clause 6   the subclauses that sources 2 or 3 say carry 27701-specific guidance                36
#   Annex A    every controller control, 7.2.1-7.5.4                                                31
#   Annex B    every processor control, 8.2.1-8.5.8                                                 18
#   The earlier declared total of 134 had no source and is dropped.
#
# Unconfirmed ids (id_source "unconfirmed" in control_results): 6.3.2.2, 6.12.1.1, 6.14.2.1, 6.15.2.2, 6.15.2.3
#   6.12.1.1, 6.14.2.1, 6.15.2.2: listed by source 2, marked "no change" by source 3.
#   6.3.2.2, 6.15.2.3: marked as extended by source 3 (6.15.2.3 also cited by source 4), absent from source 2.
#   Considered and not included: 5.4.1.1 (no source names it).
#
# Input contract (everything under input.iso27701):
#   scope.pii_controller / scope.pii_processor
#       Annex A applies unless scope.pii_controller is the boolean false; Annex B unless scope.pii_processor is
#       the boolean false. Clauses 5 and 6 always apply. Missing data never shrinks scope.
#   evidence.<area>.<fact>
#       System facts for the 8 technical controls (evidence_spec below; limits are this library's defaults,
#       not values from the standard). A fact that is absent or of the wrong type is evidence_missing,
#       never a pass. A pass covers the technical facts only.
#   attestations["<control id>"] = {attested: true, by: "<name>", date: "<date>"}
#       Evidence for the 100 organisational controls. attested: false fails the control; any other entry without
#       attested == true, by and date is not_attested; no entry is evidence_missing.
#   Legacy booleans (pims_requirements.*, pii_controller.*, pii_processor.*, data_subject_rights.*), the input
#       paths of the module before this rebuild, are still read for the control each one evidences
#       (legacy_inputs below). A control passes on them only when every mapped field is == true; any mapped
#       field that is false fails the control, whatever its attestation says. Two old fields map to no 2019
#       control and are no longer read: pii_processor.privacy_by_design.controls_throughout_lifecycle and
#       pii_controller.privacy_by_design.transmission_controls (7.4.9 is now decided from evidence).
#
# Report contract: total_controls = controls in scope; failed_controls = controls in scope that do not pass;
# control_results lists every control in scope in clause order with status pass | fail | evidence_missing |
# not_attested (the vocabulary of nist_800_53.main and tisax.main), basis evidence | attestation, and id_source
# confirmed | unconfirmed. There is no separate reason field: the status says why a control did not pass.
# A compliant result means every control in scope passed here.
#
# OPA endpoint: POST http://<host>:8182/v1/data/iso27701/main/compliance_report

edition := "2019"

controls := {
	# Clause 5: PIMS requirements extending ISO/IEC 27001 (ref = 27001:2013 clause)
	"5.2.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 4.1", "title": "Organisational context covers privacy and the PII controller or processor role", "id_source": "confirmed"},
	"5.2.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 4.2", "title": "Interested parties with a stake in PII processing and their requirements", "id_source": "confirmed"},
	"5.2.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 4.3", "title": "Management system scope covers the processing of PII", "id_source": "confirmed"},
	"5.2.4": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 4.4", "title": "Management system run and improved as a privacy information management system", "id_source": "confirmed"},
	"5.3.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 5.1", "title": "Top management commitment extends to privacy", "id_source": "confirmed"},
	"5.3.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 5.2", "title": "Policy set covers privacy as well as security", "id_source": "confirmed"},
	"5.3.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 5.3", "title": "Roles, responsibilities and authorities for privacy assigned", "id_source": "confirmed"},
	"5.4.1.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 6.1.2", "title": "Risk assessment covers privacy risks, including risks to PII principals", "id_source": "confirmed"},
	"5.4.1.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 6.1.3", "title": "Risk treatment and statement of applicability cover the PIMS controls", "id_source": "confirmed"},
	"5.4.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 6.2", "title": "Objectives and plans cover privacy", "id_source": "confirmed"},
	"5.5.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 7.1", "title": "Resources for the PIMS provided", "id_source": "confirmed"},
	"5.5.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 7.2", "title": "Competence of people affecting privacy", "id_source": "confirmed"},
	"5.5.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 7.3", "title": "Awareness of the privacy policy and of one's part in it", "id_source": "confirmed"},
	"5.5.4": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 7.4", "title": "Internal and external communication on privacy", "id_source": "confirmed"},
	"5.5.5": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 7.5", "title": "Documented information for the PIMS controlled", "id_source": "confirmed"},
	"5.6.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 8.1", "title": "Operational planning and control, including changes affecting PII", "id_source": "confirmed"},
	"5.6.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 8.2", "title": "Privacy risk assessments carried out at planned intervals", "id_source": "confirmed"},
	"5.6.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 8.3", "title": "Privacy risk treatment plan carried out", "id_source": "confirmed"},
	"5.7.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 9.1", "title": "Privacy performance monitored, measured and evaluated", "id_source": "confirmed"},
	"5.7.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 9.2", "title": "Internal audits cover the PIMS", "id_source": "confirmed"},
	"5.7.3": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 9.3", "title": "Management reviews cover the PIMS", "id_source": "confirmed"},
	"5.8.1": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 10.1", "title": "Nonconformities corrected, including privacy ones", "id_source": "confirmed"},
	"5.8.2": {"group": "clause_5", "ref": "ISO/IEC 27001:2013 10.2", "title": "PIMS continually improved", "id_source": "confirmed"},
	# Clause 6: PIMS guidance extending ISO/IEC 27002 (ref = 27002:2013 control)
	"6.2.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.5.1.1", "title": "Security policies address PII protection", "id_source": "confirmed"},
	"6.3.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.6.1.1", "title": "Privacy roles and a privacy point of contact named", "id_source": "confirmed"},
	"6.3.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.6.2.1", "title": "Mobile device rules cover PII", "id_source": "confirmed"},
	"6.3.2.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.6.2.2", "title": "Teleworking rules cover PII", "id_source": "unconfirmed"},
	"6.4.2.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.7.2.2", "title": "Awareness and training cover privacy and breach consequences", "id_source": "confirmed"},
	"6.5.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.8.2.1", "title": "Information classification takes PII into account", "id_source": "confirmed"},
	"6.5.2.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.8.2.2", "title": "People can recognise PII through labelling", "id_source": "confirmed"},
	"6.5.3.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.8.3.1", "title": "Removable media holding PII controlled", "id_source": "confirmed"},
	"6.5.3.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.8.3.2", "title": "Media holding PII disposed of securely", "id_source": "confirmed"},
	"6.5.3.3": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.8.3.3", "title": "Physical transfer of media holding PII controlled", "id_source": "confirmed"},
	"6.6.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.9.2.1", "title": "User registration and removal on systems processing PII", "id_source": "confirmed"},
	"6.6.2.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.9.2.2", "title": "Access to PII provisioned under control", "id_source": "confirmed"},
	"6.6.4.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.9.4.2", "title": "Secure log-on to systems processing PII", "id_source": "confirmed"},
	"6.7.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.10.1.1", "title": "Cryptography protects PII", "id_source": "confirmed"},
	"6.8.2.7": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.11.2.7", "title": "Equipment holding PII wiped before disposal or reuse", "id_source": "confirmed"},
	"6.8.2.9": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.11.2.9", "title": "Clear desk and clear screen extend to PII", "id_source": "confirmed"},
	"6.9.3.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.12.3.1", "title": "Backups holding PII protected and restorable", "id_source": "confirmed"},
	"6.9.4.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.12.4.1", "title": "Processing of PII recorded in event logs", "id_source": "confirmed"},
	"6.9.4.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.12.4.2", "title": "Logs that hold PII protected", "id_source": "confirmed"},
	"6.10.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.13.2.1", "title": "Transfer rules cover PII", "id_source": "confirmed"},
	"6.10.2.4": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.13.2.4", "title": "People with access to PII bound to confidentiality", "id_source": "confirmed"},
	"6.11.1.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.14.1.2", "title": "PII sent over public networks protected", "id_source": "confirmed"},
	"6.11.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.14.2.1", "title": "Secure development rules address privacy", "id_source": "confirmed"},
	"6.11.2.5": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.14.2.5", "title": "Systems engineered with privacy by design and by default", "id_source": "confirmed"},
	"6.11.2.7": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.14.2.7", "title": "Outsourced development held to the same privacy rules", "id_source": "confirmed"},
	"6.11.3.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.14.3.1", "title": "PII not used as test data without protection", "id_source": "confirmed"},
	"6.12.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.15.1.1", "title": "Supplier security policy covers PII", "id_source": "unconfirmed"},
	"6.12.1.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.15.1.2", "title": "Supplier agreements carry PII protection terms", "id_source": "confirmed"},
	"6.13.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.16.1.1", "title": "Incident responsibilities cover PII breaches", "id_source": "confirmed"},
	"6.13.1.5": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.16.1.5", "title": "PII breaches responded to, recorded and notified", "id_source": "confirmed"},
	"6.14.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.17.2.1", "title": "Availability of facilities processing PII", "id_source": "unconfirmed"},
	"6.15.1.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.18.1.1", "title": "Privacy laws and contract terms that apply are identified", "id_source": "confirmed"},
	"6.15.1.3": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.18.1.3", "title": "Records of PII processing protected and retained", "id_source": "confirmed"},
	"6.15.2.1": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.18.2.1", "title": "Independent review covers privacy", "id_source": "confirmed"},
	"6.15.2.2": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.18.2.2", "title": "Adherence to privacy policies reviewed", "id_source": "unconfirmed"},
	"6.15.2.3": {"group": "clause_6", "ref": "ISO/IEC 27002:2013 A.18.2.3", "title": "Technical compliance reviews cover PII processing", "id_source": "unconfirmed"},
	# Annex A / clause 7: PII controllers
	"7.2.1": {"group": "annex_a", "ref": "Annex A A.7.2.1", "title": "Purposes of processing identified and documented", "id_source": "confirmed"},
	"7.2.2": {"group": "annex_a", "ref": "Annex A A.7.2.2", "title": "Lawful basis identified for each purpose", "id_source": "confirmed"},
	"7.2.3": {"group": "annex_a", "ref": "Annex A A.7.2.3", "title": "When and how consent is sought decided", "id_source": "confirmed"},
	"7.2.4": {"group": "annex_a", "ref": "Annex A A.7.2.4", "title": "Consent obtained and kept on record", "id_source": "confirmed"},
	"7.2.5": {"group": "annex_a", "ref": "Annex A A.7.2.5", "title": "Privacy impact assessment for new or changed processing", "id_source": "confirmed"},
	"7.2.6": {"group": "annex_a", "ref": "Annex A A.7.2.6", "title": "Processor contracts carry the required terms", "id_source": "confirmed"},
	"7.2.7": {"group": "annex_a", "ref": "Annex A A.7.2.7", "title": "Joint controller roles agreed", "id_source": "confirmed"},
	"7.2.8": {"group": "annex_a", "ref": "Annex A A.7.2.8", "title": "Records of PII processing kept", "id_source": "confirmed"},
	"7.3.1": {"group": "annex_a", "ref": "Annex A A.7.3.1", "title": "Obligations to PII principals determined and met", "id_source": "confirmed"},
	"7.3.2": {"group": "annex_a", "ref": "Annex A A.7.3.2", "title": "Information owed to PII principals determined", "id_source": "confirmed"},
	"7.3.3": {"group": "annex_a", "ref": "Annex A A.7.3.3", "title": "Clear information given to PII principals", "id_source": "confirmed"},
	"7.3.4": {"group": "annex_a", "ref": "Annex A A.7.3.4", "title": "Way to change or withdraw consent provided", "id_source": "confirmed"},
	"7.3.5": {"group": "annex_a", "ref": "Annex A A.7.3.5", "title": "Way to object to processing provided", "id_source": "confirmed"},
	"7.3.6": {"group": "annex_a", "ref": "Annex A A.7.3.6", "title": "Access, correction and erasure handled", "id_source": "confirmed"},
	"7.3.7": {"group": "annex_a", "ref": "Annex A A.7.3.7", "title": "Third parties told of corrections, erasures and objections", "id_source": "confirmed"},
	"7.3.8": {"group": "annex_a", "ref": "Annex A A.7.3.8", "title": "Copy of their PII given to principals on request", "id_source": "confirmed"},
	"7.3.9": {"group": "annex_a", "ref": "Annex A A.7.3.9", "title": "Requests from PII principals handled on time", "id_source": "confirmed"},
	"7.3.10": {"group": "annex_a", "ref": "Annex A A.7.3.10", "title": "Automated decisions about principals addressed", "id_source": "confirmed"},
	"7.4.1": {"group": "annex_a", "ref": "Annex A A.7.4.1", "title": "Collection limited to what the purpose needs", "id_source": "confirmed"},
	"7.4.2": {"group": "annex_a", "ref": "Annex A A.7.4.2", "title": "Processing limited to the stated purposes", "id_source": "confirmed"},
	"7.4.3": {"group": "annex_a", "ref": "Annex A A.7.4.3", "title": "PII kept accurate and of adequate quality", "id_source": "confirmed"},
	"7.4.4": {"group": "annex_a", "ref": "Annex A A.7.4.4", "title": "Minimisation objectives set and met", "id_source": "confirmed"},
	"7.4.5": {"group": "annex_a", "ref": "Annex A A.7.4.5", "title": "PII de-identified or deleted when processing ends", "id_source": "confirmed"},
	"7.4.6": {"group": "annex_a", "ref": "Annex A A.7.4.6", "title": "Temporary files holding PII removed", "id_source": "confirmed"},
	"7.4.7": {"group": "annex_a", "ref": "Annex A A.7.4.7", "title": "PII kept no longer than needed", "id_source": "confirmed"},
	"7.4.8": {"group": "annex_a", "ref": "Annex A A.7.4.8", "title": "PII disposed of by documented means", "id_source": "confirmed"},
	"7.4.9": {"group": "annex_a", "ref": "Annex A A.7.4.9", "title": "PII protected in transmission", "id_source": "confirmed"},
	"7.5.1": {"group": "annex_a", "ref": "Annex A A.7.5.1", "title": "Basis for cross-border transfer identified", "id_source": "confirmed"},
	"7.5.2": {"group": "annex_a", "ref": "Annex A A.7.5.2", "title": "Destinations of transfers listed", "id_source": "confirmed"},
	"7.5.3": {"group": "annex_a", "ref": "Annex A A.7.5.3", "title": "Transfers of PII recorded", "id_source": "confirmed"},
	"7.5.4": {"group": "annex_a", "ref": "Annex A A.7.5.4", "title": "Disclosures of PII to third parties recorded", "id_source": "confirmed"},
	# Annex B / clause 8: PII processors
	"8.2.1": {"group": "annex_b", "ref": "Annex B B.8.2.1", "title": "Customer contract covers the processor's support duties", "id_source": "confirmed"},
	"8.2.2": {"group": "annex_b", "ref": "Annex B B.8.2.2", "title": "PII processed only for the customer's purposes", "id_source": "confirmed"},
	"8.2.3": {"group": "annex_b", "ref": "Annex B B.8.2.3", "title": "No marketing use without the principal's consent", "id_source": "confirmed"},
	"8.2.4": {"group": "annex_b", "ref": "Annex B B.8.2.4", "title": "Customer told when an instruction would break the law", "id_source": "confirmed"},
	"8.2.5": {"group": "annex_b", "ref": "Annex B B.8.2.5", "title": "Customer given what it needs to show its own compliance", "id_source": "confirmed"},
	"8.2.6": {"group": "annex_b", "ref": "Annex B B.8.2.6", "title": "Records of processing done for the customer kept", "id_source": "confirmed"},
	"8.3.1": {"group": "annex_b", "ref": "Annex B B.8.3.1", "title": "Customer helped to meet its obligations to principals", "id_source": "confirmed"},
	"8.4.1": {"group": "annex_b", "ref": "Annex B B.8.4.1", "title": "Temporary files holding PII removed", "id_source": "confirmed"},
	"8.4.2": {"group": "annex_b", "ref": "Annex B B.8.4.2", "title": "PII returned, transferred or disposed of at contract end", "id_source": "confirmed"},
	"8.4.3": {"group": "annex_b", "ref": "Annex B B.8.4.3", "title": "PII protected in transmission", "id_source": "confirmed"},
	"8.5.1": {"group": "annex_b", "ref": "Annex B B.8.5.1", "title": "Customer told of the basis for cross-border transfers", "id_source": "confirmed"},
	"8.5.2": {"group": "annex_b", "ref": "Annex B B.8.5.2", "title": "Customer told of transfer destinations", "id_source": "confirmed"},
	"8.5.3": {"group": "annex_b", "ref": "Annex B B.8.5.3", "title": "Disclosures to third parties recorded", "id_source": "confirmed"},
	"8.5.4": {"group": "annex_b", "ref": "Annex B B.8.5.4", "title": "Customer told of disclosure requests", "id_source": "confirmed"},
	"8.5.5": {"group": "annex_b", "ref": "Annex B B.8.5.5", "title": "Only legally binding disclosures made", "id_source": "confirmed"},
	"8.5.6": {"group": "annex_b", "ref": "Annex B B.8.5.6", "title": "Subcontractors used disclosed to the customer", "id_source": "confirmed"},
	"8.5.7": {"group": "annex_b", "ref": "Annex B B.8.5.7", "title": "Subcontractors engaged only as the contract allows", "id_source": "confirmed"},
	"8.5.8": {"group": "annex_b", "ref": "Annex B B.8.5.8", "title": "Customer told before a subcontractor changes", "id_source": "confirmed"},
}

standard_total := 108 # controls in the list above (tested)

unconfirmed_ids := ["6.3.2.2", "6.12.1.1", "6.14.2.1", "6.15.2.2", "6.15.2.3"]

groups := {
	"clause_5": "Clause 5: PIMS requirements related to ISO/IEC 27001",
	"clause_6": "Clause 6: PIMS guidance related to ISO/IEC 27002",
	"annex_a": "Annex A (clause 7): additional controls for PII controllers",
	"annex_b": "Annex B (clause 8): additional controls for PII processors",
}

# What a pass needs, in this library's own words, per group (organisational controls).
_group_need := {
	"clause_5": "the requirement is met with privacy and PII processing included",
	"clause_6": "the security control is in place with the PII protection the PIMS adds",
	"annex_a": "the controller control is implemented and kept current",
	"annex_b": "the processor control is implemented and kept current",
}

# Facts for the technical controls, read from input.iso27701.evidence.<fact>. Tests: true / false (boolean),
# zero (number == 0), max / min (number <= / >= limit).
evidence_spec := {
	"6.6.2.1": [
		{"fact": "accounts.shared_accounts", "test": "zero"},
		{"fact": "accounts.dormant_enabled_accounts", "test": "zero"},
	],
	"6.6.4.2": [
		{"fact": "authentication.mfa_for_pii_systems", "test": "true"},
		{"fact": "authentication.failed_login_lockout", "test": "true"},
	],
	"6.7.1.1": [
		{"fact": "encryption.pii_at_rest_encrypted", "test": "true"},
		{"fact": "crypto.weak_algorithms_permitted", "test": "false"},
	],
	"6.9.3.1": [
		{"fact": "backup.configured", "test": "true"},
		{"fact": "backup.encrypted", "test": "true"},
		{"fact": "backup.last_success_age_days", "test": "max", "limit": 7},
	],
	"6.9.4.1": [
		{"fact": "logging.audit_daemon_active", "test": "true"},
		{"fact": "logging.pii_access_logged", "test": "true"},
	],
	"6.9.4.2": [
		{"fact": "logging.central_forwarding", "test": "true"},
		{"fact": "logging.log_access_restricted", "test": "true"},
	],
	"7.4.9": [
		{"fact": "transport.tls_min_version", "test": "min", "limit": 1.2},
		{"fact": "transport.cleartext_services_enabled", "test": "zero"},
	],
	"8.4.3": [
		{"fact": "transport.tls_min_version", "test": "min", "limit": 1.2},
		{"fact": "transport.cleartext_services_enabled", "test": "zero"},
	],
}

# Earlier input paths (under input.iso27701), mapped by meaning to the 2019 control each one evidences.
legacy_inputs := {
	"5.2.1": ["pims_requirements.context.privacy_factors_identified", "pims_requirements.context.internal_privacy_factors_documented"],
	"5.2.2": ["pims_requirements.interested_parties.stakeholders_identified", "pims_requirements.interested_parties.dpa_requirements_documented"],
	"5.2.3": ["pims_requirements.scope.pii_processing_covered", "pims_requirements.scope.third_party_interfaces_in_scope"],
	"5.3.1": ["pims_requirements.leadership.executive_sponsor_designated"],
	"5.5.1": ["pims_requirements.leadership.privacy_resources_allocated"],
	"5.3.2": ["pims_requirements.privacy_policy.approved_by_top_management", "pims_requirements.privacy_policy.reviewed_annually"],
	"5.4.1.2": ["pims_requirements.risk.privacy_risk_assessment_conducted"],
	"5.4.1.3": ["pims_requirements.risk.risk_treatment_documented"],
	"7.2.5": ["pims_requirements.risk.dpias_for_high_risk"],
	"5.4.2": ["pims_requirements.objectives.established_and_measurable", "pims_requirements.objectives.communicated"],
	"5.6.1": ["pims_requirements.planning_changes.privacy_impact_assessed"],
	"7.2.1": ["pii_controller.collection_conditions.purposes_documented"],
	"7.2.2": ["pii_controller.collection_conditions.lawful_basis_per_purpose"],
	"7.2.3": ["pii_controller.collection_conditions.consent_timing_defined"],
	"7.2.4": ["pii_controller.collection_conditions.consent_obtained_and_recorded"],
	"7.2.6": ["pii_controller.collection_conditions.processor_contracts_include_dpo"],
	"7.2.7": ["pii_controller.collection_conditions.joint_controllership_documented"],
	"7.3.1": ["pii_controller.pii_principal_obligations.obligations_determined"],
	"7.3.3": ["pii_controller.collection_conditions.privacy_notices_provided", "pii_controller.pii_principal_obligations.notice_at_collection"],
	"7.3.4": ["pii_controller.pii_principal_obligations.consent_modification_mechanism"],
	"7.3.5": ["data_subject_rights.objection.opt_out_mechanism", "data_subject_rights.objection.direct_marketing_always_honored"],
	"7.3.6": ["pii_controller.pii_principal_obligations.access_mechanism", "pii_controller.pii_principal_obligations.erasure_mechanism", "data_subject_rights.access.process_defined", "data_subject_rights.rectification.process_defined", "data_subject_rights.erasure.technical_deletion_capability", "data_subject_rights.erasure.backups_addressed", "data_subject_rights.restriction.flag_based_mechanism"],
	"7.3.7": ["data_subject_rights.rectification.propagated_to_processors"],
	"7.3.8": ["pii_controller.pii_principal_obligations.portability_mechanism", "data_subject_rights.portability.machine_readable_format", "data_subject_rights.portability.direct_transfer_supported"],
	"7.3.9": ["pii_controller.pii_principal_obligations.complaints_handled", "data_subject_rights.access.thirty_day_sla"],
	"7.3.10": ["pii_controller.pii_principal_obligations.automated_decision_safeguards", "data_subject_rights.automated_decisions.human_review_available"],
	"7.4.1": ["pii_controller.privacy_by_design.collection_limited"],
	"7.4.2": ["pii_controller.privacy_by_design.processing_limited"],
	"7.4.3": ["pii_controller.privacy_by_design.accuracy_maintained"],
	"7.4.4": ["pii_controller.privacy_by_design.minimization_goals_defined"],
	"7.4.5": ["pii_controller.privacy_by_design.deidentification_and_deletion"],
	"7.4.6": ["pii_controller.privacy_by_design.temporary_files_disposed"],
	"7.4.7": ["pii_controller.privacy_by_design.retention_schedule_enforced"],
	"7.5.1": ["pii_controller.pii_sharing.transfer_basis_established"],
	"7.5.2": ["pii_controller.pii_sharing.transfer_destinations_documented"],
	"7.5.4": ["pii_controller.pii_sharing.disclosure_records_maintained"],
	"8.2.1": ["pii_processor.collection_conditions.customer_instructions_documented"],
	"8.2.2": ["pii_processor.collection_conditions.purposes_limited_to_customer"],
	"8.2.3": ["pii_processor.collection_conditions.marketing_use_prohibited"],
	"8.5.7": ["pii_processor.collection_conditions.subprocessor_equivalent_obligations"],
	"8.3.1": ["pii_processor.pii_principal_obligations.principal_rights_mechanism"],
	"8.2.6": ["pii_processor.pii_principal_obligations.records_traceable"],
	"8.4.1": ["pii_processor.privacy_by_design.temporary_files_documented_and_disposed"],
	"8.4.2": ["pii_processor.privacy_by_design.return_transfer_disposal_on_termination"],
	"8.5.5": ["pii_processor.pii_sharing.third_party_disclosure_basis"],
	"8.5.4": ["pii_processor.pii_sharing.binding_disclosure_info_to_customer"],
	"8.5.6": ["pii_processor.pii_sharing.subprocessor_disclosures_documented"],
	"8.5.1": ["pii_processor.pii_sharing.jurisdictional_transfer_notification"],
}

# ── Input ────────────────────────────────────────────────────────────────────

_in := input.iso27701 if is_object(input.iso27701)

else := {}

_obj(x) := x if is_object(x)

else := {}

_scope := _obj(object.get(_in, "scope", {}))

_evidence := _obj(object.get(_in, "evidence", {}))

_attestations := _obj(object.get(_in, "attestations", {}))

_group_in_scope(g) if g in {"clause_5", "clause_6"}

_group_in_scope("annex_a") if object.get(_scope, "pii_controller", true) != false

_group_in_scope("annex_b") if object.get(_scope, "pii_processor", true) != false

groups_in_scope := sort([g | some g, _ in groups; _group_in_scope(g)])

groups_not_in_scope := sort([g | some g, _ in groups; not _group_in_scope(g)])

applicable := {id | some id, c in controls; _group_in_scope(c.group)}

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

_missing_facts(id) := sort([concat("", ["input.iso27701.evidence.", f.fact]) |
	some f in evidence_spec[id]
	not _typed(f)
])

_failed_facts(id) := sort([sprintf("input.iso27701.evidence.%v is %v, required %v", [f.fact, _fact(f), _wanted(f)]) |
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

_refused(a) if {
	is_object(a)
	a.attested == false
}

_legacy_values(id) := [object.get(_in, split(p, "."), null) | some p in object.get(legacy_inputs, id, [])]

_legacy_false(id) := sort([concat("", ["input.iso27701.", p]) |
	some p in object.get(legacy_inputs, id, [])
	object.get(_in, split(p, "."), null) == false
])

_legacy_all_true(id) if {
	vals := _legacy_values(id)
	count(vals) > 0
	every v in vals {
		v == true
	}
}

_att_path(id) := sprintf("input.iso27701.attestations[%q]", [id])

# ── Status per control ───────────────────────────────────────────────────────

_status(id) := "fail" if {
	_basis(id) == "evidence"
	count(_failed_facts(id)) > 0
} else := "evidence_missing" if {
	_basis(id) == "evidence"
	count(_missing_facts(id)) > 0
} else := "pass" if {
	_basis(id) == "evidence"
} else := "fail" if {
	_refused(_att(id))
} else := "fail" if {
	count(_legacy_false(id)) > 0
} else := "pass" if {
	_signed(_att(id))
} else := "pass" if {
	_legacy_all_true(id)
} else := "not_attested" if {
	_att(id) != null
} else := "evidence_missing"

_status_of[id] := _status(id) if some id in applicable

_detail(id) := concat("", ["fail: ", concat("; ", _failed_facts(id))]) if {
	_basis(id) == "evidence"
	_status_of[id] == "fail"
}

_detail(id) := sprintf("evidence missing: not collected or not of the expected type: %v", [concat(", ", _missing_facts(id))]) if {
	_basis(id) == "evidence"
	_status_of[id] == "evidence_missing"
}

_detail(id) := sprintf("fail: %v has attested false", [_att_path(id)]) if {
	_basis(id) == "attestation"
	_status_of[id] == "fail"
	_refused(_att(id))
}

_detail(id) := sprintf("fail: legacy input %v is false", [concat(", ", _legacy_false(id))]) if {
	_basis(id) == "attestation"
	_status_of[id] == "fail"
	not _refused(_att(id))
}

_detail(id) := sprintf("not attested: %v must be {attested: true, by: <name>, date: <date>}", [_att_path(id)]) if {
	_basis(id) == "attestation"
	_status_of[id] == "not_attested"
}

_detail(id) := sprintf("evidence missing: no attestation at %v; pass needs {attested: true, by, date} showing %v", [_att_path(id), _group_need[controls[id].group]]) if {
	_basis(id) == "attestation"
	_status_of[id] == "evidence_missing"
}

_finding(id) := sprintf("ISO 27701 %v (%v): %v", [id, controls[id].title, _detail(id)])

_control_messages := {_finding(id) | some id, st in _status_of; st != "pass"}

# Input problems that are not controls but still block a compliant result.
_input_notes contains sprintf("ISO 27701 input: attestation key %q is not a control id in this list", [k]) if {
	some k, _ in _attestations
	not controls[k]
}

_input_notes contains "ISO 27701 input: input.iso27701 is missing or not an object; no control can be evaluated" if {
	not is_object(input.iso27701)
}

violations := sort([v | some v in (_control_messages | _input_notes)])

# ── Report ───────────────────────────────────────────────────────────────────

_num_key(id) := [to_number(x) | some x in split(id, ".")]

_order := [pair[1] | some pair in sort([[_num_key(id), id] | some id in applicable])]

control_results := [{
	"id": id,
	"title": controls[id].title,
	"group": controls[id].group,
	"ref": controls[id].ref,
	"basis": _basis(id),
	"id_source": controls[id].id_source,
	"status": _status_of[id],
	"findings": [_finding(id) | _status_of[id] != "pass"],
} |
	some id in _order
]

control_result_counts := {s: count([id | some id, st in _status_of; st == s]) | some s in ["pass", "fail", "evidence_missing", "not_attested"]}

failed_control_ids := [id | some id in _order; _status_of[id] != "pass"]

group_results[g] := {
	"title": groups[g],
	"in_scope": _group_in_scope(g),
	"controls": count(ids),
	"evidence_based": count([id | some id in ids; _basis(id) == "evidence"]),
	"attestation_based": count([id | some id in ids; _basis(id) == "attestation"]),
	"passed": count([id | some id in ids; object.get(_status_of, id, "") == "pass"]),
	"not_passed": count([id | some id in ids; _group_in_scope(g); object.get(_status_of, id, "") != "pass"]),
} if {
	some g, _ in groups
	ids := [id | some id, c in controls; c.group == g]
}

# The four area packages kept from the earlier layout, as views over control_results.
_module_ids := {
	"pims_requirements": {id | some id in applicable; controls[id].group in {"clause_5", "clause_6"}},
	"pii_controller": {id | some id in applicable; controls[id].group == "annex_a"},
	"pii_processor": {id | some id in applicable; controls[id].group == "annex_b"},
	"data_subject_rights": {id | some id in applicable; _is_rights(id)},
}

_is_rights(id) if startswith(id, "7.3.")

_is_rights("8.3.1")

_module_ok(ids) if {
	count(ids) > 0
	every id in ids {
		_status_of[id] == "pass"
	}
} else := false

module_reports[m] := {
	"standard": "ISO/IEC 27701:2019",
	"domain": _module_domain[m],
	"in_scope": count(ids) > 0,
	"compliant": _module_ok(ids),
	"total_controls": count(ids),
	"failed_controls": count([id | some id in ids; _status_of[id] != "pass"]),
	"violation_count": count(msgs),
	"violations": msgs,
} if {
	some m, ids in _module_ids
	msgs := sort([_finding(id) | some id in ids; _status_of[id] != "pass"])
}

_module_domain := {
	"pims_requirements": "Clauses 5-6: PIMS requirements and ISO/IEC 27002 extensions",
	"pii_controller": "Annex A / clause 7: PII controllers",
	"pii_processor": "Annex B / clause 8: PII processors",
	"data_subject_rights": "Obligations to PII principals (7.3.1-7.3.10, 8.3.1)",
}

default overall_compliant := false

overall_compliant if {
	count(applicable) > 0
	count(violations) == 0
}

default compliant := false

compliant := overall_compliant

modules_passing := count([m | some m, r in module_reports; r.compliant == true])

compliance_report := {
	"framework": "ISO/IEC 27701 Privacy Information Management System",
	"framework_key": "iso27701",
	"standard": "ISO/IEC 27701:2019 — Privacy Information Management System",
	"edition": edition,
	"control_list_basis": "Compiled from public secondary sources; not checked against the purchased standard. Verify against the purchased standard when one is bought.",
	"unconfirmed_ids": unconfirmed_ids,
	"standard_total": 108, # literal so the coverage stamp reads it; equals standard_total (tested)
	"groups_in_scope": groups_in_scope,
	"groups_not_in_scope": groups_not_in_scope,
	"group_results": group_results,
	"compliant": overall_compliant,
	"overall_compliant": overall_compliant,
	"total_controls": count(applicable),
	"failed_controls": count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"violations": violations,
	"violation_count": count(violations),
	"modules_passing": modules_passing,
	"modules_total": 4,
	"modules": {m: {"compliant": r.compliant, "details": r} | some m, r in module_reports},
}
