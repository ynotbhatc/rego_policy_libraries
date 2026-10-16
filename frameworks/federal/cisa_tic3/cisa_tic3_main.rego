# CISA Trusted Internet Connections (TIC) 3.0 — Core Guidance Volume 3: Security Capabilities Catalog
# Version 3.3, "Publication: September 2026" on the cover (revision history: 3.3 dated July 2025; the
# document states "The only changes in 2026 were updated footnote links"). Current edition on the CISA
# "TIC 3.0 Core Guidance Documents" page as retrieved 2026-10-14.
#
# Source: https://www.cisa.gov/sites/default/files/2026-09/TIC_3.0_Security_Capabilities_Catalogs_September_2026_17.pdf
#   sha256 e2efd5b1574958a43504b1f0b714d3ed55028dd1c0c12b33921d6f6facd0afa9, 27 pages, retrieved 2026-10-14.
#   Linked from https://www.cisa.gov/resources-tools/resources/trusted-internet-connections-tic-30-core-guidance-documents
# Notice: the document is marked TLP:CLEAR and says "Information is subject to standard copyright rules"; it
# is not declared public domain (the PDF author metadata carries a "(CTR)" contractor marking), so the
# capability descriptions are NOT copied: each row's `summary` is a one-line summary written for this module.
# Capability identifiers and NIST CSF 2.0 category mappings are extracted from the tables by a script;
# capability names are transcribed from the tables' Capability column and were diffed mechanically against
# it (no differences; "Micro segmentation" is kept as the column prints it — the description spells it
# "Microsegmentation").
#
# Shape: one attested row per security capability — every row of Tables 3–15 (116 rows; the catalog prints
# no total, 116 is the counted row total). Ids are the catalog's "Capability Identifier" column as printed,
# including its 3.UNL prefix for the five universal capabilities added in v3.0 (SCRMA, RLMAN, STEXE, CMREP,
# GPAUD). Two identifiers carry a stray space in the PDF text layer and are normalised (printed form kept
# as `printed_id`): "3 UNL.SCRMA" -> 3.UNL.SCRMA, "3.PE P.EM.EDRPR" -> 3.PEP.EM.EDRPR.
#
# Groups (catalog §4.1 Universal, §4.2 PEP groups)                          rows
#   universal            Universal Security Capabilities (Table 3)                   25
#   files                Files PEP (Table 4)                                          4
#   email                Email PEP (Table 5)                                         20
#   web                  Web PEP (Table 6)                                           13
#   networking           Networking PEP (Table 7)                                     6
#   resiliency           Resiliency PEP (Table 8)                                     3
#   dns                  Domain Name System PEP (Table 9)                             5
#   intrusion_detection  Intrusion Detection PEP (Table 10)                           6
#   enterprise           Enterprise PEP (Table 11)                                    6
#   ucc                  Unified Communications and Collaboration PEP (Table 12)      8
#   data_protection      Data Protection PEP (Table 13)                               7
#   services             Services PEP (Table 14)                                      5
#   identity             Identity PEP (Table 15)                                      8
#
# Applicability: universal capabilities apply to every use case and are always evaluated. PEP capabilities
# apply per use case (§4.2), so input.cisa_tic3.pep_groups_in_scope (optional) lists the PEP group keys in
# scope; absent = every PEP group is evaluated; [] = universal capabilities only. A present but malformed
# value (not an array, or an unknown group key) is a violation and evaluation falls back to all groups.
#
# Input: input.cisa_tic3.capabilities["3.UNI.BRECO"] == true means the agency attests the capability is
# implemented. Fail-closed: a missing or non-object capabilities container is a FAIL-CLOSED violation; a
# missing, false or non-true value for an in-scope capability is a violation; an unknown id is a violation.
#
# Query: POST /v1/data/cisa_tic3/main/compliance_report

# METADATA
# title: "CISA TIC 3.0 Security Capabilities Catalog v3.3 — 116 universal and PEP security capabilities, attested"
# custom:
#   class: compliance
#   framework: cisa_tic3
#   source: cisa
#   domains: [us-federal, network, zero-trust]
#   coverage:
#     checks: 120
#     cited: 118
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cisa_tic3.main

import rego.v1

source := {
	"publication": "TIC 3.0 Core Guidance Volume 3: Security Capabilities Catalog",
	"version": "3.3",
	"published": "September 2026",
	"url": "https://www.cisa.gov/sites/default/files/2026-09/TIC_3.0_Security_Capabilities_Catalogs_September_2026_17.pdf",
	"sha256": "e2efd5b1574958a43504b1f0b714d3ed55028dd1c0c12b33921d6f6facd0afa9",
	"retrieved": "2026-10-14",
}

groups := {
	"universal": "Universal Security Capabilities (Table 3)",
	"files": "Files PEP (Table 4)",
	"email": "Email PEP (Table 5)",
	"web": "Web PEP (Table 6)",
	"networking": "Networking PEP (Table 7)",
	"resiliency": "Resiliency PEP (Table 8)",
	"dns": "Domain Name System PEP (Table 9)",
	"intrusion_detection": "Intrusion Detection PEP (Table 10)",
	"enterprise": "Enterprise PEP (Table 11)",
	"ucc": "Unified Communications and Collaboration PEP (Table 12)",
	"data_protection": "Data Protection PEP (Table 13)",
	"services": "Services PEP (Table 14)",
	"identity": "Identity PEP (Table 15)",
}

capabilities := {
	# ── Universal Security Capabilities (Table 3) ──
	"3.UNI.BRECO": {"group": "universal", "name": "Backup and Recovery", "summary": "Copies of configuration and data are kept so service can be restored quickly after an attack, failure or corruption", "csf": ["GV.OC", "GV.PO", "ID.AM", "PR.DS", "PR.IR", "RS.MI", "RC.RP"]},
	"3.UNI.CLMAN": {"group": "universal", "name": "Central Log Management with Analysis", "summary": "Telemetry is collected and stored centrally for data fusion and analysed to find and respond to malicious activity", "csf": ["ID.AM", "PR.PS", "DE.AE", "RS.AN"]},
	"3.UNI.CMANA": {"group": "universal", "name": "Configuration Management", "summary": "A formal plan documents the environment, controls changes to it and monitors for deviations, preferably automatically", "csf": ["GV.RM", "ID.AM", "PR.DS", "PR.IR"]},
	"3.UNI.IRPIH": {"group": "universal", "name": "Incident Response Planning and Incident Handling", "summary": "Documented and implemented procedures and tooling detect, respond to, contain and recover from cyberattacks", "csf": ["GV.RM", "GV.RR", "GV.OV", "ID.AM", "ID.RA", "ID.IM", "PR.IR", "DE.AE", "RS.MA", "RS.AN", "RS.MI", "RC.RP", "RS.CO"]},
	"3.UNI.INVENT": {"group": "universal", "name": "Inventory", "summary": "A current inventory of systems, networks and components is kept so only authorised devices get access and unmanaged ones are found and restricted", "csf": ["ID.AM", "PR.AA", "PR.DS", "PR.IR"]},
	"3.UNI.LPRIV": {"group": "universal", "name": "Least Privilege", "summary": "Each entity is given only the minimum resources and authorisations it needs for its function", "csf": ["GV.RR", "GV.PO", "ID.AM", "PR.AA", "PR.IR", "PR.PS", "DE.CM"]},
	"3.UNI.SADMI": {"group": "universal", "name": "Secure Administration", "summary": "Administrative tasks are carried out securely, over secure protocols", "csf": ["DE.CM", "RS.AN"]},
	"3.UNI.SAUTH": {"group": "universal", "name": "Strong Authentication", "summary": "Users, devices and other entities are verified by rigorous means such as MFA before access is granted", "csf": ["GV.SC", "ID.AM", "PR.AA", "PR.IR"]},
	"3.UNI.TSYNC": {"group": "universal", "name": "Time Synchronization", "summary": "System clocks across servers, workstations and network devices are synchronised so timestamps can be compared accurately", "csf": ["PR.PS", "DE.CM"]},
	"3.UNI.VMANG": {"group": "universal", "name": "Vulnerability Management", "summary": "Vulnerabilities are proactively discovered by active and passive means and mitigated", "csf": ["GV.RM", "ID.RA", "ID.IM", "PR.IR", "DE.CM", "DE.AE"]},
	"3.UNI.PMANA": {"group": "universal", "name": "Patch Management", "summary": "Patches for products and systems are identified, acquired, installed and verified", "csf": ["GV.SC", "ID.AM", "PR.AT", "PR.PS", "DE.CM"]},
	"3.UNI.AACCO": {"group": "universal", "name": "Auditing and Accounting", "summary": "Business records such as logs are captured and available for audit, with an audit design that can detect insider misuse such as separation-of-duties violations", "csf": ["GV.RM", "GV.SC", "PR.AA", "PR.PS", "PR.IR"]},
	"3.UNI.RESIL": {"group": "universal", "name": "Resilience", "summary": "Systems, services and protections keep acceptable performance under adverse conditions", "csf": ["GV.OC", "ID.RA", "PR.IR"]},
	"3.UNI.ETINT": {"group": "universal", "name": "Enterprise Threat Intelligence", "summary": "Threat intelligence from private or government sources is used to put mitigations in place for identified risks", "csf": ["GV.RM", "ID.RA", "DE.CM", "DE.AE"]},
	"3.UNI.SAWAR": {"group": "universal", "name": "Situational Awareness", "summary": "Current and historical awareness is maintained across all components", "csf": ["ID.AM", "ID.RA", "PR.AT", "PR.DS", "PR.PS", "PR.IR", "DE.CM", "DE.AE", "RC.CO"]},
	"3.UNI.DTDIS": {"group": "universal", "name": "Dynamic Threat Discovery", "summary": "Dynamic techniques such as heuristics and baselining are used to discover new malicious activity", "csf": ["ID.AM", "ID.RA", "DE.AE", "PR.PS", "DE.CM"]},
	"3.UNI.PEPAR": {"group": "universal", "name": "Policy Enforcement Parity", "summary": "Security protections and policies are applied consistently whatever the communication mechanism, forwarding path or endpoint", "csf": ["GV.PO", "ID.AM", "PR.AA", "PR.AT"]},
	"3.UNI.EUSSE": {"group": "universal", "name": "Effective Use of Shared Services", "summary": "Shared services are used where applicable, tailored and measured so conformance can be independently validated, and protect tenants from external and internal threats", "csf": ["GV.SC", "ID.AM", "ID.IM", "ID.RA", "PR.AT", "RS.CO"]},
	"3.UNI.IDMRP": {"group": "universal", "name": "Integrated Desktop, Mobile, and Remote Policies", "summary": "Policies for an agency entity are defined and enforced regardless of where it is located", "csf": ["GV.PO", "ID.AM", "PR.AA", "PR.DS", "PR.PS", "PR.IR", "DE.CM"]},
	"3.UNI.UATRA": {"group": "universal", "name": "User Awareness and Training", "summary": "All users know their roles and responsibilities and receive cybersecurity education to work securely", "csf": ["GV.SC", "GV.RM", "GV.RR", "PR.AT", "RS.CO"]},
	"3.UNL.SCRMA": {"group": "universal", "name": "Supply Chain Risk Management", "summary": "A systematic process manages cyber supply chain risks, threats and vulnerabilities, with response strategies for supplier, product and service risks", "csf": ["GV.RM", "GV.SC", "GV.RR", "ID.RA", "RS.MA"], "printed_id": "3 UNL.SCRMA"},
	"3.UNL.RLMAN": {"group": "universal", "name": "Resource Lifecycle Management", "summary": "Resources are managed end to end from development to retirement, provisioned and decommissioned together with the applications they support", "csf": ["ID.AM", "PR.IR", "PR.PS"]},
	"3.UNL.STEXE": {"group": "universal", "name": "Security Test and Exercise", "summary": "Security tests such as penetration testing or red teaming and emergency exercises verify resistance to compromise and find gaps in plans", "csf": ["GV.SC", "GV.PO", "ID.RA", "ID.IM", "PR.DS", "PR.PS", "PR.IR", "RS.AN"]},
	"3.UNL.CMREP": {"group": "universal", "name": "Continuous Monitoring Reporting", "summary": "Ongoing awareness of security posture, vulnerabilities and threats is maintained and reported to support risk decisions", "csf": ["GV.RR", "ID.AM", "ID.RA", "PR.DS", "PR.PS", "DE.CM", "DE.AE"]},
	"3.UNL.GPAUD": {"group": "universal", "name": "Governance and Policy Auditing", "summary": "The definition, application and enforcement of agency rules and policies are validated", "csf": ["GV.RM", "GV.SC", "GV.RR", "GV.OV", "ID.IM", "PR.PS"]},
	# ── Files PEP (Table 4) ──
	"3.PEP.FI.AMALW": {"group": "files", "name": "Anti-malware", "summary": "Malicious code is detected and quarantined or removed", "csf": ["PR.DS", "PR.PS", "PR.IR", "DE.CM", "DE.AE", "RS.MI"]},
	"3.PEP.FI.CDREC": {"group": "files", "name": "Content Disarm and Reconstruction", "summary": "Unapproved active content in files is detected and removed", "csf": ["PR.PS", "DE.CM", "DE.AE"]},
	"3.PEP.FI.DCHAM": {"group": "files", "name": "Detonation Chamber", "summary": "Files are executed in isolated, protected environments to detect malicious code", "csf": ["DE.CM", "DE.AE", "RS.AN", "RS.MI"]},
	"3.PEP.FI.DLPRE": {"group": "files", "name": "Data Loss Prevention", "summary": "Malicious or accidental exfiltration of agency data is detected", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	# ── Email PEP (Table 5) ──
	"3.PEP.EM.APPRO": {"group": "email", "name": "Anti-phishing Protections", "summary": "Phishing emails are detected and users are prevented from reaching them", "csf": ["PR.AT", "PR.IR", "DE.CM"]},
	"3.PEP.EM.ASPRO": {"group": "email", "name": "Anti-spam Protections", "summary": "Spam is detected and quarantined", "csf": ["PR.IR", "PR.DS", "DE.CM"]},
	"3.PEP.EM.ARCHA": {"group": "email", "name": "Authenticated Received Chain", "summary": "Intermediaries such as mailing lists or forwarders sign their own authentication of the original message so downstream receivers can trust it after modification", "csf": ["PR.AA", "PR.IR"]},
	"3.PEP.EM.DLPRE": {"group": "email", "name": "Data Loss Prevention", "summary": "Malicious or accidental exfiltration of agency data by email is detected", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	"3.PEP.EM.DSVIE": {"group": "email", "name": "Domain Signature Verification for Incoming Email", "summary": "Incoming email is authenticated using DMARC (RFC 7489)", "csf": ["PR.AA", "PR.IR"]},
	"3.PEP.EM.DSOEM": {"group": "email", "name": "Domain Signatures for Outgoing Email", "summary": "Outgoing email is signed so external parties can validate it under DMARC (RFC 7489)", "csf": ["PR.AA", "DE.CM", "PR.IR"]},
	"3.PEP.EM.EETRA": {"group": "email", "name": "Encryption for Email Transmission", "summary": "Email services use encrypted connections, where possible, between clients and other mail servers", "csf": ["PR.DS", "PR.IR"]},
	"3.PEP.EM.MLPRO": {"group": "email", "name": "Malicious Link Protections", "summary": "Malicious links in email are detected and users are prevented from reaching them", "csf": ["PR.DS", "PR.IR", "DE.AE", "DE.CM"]},
	"3.PEP.EM.LCTPR": {"group": "email", "name": "Link Click-through Protections", "summary": "Clicked email links are routed through a check of the destination's security before access is allowed", "csf": ["PR.IR", "DE.CM"]},
	"3.PEP.EM.SDENY": {"group": "email", "name": "Sender Denylisting", "summary": "Mail from denylisted senders, domains or mail servers is refused", "csf": ["PR.AA", "PR.DS", "DE.CM"]},
	"3.PEP.EM.PDPRO": {"group": "email", "name": "Post-Delivery Protections", "summary": "Updated protections are applied to mail already delivered so it can be quarantined or mitigated in mailboxes", "csf": ["PR.DS", "PR.IR", "RS.MI"]},
	"3.PEP.EM.MFPRO": {"group": "email", "name": "Malicious File Protections", "summary": "Malicious email attachments are detected and users are prevented from opening them", "csf": ["PR.IR", "DE.CM", "DE.AE", "RS.AN"]},
	"3.PEP.EM.AEPRO": {"group": "email", "name": "Adaptive Email Protections", "summary": "Email protections are applied and enforced on the basis of risk analysis", "csf": ["GV.RM", "GV.RR", "ID.RA", "RS.AN"]},
	"3.PEP.EM.ELABE": {"group": "email", "name": "Email Labeling", "summary": "Incoming and outgoing email is tagged automatically to manage risk", "csf": ["ID.AM", "DE.CM"]},
	"3.PEP.EM.UTIPP": {"group": "email", "name": "User Tipping", "summary": "Users can report suspected phishing, spam or malicious emails, attachments or links", "csf": ["RS.CO"]},
	"3.PEP.EM.CFILT": {"group": "email", "name": "Content Filtering", "summary": "Unapproved content in email is detected and removed or access to it denied", "csf": ["DE.CM", "DE.AE", "RS.AN"]},
	"3.PEP.EM.UDSOE": {"group": "email", "name": "User Digital Signatures for Outgoing Email", "summary": "Users can digitally sign email so recipients can authenticate the sender and contents", "csf": ["PR.AA", "PR.DS"]},
	"3.PEP.EM.EOEMA": {"group": "email", "name": "Encryption for Outgoing Email", "summary": "Outgoing email can be encrypted so only intended recipients can read it", "csf": ["PR.AA", "PR.DS"]},
	"3.PEP.EM.MCQUE": {"group": "email", "name": "Mail Content Query", "summary": "Email can be searched and discovered across agency mailboxes", "csf": ["RS.AN"]},
	"3.PEP.EM.EDRPR": {"group": "email", "name": "Email Domain Reputation Protections", "summary": "The reputation of the agency's email domain is monitored and protected by policy", "csf": ["GV.RM", "GV.PO", "PR.IR", "PR.PS"], "printed_id": "3.PE P.EM.EDRPR"},
	# ── Web PEP (Table 6) ──
	"3.PEP.WE.BINSP": {"group": "web", "name": "Break and Inspect", "summary": "Encrypted traffic is terminated, inspected or logged in plaintext under policy, and re-encrypted where applicable before forwarding", "csf": ["PR.PS", "PR.IR", "DE.CM"]},
	"3.PEP.WE.ACMIT": {"group": "web", "name": "Active Content Mitigation", "summary": "Unapproved active web content is detected and removed", "csf": ["PR.PS", "DE.CM", "DE.AE"]},
	"3.PEP.WE.CDENY": {"group": "web", "name": "Certificate Denylisting", "summary": "Communication with entities presenting known-bad certificates is blocked", "csf": ["PR.PS", "DE.CM"]},
	"3.PEP.WE.CFILT": {"group": "web", "name": "Content Filtering", "summary": "Unapproved web content is detected and removed or access to it denied", "csf": ["PR.PS", "PR.IR", "DE.CM", "DE.AE"]},
	"3.PEP.WE.APROX": {"group": "web", "name": "Authenticated Proxy", "summary": "Entities must authenticate to the web proxy, enabling user-, group- and location-aware controls", "csf": ["PR.AA", "PR.IR"]},
	"3.PEP.WE.DLPRE": {"group": "web", "name": "Data Loss Prevention", "summary": "Malicious or accidental exfiltration of agency data over the web is detected", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	"3.PEP.WE.DRESF": {"group": "web", "name": "Domain Resolution Filtering", "summary": "Use of unauthorised DNS-over-HTTPS resolution services is prevented", "csf": ["PR.PS", "PR.IR", "DE.CM"]},
	"3.PEP.WE.PCENF": {"group": "web", "name": "Protocol Compliance Enforcement", "summary": "Web traffic is checked for compliance with IETF protocol definitions", "csf": ["PR.PS", "PR.IR"]},
	"3.PEP.WE.DCFIL": {"group": "web", "name": "Domain Category Filtering", "summary": "Different protections are applied to different categories of domains (for example banking, medical)", "csf": ["GV.PO", "PR.AA", "PR.IR"]},
	"3.PEP.WE.DREPF": {"group": "web", "name": "Domain Reputation Filtering", "summary": "Domains are denylisted on the basis of reputation defined by the agency or an external party", "csf": ["PR.IR"]},
	"3.PEP.WE.BCONT": {"group": "web", "name": "Bandwidth Control", "summary": "Bandwidth used by different classes of domains can be limited", "csf": ["PR.IR"]},
	"3.PEP.WE.MCFIL": {"group": "web", "name": "Malicious Content Filtering", "summary": "Malicious web content is detected and removed", "csf": ["PR.DS", "PR.IR", "DE.CM", "DE.AE"]},
	"3.PEP.WE.ACONT": {"group": "web", "name": "Access Control", "summary": "Policies limit what actions connected users and entities may perform", "csf": ["GV.PO", "PR.AA"]},
	# ── Networking PEP (Table 7) ──
	"3.PEP.NE.ACONT": {"group": "networking", "name": "Access Control", "summary": "Unauthorised network traffic is prevented from entering, leaving or transiting the network", "csf": ["PR.AA", "PR.IR", "DE.CM"]},
	"3.PEP.NE.IADEN": {"group": "networking", "name": "Internet Address Denylisting", "summary": "Traffic from or to denylisted internet addresses is blocked", "csf": ["PR.IR", "DE.CM"]},
	"3.PEP.NE.HCONT": {"group": "networking", "name": "Host Containment", "summary": "A host's network access can be revoked or quarantined", "csf": ["PR.AA", "PR.IR", "PR.PS"]},
	"3.PEP.NE.NSEGM": {"group": "networking", "name": "Network Segmentation", "summary": "The network is split into subnetworks with controls between them to reduce attack surface", "csf": ["DE.CM", "ID.RA", "PR.AA", "PR.IR"]},
	"3.PEP.NE.MICRO": {"group": "networking", "name": "Micro segmentation", "summary": "The network is divided physically or virtually by application and data-flow needs, with controls protecting the data", "csf": ["PR.AA", "PR.DS", "PR.IR", "PR.PS"]},
	"3.PEP.NE.RCONT": {"group": "networking", "name": "Resource Containment", "summary": "A resource's access to other resources can be removed or quarantined", "csf": ["PR.DS", "PR.IR", "RS.MI"]},
	# ── Resiliency PEP (Table 8) ──
	"3.PEP.RE.DDSPR": {"group": "resiliency", "name": "Distributed Denial of Service Protections", "summary": "The effects of DDoS attacks are mitigated", "csf": ["PR.IR"]},
	"3.PEP.RE.EEXPS": {"group": "resiliency", "name": "Elastic Expansion", "summary": "Resources available to services can be expanded dynamically as conditions require", "csf": ["ID.AM", "PR.DS"]},
	"3.PEP.RE.RDELI": {"group": "resiliency", "name": "Regional Delivery", "summary": "Agency services are deployed across geographically diverse locations", "csf": ["ID.AM", "PR.AA", "PR.DS"]},
	# ── Domain Name System PEP (Table 9) ──
	"3.PEP.DO.DNSIN": {"group": "dns", "name": "Domain Name Sinkholing", "summary": "DNS queries for malicious domains are answered so clients cannot reach them", "csf": ["PR.PS", "PR.IR"]},
	"3.PEP.DO.DNVAC": {"group": "dns", "name": "Domain Name Verification for Agency Clients", "summary": "Agency clients' DNS lookups, internal and external, are validated with DNSSEC", "csf": ["PR.DS", "PR.IR"]},
	"3.PEP.DO.DNVAD": {"group": "dns", "name": "Domain Name Validation for Agency Domains", "summary": "All agency domains are signed with DNSSEC so external parties can validate their resolution", "csf": ["PR.DS", "PR.IR"]},
	"3.PEP.DO.DNMON": {"group": "dns", "name": "Domain Name Monitoring", "summary": "Creation of or changes to agency domains are discovered", "csf": ["ID.RA", "PR.AA", "DE.AE", "DE.CM"]},
	"3.PEP.DO.PDSER": {"group": "dns", "name": "CISA's Protective DNS Service", "summary": "CISA's shared Protective DNS service is used for domain sinkholing protection", "csf": ["PR.DS", "PR.IR"]},
	# ── Intrusion Detection PEP (Table 10) ──
	"3.PEP.IN.EDRES": {"group": "intrusion_detection", "name": "Endpoint Detection and Response", "summary": "Endpoint and network event data are combined to detect malicious activity", "csf": ["DE.AE", "DE.CM", "RS.AN"]},
	"3.PEP.IN.IDPSY": {"group": "intrusion_detection", "name": "Intrusion Detection and Prevention Systems", "summary": "Malicious activity is detected and reported, and prevention systems try to stop it", "csf": ["DE.AE", "DE.CM", "RS.AN"]},
	"3.PEP.IN.AACON": {"group": "intrusion_detection", "name": "Adaptive Access Control", "summary": "Access decisions take extra context such as risk, operational need and heuristics into account", "csf": ["PR.AA", "DE.CM", "PR.IR"]},
	"3.PEP.IN.DPLAT": {"group": "intrusion_detection", "name": "Deception Platforms", "summary": "Decoy machines or networks divert attacks away from operational systems", "csf": ["ID.AM", "PR.PS", "DE.AE", "RS.AN"]},
	"3.PEP.IN.CTLMO": {"group": "intrusion_detection", "name": "Certificate Transparency Log Monitoring", "summary": "Certificate transparency logs are watched for new certificates issued for agency domains", "csf": ["DE.CM"]},
	"3.PEP.IN.NDRES": {"group": "intrusion_detection", "name": "Network Detection and Response", "summary": "Network event data is collected and analysed to detect and remediate malicious activity", "csf": ["ID.AM", "PR.IR", "DE.AE", "DE.CM", "RS.AN"]},
	# ── Enterprise PEP (Table 11) ──
	"3.PEP.EN.SOARE": {"group": "enterprise", "name": "Security Orchestration, Automation, and Response", "summary": "SOAR tooling defines, prioritises and automates incident response", "csf": ["ID.RA", "ID.IM", "DE.AE", "DE.CM", "RS.MA", "RS.AN", "RS.CO"]},
	"3.PEP.EN.SITDE": {"group": "enterprise", "name": "Shadow Information Technology Detection", "summary": "Unauthorised software and systems in use by the agency are detected", "csf": ["ID.AM", "PR.PS", "PR.IR", "DE.CM"]},
	"3.PEP.EN.VPNET": {"group": "enterprise", "name": "Virtual Private Network", "summary": "VPNs secure communication between networks across unprotected or public networks", "csf": ["PR.AA", "PR.DS", "PR.IR", "PR.PS"]},
	"3.PEP.EN.ACONT": {"group": "enterprise", "name": "Application Container", "summary": "Applications are isolated by virtualisation to a known set of dependencies, access methods and interfaces", "csf": ["ID.AM", "PR.AA", "PR.DS"]},
	"3.PEP.EN.RDACC": {"group": "enterprise", "name": "Remote Desktop Access", "summary": "A secured means is provided to connect to and control remote physical or virtual computers", "csf": ["ID.AM", "PR.AA", "PR.DS"]},
	"3.PEP.EN.CMONI": {"group": "enterprise", "name": "Costs Monitoring", "summary": "Costs incurred by enterprise resources are monitored", "csf": ["ID.AM", "PR.IR", "PR.PS"]},
	# ── Unified Communications and Collaboration PEP (Table 12) ──
	"3.PEP.UN.IVERI": {"group": "ucc", "name": "Identity Verification", "summary": "Access to virtual meetings is limited to appropriate people, for example via a host-controlled waiting room", "csf": ["PR.AA", "PR.IR"]},
	"3.PEP.UN.ECOMM": {"group": "ucc", "name": "Encrypted Communication", "summary": "Meeting communications and shared data are encrypted at rest and in transit, end to end where supported", "csf": ["PR.DS", "PR.PS"]},
	"3.PEP.UN.CTERM": {"group": "ucc", "name": "Connection Termination", "summary": "Meeting hosts can control participation through timeouts, prompts, per-meeting codes, eviction and duration limits", "csf": ["GV.PO", "PR.AA", "PR.IR", "PR.AT"]},
	"3.PEP.UN.DLPRE": {"group": "ucc", "name": "Data Loss Prevention", "summary": "Sharing of information between collaboration participants is controlled, for example by keyword, attachment type or size, or audio/visual filters", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	"3.PEP.UN.APPRO": {"group": "ucc", "name": "Anti-phishing Protections", "summary": "Phishing in collaboration communications is detected and users are prevented from reaching it", "csf": ["PR.AT", "PR.IR", "DE.CM"]},
	"3.PEP.UN.MLPRO": {"group": "ucc", "name": "Malicious Link Protections", "summary": "Malicious links in collaboration communications are detected and blocked", "csf": ["PR.AT", "PR.IR", "DE.CM"]},
	"3.PEP.UN.LCTPR": {"group": "ucc", "name": "Link Click-through Protections", "summary": "Clicked links in collaboration communications are routed through a destination security check before access", "csf": ["PR.IR", "DE.CM"]},
	"3.PEP.UN.MFPRO": {"group": "ucc", "name": "Malicious File Protections", "summary": "Malicious files in collaboration communications are detected and blocked", "csf": ["PR.AT", "DE.CM", "DE.AE", "RS.AN"]},
	# ── Data Protection PEP (Table 13) ──
	"3.PEP.DA.ACONT": {"group": "data_protection", "name": "Access Control", "summary": "Policies define which activities users and entities may perform on data and resources", "csf": ["GV.PO", "GV.RR", "GV.SC", "ID.RA", "PR.AA", "PR.IR", "PR.DS", "PR.PS", "DE.CM"]},
	"3.PEP.DA.PDRES": {"group": "data_protection", "name": "Protections for Data at Rest", "summary": "Data stored on any device or medium is protected", "csf": ["PR.DS", "PR.PS", "PR.IR"]},
	"3.PEP.DA.PDTRA": {"group": "data_protection", "name": "Protections for Data in Transit", "summary": "Data moving between locations, over the internet or private networks, is protected", "csf": ["PR.DS", "PR.IR"]},
	"3.PEP.DA.DLPRE": {"group": "data_protection", "name": "Data Loss Prevention", "summary": "Malicious or accidental exfiltration of agency data is detected", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	"3.PEP.DA.DAUTE": {"group": "data_protection", "name": "Data Access and Use Telemetry", "summary": "Sensitive agency data, including at service providers, is identified and access to or changes of it are logged in detail", "csf": ["GV.OC", "GV.RM", "ID.AM", "PR.AA", "PR.DS", "PR.IR", "PR.PS", "DE.AE", "DE.CM"]},
	"3.PEP.DA.DLABE": {"group": "data_protection", "name": "Data Labeling", "summary": "Data is tagged by category to control its use and indicate its risk level", "csf": ["ID.AM", "PR.AA", "PR.DS", "DE.CM"]},
	"3.PEP.DA.DINVE": {"group": "data_protection", "name": "Data Inventory", "summary": "A current inventory of agency data is developed, documented and maintained", "csf": ["GV.OC", "ID.AM", "PR.DS", "PR.IR", "DE.CM", "RC.RP"]},
	# ── Services PEP (Table 14) ──
	"3.PEP.SE.ACMIT": {"group": "services", "name": "Active Content Mitigation", "summary": "Unapproved active content in services traffic is detected and removed", "csf": ["DE.AE", "DE.CM"]},
	"3.PEP.SE.DLPRE": {"group": "services", "name": "Data Loss Prevention", "summary": "Malicious or accidental exfiltration of agency data through services is detected", "csf": ["ID.AM", "PR.DS", "PR.IR"]},
	"3.PEP.SE.PCENF": {"group": "services", "name": "Protocol Compliance Enforcement", "summary": "Services traffic is checked for compliance with IETF protocol definitions", "csf": ["PR.PS", "PR.IR"]},
	"3.PEP.SE.MCFIL": {"group": "services", "name": "Malicious Content Filtering", "summary": "Malicious content in services traffic is detected and removed", "csf": ["DE.AE", "DE.CM", "PR.IR", "RS.AN"]},
	"3.PEP.SE.ACONT": {"group": "services", "name": "Access Control", "summary": "Policies limit what actions connected users and entities may perform on services", "csf": ["GV.PO", "PR.AA"]},
	# ── Identity PEP (Table 15) ──
	"3.PEP.ID.AAUTH": {"group": "identity", "name": "Adaptive Authentication", "summary": "Authentication strength is matched to the risk of the requested authorisation", "csf": ["GV.RR", "PR.AA", "PR.IR"]},
	"3.PEP.ID.SIDEN": {"group": "identity", "name": "Service Identity", "summary": "Users and entities can authenticate the identity of agency services", "csf": ["ID.AM", "PR.AA", "PR.IR"]},
	"3.PEP.ID.EINVE": {"group": "identity", "name": "Entitlement Inventory", "summary": "A current inventory of user and entity permissions to agency resources is maintained", "csf": ["GV.SC", "ID.AM", "PR.AA", "PR.IR"]},
	"3.PEP.ID.SMANA": {"group": "identity", "name": "Secrets Management", "summary": "A formal process tracks and manages credentials such as certificates, passwords and API keys", "csf": ["GV.PO", "GV.SC", "ID.AM", "PR.AA", "PR.DS", "PR.IR"]},
	"3.PEP.ID.BBASE": {"group": "identity", "name": "Behavioral Baselining", "summary": "User and entity behaviour is captured to support dynamic threat discovery and vulnerability management", "csf": ["ID.RA", "DE.CM", "RS.AN"]},
	"3.PEP.ID.EIAMA": {"group": "identity", "name": "Enterprise Identity and Access Management", "summary": "Agency identities are visible across environments and changes to them go through a formal, preferably automated process", "csf": ["GV.RR", "ID.AM", "ID.IM", "PR.AA", "PR.IR"]},
	"3.PEP.ID.MAUTH": {"group": "identity", "name": "Multi-factor Authentication", "summary": "Two or more factors verify user or entity identity", "csf": ["PR.AA", "PR.DS", "PR.IR"]},
	"3.PEP.ID.CAUTH": {"group": "identity", "name": "Continuous Authentication", "summary": "Identity is validated and re-authenticated throughout the lifecycle of an entity's interactions", "csf": ["PR.AA", "PR.DS", "PR.IR", "DE.CM"]},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "cisa_tic3", {})

_given := c if {
	c := _in.capabilities
	is_object(c)
}

_supplied if _given

_true(id) if _given[id] == true

_pep_groups := {g | some g; _ = groups[g]; g != "universal"}

_scope_declared if "pep_groups_in_scope" in object.keys(_in)

_scope_valid if {
	s := _in.pep_groups_in_scope
	is_array(s)
	every g in s { g in _pep_groups }
}

# PEP groups evaluated: the declared list when valid; every PEP group when absent or malformed (strict)
pep_scope := s if {
	_scope_valid
	s := {g | some g in _in.pep_groups_in_scope}
} else := _pep_groups

applicable[id] := c if {
	some id, c in capabilities
	c.group == "universal"
}

applicable[id] := c if {
	some id, c in capabilities
	c.group in pep_scope
}

violations contains "CISA TIC 3.0: FAIL-CLOSED - capability attestations 'input.cisa_tic3.capabilities' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, c in applicable
	not _true(id)
	msg := sprintf("CISA TIC 3.0 %v (%v, %v): not attested — %v", [id, groups[c.group], c.name, c.summary])
}

violations contains msg if {
	some id, _ in _given
	not capabilities[id]
	msg := sprintf("CISA TIC 3.0 Input Contract: unknown capability id %v — ids are the catalog's Capability Identifiers such as 3.UNI.BRECO or 3.PEP.WE.BINSP", [id])
}

violations contains msg if {
	_scope_declared
	not _scope_valid
	msg := sprintf("CISA TIC 3.0 Input Contract: input.cisa_tic3.pep_groups_in_scope must be an array of PEP group keys %v; got %v — every PEP group is evaluated", [sort(_pep_groups), _in.pep_groups_in_scope])
}

group_reports[g] := r if {
	some g, label in groups
	members := {id | some id; c := capabilities[id]; c.group == g}
	ids := {id | some id in members; applicable[id]}
	r := {
		"name": label,
		"in_scope": count(ids) > 0,
		"capabilities": count(members),
		"evaluated": count(ids),
		"attested": count({id | some id in ids; _true(id)}),
		"gaps": sort([id | some id in ids; not _true(id)]),
	}
}

compliance_report := {
	"framework": "CISA Trusted Internet Connections (TIC) 3.0",
	"standard": "TIC 3.0 Core Guidance Volume 3: Security Capabilities Catalog, Version 3.3 (September 2026)",
	"source": source,
	"compliant": compliant,
	"total_controls": count(capabilities),
	"pep_groups_in_scope": sort([g | some g in pep_scope]),
	"capabilities_evaluated": count(applicable),
	"capabilities_attested": count({id | some id; _ = applicable[id]; _true(id)}),
	"groups": group_reports,
	"violation_count": count(violations),
	"violations": violations,
}
