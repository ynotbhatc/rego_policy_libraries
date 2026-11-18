# HIPAA Administrative Simplification

These policies check 45 CFR Parts 160, 162 and 164 (Security Rule, Breach Notification and Privacy Rule) and the HITECH Act. Every control id is the regulation's own paragraph citation. The entry point is `data.hipaa.main.compliance_report`. The headers of `hipaa_main.rego` and `hipaa_security_rule.rego` describe the modules, the sources and how each row is decided.

## Required and addressable specifications

The Security Rule marks each implementation specification "(Required)" or "(Addressable)" (45 CFR 164.306(d)(1)). The 22 addressable and 24 required markings in `hipaa_security_rule.rego` were checked against the eCFR current text of §§ 164.308–164.316 on 2026-11-17.

There are two ways to meet an addressable specification (45 CFR 164.306(d)(3)):

1. Implement the specification. The module's fact checks show this.
2. Document why implementing it is not reasonable and appropriate. Then either implement an equivalent alternative measure, or document why no alternative is reasonable and appropriate.

The module reads option 2 from:

```json
{"hipaa": {"addressable_decisions": {
  "164.312(a)(2)(iv)": {
    "not_reasonable_and_appropriate_documented": true,
    "equivalent_alternative_implemented": true
  }
}}}
```

`"no_reasonable_alternative_documented": true` can replace `equivalent_alternative_implemented`. If neither option is evidenced, the specification fails. A decision sent for a required specification, a standard or an unknown id is reported as an input-contract violation, and it never satisfies that row.

## Advisories

Some checks use a period, frequency or mechanism that this library chose and the regulation does not state. Each module reports these in `advisories`, and `hipaa.main` collects them all. An advisory message starts with "Advisory (", never cites 45 CFR as a requirement, and never changes `compliant` or the violation count.

**Access control (164.312(a))**
- Advisories: key rotation within 365 days; key-management policy; the weak-algorithm denylist; automatic logoff within 15 minutes; screen lock; generic account names; 90-day reviews of emergency accounts and of ePHI access; emergency-procedure testing; per-user access justification; "full" ePHI access (minimum necessary is decided in `hipaa.privacy_rule`).
- Still enforced: unique user identification, a documented emergency access procedure, and automatic logoff with a positive predetermined timeout. Encryption at rest and access limited to granted rights are also enforced; the latter can be shown by role-based access or by a direct statement.

**Audit controls (164.312(b))**
- Advisories: the required event list; user id, timestamp, source IP and action-type fields; six-year retention (164.316(b)(2)(i) covers 164.316 documentation, not logs); offsite backup; tamper evidence; centralisation; weekly review; alerting; after-hours monitoring.
- Still enforced: logging is enabled on every ePHI system (record), and a review is evidenced (examine).

**Person or entity authentication (164.312(d))**
- Advisories: MFA for remote and privileged access; SMS MFA; password length, complexity, age, history and lockout; non-expiring passwords; re-authentication; concurrent sessions; certificate authentication for service accounts.
- Still enforced: evidence that ePHI access is authenticated, and no default passwords.

**Integrity (164.312(c))**
- Advisories: integrity-check frequency; change management; write protection of archives; the weak-hash list; digital signatures on exports; backup, offsite copies, backup frequency, restore tests and their age, secure deletion and media re-use. The last group is decided in `hipaa.security_rule` by 164.308(a)(7)(ii)(A) and 164.310(d)(2)(i)–(ii).
- Still enforced: (c)(1) policies and procedures, and a (c)(2) mechanism per system (integrity checking, or checksums/hashes).

**Transmission security (164.312(e))**
- Advisories: network segmentation; minimum TLS version and old SSL/TLS protocols; weak ciphers; certificate monitoring and expiry; mTLS; VPN requirement, VPN protocol and split tunnelling; API request signing; email DLP.
- Still enforced: encryption in transit, no plaintext protocols, and encrypted ePHI email, all cited to (e)(2)(ii). Also an (e)(2)(i) integrity measure, shown by message authentication or by a direct statement.

**Security Rule (164.308, 164.310)**
- Advisories: 12-month cadences for risk analysis, training, contingency testing and evaluation (the regulation says "periodic" or sets none); forensic capability; business-associate inventory and monitoring; workstation screen lock and physical-access restriction under 164.310(b). Physical restriction is decided under 164.310(c).
- 164.308(a)(6)(i) is now decided by implemented incident-response procedures. Breach-notification procedures are Subpart D and are decided in `hipaa.hitech`.

**Privacy Rule**
- 164.530(b)(2) trains new staff "within a reasonable period". The former 30-day flag still counts as evidence, and an annual refresher is an advisory.
- 164.520(c) facility and web posting apply only to an entity with a delivery site or a website. An entity without one declares `npp.no_physical_service_delivery_site` / `npp.no_customer_service_website`.

**HITECH**
- Advisories: corrective-action-plan readiness (42 U.S.C. §17939 sets penalties, not this duty), and the CMS EHR-incentive security and meaningful-use measures. Those measures are not HIPAA obligations, and they made addressable specifications mandatory.

## Proposed Security Rule update (NPRM)

HHS published a proposed rule, "HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information", on 6 January 2025 (90 FR 898, Federal Register document 2024-30983). It would remove the required/addressable distinction and make most specifications mandatory. When checked on 2026-11-17:

- The Federal Register held no final rule for it.
- The eCFR text still carried the addressable markings.
- The Unified Agenda (RIN 0945-AA22) listed final action as a target date only.

These policies therefore implement the regulation currently in force. If a final rule is published, the addressable path and the status table need to be revisited.
