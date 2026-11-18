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

The technical modules have some checks that use periods chosen by this library, not by the regulation:

- key rotation within 365 days;
- automatic logoff within 15 minutes;
- 90-day reviews of emergency accounts and of ePHI access.

`hipaa.access_control` reports these in `advisories`. Advisory messages do not cite 45 CFR and do not change `compliant`. Automatic logoff (164.312(a)(2)(iii)) only requires a predetermined inactivity time, so the check is that a positive timeout is set.

## Proposed Security Rule update (NPRM)

HHS published a proposed rule, "HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information", on 6 January 2025 (90 FR 898, Federal Register document 2024-30983). It would remove the required/addressable distinction and make most specifications mandatory. When checked on 2026-11-17:

- The Federal Register held no final rule for it.
- The eCFR text still carried the addressable markings.
- The Unified Agenda (RIN 0945-AA22) listed final action as a target date only.

These policies therefore implement the regulation currently in force. If a final rule is published, the addressable path and the status table need to be revisited.
