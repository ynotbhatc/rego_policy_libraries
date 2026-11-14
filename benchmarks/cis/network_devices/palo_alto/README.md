# CIS Palo Alto Firewall 11 Benchmark v1.2.1

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_palo_alto.py` from the CIS workbook

All 79 recommendations (62 Automated, 17 Manual; 69 Level 1, 10 Level 2). 66 are decided from the collected
configuration and fail closed with an "evidence missing" message when the fact was not collected; 13 judgement
items are attestation booleans. Messages carry the control id and our own wording, not CIS text.

Query: `POST /v1/data/cis_palo_alto_panos/main/compliance_report` (roll-up package `cis_palo_alto_panos`).

## Profile

`input.cis_profile.level` is `1` or `2` (Level 2 includes Level 1). Absent, it is `2`. `total_controls` is the
number in scope: 69 at Level 1, 79 at Level 2. On empty input every one of them fails.

## Sections

| Section | Recommendations | Attested |
|---|---|---|
| 1 Device setup | 26 | 1.2.1, 1.2.2, 1.2.5, 1.6.3, 1.7.1 |
| 2 User identification | 8 | 2.1, 2.5, 2.6, 2.7 |
| 3 High availability | 3 | |
| 4 Dynamic updates | 2 | |
| 5 WildFire | 8 | 5.1, 5.7 |
| 6 Security profiles | 25 | |
| 7 Security policies | 4 | |
| 8 Decryption | 3 | 8.2, 8.3 |

2.1, 2.6 and 5.1 are Automated in the workbook but attested here: 2.1 is read from traffic logs, 2.6 is an
Active Directory setting, and the 5.1 defaults differ by PAN-OS release. Manual recommendations with a decidable
setting (1.2.4, 5.8, 6.2, 6.20, 6.24, 6.25, 7.4) are checked like Automated ones. 6.22-6.25 apply only while the
named license is active.

## Facts

`input.panos_config` is the running configuration (`show config running`) converted from XML to JSON: `-` in
element names becomes `_`, every `<entry>` list is an array of objects keyed by `name`, every `<member>` list is an
array of strings, booleans stay `"yes"`/`"no"`. The full path list is in the header of `cis_palo_alto_panos.rego`.

| Input | Source |
|---|---|
| `deviceconfig.system`, `deviceconfig.setting`, `deviceconfig.high_availability` | device setup, services, update schedules, HA |
| `mgt_config.password_complexity`, `mgt_config.password_profile[]` | admin password rules |
| `shared.*` | server profiles, log settings, authentication and log forwarding profiles |
| `network.profiles.{interface_management,zone_protection}[]`, `zone[]`, `user_id.{setting,include_exclude_network[]}` | interfaces, zones, User-ID |
| `profiles.<kind>[]`, `profile_group[]` | antivirus, anti-spyware, vulnerability, URL filtering, data filtering, WildFire |
| `rulebase.{security,default_security_rules,decryption}[]` | policies |
| `licenses[]` | `request license info` |
| `site.{untrusted_zones,internet_zones,url_block_categories}` | the operator's zone classification and URL block list |
| `attest.*` | attestation booleans |

An absent list is evidence missing. An empty rule list or an empty `site` list also counts as evidence missing.

Regenerate: see `tools/cis_generators/README.md`.
