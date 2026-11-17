# CIS Cisco IOS XE 17.x Benchmark v2.2.2

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_cisco_ios_xe_17.py` from the CIS workbook

All 84 recommendations (51 Automated, 33 Manual; 75 Level 1, 9 Level 2). 64 are decided from the collected running
configuration and fail closed with an "evidence missing" message when the fact was not collected; 20 judgement
items are attestation booleans. Messages carry the control id and our own wording, not CIS text.

Query: `POST /v1/data/cis_cisco_ios_xe_17/main/compliance_report` (roll-up package `cis_cisco_ios_xe_17`).

This is a new module. The older `network_devices/cisco` (`cis_cisco_ios`) and `network/cisco` (`cis.network.cisco`)
modules are generic IOS, read `input.cisco_config` and do not claim IOS XE.

## Profile

`input.cis_profile.level` is `1` or `2` (Level 2 includes Level 1). Absent, it is `2`. `total_controls` is the number
in scope: 75 at Level 1, 84 at Level 2. On empty input every one of them fails.

## Sections

| Section | Recommendations |
|---|---|
| 1 Management plane | 37 |
| 2 Control plane | 29 |
| 3 Data plane | 18 |

Attested: 1.2.4, 1.5.1, 1.5.6, 1.5.10, 2.1.1.1.3, 3.1.4, 3.2.1, 3.2.2 and every routing-protocol authentication item
(3.3.1.1 to 3.3.1.9, 3.3.2.1, 3.3.2.2, 3.3.3.1); all are Manual in the workbook. Manual recommendations with a
decidable configuration line (1.2.1, 1.5.4, 1.5.5, 2.1.1.2, 2.1.2, 2.1.3, 2.1.7, 2.3.1.4, 2.4.2, 2.4.4, 3.1.1, 3.1.2,
3.1.3) are checked like Automated ones. Rules that only apply when a service is on (1.1.5, 1.2.9, 1.2.10 with the HTTP
server; 1.5.7 and 1.5.8 with SNMP) pass when it is off. The aux-line checks (1.2.3, 1.2.6) pass on a device with no
aux line once the line sections were collected.

## Facts

`input.ios_xe_config` is the parsed `show running-config all` (for example `ansible_net_config` from cisco.ios facts,
split by the collector):

| Input | Source |
|---|---|
| `lines[]` | every top-level (unindented) line, section headers included; `!` comment lines are ignored |
| `sections[]` | `{header, lines[]}` for each top-level line with an indented body, body lines without indentation |
| `banners` | `{exec, login, motd}` banner text without delimiters |
| `attest.*` | attestation booleans |

Patterns are anchored on a command word, so a commented line, a `no` form or a longer command never matches. Use
the `all` form: exec-timeout, `ip ssh time-out` and `no exec` are not shown when left at their default.
An absent list is evidence missing.

Regenerate: see `tools/cis_generators/README.md`.
