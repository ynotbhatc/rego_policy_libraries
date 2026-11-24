# CIS Apple iOS 27 Benchmark v1.0.0

**Version:** v1.1 · generated 2026-11-17, profile-selector validation 2026-11-24, by `tools/cis_generators/gen_ios_27.py` from the CIS workbook

105 recommendations (end-user and institutionally owned device profiles, Level 1 and Level 2; some belong to both
ownerships). 80 are decided from configuration-profile keys and fail closed with an "evidence missing" message when
the key was not collected; 25 are attestation booleans (on-device settings and judgement items). Messages carry the
control id and our own wording, not CIS text. This replaces the earlier hand-written iOS module (24 checks).

Query: `POST /v1/data/cis/mobile/ios/main/compliance_report` (roll-up package `cis.mobile.ios`).

## Profile

`input.cis_profile.ownership` is `end_user` or `institutional` (default `institutional`); `input.cis_profile.level`
is `1` or `2` (default `2`, includes Level 1). `total_controls` is the number in scope:

| Ownership | Level 1 | Level 2 |
|---|---|---|
| end_user | 45 | 53 |
| institutional | 56 | 69 |

On empty input every in-scope recommendation fails (`failed_controls == total_controls`).

The defaults apply only when the selector is absent. A selector that is present with any other value is invalid
evidence, not a default: `level` other than the number `1` or `2` (the string `"2"` included) scopes the report at
Level 2 and fails every Level 2 recommendation of the ownership; `ownership` other than `end_user` or `institutional`
scopes it as institutional and fails every recommendation, because the set that applies could not be chosen. Both
carry a `cis_profile.<selector>: evidence invalid — …` finding.

## Facts

| Input | Source |
|---|---|
| `ios_profile.restrictions.<key>` | `com.apple.applicationaccess` payload keys, effective values |
| `ios_profile.passcode.<key>` | `com.apple.mobiledevice.passwordpolicy` keys |
| `ios_profile.profile.{removal,consent_message}` | profile removal control (`always` / `with_authorization` / `never`) and consent text |
| `ios_profile.mail_accounts[]` | mail payloads (`PreventMove`, `allowMailDrop`) |
| `ios_profile.attest.*` | attestation booleans |

A key that is absent is evidence missing; the Apple payload defaults are not assumed. The attested recommendations
are 2.3.1, 2.5.1, 2.6.1, 2.8.1, 3.3.1, 3.5.1, 3.6.1, 3.8.1, 3.9.1 and the on-device section 4 (4.8 and 4.11 are
Automated in the workbook but have no profile key).

Regenerate: see `tools/cis_generators/README.md`.
