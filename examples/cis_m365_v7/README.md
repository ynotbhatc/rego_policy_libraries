# A sample Microsoft 365 tenant

`facts.json` is the input for one fictional tenant, Contoso (`contoso.example`), in the shape the CIS Microsoft 365
Foundations Benchmark v7.0.0 module in this library reads (`benchmarks/cis/saas/m365_v7/`): admin center, Defender,
Purview, Intune, Entra, Exchange, SharePoint, Teams and Fabric settings as the Graph and PowerShell collectors
return them, plus the sign-offs for the recommendations that need a person to confirm them. Nothing in it comes
from a real tenant; it starts from the module's compliant test fixture with six values changed.

## Run it

From the repository root:

```bash
opa eval -d benchmarks/cis/saas/m365_v7 --ignore tests -i examples/cis_m365_v7/facts.json \
  -f pretty 'data.cis_m365_v7.main.compliance_report'
```

`bash examples/cis_m365_v7/check.sh` asserts the result below, so the sample cannot rot.

## What the output means

- The report has no bare `compliant`. It has `assessed_controls_compliant`, here `false`, which speaks only for
  the controls the module evaluated from evidence (`evaluated_control_ids`); see the module README for why.
- `total_controls` is 160, every recommendation in the benchmark: no `cis_profile` is given, so the default
  (E5 licence, Level 2) puts all of them in scope. `controls_evaluated` is 144, read from settings; the other 16
  pass on the sign-offs in `attestations`.
- `failed_controls` is 6; `control_result_counts` shows 154 pass, 6 fail, 0 evidence missing.
- `violations` has one line per failing recommendation, starting with `CIS <id>:`.

Only the failures:

```bash
opa eval -d benchmarks/cis/saas/m365_v7 --ignore tests -i examples/cis_m365_v7/facts.json \
  -f json 'data.cis_m365_v7.main.compliance_report' | jq -r '.result[0].expressions[0].value.violations[]'
```

## What is wrong with this tenant

- **2.1.9**: mail from `contoso.example` is not DKIM-signed; the signing configuration is switched off
- **5.2.2.3**: the Conditional Access policy that should block legacy sign-in protocols exists but is disabled
- **6.5.4**: SMTP client submission with a password alone is still allowed
- **7.2.3** and **7.2.6**: SharePoint lets people share with anyone, including through links that need no
  sign-in. One setting, two recommendations
- **8.5.1**: anonymous people can join Teams meetings

Fix one and run again: set `exchange.transport_config.SmtpClientAuthenticationDisabled` to `true` and
`failed_controls` drops to 5. Delete the whole `teams` object and the 16 Teams recommendations do not pass: each
is reported `evidence missing`, because settings that were not collected are not settings that passed.

## Where facts come from

The module README lists each section's inputs and the Graph or PowerShell source that produces them; a source the
collector could not reach goes under that section's `unavailable` key and names the controls it blocks. The AAC
product collectors produce this shape.
