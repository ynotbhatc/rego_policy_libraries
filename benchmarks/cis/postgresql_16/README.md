# CIS PostgreSQL 16 (v1.1.0)

Rego for the CIS PostgreSQL 16 Benchmark. 71 recommendations (41 Automated, 30 Manual); every one
has a rule. Ids, Automated/Manual status and profile are read from the benchmark workbook; the check logic
and every message are written here from the audit procedure, not copied from the benchmark.

- 60 recommendations: Level 1 - PostgreSQL
- 11 recommendations: Level 1 - PostgreSQL on Linux

Entrypoints:

- `data.cis_postgresql_16.main.compliance_report` is the framework-key report (`compliant`, `total_controls`,
  `failed_controls`, `violations`, `violation_count`). On empty input it fails closed: `compliant` is false and
  `failed_controls == total_controls`.
- `data.cis.postgresql_16` is the benchmark package itself (`controls`, `passed`, `violations`, `sections`).

Input is `input.postgresql.*`, the same fact contract as the PostgreSQL 17 module (`benchmarks/cis/postgresql`);
a collector that feeds one feeds the other. An Automated recommendation whose fact is absent reports
`<id>: evidence missing`; a Manual one passes only when `input.postgresql.attest.<key>` is true.

How PostgreSQL 16 differs from the PostgreSQL 17 module:

- no 4.10 (login accounts have passwords): the 16 benchmark has 71 recommendations, not 72.
- 4.8 audits the role-tree result (login roles that are superusers or inherit one), fact `login_roles_with_superuser_path`, instead of the login superusers list; every row must be in `policy.authorized_superusers`.
- 6.8 audits only `ssl` being on; the pg_hba host/hostnossl rules and live non-TLS sessions are not part of the 16 audit.
- 6.10 allows only the three TLS 1.3 suite names in `ssl_ciphers` and no live session on another cipher (fact `ssl.unapproved_cipher_sessions`); 17 allows four ECDHE GCM suites and looks at TLS 1.2 sessions.
- 6.10 is in the Level 1 - PostgreSQL on Linux profile in 16 and in Level 1 - PostgreSQL in 17.
- install paths in 1.3, 1.4 and 2.2 name PostgreSQL 16; the facts are the same.

Generated. Do not edit by hand; regenerate with:

```
/usr/bin/python3 tools/cis_generators/gen_postgresql_16.py <CIS_PostgreSQL_16_workbook.xlsx> benchmarks/cis/postgresql_16
opa fmt -w benchmarks/cis/postgresql_16
```
