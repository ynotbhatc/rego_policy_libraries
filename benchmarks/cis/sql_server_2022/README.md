# CIS Microsoft SQL Server 2022 Benchmark v1.3.0

All 48 recommendations of the benchmark (37 Automated, 11 Manual), generated from the
benchmark's workbook by `tools/cis_generators/gen_sql_server_2022.py`. Do not edit the `.rego`
files by hand: change the generator and regenerate.

| | |
|---|---|
| Framework key | `cis_sql_server_2022` |
| Entrypoint | `data.cis.sql_server_2022.main.compliance_report` |
| Roll-up | `data.cis.sql_server_2022` (recommendations table, profile selector, violations) |
| Profiles | `input.cis_profile`: `platform` `database_engine` (default) or `aws_rds`; `level` 1 or 2 (default 2, the strictest). Database Engine L1 45, L2 48, AWS RDS L1 30 |

## How a recommendation is decided

- Automated: from collected facts. Facts that were not collected give
  `<id>: evidence missing — <field> not collected`, never a pass.
- Manual: an attestation boolean, `input.sql.attest.<name>`. Not attested is a violation.
- An empty input fails closed: `compliant` is false and `failed_controls` equals `total_controls`.
- Recommendations outside the selected profile raise nothing and are not counted in `total_controls`.

Recommendation ids, Automated/Manual status and profiles come from the workbook. The wording
of every message is ours; the benchmark's text is not reproduced here.

## Input

The fact contract is the one `benchmarks/cis/sql_server_2025/` reads, path for path (root `input.sql`),
so one collector feeds both modules. The 2022 benchmark has the same recommendations as the 2025 one
except 3.15 (external REST endpoint review), which does not exist here. Only 6.2 is queried differently: the 2022 query lists
assemblies above `SAFE_ACCESS`; `sql.user_assemblies[]` may hold either all user assemblies or only those,
and any row whose `permission_set_desc` is not `SAFE_ACCESS` fails.

## Regenerate

```bash
python3 tools/cis_generators/gen_sql_server_2022.py CIS_Microsoft_SQL_Server_2022_Benchmark_v1.3.0.xlsx .
opa test benchmarks/cis/sql_server_2022
```
