# CIS module generators

Generators that build a CIS benchmark module from the benchmark's own text. The
PDFs are CIS-licensed and are not committed; each script reads a `pdftotext -layout`
extraction supplied on the command line, verifies the recommendation ids and
titles it finds against its hand-authored logic table (a recommendation without
logic, or logic without a recommendation, aborts), and emits the module and its
tests.

- `gen_oracle_db_23ai.py <23ai.txt>` — CIS Oracle Database 23ai Benchmark v1.0.0,
  all 87 recommendations. Logic is written from each recommendation's audit SQL:
  parameter and profile checks read the queried value, privilege checks read the
  rows the query returns, audit checks read the enabled unified-audit options; the
  nine Manual recommendations are attestation booleans. The input contract is the
  Oracle Database 19c STIG module's, so one collector feeds both.

The CIS OCI Foundations module (`benchmarks/cis/oci/`) is hand-written from the
public Prowler mapping of v3.1.0 and needs no generator.
