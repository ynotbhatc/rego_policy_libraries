# A sample PCI DSS v4.0.1 assessment

`facts.json` is the input for one fictional merchant, Example Outfitters, whose cardholder data environment is two
hosts (`pay01.example.com`, `db01.example.com`, both in 192.0.2.0/24) behind an online shop. It is in the shape the
`pci_dss` module reads (`input.pci` and `input.cloud`): CDE scope, program management, and the evidence for all twelve
requirements, from firewall rules and stored-data encryption to password policy, log retention, scanning and
payment-page monitoring. Nothing in it comes from a real organization.

Scope as the file states it: e-commerce with hosted payment pages and public web applications in scope; wireless is
not part of the CDE and carries no card data; no POS or POI terminals; the merchant is not a service provider;
1.5 million card transactions a year (validation level 2). VPN access uses MFA and there is no remote desktop.

## Run it

From the repository root:

```bash
opa eval -d frameworks/financial/pci_dss -i examples/pci_dss/facts.json -f pretty 'data.pci_dss.main.compliance_report'
```

`bash examples/pci_dss/check.sh` asserts the result below.

## What the output means

- `standard` is `PCI DSS v4.0.1`; `compliant` is `false`.
- `total_controls` is 12 (the twelve requirements), `failed_controls` is 3 and `requirements_passing` is 9.
- `violations` names the failing requirements: `req_8_authentication`, `req_10_logging_monitoring`,
  `req_11_security_testing`.
- `requirement_details` shows why: each requirement breaks down into sub-requirements (8.3, 10.5, 11.3, ...), and the
  checks that are `false` are the findings. `scores` gives the share of passing checks per requirement and a
  weighted overall score (about 97.7).
- `compliance_status.cde_scope_defined` is `true`: the CDE boundaries, inventory, data flows and network diagram are
  documented. Without that, the report is non-compliant even if every requirement passes.
- `validation_level` is `Level 2`, from `pci.transaction_volume.annual`.

This module reports at requirement level, so its violations name requirements, not individual checks. Each one
carries a `status`: `fail` when a fact is present and non-compliant (the title lists the failing checks), or
`evidence_missing` when the checks that fail only lack facts (the title says "evidence missing" and names the input
paths). `requirement_results` gives the same status for all twelve requirements, passes included, and
`requirement_result_counts` totals them (here 9 pass, 3 fail). Delete `pci.data_discovery` from the file and
requirement 3 becomes `evidence_missing`, naming `input.pci.data_discovery.quarterly.conducted` and the other
data-discovery facts (`failed_controls` becomes 4).

## What is wrong with this merchant

- **8.3** (`password_requirements`): the minimum password length is 8 and the file does not claim the systems are
  unable to take 12
- **10.5** (`retention_12_months`): only one month of audit logs is kept online; three are required
- **11.3** (`internal_scanning`): internal vulnerability scans run every 120 days instead of at least quarterly
- **11.6** (`payment_page_integrity`): nobody keeps an inventory of the scripts on the payment page

Fix one in the file: set `pci.passwords.minimum_length` to 12 and requirement 8 passes; `failed_controls` drops to 2.
