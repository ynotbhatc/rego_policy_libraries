# A sample AWS account

`facts.json` is the input for one fictional AWS account, `example-prod` (account id 111122223333, region
us-east-1), in the shape the CIS Amazon Web Services Foundations Benchmark v7.1.0 module in this library reads:
the IAM account summary, credential report, password policy, IAM users, roles and policies, CloudTrail trails,
Config recorders, KMS keys, S3 buckets, VPCs, security groups, network ACLs, the Bedrock inventories and the
sign-offs for the manual recommendations (`attest`). Nothing in it comes from a real account.

The account is mostly well configured and has a handful of ordinary gaps, so the result is mixed.

## Run it

From the repository root:

```bash
opa eval -d benchmarks/cis/aws -i examples/cis_aws/facts.json -f pretty 'data.cis_aws.main.compliance_report'
```

## What the output means

- `compliant` is `false`: at least one recommendation failed.
- `total_controls` is 94, every recommendation in v7.1.0, because the file sets `"cis_profile": {"level": 2}`
  (Level 2 includes Level 1). Set `"level": 1` and you get the Level 1 profile, 49 recommendations.
- `failed_controls` is 6 and `passed_controls` is 88; `level_1.failed` is 3 and `level_2.failed` is 3.
- `evidence_missing_count` is 1: one recommendation failed because its facts were not collected, not because the
  account is misconfigured.
- `violations` has one line per failing recommendation, starting with its id. `section_results` groups them by
  section (identity and access, storage, logging, monitoring, networking, generative AI).

To see only the failures:

```bash
opa eval -d benchmarks/cis/aws -i examples/cis_aws/facts.json -f json 'data.cis_aws.main.compliance_report' \
  | jq -r '.result[0].expressions[0].value.violations[]'
```

## What is wrong with this account

- **2.8**: the IAM password policy allows passwords of 8 characters
- **4.2**: the CloudTrail trail `main` does not validate its log files, so tampering with them would go unnoticed
- **4.6**: the customer-managed KMS key `k1` is never rotated
- **4.7**: evidence missing: the VPC flow-log inventory (`flow_logs`) was not collected, so the module cannot tell
  whether flow logging is on. It fails instead of passing
- **5.3**: nobody has signed off that an alarm fires when the root user is used (`attest.alarm_root_account_usage`
  is `false`)
- **6.3**: security group `sg-1` (`web`) lets the whole internet reach SSH on port 22

Fix one in the file and run the command again: set `password_policy.MinimumPasswordLength` to 14 and
`failed_controls` drops to 5. Delete another inventory, for example `s3_buckets`, and the two S3 recommendations
that read it (3.1.1, 3.1.4) fail with "evidence missing" (`failed_controls` rises to 8), because a fact that was not
collected is not a fact that passed.

## Where facts come from

This library evaluates facts; it does not collect them. Each inventory is what the AWS CLI or API prints (field
names as those tools print them), with `region` on regional resources; the full input contract is in the header
of [`benchmarks/cis/aws/cis_aws_foundations.rego`](../../benchmarks/cis/aws/cis_aws_foundations.rego) and in
[`benchmarks/cis/aws/README.md`](../../benchmarks/cis/aws/README.md). The collectors in the companion product,
[Ansible Automated Compliance](https://github.com/Ansible-Automated-Compliance/aac), produce this document; any
tool that writes the same JSON works equally well.

## Keeping it true

`bash examples/cis_aws/check.sh` evaluates the file and fails if the result is no longer the one described here
(94 recommendations, these 6 failing, 1 of them evidence missing).
