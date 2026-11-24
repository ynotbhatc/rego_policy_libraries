"""CIS Amazon Web Services Foundations Benchmark v7.1.0 -> benchmarks/cis/aws/ (engine, entrypoint, Level 2 view, tests).

    python3 tools/cis_generators/gen_aws.py <workbook.xlsx | dump.json> benchmarks/cis/aws

The first argument is the CIS workbook (dumped through dump_workbook.py, needs openpyxl) or a JSON file that
dump_workbook.py already wrote. Ids, Level 1/Level 2 profile and Automated/Manual status come from the workbook;
the logic table below is hand-authored from each recommendation's audit procedure (AWS CLI / API output). Every
logic entry carries a keyword that must occur in the workbook title of its id, so logic cannot attach to a
renumbered recommendation. The run aborts on any count, id, status or keyword mismatch. Wording is original
(neutralize.py for titles; finding texts are written here). Helper rules live in aws_lib.rego.tmpl. The generator
writes only the files listed in OWNED and runs `opa fmt -w` on them.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cis_genlib import load_workbook_json, rego_str, u  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

BENCH = "CIS Amazon Web Services Foundations Benchmark"
VERSION = "v7.1.0"
EXPECTED = (94, 44, 50)  # recommendations, Automated, Manual
OWNED = ["cis_aws_foundations.rego", "cis_aws_main.rego", "l2_validation.rego",
         "tests/test_cis_aws_v7_controls.rego", "tests/test_cis_aws_v7_logic.rego",
         "tests/test_cis_aws_v7_reports.rego", "tests/test_cis_aws_v7_l2.rego"]
TITLE_OVERRIDE = {
    "2.1.1": "Organization root access is handled centrally",
    "2.1.2": "Organization-wide guardrails cover every member account",
    "2.1.3": "The Organizations management account carries no workloads",
    "2.1.4": "OUs are laid out by environment and data sensitivity",
    "2.1.5": "A delegated administrator manages Organizations policies",
    "2.1.6": "Delegated administrators manage integrated services",
    "2.2": "Account contact details are kept current",
    "2.3": "A security contact is registered",
    "2.4": "The root user has no access keys",
    "2.5": "The root user is protected by MFA",
    "2.6": "The root user uses a hardware MFA device",
    "2.7": "Root credentials are kept out of daily administration",
    "2.8": "Password policy minimum length is 14 or more",
    "2.9": "Password policy blocks reuse of recent passwords",
    "2.10": "Console users have MFA",
    "2.11": "Credentials idle for 45 days are disabled",
    "2.12": "Access keys are rotated within 90 days",
    "2.13": "IAM users get permissions through groups only",
    "2.14": "No attached policy grants full administrative access",
    "2.15": "A role exists for AWS Support incident handling",
    "2.16": "EC2 instances reach AWS through instance roles",
    "2.17": "Expired server certificates are removed from IAM",
    "2.18": "An external access analyzer is active in every region",
    "2.19": "IAM identities are managed centrally",
    "2.20": "Use of the CloudShell full-access policy is restricted",
    "2.21": "Resource policies avoid wildcard principals",
    "3.1.1": "S3 bucket policies refuse plain HTTP",
    "3.1.2": "S3 versioned buckets require MFA to delete",
    "3.1.3": "S3 data is discovered and classified",
    "3.1.4": "S3 public access is blocked",
    "3.1.5": "S3 buckets use an appropriate encryption key arrangement",
    "3.2.1": "RDS storage is encrypted",
    "3.2.2": "RDS minor engine upgrades are automatic",
    "3.2.3": "RDS instances are not reachable from the internet",
    "3.2.4": "RDS uses Multi-AZ where availability matters",
    "3.2.5": "RDS instances have deletion protection",
    "3.3.1": "EFS file systems are encrypted",
    "4.1": "CloudTrail covers every region",
    "4.2": "CloudTrail validates log file integrity",
    "4.3": "AWS Config records in every region",
    "4.4": "The CloudTrail bucket has access logging",
    "4.5": "CloudTrail logs are encrypted with a KMS key",
    "4.6": "Customer symmetric KMS keys rotate",
    "4.7": "Every VPC has flow logs",
    "4.8": "CloudTrail records S3 object writes",
    "4.9": "CloudTrail records S3 object reads",
    "4.10": "Managed web front ends log access",
    "5.1": "An alarm covers unauthorized API calls",
    "5.2": "An alarm covers console sign-in without MFA",
    "5.3": "An alarm covers root account use",
    "5.4": "An alarm covers IAM policy changes",
    "5.5": "An alarm covers CloudTrail configuration changes",
    "5.6": "An alarm covers console authentication failures",
    "5.7": "An alarm covers KMS key disabling or deletion",
    "5.8": "An alarm covers S3 bucket policy changes",
    "5.9": "An alarm covers AWS Config changes",
    "5.10": "An alarm covers security group changes",
    "5.11": "An alarm covers network ACL changes",
    "5.12": "An alarm covers network gateway changes",
    "5.13": "An alarm covers route table changes",
    "5.14": "An alarm covers VPC changes",
    "5.15": "An alarm covers Organizations changes",
    "5.16": "Security Hub is on",
    "6.1.1": "New EBS volumes are encrypted by default in every region",
    "6.1.2": "Port 445 is not open to the internet",
    "6.2": "No network ACL opens administration ports to the internet",
    "6.3": "No security group opens administration ports to IPv4 internet",
    "6.4": "No security group opens administration ports to IPv6 internet",
    "6.5": "Default security groups carry no rules",
    "6.6": "VPC peering routes are minimal",
    "6.7": "EC2 instances require IMDSv2",
    "6.8": "VPC endpoints serve AWS service traffic",
    "7.1.1": "Model invocation policies are least privilege",
    "7.1.2": "Invocation and model management roles are separate",
    "7.1.3": "Bedrock agent roles are least privilege",
    "7.1.4": "SCPs limit model use to an approved list",
    "7.1.5": "Bedrock service roles are bound to the owning account and resource",
    "7.1.6": "Bedrock long-term API keys expire and are rotated",
    "7.2.1": "Every invocation point has a guardrail",
    "7.2.2": "Invocation points without a guardrail are monitored",
    "7.2.3": "Guardrail checks run outside agent reasoning",
    "7.2.4": "Guardrails apply content and prompt-attack filtering",
    "7.2.5": "Guardrails filter sensitive information where personal data is handled",
    "7.2.6": "RAG guardrails use contextual grounding checks",
    "7.3.1": "Bedrock resources use an appropriate encryption key arrangement",
    "7.3.2": "Bedrock data retention fits the data sensitivity",
    "7.4.1": "CloudTrail captures Bedrock data-plane events",
    "7.4.2": "Model invocation logging is on in each operating region",
    "7.4.3": "Invocation log destinations protect what they receive",
    "7.4.4": "Knowledge base ingestion logs are delivered",
    "7.5.1": "Bedrock is reached over interface VPC endpoints",
    "7.5.2": "Bedrock jobs run in a VPC without public egress",
    "7.5.3": "Knowledge base vector stores are not public",
    "7.5.4": "Marketplace model endpoints are isolated in a VPC",
}


def load(path):
    if path.lower().endswith(".xlsx"):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "aws.json")
            subprocess.run([sys.executable, os.path.join(HERE, "dump_workbook.py"), path, out], check=True,
                           stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            return load_workbook_json(out)
    return load_workbook_json(path)


def sort_key(cid):
    return [int(x) for x in cid.split(".")]


ACCT = "111122223333"
R = "us-east-1"
NOW = "2026-11-17T00:00:00Z"
KB_ARN = f"arn:aws:bedrock:{R}:{ACCT}:knowledge-base/kb1"
PROFILE_ARN = f"arn:aws:iam::{ACCT}:instance-profile/app"
KMS_ARN = f"arn:aws:kms:{R}:{ACCT}:key/1234"
ALL_BLOCK = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def _row(user, pw, mfa, k1, k1rot, k1used):
    return {"user": user, "user_creation_time": "2025-01-01T00:00:00+00:00", "password_enabled": pw,
            "password_last_used": "2026-11-10T00:00:00+00:00" if pw == "true" else "N/A", "mfa_active": mfa,
            "access_key_1_active": k1, "access_key_1_last_rotated": k1rot, "access_key_1_last_used_date": k1used,
            "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"}


GREEN = {
    "assessment_time": NOW,
    "regions": [{"RegionName": R}],
    "account_summary": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1, "AccountPasswordPresent": 1},
    "password_policy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24},
    "credential_report": [
        _row("<root_account>", "not_supported", "true", "false", "N/A", "N/A"),
        _row("alice", "true", "true", "true", "2026-09-01T00:00:00+00:00", "2026-11-01T00:00:00+00:00")],
    "iam_users": [{"UserName": "alice", "attached_policies": [], "inline_policies": []}],
    "iam_policies": [{"PolicyName": "ReadOnly", "Arn": f"arn:aws:iam::{ACCT}:policy/ReadOnly", "AttachmentCount": 1,
                      "DefaultVersionDocument": {"Version": "2012-10-17", "Statement": [
                          {"Effect": "Allow", "Action": ["s3:Get*"], "Resource": "*"}]}}],
    "support_policy_entities": {"PolicyRoles": [{"RoleName": "support"}], "PolicyUsers": [], "PolicyGroups": []},
    "iam_server_certificates": [{"ServerCertificateName": "c1", "Expiration": "2027-06-01T00:00:00Z"}],
    "access_analyzers": [{"region": R, "name": "external", "type": "ACCOUNT", "status": "ACTIVE"}],
    "s3_buckets": [{"Name": "app-data", "public_access_block": ALL_BLOCK, "policy": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}],
    "rds_instances": [{"DBInstanceIdentifier": "db1", "StorageEncrypted": True, "AutoMinorVersionUpgrade": True,
                       "PubliclyAccessible": False}],
    "efs_file_systems": [{"FileSystemId": "fs-1", "Encrypted": True}],
    "ebs_encryption_by_default": [{"region": R, "EbsEncryptionByDefault": True}],
    "security_groups": [
        {"GroupId": "sg-1", "GroupName": "web", "region": R, "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}], "IpPermissionsEgress": []},
        {"GroupId": "sg-def", "GroupName": "default", "region": R, "IpPermissions": [], "IpPermissionsEgress": []}],
    "network_acls": [{"NetworkAclId": "acl-1", "Entries": [
        {"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/8",
         "PortRange": {"From": 22, "To": 22}},
        {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"}]}],
    "ec2_instances": [{"InstanceId": "i-1", "region": R, "State": {"Name": "running"},
                       "IamInstanceProfile": {"Arn": PROFILE_ARN}, "MetadataOptions": {"HttpTokens": "required", "State": "applied"}}],
    "iam_instance_profiles": [{"Arn": PROFILE_ARN, "Roles": [{"RoleName": "app"}]}],
    "cloudtrail_trails": [{"Name": "main", "TrailARN": f"arn:aws:cloudtrail:{R}:{ACCT}:trail/main", "HomeRegion": R,
                           "IsMultiRegionTrail": True, "LogFileValidationEnabled": True, "KmsKeyId": KMS_ARN,
                           "status": {"IsLogging": True},
                           "event_selectors": {"AdvancedEventSelectors": [
                               {"Name": "s3", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                                                                 {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]},
                               {"Name": "bedrock", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                                                                      {"Field": "resources.type", "Equals": ["AWS::Bedrock::AgentAlias"]}]}]}}],
    "config_recorders": [{"region": R, "name": "default", "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}],
    "config_recorder_status": [{"region": R, "name": "default", "recording": True, "lastStatus": "SUCCESS"}],
    "kms_keys": [{"KeyId": "k1", "region": R, "KeySpec": "SYMMETRIC_DEFAULT", "KeyManager": "CUSTOMER", "KeyRotationEnabled": True}],
    "vpcs": [{"VpcId": "vpc-1", "region": R}],
    "flow_logs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE", "region": R}],
    "securityhub_hubs": [{"region": R, "HubArn": f"arn:aws:securityhub:{R}:{ACCT}:hub/default", "SubscribedAt": "2025-01-01T00:00:00.000Z"}],
    "iam_roles": [{"RoleName": "bedrock-kb", "Path": "/", "Arn": f"arn:aws:iam::{ACCT}:role/bedrock-kb",
                   "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                       {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"aws:SourceAccount": ACCT},
                                      "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{R}:{ACCT}:knowledge-base/*"}}}]}},
                  {"RoleName": "plain", "Path": "/", "Arn": f"arn:aws:iam::{ACCT}:role/plain",
                   "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                               "Action": "sts:AssumeRole"}]}}],
    "bedrock_api_keys": [{"UserName": "svc", "ServiceName": "bedrock.amazonaws.com", "Status": "Active",
                          "CreateDate": "2026-10-20T00:00:00Z", "ExpirationDate": "2027-01-01T00:00:00Z"}],
    "bedrock_regions": [R],
    "bedrock_resource_types_in_use": ["AWS::Bedrock::AgentAlias"],
    "bedrock_modalities_in_use": ["text"],
    "bedrock_guardrails": [{"region": R, "id": "g1", "name": "gr", "blockedInputMessaging": "blocked", "blockedOutputsMessaging": "blocked",
                            "contentPolicy": {"filters": [
                                {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                                {"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"}]}}],
    "bedrock_invocation_logging": [{"region": R, "loggingConfig": {
        "cloudWatchConfig": {"logGroupName": "/bedrock/invocations", "roleArn": f"arn:aws:iam::{ACCT}:role/bedrock-logs"},
        "textDataDeliveryEnabled": True, "imageDataDeliveryEnabled": False, "embeddingDataDeliveryEnabled": False,
        "videoDataDeliveryEnabled": False}}],
    "bedrock_knowledge_bases": [{"region": R, "knowledgeBaseId": "kb1", "knowledgeBaseArn": KB_ARN, "storageConfiguration": {
        "type": "OPENSEARCH_SERVERLESS", "opensearchServerlessConfiguration": {
            "collectionArn": f"arn:aws:aoss:{R}:{ACCT}:collection/abc123"}}}],
    "log_delivery_sources": [{"region": R, "name": "kb1-src", "logType": "APPLICATION_LOGS", "resourceArns": [KB_ARN]}],
    "log_deliveries": [{"region": R, "deliverySourceName": "kb1-src", "deliveryDestinationType": "CWL",
                        "deliveryDestinationArn": f"arn:aws:logs:{R}:{ACCT}:log-group:kb"}],
    "opensearch_serverless_collections": [{"region": R, "id": "abc123", "name": "kbcoll"}],
    "opensearch_serverless_network_policies": [{"region": R, "name": "p1", "policy": [
        {"Rules": [{"ResourceType": "collection", "Resource": ["collection/kbcoll"]}], "AllowFromPublic": False,
         "SourceServices": ["bedrock.amazonaws.com"]}]}],
    "bedrock_endpoint_requirements": [{"region": R, "vpc_id": "vpc-1", "service_name": f"com.amazonaws.{R}.bedrock-runtime"}],
    "vpc_endpoints": [{"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "ServiceName": f"com.amazonaws.{R}.bedrock-runtime",
                       "VpcEndpointType": "Interface", "State": "available", "PrivateDnsEnabled": True,
                       "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"},
                                                                    "Action": ["bedrock:InvokeModel"], "Resource": "*"}]})}],
    "bedrock_jobs": [{"region": R, "type": "batch", "jobArn": f"arn:aws:bedrock:{R}:{ACCT}:model-invocation-job/j1",
                      "vpcConfig": {"subnetIds": ["subnet-1"], "securityGroupIds": ["sg-1"]}}],
    "subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
    "route_tables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1", "Main": False}],
                      "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]}],
    "bedrock_marketplace_endpoints": [{"region": R, "endpointArn": f"arn:aws:sagemaker:{R}:{ACCT}:endpoint/ep1", "models": [
        {"ModelName": "m1", "EnableNetworkIsolation": True, "VpcConfig": {"SecurityGroupIds": ["sg-1"], "Subnets": ["subnet-1"]}}]}],
    "attest": {},
}

# ── logic table ──────────────────────────────────────────────────────────────────────
# F(id, keyword, evidence keys, findings, fail patch[, miss patch]): decided from collected facts.
#   findings: (message, [sprintf args], [rego body lines]); each becomes one violation rule that also requires the
#   recommendation to be in scope and its evidence present.
# A(id, keyword, attestation key): input.attest.<key> == true.
C = []
OBJECT_KEYS = {"account_summary", "password_policy", "support_policy_entities"}


def add(p, v):
    return {"op": "add", "path": p, "value": v}


def rm(p):
    return {"op": "remove", "path": p}


def F(cid, kw, ev, rules, fail, miss=None):
    C.append({"id": cid, "kw": kw, "kind": "fact", "ev": ev, "rules": rules, "fail": fail if isinstance(fail, list) else [fail],
              "miss": miss or [rm("/" + ev[0])]})


def A(cid, kw, key):
    C.append({"id": cid, "kw": kw, "kind": "attest", "attest": key})


def each(lst, var="x"):
    return f"some {var} in input.{lst}"


# Manual recommendations: attestation booleans under input.attest.
for _cid, _kw, _key in [
    ("2.1.1", "centralized root", "org_root_access_centralized"),
    ("2.1.2", "authorization guardrails", "org_authorization_guardrails_in_place"),
    ("2.1.3", "management account", "org_management_account_runs_no_workloads"),
    ("2.1.4", "organizational units", "org_units_structured_by_environment"),
    ("2.1.5", "delegated admin manages", "org_policies_managed_by_delegated_admin"),
    ("2.1.6", "delegated admins", "org_services_managed_by_delegated_admins"),
    ("2.2", "contact details", "account_contact_details_current"),
    ("2.3", "security contact", "security_contact_registered"),
    ("2.6", "hardware mfa", "root_hardware_mfa"),
    ("2.7", "root", "root_not_used_for_daily_tasks"),
    ("2.19", "identity federation", "iam_users_managed_centrally"),
    ("2.20", "awscloudshellfullaccess", "cloudshell_full_access_restricted"),
    ("2.21", "principal", "resource_policies_have_no_wildcard_principal"),
    ("3.1.2", "mfa delete", "s3_mfa_delete_enabled"),
    ("3.1.3", "discovered", "s3_data_classified_and_secured"),
    ("3.1.5", "encryption at rest", "s3_encryption_key_management_appropriate"),
    ("3.2.4", "multi-az", "rds_multi_az_where_availability_needed"),
    ("3.2.5", "deletion protection", "rds_deletion_protection_enabled"),
    ("4.1", "cloudtrail", "cloudtrail_enabled_all_regions"),
    ("4.4", "server access logging", "cloudtrail_bucket_access_logging_enabled"),
    ("4.10", "access logging", "web_frontend_access_logging_enabled"),
    ("5.1", "unauthorized api", "alarm_unauthorized_api_calls"),
    ("5.2", "without mfa", "alarm_console_sign_in_without_mfa"),
    ("5.3", "root", "alarm_root_account_usage"),
    ("5.4", "iam policy", "alarm_iam_policy_changes"),
    ("5.5", "cloudtrail configuration", "alarm_cloudtrail_configuration_changes"),
    ("5.6", "authentication failures", "alarm_console_authentication_failures"),
    ("5.7", "customer created cmks", "alarm_cmk_disable_or_deletion"),
    ("5.8", "s3 bucket policy", "alarm_s3_bucket_policy_changes"),
    ("5.9", "config configuration", "alarm_config_configuration_changes"),
    ("5.10", "security group changes", "alarm_security_group_changes"),
    ("5.11", "network access control list", "alarm_nacl_changes"),
    ("5.12", "network gateways", "alarm_network_gateway_changes"),
    ("5.13", "route table", "alarm_route_table_changes"),
    ("5.14", "vpc changes", "alarm_vpc_changes"),
    ("5.15", "organizations", "alarm_organizations_changes"),
    ("6.6", "peering", "vpc_peering_routes_least_access"),
    ("6.8", "vpc endpoints", "vpc_endpoints_used_for_aws_services"),
    ("7.1.1", "least privilege", "genai_invocation_policies_least_privilege"),
    ("7.1.2", "separation", "genai_invocation_and_management_roles_separated"),
    ("7.1.3", "agent execution roles", "bedrock_agent_roles_least_privilege"),
    ("7.1.4", "service control policies", "scp_restricts_genai_models_to_approved_list"),
    ("7.2.1", "guardrail is associated", "guardrail_on_every_invocation_point"),
    ("7.2.2", "without a guardrail", "unguarded_invocation_points_monitored"),
    ("7.2.3", "independently", "guardrail_evaluation_independent_of_agent_reasoning"),
    ("7.2.5", "sensitive information", "guardrails_filter_sensitive_information"),
    ("7.2.6", "contextual grounding", "guardrails_apply_contextual_grounding"),
    ("7.3.1", "encryption at rest", "bedrock_encryption_key_management_appropriate"),
    ("7.3.2", "retention", "bedrock_data_retention_matches_sensitivity"),
    ("7.4.3", "log destinations", "bedrock_log_destinations_protected"),
]:
    A(_cid, _kw, _key)

# Section 2: identity and access management
F("2.4", "root", ["account_summary"],
  [("the account summary reports root access keys, or the key count was not collected", [],
    ["not input.account_summary.AccountAccessKeysPresent == 0"])],
  add("/account_summary/AccountAccessKeysPresent", 1))
F("2.5", "root", ["account_summary"],
  [("the root user has no MFA device and still has a password, or the summary fields were not collected", [], ["not root_mfa_ok"])],
  [add("/account_summary/AccountMFAEnabled", 0), add("/account_summary/AccountPasswordPresent", 1)])
F("2.8", "minimum length", ["password_policy"],
  [("the password policy sets no minimum length of 14 or more", [], ["not pw_min_length_ok"])],
  add("/password_policy/MinimumPasswordLength", 8))
F("2.9", "password reuse", ["password_policy"],
  [("the password policy remembers fewer than 24 passwords or none", [], ["not pw_reuse_ok"])],
  add("/password_policy/PasswordReusePrevention", 5))
F("2.10", "console password", ["credential_report"],
  [("user %s has a console password and no active MFA device", ['nm(x, "user")'],
    [each("credential_report"), "truthy(x.password_enabled)", "not truthy(object.get(x, \"mfa_active\", null))"]),
   ("user %s: password_enabled not collected", ['nm(x, "user")'],
    [each("credential_report"), 'not has_str(x, "password_enabled")'])],
  add("/credential_report/1/mfa_active", "false"))
F("2.11", "unused for 45 days", ["credential_report"],
  [("user %s has a console password unused for %d days (limit 45)", ['nm(x, "user")', "pw_idle_days(x)"],
    [each("credential_report"), 'x.user != "<root_account>"', "truthy(x.password_enabled)", "pw_idle_days(x) >= 45"]),
   ("user %s: password usage timestamps not collected", ['nm(x, "user")'],
    [each("credential_report"), 'x.user != "<root_account>"', "truthy(x.password_enabled)", "not pw_idle_days(x)"]),
   ("user %s has active access key %s unused for %d days (limit 45)", ['nm(x, "user")', "n", "key_idle_days(x, n)"],
    [each("credential_report"), 'x.user != "<root_account>"', 'some n in ["1", "2"]', "key_active(x, n)", "key_idle_days(x, n) >= 45"]),
   ("user %s: access key %s usage timestamps not collected", ['nm(x, "user")', "n"],
    [each("credential_report"), 'x.user != "<root_account>"', 'some n in ["1", "2"]', "key_active(x, n)", "not key_idle_days(x, n)"]),
   ("user %s: access key %s state not collected", ['nm(x, "user")', "n"],
    [each("credential_report"), 'x.user != "<root_account>"', 'some n in ["1", "2"]', 'not has_str(x, sprintf("access_key_%s_active", [n]))'])],
  add("/credential_report/1/password_last_used", "2026-01-01T00:00:00+00:00"))
F("2.12", "rotated every 90 days", ["credential_report"],
  [("user %s has active access key %s last rotated %d days ago (limit 90)", ['nm(x, "user")', "n", "key_rotation_days(x, n)"],
    [each("credential_report"), 'some n in ["1", "2"]', "key_active(x, n)", "key_rotation_days(x, n) > 90"]),
   ("user %s: access key %s rotation date not collected", ['nm(x, "user")', "n"],
    [each("credential_report"), 'some n in ["1", "2"]', "key_active(x, n)", "not key_rotation_days(x, n)"]),
   ("user %s: access key %s state not collected", ['nm(x, "user")', "n"],
    [each("credential_report"), 'some n in ["1", "2"]', 'not has_str(x, sprintf("access_key_%s_active", [n]))'])],
  add("/credential_report/1/access_key_1_last_rotated", "2026-01-01T00:00:00+00:00"))
F("2.13", "groups", ["iam_users"],
  [("user %s has %d directly attached managed policies", ['nm(x, "UserName")', "count(x.attached_policies)"],
    [each("iam_users"), "count(x.attached_policies) > 0"]),
   ("user %s has %d inline policies", ['nm(x, "UserName")', "count(x.inline_policies)"],
    [each("iam_users"), "count(x.inline_policies) > 0"]),
   ("user %s: attached or inline policy lists not collected", ['nm(x, "UserName")'],
    [each("iam_users"), 'not has_list(x, "attached_policies")']),
   ("user %s: attached or inline policy lists not collected", ['nm(x, "UserName")'],
    [each("iam_users"), 'not has_list(x, "inline_policies")'])],
  add("/iam_users/0/attached_policies/-", {"PolicyName": "Direct"}))
F("2.14", "administrative privileges", ["iam_policies"],
  [("attached policy %s has an Allow statement with Action * on Resource *", ['nm(x, "PolicyName")'],
    [each("iam_policies"), 'object.get(x, "AttachmentCount", 1) > 0', "admin_policy(x)"]),
   ("policy %s: default version document not collected", ['nm(x, "PolicyName")'],
    [each("iam_policies"), "not policy_doc_ok(x)"])],
  add("/iam_policies/0/DefaultVersionDocument/Statement/-", {"Effect": "Allow", "Action": "*", "Resource": "*"}))
F("2.15", "support role", ["support_policy_entities"],
  [("no IAM role is attached to the AWSSupportAccess policy, or the role list was not collected", [], ["not support_role_attached"])],
  add("/support_policy_entities/PolicyRoles", []))
F("2.16", "instance roles", ["ec2_instances", "iam_instance_profiles"],
  [("instance %s has no instance profile", ['nm(x, "InstanceId")'],
    [each("ec2_instances"), "live(x)", 'not has_str(object.get(x, "IamInstanceProfile", {}), "Arn")']),
   ("instance %s uses profile %s that holds no role", ['nm(x, "InstanceId")', "a"],
    [each("ec2_instances"), "live(x)", "a := x.IamInstanceProfile.Arn", "not profile_has_role(a)"])],
  rm("/ec2_instances/0/IamInstanceProfile"))
F("2.17", "expired", ["iam_server_certificates"],
  [("IAM server certificate %s expired at %s", ['nm(x, "ServerCertificateName")', "x.Expiration"],
    [each("iam_server_certificates"), "time.parse_rfc3339_ns(x.Expiration) < now_ns"]),
   ("IAM server certificate %s: expiration not collected", ['nm(x, "ServerCertificateName")'],
    [each("iam_server_certificates"), "not age_days(object.get(x, \"Expiration\", null))"])],
  add("/iam_server_certificates/0/Expiration", "2020-01-01T00:00:00Z"))
F("2.18", "external access analyzer", ["regions", "access_analyzers"],
  [("no regions were collected, so analyzer coverage cannot be judged", [], ["count(input.regions) == 0"]),
   ("region %s has no ACTIVE account or organization access analyzer", ["r"],
    ["some r in region_names", "not region_has_active_analyzer(r)"])],
  add("/access_analyzers/0/status", "FAILED"))

# Section 3: storage
F("3.1.1", "deny http", ["s3_buckets"],
  [("bucket %s has no bucket policy that denies plain-HTTP requests", ['nm(x, "Name")'],
    [each("s3_buckets"), "not bucket_denies_http(x)"])],
  add("/s3_buckets/0/policy/Statement/0/Condition/Bool/aws:SecureTransport", "true"))
F("3.1.4", "block public access", ["s3_buckets"],
  [("bucket %s has no complete Block Public Access setting and the account setting is not complete either", ['nm(x, "Name")'],
    [each("s3_buckets"), 'not all_four_blocked(object.get(x, "public_access_block", null))', "not account_bpa_ok"])],
  add("/s3_buckets/0/public_access_block/BlockPublicAcls", False))
F("3.2.1", "encryption-at-rest", ["rds_instances"],
  [("RDS instance %s: storage encryption is off or not reported", ['nm(x, "DBInstanceIdentifier")'],
    [each("rds_instances"), "not is_true(object.get(x, \"StorageEncrypted\", null))"])],
  add("/rds_instances/0/StorageEncrypted", False))
F("3.2.2", "auto minor version", ["rds_instances"],
  [("RDS instance %s: automatic minor version upgrade is off or not reported", ['nm(x, "DBInstanceIdentifier")'],
    [each("rds_instances"), "not is_true(object.get(x, \"AutoMinorVersionUpgrade\", null))"])],
  add("/rds_instances/0/AutoMinorVersionUpgrade", False))
F("3.2.3", "publicly accessible", ["rds_instances"],
  [("RDS instance %s is publicly accessible or its flag was not reported", ['nm(x, "DBInstanceIdentifier")'],
    [each("rds_instances"), "not is_false(object.get(x, \"PubliclyAccessible\", null))"])],
  add("/rds_instances/0/PubliclyAccessible", True))
F("3.3.1", "efs", ["efs_file_systems"],
  [("EFS file system %s: encryption is off or not reported", ['nm(x, "FileSystemId")'],
    [each("efs_file_systems"), "not is_true(object.get(x, \"Encrypted\", null))"])],
  add("/efs_file_systems/0/Encrypted", False))

# Section 4: logging
F("4.2", "log file validation", ["cloudtrail_trails"],
  [("no trail was collected, so no log file is validated", [], ["count(input.cloudtrail_trails) == 0"]),
   ("trail %s has log file validation off or not reported", ['nm(x, "Name")'],
    [each("cloudtrail_trails"), "not is_true(object.get(x, \"LogFileValidationEnabled\", null))"])],
  add("/cloudtrail_trails/0/LogFileValidationEnabled", False))
F("4.3", "aws config", ["regions", "config_recorders", "config_recorder_status"],
  [("no regions were collected, so Config coverage cannot be judged", [], ["count(input.regions) == 0"]),
   ("region %s has no AWS Config recorder", ["r"], ["some r in region_names", "not region_has_recorder(r)"]),
   ("recorder %s in %s does not record all supported resource types", ['nm(x, "name")', "region_of(x)"],
    [each("config_recorders"), "not x.recordingGroup.allSupported == true"]),
   ("no recorder includes global resource types", [], ["not any_global_recorder"]),
   ("recorder %s in %s is not recording successfully, or its status was not collected", ['nm(x, "name")', "region_of(x)"],
    [each("config_recorders"), "not recorder_ok(x)"])],
  add("/config_recorders/0/recordingGroup/allSupported", False))
F("4.5", "encrypted at rest", ["cloudtrail_trails"],
  [("no trail was collected, so no trail log is encrypted with a KMS key", [], ["count(input.cloudtrail_trails) == 0"]),
   ("trail %s has no KMS key for log encryption", ['nm(x, "Name")'], [each("cloudtrail_trails"), "not nonempty(object.get(x, \"KmsKeyId\", null))"])],
  add("/cloudtrail_trails/0/KmsKeyId", ""))
F("4.6", "rotation", ["kms_keys"],
  [("customer symmetric key %s has rotation off or not reported", ['nm(x, "KeyId")'],
    [each("kms_keys"), 'x.KeySpec == "SYMMETRIC_DEFAULT"', 'object.get(x, "KeyManager", "") != "AWS"', "not is_true(object.get(x, \"KeyRotationEnabled\", null))"]),
   ("key %s: key spec not collected", ['nm(x, "KeyId")'], [each("kms_keys"), 'not has_str(x, "KeySpec")'])],
  add("/kms_keys/0/KeyRotationEnabled", False))
F("4.7", "flow logging", ["vpcs", "flow_logs"],
  [("VPC %s has no ACTIVE flow log", ['nm(x, "VpcId")'], [each("vpcs"), "not vpc_has_flow_log(x)"])],
  add("/flow_logs/0/FlowLogStatus", "INACTIVE"))
for _cid, _kw, _dir in [("4.8", "write events", "write"), ("4.9", "read events", "read")]:
    F(_cid, _kw, ["cloudtrail_trails"],
      [("no trail was collected, so no S3 object-level events are recorded", [], ["count(input.cloudtrail_trails) == 0"]),
       ("trail %s is not a multi-region trail", ['nm(x, "Name")'], [each("cloudtrail_trails"), "not is_true(object.get(x, \"IsMultiRegionTrail\", null))"]),
       (f"trail %s does not log every S3 object {_dir} event", ['nm(x, "Name")'],
        [each("cloudtrail_trails"), "trail_selectors_collected(x)", f'not trail_logs_s3(x, "{_dir}")']),
       ("trail %s: event selectors not collected", ['nm(x, "Name")'],
        [each("cloudtrail_trails"), "not trail_selectors_collected(x)"])],
      add("/cloudtrail_trails/0/event_selectors", {"AdvancedEventSelectors": []}))
F("5.16", "security hub", ["regions", "securityhub_hubs"],
  [("no regions were collected, so Security Hub coverage cannot be judged", [], ["count(input.regions) == 0"]),
   ("region %s has no Security Hub subscription", ["r"], ["some r in region_names", "not region_has_hub(r)"])],
  add("/securityhub_hubs", []))

# Section 6: networking
F("6.1.1", "ebs volume encryption", ["regions", "ebs_encryption_by_default"],
  [("no regions were collected, so EBS coverage cannot be judged", [], ["count(input.regions) == 0"]),
   ("region %s does not encrypt new EBS volumes by default", ["r"], ["some r in region_names", "not region_ebs_encrypted(r)"])],
  add("/ebs_encryption_by_default/0/EbsEncryptionByDefault", False))
_BAD = {"IpProtocol": "tcp", "FromPort": 1, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
_SG_UNCOLLECTED = ("security group %s has a rule without a protocol or port range", ['nm(x, "GroupId")'],
                   [each("security_groups"), "some perm in x.IpPermissions", "not perm_collected(perm)"])
_SG_NOLIST = ("security group %s: IpPermissions not collected", ['nm(x, "GroupId")'],
              [each("security_groups"), 'not has_list(x, "IpPermissions")'])
F("6.1.2", "cifs", ["security_groups"],
  [("security group %s allows 0.0.0.0/0 to port 445", ['nm(x, "GroupId")'],
    [each("security_groups"), "some perm in x.IpPermissions", "perm_collected(perm)", "perm_covers(perm, 445)", "perm_open_v4(perm)"]),
   ("security group %s allows ::/0 to port 445", ['nm(x, "GroupId")'],
    [each("security_groups"), "some perm in x.IpPermissions", "perm_collected(perm)", "perm_covers(perm, 445)", "perm_open_v6(perm)"]),
   _SG_UNCOLLECTED, _SG_NOLIST],
  add("/security_groups/0/IpPermissions/-", _BAD))
F("6.2", "network acls", ["network_acls"],
  [("network ACL %s allows 0.0.0.0/0 to port %d (rules %v)", ['nm(x, "NetworkAclId")', "port", "sort(nacl_exposed(x, port))"],
    [each("network_acls"), "some port in admin_ports", "count(nacl_exposed(x, port)) > 0"]),
   ("network ACL %s has an entry without rule number, action, protocol or direction", ['nm(x, "NetworkAclId")'],
    [each("network_acls"), "some e in x.Entries", "not nacl_entry_collected(e)"]),
   ("network ACL %s: Entries not collected", ['nm(x, "NetworkAclId")'], [each("network_acls"), 'not has_list(x, "Entries")'])],
  add("/network_acls/0/Entries/-", {"RuleNumber": 50, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}))
F("6.3", "0.0.0.0/0 to remote", ["security_groups"],
  [("security group %s allows 0.0.0.0/0 to administration port %d", ['nm(x, "GroupId")', "port"],
    [each("security_groups"), "some perm in x.IpPermissions", "perm_collected(perm)", "perm_tcp_udp_all(perm)", "some port in admin_ports",
     "perm_covers(perm, port)", "perm_open_v4(perm)"]), _SG_UNCOLLECTED, _SG_NOLIST],
  add("/security_groups/0/IpPermissions/-", _BAD))
F("6.4", "::/0 to remote", ["security_groups"],
  [("security group %s allows ::/0 to administration port %d", ['nm(x, "GroupId")', "port"],
    [each("security_groups"), "some perm in x.IpPermissions", "perm_collected(perm)", "some port in admin_ports",
     "perm_covers(perm, port)", "perm_open_v6(perm)"]), _SG_UNCOLLECTED, _SG_NOLIST],
  add("/security_groups/0/IpPermissions/-", _BAD))
F("6.5", "default security group", ["security_groups"],
  [("default security group %s has inbound rules", ['nm(x, "GroupId")'],
    [each("security_groups"), 'x.GroupName == "default"', "count(x.IpPermissions) > 0"]),
   ("default security group %s has outbound rules", ['nm(x, "GroupId")'],
    [each("security_groups"), 'x.GroupName == "default"', "count(x.IpPermissionsEgress) > 0"]),
   ("default security group %s: rule lists not collected", ['nm(x, "GroupId")'],
    [each("security_groups"), 'x.GroupName == "default"', 'not has_list(x, "IpPermissions")']),
   ("default security group %s: rule lists not collected", ['nm(x, "GroupId")'],
    [each("security_groups"), 'x.GroupName == "default"', 'not has_list(x, "IpPermissionsEgress")']),
   ("security group %s: group name not collected, so default groups cannot be told apart", ['nm(x, "GroupId")'],
    [each("security_groups"), 'not has_str(x, "GroupName")'])],
  add("/security_groups/1/IpPermissions/-", _BAD))
F("6.7", "imdsv2", ["ec2_instances"],
  [("instance %s does not require IMDSv2 (HttpTokens %s, State %s)",
    ['nm(x, "InstanceId")', 'imds_field(x, "HttpTokens")', 'imds_field(x, "State")'],
    [each("ec2_instances"), "live(x)", "not imds_v2(x)"])],
  add("/ec2_instances/0/MetadataOptions/HttpTokens", "optional"))

# Section 7: generative AI (Amazon Bedrock)
F("7.1.5", "trust policies", ["iam_roles"],
  [("role %s: a Bedrock trust statement lacks aws:SourceAccount for the owning account", ['nm(x, "RoleName")'],
    [each("iam_roles"), 'not startswith(object.get(x, "Path", ""), "/aws-service-role/")', "role_doc_ok(x)",
     "some s in statements(x.AssumeRolePolicyDocument)", "bedrock_trust_stmt(s)", "not source_account_ok(x, s)"]),
   ("role %s: a Bedrock trust statement lacks an aws:SourceArn pinned to a Bedrock resource type in the owning account", ['nm(x, "RoleName")'],
    [each("iam_roles"), 'not startswith(object.get(x, "Path", ""), "/aws-service-role/")', "role_doc_ok(x)",
     "some s in statements(x.AssumeRolePolicyDocument)", "bedrock_trust_stmt(s)", "not source_arn_ok(x, s)"]),
   ("role %s: trust policy or ARN not collected", ['nm(x, "RoleName")'],
    [each("iam_roles"), 'not startswith(object.get(x, "Path", ""), "/aws-service-role/")', "not role_doc_ok(x)"])],
  rm("/iam_roles/0/AssumeRolePolicyDocument/Statement/0/Condition/StringEquals"))
F("7.1.6", "long-term api keys", ["bedrock_api_keys"],
  [("Bedrock API key of %s is Active with no expiration date", ['nm(x, "UserName")'],
    [each("bedrock_api_keys"), 'lower(object.get(x, "Status", "")) == "active"', "not nonempty(object.get(x, \"ExpirationDate\", null))"]),
   ("Bedrock API key of %s is Active and %d days old (limit 90)", ['nm(x, "UserName")', "age_days(x.CreateDate)"],
    [each("bedrock_api_keys"), 'lower(object.get(x, "Status", "")) == "active"', "age_days(x.CreateDate) > 90"]),
   ("Bedrock API key of %s: status or creation date not collected", ['nm(x, "UserName")'],
    [each("bedrock_api_keys"), 'not has_str(x, "Status")']),
   ("Bedrock API key of %s: status or creation date not collected", ['nm(x, "UserName")'],
    [each("bedrock_api_keys"), 'lower(object.get(x, "Status", "")) == "active"', "not age_days(object.get(x, \"CreateDate\", null))"])],
  add("/bedrock_api_keys/0/CreateDate", "2026-01-01T00:00:00Z"))
F("7.2.4", "content and prompt-attack filters", ["bedrock_guardrails"],
  [("guardrail %s has no content policy filters", ['nm(x, "name")'], [each("bedrock_guardrails"), "not has_filters(x)"]),
   ("guardrail %s leaves %s unfiltered on input or output", ['nm(x, "name")', "f.type"],
    [each("bedrock_guardrails"), "some f in x.contentPolicy.filters", "upper(f.type) in harmful_types",
     "not strength_on(object.get(f, \"inputStrength\", null))"]),
   ("guardrail %s leaves %s unfiltered on input or output", ['nm(x, "name")', "f.type"],
    [each("bedrock_guardrails"), "some f in x.contentPolicy.filters", "upper(f.type) in harmful_types",
     "not strength_on(object.get(f, \"outputStrength\", null))"]),
   ("guardrail %s has no prompt-attack filter with an input strength", ['nm(x, "name")'],
    [each("bedrock_guardrails"), "not prompt_attack_ok(x)"]),
   ("guardrail %s has an empty blocked-input or blocked-output message", ['nm(x, "name")'],
    [each("bedrock_guardrails"), "not nonempty(object.get(x, \"blockedInputMessaging\", null))"]),
   ("guardrail %s has an empty blocked-input or blocked-output message", ['nm(x, "name")'],
    [each("bedrock_guardrails"), "not nonempty(object.get(x, \"blockedOutputsMessaging\", null))"])],
  add("/bedrock_guardrails/0/contentPolicy/filters/1/inputStrength", "NONE"))
F("7.4.1", "data-plane events", ["cloudtrail_trails", "bedrock_regions", "bedrock_resource_types_in_use"],
  [("no actively logging trail covers region %s with advanced selectors for every Bedrock resource type in use", ["r"],
    ["some r in bedrock_regions", "not region_has_bedrock_trail(r)"])],
  add("/bedrock_resource_types_in_use/-", "AWS::Bedrock::KnowledgeBase"))
F("7.4.2", "model invocation logging", ["bedrock_regions", "bedrock_invocation_logging", "bedrock_modalities_in_use"],
  [("region %s: model invocation logging is off or its configuration was not collected", ["r"],
    ["some r in bedrock_regions", "count(logging_cfgs(r)) == 0"]),
   ("region %s: invocation logging has no usable destination", ["r"],
    ["some r in bedrock_regions", "some c in logging_cfgs(r)", "not logging_destination_ok(c)"]),
   ("region %s: invocation logging does not deliver the %s modality the workload processes", ["r", "m"],
    ["some r in bedrock_regions", "some c in logging_cfgs(r)", "some m0 in input.bedrock_modalities_in_use", "m := lower(m0)",
     "not modality_on(c, m)"])],
  add("/bedrock_invocation_logging/0/loggingConfig/textDataDeliveryEnabled", False))
F("7.4.4", "knowledge base ingestion", ["bedrock_knowledge_bases", "log_delivery_sources", "log_deliveries"],
  [("knowledge base %s has no APPLICATION_LOGS delivery source paired with a delivery that has a destination",
    ['nm(x, "knowledgeBaseId")'], [each("bedrock_knowledge_bases"), "not kb_logging_ok(x)"])],
  add("/log_deliveries/0/deliveryDestinationArn", ""))
F("7.5.1", "interface vpc endpoints", ["bedrock_endpoint_requirements", "vpc_endpoints"],
  [("no available interface endpoint for %s in %s", ["q.service_name", "q.vpc_id"],
    [each("bedrock_endpoint_requirements", "q"), "count(req_endpoints(q)) == 0"]),
   ("endpoint %s carries the default full-access policy, or its policy was not collected", ['nm(e, "VpcEndpointId")'],
    [each("bedrock_endpoint_requirements", "q"), "some e in req_endpoints(q)", "not endpoint_policy_restricted(e)"]),
   ("endpoint %s has private DNS off and callers are not recorded as using the endpoint-specific name", ['nm(e, "VpcEndpointId")'],
    [each("bedrock_endpoint_requirements", "q"), "some e in req_endpoints(q)", "not is_true(object.get(e, \"PrivateDnsEnabled\", null))",
     'not attested("bedrock_endpoint_specific_dns_used")'])],
  add("/vpc_endpoints/0/PrivateDnsEnabled", False))
F("7.5.2", "private vpc", ["bedrock_jobs", "subnets", "route_tables"],
  [("Bedrock job %s has no VPC configuration with subnets and security groups", ['nm(x, "jobArn")'],
    [each("bedrock_jobs"), "not job_vpc_ok(x)"]),
   ("subnet %s of job %s: route table not collected", ["s", 'nm(x, "jobArn")'],
    [each("bedrock_jobs"), "some s in x.vpcConfig.subnetIds", "count(subnet_tables(s)) == 0"]),
   ("subnet %s of job %s has a default route to an internet or NAT gateway", ["s", 'nm(x, "jobArn")'],
    [each("bedrock_jobs"), "some s in x.vpcConfig.subnetIds", "some t in subnet_tables(s)", "default_route_out(t)"])],
  add("/route_tables/0/Routes/-", {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}))
F("7.5.3", "vector stores", ["bedrock_knowledge_bases", "opensearch_serverless_collections", "opensearch_serverless_network_policies"],
  [("knowledge base %s: storage type not collected", ['nm(x, "knowledgeBaseId")'],
    [each("bedrock_knowledge_bases"), 'not has_str(object.get(x, "storageConfiguration", {}), "type")']),
   ("knowledge base %s uses store type %s; its private-endpoint check is not recorded as attested", ['nm(x, "knowledgeBaseId")', "x.storageConfiguration.type"],
    [each("bedrock_knowledge_bases"), 'x.storageConfiguration.type != "OPENSEARCH_SERVERLESS"', 'not attested("bedrock_other_vector_stores_private")']),
   ("knowledge base %s: backing collection could not be resolved", ['nm(x, "knowledgeBaseId")'],
    [each("bedrock_knowledge_bases"), 'x.storageConfiguration.type == "OPENSEARCH_SERVERLESS"', "not kb_collection_name(x)"]),
   ("collection %s has a network rule that allows public access", ["n"],
    [each("bedrock_knowledge_bases"), "n := kb_collection_name(x)", "some rule in matching_rules(n)", "is_true(rule.AllowFromPublic)"]),
   ("collection %s has no network rule that is private and lists bedrock.amazonaws.com", ["n"],
    [each("bedrock_knowledge_bases"), "n := kb_collection_name(x)", "not private_bedrock_rule(n)"])],
  add("/opensearch_serverless_network_policies/0/policy/0/AllowFromPublic", True))
F("7.5.4", "marketplace", ["bedrock_marketplace_endpoints"],
  [("endpoint %s: backing models not collected", ['nm(x, "endpointArn")'],
    [each("bedrock_marketplace_endpoints"), 'not has_list(x, "models")']),
   ("endpoint %s: no backing model was collected", ['nm(x, "endpointArn")'],
    [each("bedrock_marketplace_endpoints"), "count(x.models) == 0"]),
   ("endpoint %s: model %s does not enable network isolation", ['nm(x, "endpointArn")', 'nm(m, "ModelName")'],
    [each("bedrock_marketplace_endpoints"), "some m in x.models", "not is_true(object.get(m, \"EnableNetworkIsolation\", null))"]),
   ("endpoint %s: model %s has no VPC configuration with subnets and security groups", ['nm(x, "endpointArn")', 'nm(m, "ModelName")'],
    [each("bedrock_marketplace_endpoints"), "some m in x.models", "not model_vpc_ok(m)"])],
  add("/bedrock_marketplace_endpoints/0/models/0/EnableNetworkIsolation", False))

GREEN["attest"] = {c["attest"]: True for c in C if c["kind"] == "attest"}


# ── checks against the workbook ──────────────────────────────────────────────────────
def verify(wb):
    n_auto = sum(1 for w in wb.values() if w["assessment"] == "Automated")
    got = (len(wb), n_auto, len(wb) - n_auto)
    if got != EXPECTED:
        raise SystemExit(f"workbook has {got[0]} recommendations ({got[1]} Automated, {got[2]} Manual), expected {EXPECTED}")
    ids = [c["id"] for c in C]
    if len(ids) != len(set(ids)) or set(ids) != set(wb):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(wb) - set(ids))}; no recommendation {sorted(set(ids) - set(wb))}")
    for c in C:
        w = wb[c["id"]]
        if (w["assessment"] == "Manual") != (c["kind"] == "attest"):
            raise SystemExit(f"{c['id']}: workbook says {w['assessment']}, logic table says {c['kind']}")
        if c["kw"].lower() not in w["title"].lower():
            raise SystemExit(f"{c['id']}: logic keyword {c['kw']!r} not in the workbook title")
        if len(w["profiles"]) != 1 or w["profiles"][0] not in ("Level 1", "Level 2"):
            raise SystemExit(f"{c['id']}: unexpected profiles {w['profiles']}")
    if set(TITLE_OVERRIDE) != set(wb):
        raise SystemExit(f"title table mismatch: {sorted(set(wb) ^ set(TITLE_OVERRIDE))}")
    n1 = sum(1 for w in wb.values() if w["level"] == 1)
    if (n1, len(wb) - n1) != (49, 45):
        raise SystemExit(f"workbook profile split {n1}/{len(wb) - n1}, expected 49/45")


def title(cid, wb):
    return TITLE_OVERRIDE.get(cid) or neutralize_title(wb[cid]["title"])


def section(cid):
    return cid.split(".")[0]


SECTION_NAMES = {"2": "identity_access", "3": "storage", "4": "logging", "5": "monitoring", "6": "networking", "7": "generative_ai"}


def ev_label(c):
    return " / ".join(f"input.{k}" for k in c["ev"])


def miss_msg(c):
    return f"{c['id']}: evidence missing — {ev_label(c)} not collected"


def att_msg(c, wb):
    return f"{c['id']}: {title(c['id'], wb)} (manual review not attested: set input.attest.{c['attest']} to true)"


def emit_control(c, wb):
    cid, uu = c["id"], u(c["id"])
    w = wb[cid]
    out = [f"# {cid} ({w['assessment']}, {w['profiles'][0]})"]
    if c["kind"] == "attest":
        out += [f"_messages contains {rego_str(att_msg(c, wb))} if {{", f'\t_in_scope("{cid}")',
                f'\tnot attested("{c["attest"]}")', "}", ""]
        return "\n".join(out)
    out += [f"default _ev_{uu} := false", "", f"_ev_{uu} if {{"] + [f'\tpresent("{k}")' for k in c["ev"]] + ["}", "",
            f"_messages contains {rego_str(miss_msg(c))} if {{", f'\t_in_scope("{cid}")', f"\tnot _ev_{uu}", "}", ""]
    t = title(cid, wb).replace("%", "%%")
    for detail, args, lines in c["rules"]:
        fmt = f"{cid}: {t} — {detail}"
        head = f"sprintf({rego_str(fmt)}, [{', '.join(args)}])" if args else rego_str(fmt.replace("%%", "%"))
        out += [f"_messages contains {head} if {{", f'\t_in_scope("{cid}")', f"\t_ev_{uu}"] + [f"\t{ln}" for ln in lines] + ["}", ""]
    return "\n".join(out)


def metadata(title_text, density, checks, entrypoint):
    return f'''# METADATA
# title: "{title_text}"
# custom:
#   class: security
#   framework: cis_aws
#   source: cis
#   domains: [cloud, aws]
#   coverage:
#     checks: {checks}
#     cited: 0
#     density: {density}
#     basis: {"size" if density == "sized" else "role"}
#     tested: true
#     entrypoint: {entrypoint}
#     guard: self
#     as_of: v2.4.2
'''


CONTRACT = """#   assessment_time                  : optional RFC 3339 reference time for the age checks (default: the clock)
#   regions[]                        : aws ec2 describe-regions -> {RegionName}; the regions the account operates in
#   remote_admin_ports[]             : optional; ports treated as remote administration (default 22 and 3389)
#   account_summary                  : aws iam get-account-summary SummaryMap -> {AccountAccessKeysPresent, AccountMFAEnabled, AccountPasswordPresent}
#   password_policy                  : aws iam get-account-password-policy PasswordPolicy; {} when AWS reports NoSuchEntity (no policy set)
#   credential_report[]              : aws iam get-credential-report parsed from CSV, one object per row with the CSV column
#                                      names as keys and the CSV strings as values ("true"/"false", RFC 3339 dates, "N/A"); includes <root_account>
#   iam_users[]                      : {UserName, attached_policies[] (list-attached-user-policies), inline_policies[] (list-user-policies)}
#   iam_policies[]                   : aws iam list-policies --only-attached, each joined with DefaultVersionDocument
#                                      (get-policy-version Document)
#   support_policy_entities          : aws iam list-entities-for-policy for AWSSupportAccess -> {PolicyRoles[], PolicyUsers[], PolicyGroups[]}
#   iam_server_certificates[]        : aws iam list-server-certificates -> {ServerCertificateName, Expiration}
#   iam_roles[]                      : aws iam list-roles -> {RoleName, Path, Arn, AssumeRolePolicyDocument}
#   iam_instance_profiles[]          : aws iam list-instance-profiles -> {Arn, Roles[]}
#   access_analyzers[]               : aws accessanalyzer list-analyzers, per region -> {region, name, type, status}
#   s3_buckets[]                     : {Name, policy (get-bucket-policy document, null when none), public_access_block
#                                      (s3api get-public-access-block configuration, null when none)}
#   s3_account_public_access_block   : optional; aws s3control get-public-access-block configuration
#   rds_instances[]                  : aws rds describe-db-instances (all regions) -> {DBInstanceIdentifier, StorageEncrypted,
#                                      AutoMinorVersionUpgrade, PubliclyAccessible}
#   efs_file_systems[]               : aws efs describe-file-systems (all regions) -> {FileSystemId, Encrypted}
#   ebs_encryption_by_default[]      : aws ec2 get-ebs-encryption-by-default per region -> {region, EbsEncryptionByDefault}
#   security_groups[]                : aws ec2 describe-security-groups (all regions) -> {GroupId, GroupName, region, IpPermissions[],
#                                      IpPermissionsEgress[]}
#   network_acls[]                   : aws ec2 describe-network-acls -> {NetworkAclId, Entries[{RuleNumber, Protocol, RuleAction, Egress,
#                                      CidrBlock, PortRange{From, To}}]}
#   ec2_instances[]                  : aws ec2 describe-instances Reservations[].Instances[] (all regions) -> {InstanceId, region, State{Name},
#                                      IamInstanceProfile{Arn}, MetadataOptions{HttpTokens, State}}
#   cloudtrail_trails[]              : aws cloudtrail describe-trails trailList joined with status (get-trail-status) and
#                                      event_selectors (get-event-selectors) -> {Name, HomeRegion, IsMultiRegionTrail,
#                                      LogFileValidationEnabled, KmsKeyId, status{IsLogging}, event_selectors{EventSelectors[],
#                                      AdvancedEventSelectors[]}}
#   config_recorders[]               : aws configservice describe-configuration-recorders per region -> {region, name, recordingGroup}
#   config_recorder_status[]         : aws configservice describe-configuration-recorder-status per region -> {region, name, recording, lastStatus}
#   kms_keys[]                       : customer and AWS keys: describe-key KeyMetadata fields joined with get-key-rotation-status ->
#                                      {KeyId, region, KeySpec, KeyManager, KeyRotationEnabled}
#   vpcs[]                           : aws ec2 describe-vpcs (all regions) -> {VpcId, region}
#   flow_logs[]                      : aws ec2 describe-flow-logs (all regions) -> {ResourceId, FlowLogStatus, region}
#   securityhub_hubs[]               : aws securityhub describe-hub per region where it is enabled -> {region, HubArn, SubscribedAt}
#   bedrock_regions[]                : regions where the account operates Amazon Bedrock (empty: none)
#   bedrock_resource_types_in_use[]  : AWS::Bedrock::* resource types the account uses (empty: none)
#   bedrock_modalities_in_use[]      : text / image / embedding / video modalities the workloads process
#   bedrock_api_keys[]               : aws iam list-service-specific-credentials --all-users --service-name bedrock.amazonaws.com
#   bedrock_guardrails[]             : aws bedrock get-guardrail output per guardrail in use, plus region
#   bedrock_invocation_logging[]     : {region, loggingConfig} from get-model-invocation-logging-configuration (loggingConfig null or {} when disabled)
#   bedrock_knowledge_bases[]        : aws bedrock-agent get-knowledge-base -> {region, knowledgeBaseId, knowledgeBaseArn, storageConfiguration}
#   log_delivery_sources[]           : aws logs describe-delivery-sources -> {region, name, logType, resourceArns[]}
#   log_deliveries[]                 : aws logs describe-deliveries -> {region, deliverySourceName, deliveryDestinationType, deliveryDestinationArn}
#   opensearch_serverless_collections[] : batch-get-collection collectionDetails -> {region, id, name}
#   opensearch_serverless_network_policies[] : get-security-policy --type network securityPolicyDetail -> {region, name, policy[]}
#   bedrock_endpoint_requirements[]  : {region, vpc_id, service_name} for each VPC and Bedrock API family the workloads use
#   vpc_endpoints[]                  : aws ec2 describe-vpc-endpoints -> {VpcEndpointId, VpcId, ServiceName, VpcEndpointType, State,
#                                      PrivateDnsEnabled, PolicyDocument}
#   bedrock_jobs[]                   : batch inference, model customization and model import jobs (get-* joined) -> {region, type,
#                                      jobArn, vpcConfig{subnetIds[], securityGroupIds[]}}
#   subnets[]                        : aws ec2 describe-subnets -> {SubnetId, VpcId}
#   route_tables[]                   : aws ec2 describe-route-tables -> {RouteTableId, VpcId, Associations[{SubnetId, Main}], Routes[]}
#   bedrock_marketplace_endpoints[]  : list-marketplace-model-endpoints joined with the SageMaker models behind each endpoint ->
#                                      {region, endpointArn, models[{ModelName, EnableNetworkIsolation, VpcConfig{SecurityGroupIds[], Subnets[]}}]}
#   attest.<key>                     : attestation booleans for the Manual recommendations (see `attestations`)
#   attest.bedrock_endpoint_specific_dns_used / attest.bedrock_other_vector_stores_private : recorded decisions that excuse a
#                                      private-DNS-off endpoint (7.5.1) and a non-OpenSearch-Serverless vector store (7.5.3)
#   cis_profile.level                : 1 or 2 (default 2: every recommendation; Level 2 includes Level 1)
# Every regional resource carries the "region" the collector read it from; other fields are as the AWS CLI prints them."""


def engine(wb):
    ids = [c["id"] for c in C]
    l1 = [i for i in ids if wb[i]["level"] == 1]
    att = [c for c in C if c["kind"] == "attest"]
    n_auto = sum(1 for i in ids if wb[i]["assessment"] == "Automated")
    ev_keys = sorted({k for c in C if c["kind"] == "fact" for k in c["ev"]})
    parts = [metadata(f"{BENCH} {VERSION}", "sized", 0, "none"), "package cis_aws", "",
             f"# {BENCH} {VERSION}. Generated by tools/cis_generators/gen_aws.py from the CIS workbook: do not edit by",
             "# hand, regenerate.",
             f"# All {len(ids)} recommendations ({n_auto} Automated, {len(ids) - n_auto} Manual; {len(l1)} Level 1, {len(ids) - len(l1)} Level 2)",
             "# in six sections: 2 Identity and Access Management, 3 Storage, 4 Logging, 5 Monitoring, 6 Networking, 7 Generative AI.",
             "# Ids, profile and status come from the workbook; messages are our own words.",
             "#",
             f"# The {n_auto} Automated recommendations are decided from collected AWS inventories. Per-resource checks iterate",
             "# the collected list: an EMPTY list means no resources of that kind and passes, an ABSENT list raises",
             "# \"<id>: evidence missing — <input path> not collected\" (never a pass), and a resource that lacks the audited",
             "# property is a finding for that resource. Checks that need something to EXIST (a support role, a trail, an analyzer",
             "# in every region) fail when it is not there; \"every region\" checks fail when input.regions is empty.",
             f"# The {len(att)} Manual recommendations pass only on an explicit attestation: input.attest.<key> == true.",
             "# input.cis_profile.level selects Level 1 (1) or Level 1 + Level 2 (2, the default); out-of-profile",
             "# recommendations raise nothing.",
             "#",
             "# This package is the engine. cis_aws.main (the /v1/data/cis_aws/main/compliance_report entrypoint) and",
             "# cis_aws.l2 (the Level 2 view) read its rules.",
             "#",
             "# Input contract (one account):",
             CONTRACT, "", "import rego.v1", "",
             "default compliant := false", "", "compliant if count(violations) == 0", "",
             "# ── profile ──────────────────────────────────────────────────────────────────────────",
             "default level := 2", "", 'level := 1 if lower(sprintf("%v", [input.cis_profile.level])) in {"1", "level1", "level 1", "level_1"}', "",
             "in_scope contains id if {", "\tsome id, r in recommendations", "\tr.level <= level", "}", "",
             "_in_scope(id) if id in in_scope", ""]
    rec = {}
    for c in C:
        w = wb[c["id"]]
        rec[c["id"]] = {"section": section(c["id"]), "level": w["level"], "assessment": w["assessment"],
                        "check": "attestation" if c["kind"] == "attest" else "configuration", "title": title(c["id"], wb)}
    parts += ["# ── recommendation table (ids, profile level and status from the workbook) ─────────────",
              "recommendations := " + json.dumps(rec, indent="\t", ensure_ascii=False), "",
              "# Manual recommendations: control id -> attestation key under input.attest.",
              "attestations := " + json.dumps({c["id"]: c["attest"] for c in att}, indent="\t"), "",
              "attested(key) if input.attest[key] == true", "",
              "# ── evidence ──────────────────────────────────────────────────────────────────────────",
              "# Automated recommendation -> the inventories it reads. Object keys must be objects (an empty object is a",
              "# collected \"nothing configured\"); every other key is a list.",
              "evidence := " + json.dumps({c["id"]: c["ev"] for c in C if c["kind"] == "fact"}, indent="\t"), "",
              "_object_keys := " + json.dumps(sorted(OBJECT_KEYS)).replace("[", "{").replace("]", "}"), "",
              "present(k) if {", "\tk in _object_keys", "\tis_object(input[k])", "}", "",
              "present(k) if {", "\tnot k in _object_keys", "\tis_array(input[k])", "}", ""]
    parts.append(open(os.path.join(HERE, "aws_lib.rego.tmpl")).read())
    parts.append("# ── recommendations ───────────────────────────────────────────────────────────────────\n")
    for c in C:
        parts.append(emit_control(c, wb))
    parts.append(f'''# ── aggregate ─────────────────────────────────────────────────────────────────────────
violations := sort([v | some v in _messages])

control_id(v) := regex.find_n(`^[0-9]+(\\.[0-9]+)*`, v, 1)[0]

failing_controls := {{control_id(v) | some v in violations}}

total_controls := count(in_scope)

evidence_violations := [v | some v in violations; contains(v, ": evidence missing — ")]

# A fact that was collected with the wrong type (a string where the AWS API returns a boolean or a number).
evidence_invalid := [v | some v in violations; contains(v, " — evidence invalid — ")]

section_names := {json.dumps(SECTION_NAMES)}

# Counts are distinct recommendations, never messages: one control can fail on many resources.
compliance_summary := {{
	"benchmark": "{BENCH} {VERSION}",
	"profile_level": level,
	"total_controls": total_controls,
	"passing_controls": total_controls - count(failing_controls),
	"failing_controls": count(failing_controls),
	"sections": {{name: {{
		"total": count({{id | some id in in_scope; recommendations[id].section == sec}}),
		"failed": count({{id | some id in failing_controls; recommendations[id].section == sec}}),
		"violations": [v | some v in violations; startswith(v, concat("", [sec, "."]))],
	}} |
		some sec, name in section_names
	}},
}}
''')
    for k in ev_keys:
        assert f"#   {k}" in CONTRACT, k
    return "\n".join(parts)


def main_module(wb):
    return metadata(f"{BENCH} {VERSION}", "orchestrator", 1, "compliance_report") + f'''package cis_aws.main

import rego.v1

import data.cis_aws as bench

# {BENCH} {VERSION}
#
# Entry point for the cis_aws framework key. The {len(C)} recommendations are evaluated in
# cis_aws_foundations.rego (package cis_aws, which also documents the input contract); this module
# republishes them in the framework-key compliance_report shape. Generated by tools/cis_generators/gen_aws.py.
#
# total_controls is the number of recommendations in the selected profile (input.cis_profile.level:
# 1 => Level 1 only, otherwise Level 1 + Level 2). failed_controls counts distinct failing recommendations.
#
# OPA endpoint: POST http://<host>:8181/v1/data/cis_aws/main/compliance_report

default compliant := false

compliant if {{
	_facts_supplied
	count(violations) == 0
}}

violations contains v if some v in bench.violations

# Optional identity fields are read through defaulted helpers: an undefined field inside the object
# literal would make the whole report undefined (library rule #5).
default _entity_name := ""

_entity_name := input.entity_name

default _account_id := ""

_account_id := input.account_id

default _assessed_at := ""

_assessed_at := input.assessment_date

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# An input that carries no facts (only the profile selector or identity fields) is reported as fully
# non-compliant with an explicit violation, never as a pass. The engine also fails every recommendation
# whose evidence is missing, so a partial input cannot pass the controls it does not cover.
# ---------------------------------------------------------------------------
_non_fact_keys := {{"cis_profile", "entity_name", "assessment_date", "assessment_time", "account_id"}}

default _facts_supplied := false

_facts_supplied if count({{k | some k, _ in input; not k in _non_fact_keys}}) > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_aws"],
)

default _total_controls := {len(C)}

_total_controls := bench.total_controls

_bench_violations := sort([v | some v in violations])

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := _bench_violations if _facts_supplied

_failed := _total_controls if not _facts_supplied

_failed := min([_total_controls, count(bench.failing_controls)]) if _facts_supplied

_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

_level_ids(l) := {{id | some id in bench.in_scope; bench.recommendations[id].level == l}}

_level_failed(l) := count(_level_ids(l)) if not _facts_supplied

_level_failed(l) := count(_level_ids(l) & bench.failing_controls) if _facts_supplied

_section(s) := [v | some v in _violations; startswith(v, concat("", [s, "."]))]

compliance_report := {{
	"framework": "cis_aws",
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"profile": sprintf("level%d", [bench.level]),
	"entity_name": _entity_name,
	"account_id": _account_id,
	"assessed_at": _assessed_at,
	"compliant": compliant,
	"total_controls": _total_controls,
	"standard_total": {len(C)},
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"level_1": {{"total": count(_level_ids(1)), "failed": _level_failed(1)}},
	"level_2": {{"total": count(_level_ids(2)), "failed": _level_failed(2)}},
	"violations": _violations,
	"violation_count": count(_violations),
	"evidence_missing_count": count(bench.evidence_violations),
	"evidence_invalid_count": count(bench.evidence_invalid),
	"section_results": {{
		"identity_access": _section("2"),
		"storage": _section("3"),
		"logging": _section("4"),
		"monitoring": _section("5"),
		"networking": _section("6"),
		"generative_ai": _section("7"),
	}},
}}
'''


def l2_module(wb):
    n2 = sum(1 for c in C if wb[c["id"]]["level"] == 2)
    return metadata(f"{BENCH} {VERSION} - Level 2 Additional Controls", "section", 1, "compliance_report") + f'''package cis_aws.l2

# {BENCH} {VERSION} - Level 2 additional recommendations.
# The {n2} recommendations the workbook assigns to the Level 2 profile (Level 2 extends Level 1; cis_aws.main
# reports both). Each is evaluated once, in cis_aws_foundations.rego; this module selects the Level 2 subset
# and reports it as "CIS L2 <id>: ...". Generated by tools/cis_generators/gen_aws.py.

import rego.v1

import data.cis_aws as bench

default compliant := false

compliant if {{
	count(object.keys(input)) > 0
	count(violations) == 0
}}

l2_ids := {{id | some id, r in bench.recommendations; r.level == 2}}

control_id(v) := regex.find_n(`^[0-9]+(\\.[0-9]+)*`, v, 1)[0]

violations contains sprintf("CIS L2 %s", [v]) if {{
	some v in bench.violations
	control_id(v) in l2_ids
}}

failing_l2_controls := {{id | some v in bench.violations; id := control_id(v); id in l2_ids}}

compliance_report := {{
	"profile": "level2",
	"benchmark": "{BENCH} {VERSION}",
	"l2_controls": count(l2_ids),
	"l2_violations": count(failing_l2_controls),
	"l2_compliant": compliant,
	"l2_violation_list": sort([v | some v in violations]),
	"note": "Level 2 recommendations supplement Level 1. With input.cis_profile.level 1 the engine leaves them out and this view is empty.",
}}
'''




TEST_HEAD = '''package {pkg}

import rego.v1

import data.cis_aws as b

# {what} Generated by tools/cis_generators/gen_aws.py; regenerate, do not edit.

green := {green}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}
'''


def j(x):
    return json.dumps(x, ensure_ascii=False)


def control_tests(wb):
    out = [TEST_HEAD.format(pkg="cis_aws.v7_controls_test", green=json.dumps(GREEN, indent="\t", ensure_ascii=False),
                            what=f"Per-recommendation tests for {BENCH} {VERSION}: every recommendation has a pass test (green input) "
                                 "and a fail test; Automated recommendations also have an evidence-missing test; attestations fail "
                                 "when false or absent."),
           "test_green_input_is_compliant if {\n\tvs := b.violations with input as green\n\tcount(vs) == 0\n}\n"]
    for c in C:
        cid, uu = c["id"], u(c["id"])
        out.append(f'test_{uu}_pass if {{\n\tvs := b.violations with input as green\n\tnot _has_id(vs, "{cid}")\n}}\n')
        if c["kind"] == "attest":
            m = rego_str(att_msg(c, wb))
            key = c["attest"]
            out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {j([add('/attest/' + key, False)])})\n"
                       f"\tvs := b.violations with input as inp\n\t{m} in vs\n}}\n")
            out.append(f"test_{uu}_not_attested_when_absent if {{\n\tinp := json.patch(green, {j([rm('/attest/' + key)])})\n"
                       f"\tvs := b.violations with input as inp\n\t{m} in vs\n}}\n")
            continue
        mm = rego_str(miss_msg(c))
        out.append(f"test_{uu}_fail if {{\n\tinp := json.patch(green, {j(c['fail'])})\n\tvs := b.violations with input as inp\n"
                   f'\t_has_id(vs, "{cid}")\n\tnot {mm} in vs\n}}\n')
        out.append(f"test_{uu}_evidence_missing if {{\n\tinp := json.patch(green, {j(c['miss'])})\n"
                   f"\tvs := b.violations with input as inp\n\t{mm} in vs\n}}\n")
    return "\n".join(out)


def report_tests(wb):
    n1 = sum(1 for c in C if wb[c["id"]]["level"] == 1)
    n2 = len(C) - n1
    na = sum(1 for c in C if wb[c["id"]]["assessment"] == "Automated")
    return TEST_HEAD.format(pkg="cis_aws.main_test", green="data.cis_aws.v7_controls_test.green",
                            what="Report and profile tests (framework-key contract, fail-closed, Level 1 / Level 2).") + f'''
test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == {len(C)}
	count([id | some id, r in b.recommendations; r.level == 1]) == {n1}
	count([id | some id, r in b.recommendations; r.level == 2]) == {n2}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {na}
	count(b.attestations) == {len(C) - na}
}}

test_empty_input_level_2_default if {{
	r := data.cis_aws.main.compliance_report with input as {{}}
	r.compliant == false
	r.total_controls == {len(C)}
	r.failed_controls == {len(C)}
	r.passed_controls == 0
	r.compliance_percentage == 0
	r.violation_count == count(r.violations)
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied")
}}

test_empty_input_level_1 if {{
	r := data.cis_aws.main.compliance_report with input as {{"cis_profile": {{"level": 1}}}}
	r.compliant == false
	r.profile == "level1"
	r.total_controls == {n1}
	r.failed_controls == {n1}
	r.level_2.total == 0
}}

test_profile_only_input_is_fail_closed if {{
	r := data.cis_aws.main.compliance_report with input as {{"cis_profile": {{"level": 2}}, "account_id": "x"}}
	r.compliant == false
	r.failed_controls == r.total_controls
}}

test_every_recommendation_fails_on_empty_input if {{
	vs := b.violations with input as {{}}
	every id, _ in b.recommendations {{ _has_id(vs, id) }}
}}

test_green_report_compliant if {{
	r := data.cis_aws.main.compliance_report with input as green
	r.compliant == true
	r.failed_controls == 0
	r.passed_controls == {len(C)}
	r.compliance_percentage == 100
	r.level_1.total == {n1}
	r.level_2.total == {n2}
}}

test_level_1_ignores_level_2_findings if {{
	inp := json.patch(green, [
		{{"op": "add", "path": "/cis_profile", "value": {{"level": 1}}}},
		{{"op": "add", "path": "/security_groups/1/IpPermissions/-", "value": {{"IpProtocol": "tcp", "FromPort": 445, "ToPort": 445, "IpRanges": [{{"CidrIp": "0.0.0.0/0"}}], "Ipv6Ranges": []}}}},
	])
	vs := b.violations with input as inp
	not _has_id(vs, "6.5")
	_has_id(vs, "6.1.2")
	r := data.cis_aws.main.compliance_report with input as inp
	r.total_controls == {n1}
	r.failed_controls == 1
}}

'''



def l2_tests(wb):
    n2 = sum(1 for c in C if wb[c["id"]]["level"] == 2)
    return TEST_HEAD.format(pkg="cis_aws.l2_test", green="data.cis_aws.v7_controls_test.green",
                            what="Level 2 view tests.") + """
test_l2_view if {
	r := data.cis_aws.l2.compliance_report with input as {}
	r.l2_controls == {n2}
	r.l2_violations == {n2}
	r.l2_controls == count([id | some id, x in b.recommendations; x.level == 2])
	r.l2_compliant == false
	g := data.cis_aws.l2.compliance_report with input as green
	g.l2_compliant == true
	lvl1 := data.cis_aws.l2.compliance_report with input as object.union(green, {"cis_profile": {"level": 1}})
	lvl1.l2_violations == 0
}
""".replace("{n2}", str(n2))



def _case(name, patch, hit=(), clear=()):
    lines = [f"test_{name} if {{", f"\tinp := json.patch(green, {j(patch)})", "\tvs := b.violations with input as inp"]
    lines += [f'\t_has_id(vs, "{i}")' for i in hit] + [f'\tnot _has_id(vs, "{i}")' for i in clear] + ["}", ""]
    return "\n".join(lines)


def _sg(perm):
    return [add("/security_groups/0/IpPermissions/-", perm)]


def _acl(entries):
    return [add("/network_acls/0/Entries", entries)]


def _ne(num, proto, action, cidr, **kw):
    e = {"RuleNumber": num, "Protocol": proto, "RuleAction": action, "Egress": False, "CidrBlock": cidr}
    e.update(kw)
    return e


def _trail_sel(sel):
    return [add("/cloudtrail_trails/0/event_selectors", sel)]


def _stmt(**kw):
    return kw


def logic_tests():
    out = [TEST_HEAD.format(pkg="cis_aws.v7_logic_test", green="data.cis_aws.v7_controls_test.green",
                            what="Edge cases: port ranges and protocols, ordered NACL rules, policy document shapes, "
                                 "dates, empty versus absent lists, none-configured shapes.")]
    v4 = lambda proto, a, b_: {"IpProtocol": proto, "FromPort": a, "ToPort": b_, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    v6 = lambda proto, a, b_: {"IpProtocol": proto, "FromPort": a, "ToPort": b_, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    out += [
        _case("sg_range_covering_rdp", _sg(v4("tcp", 3380, 3390)), ["6.3"], ["6.4"]),
        _case("sg_range_beside_rdp", _sg(v4("tcp", 3390, 4000)), [], ["6.3", "6.4"]),
        _case("sg_udp_ssh_ipv6", _sg(v6("udp", 22, 22)), ["6.4"], ["6.3"]),
        _case("sg_protocol_6_is_tcp", _sg(v4("6", 22, 22)), ["6.3"]),
        _case("sg_all_traffic_ipv4", _sg({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}),
              ["6.3", "6.1.2"], ["6.4"]),
        _case("sg_all_traffic_ipv6", _sg({"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}),
              ["6.4", "6.1.2"], ["6.3"]),
        _case("sg_icmp_has_no_ports", _sg({"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                          "Ipv6Ranges": []}), [], ["6.3", "6.1.2"]),
        _case("sg_esp_has_no_ports", _sg({"IpProtocol": "50", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}), [],
              ["6.3", "6.4", "6.1.2"]),
        _case("sg_private_source", _sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                                        "Ipv6Ranges": []}), [], ["6.3", "6.4"]),
        _case("sg_rule_missing_protocol", _sg({"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}), ["6.3"]),
        _case("sg_cifs_445", _sg(v4("tcp", 445, 445)), ["6.1.2"], ["6.3"]),
        _case("nacl_deny_before_allow_passes",
              [rm("/network_acls/0/Entries/0"), add("/network_acls/0/Entries/-", _ne(90, "6", "deny", "0.0.0.0/0", PortRange={"From": 22, "To": 22})),
               add("/network_acls/0/Entries/-", _ne(91, "6", "deny", "0.0.0.0/0", PortRange={"From": 3389, "To": 3389})),
               add("/network_acls/0/Entries/-", _ne(92, "17", "deny", "0.0.0.0/0", PortRange={"From": 22, "To": 22})),
               add("/network_acls/0/Entries/-", _ne(93, "17", "deny", "0.0.0.0/0", PortRange={"From": 3389, "To": 3389})),
               add("/network_acls/0/Entries/-", _ne(100, "-1", "allow", "0.0.0.0/0"))], [], ["6.2"]),
        _case("nacl_allow_before_deny_fails", [add("/network_acls/0/Entries/-", _ne(90, "6", "allow", "0.0.0.0/0", PortRange={"From": 20, "To": 25})),
                                               add("/network_acls/0/Entries/-", _ne(100, "6", "deny", "0.0.0.0/0", PortRange={"From": 22, "To": 22}))],
              ["6.2"]),
        _case("nacl_allow_all_no_deny", [add("/network_acls/0/Entries/-", _ne(100, "-1", "allow", "0.0.0.0/0"))], ["6.2"]),
        _case("nacl_egress_ignored", [add("/network_acls/0/Entries/-", _ne(100, "-1", "allow", "0.0.0.0/0", Egress=True))], [], ["6.2"]),
        _case("nacl_private_allow", [add("/network_acls/0/Entries/-", _ne(100, "-1", "allow", "10.0.0.0/8"))], [], ["6.2"]),
        _case("nacl_range_zero_to_3389", [add("/network_acls/0/Entries/-", _ne(100, "6", "allow", "0.0.0.0/0", PortRange={"From": 0, "To": 3389}))], ["6.2"]),
        _case("iam_admin_split_over_statements_passes", [add("/iam_policies/0/DefaultVersionDocument/Statement", [
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}, {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}])], [], ["2.14"]),
        _case("iam_admin_deny_passes", [add("/iam_policies/0/DefaultVersionDocument/Statement", [
            {"Effect": "Deny", "Action": "*", "Resource": "*"}])], [], ["2.14"]),
        _case("iam_admin_lists_fail", [add("/iam_policies/0/DefaultVersionDocument/Statement", [
            {"Effect": "Allow", "Action": ["s3:Get*", "*"], "Resource": ["arn:aws:s3:::x", "*"]}])], ["2.14"]),
        _case("iam_admin_single_statement_object_fails", [add("/iam_policies/0/DefaultVersionDocument/Statement",
                                                              {"Effect": "Allow", "Action": "*", "Resource": "*"})], ["2.14"]),
        _case("iam_admin_document_as_string_fails", [add("/iam_policies/0/DefaultVersionDocument", json.dumps(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))], ["2.14"]),
        _case("iam_unattached_admin_policy_ignored", [add("/iam_policies/0/AttachmentCount", 0), add("/iam_policies/0/DefaultVersionDocument/Statement/-",
                                                                                                    {"Effect": "Allow", "Action": "*", "Resource": "*"})], [], ["2.14"]),
        _case("root_row_has_no_console_mfa_requirement", [add("/credential_report/0/mfa_active", "false")], [], ["2.10"]),
        _case("password_never_used_old_user", [add("/credential_report/1/password_last_used", "no_information"),
                                               add("/credential_report/1/user_creation_time", "2025-01-01T00:00:00+00:00")], ["2.11"]),
        _case("password_never_used_new_user", [add("/credential_report/1/password_last_used", "N/A"),
                                               add("/credential_report/1/user_creation_time", "2026-11-10T00:00:00+00:00")], [], ["2.11"]),
        _case("key_unused_for_45_days", [add("/credential_report/1/access_key_1_last_used_date", "2026-09-01T00:00:00+00:00")], ["2.11"]),
        _case("key_never_used_rotated_long_ago", [add("/credential_report/1/access_key_1_last_used_date", "N/A"),
                                                  add("/credential_report/1/access_key_1_last_rotated", "2026-01-01T00:00:00+00:00")], ["2.11", "2.12"]),
        _case("inactive_old_key_ignored", [add("/credential_report/1/access_key_1_active", "false"),
                                           add("/credential_report/1/access_key_1_last_rotated", "2020-01-01T00:00:00+00:00"),
                                           add("/credential_report/1/access_key_1_last_used_date", "N/A")], [], ["2.11", "2.12"]),
        _case("root_row_excluded_from_idle_check", [add("/credential_report/0/password_enabled", "true"), add("/credential_report/0/password_last_used", "2020-01-01T00:00:00+00:00")],
              [], ["2.11"]),
        _case("key_rotated_90_days_exactly_passes", [add("/credential_report/1/access_key_1_last_rotated", "2026-08-19T00:00:00+00:00")], [], ["2.12"]),
        _case("password_policy_empty_is_a_finding", [add("/password_policy", {})], ["2.8", "2.9"]),
        _case("password_reuse_24_passes", [add("/password_policy/PasswordReusePrevention", 24)], [], ["2.9"]),
        _case("expired_cert_unparsable_date", [add("/iam_server_certificates/0/Expiration", "soon")], ["2.17"]),
        _case("empty_regions_is_a_finding", [add("/regions", [])], ["2.18", "4.3", "5.16", "6.1.1"]),
        _case("second_region_without_coverage", [add("/regions/-", {"RegionName": "eu-west-1"})], ["2.18", "4.3", "5.16", "6.1.1"]),
        _case("empty_resource_lists_pass", [add("/rds_instances", []), add("/efs_file_systems", []), add("/s3_buckets", []),
                                            add("/ec2_instances", []), add("/iam_users", []), add("/vpcs", [])],
              [], ["3.2.1", "3.3.1", "3.1.1", "3.1.4", "6.7", "2.13", "4.7"]),
        _case("no_trail_fails_every_trail_check", [add("/cloudtrail_trails", [])], ["4.2", "4.5", "4.8", "4.9"]),
        _case("s3_policy_none_fails", [add("/s3_buckets/0/policy", None)], ["3.1.1"]),
        _case("s3_policy_tls_minimum_passes", [add("/s3_buckets/0/policy", {"Statement": [
            {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": ["s3:*"], "Resource": "arn:aws:s3:::app-data/*",
             "Condition": {"NumericLessThan": {"s3:TlsVersion": "1.2"}}}]})], [], ["3.1.1"]),
        _case("s3_policy_tls_below_12_fails", [add("/s3_buckets/0/policy", {"Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::app-data/*",
             "Condition": {"NumericLessThan": {"s3:TlsVersion": "1.0"}}}]})], ["3.1.1"]),
        _case("s3_policy_json_string_passes", [add("/s3_buckets/0/policy", json.dumps({"Statement": {
            "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::app-data/*",
            "Condition": {"Bool": {"aws:SecureTransport": False}}}}))], [], ["3.1.1"]),
        _case("s3_policy_allow_effect_fails", [add("/s3_buckets/0/policy/Statement/0/Effect", "Allow")], ["3.1.1"]),
        _case("s3_policy_other_bucket_resource_fails", [add("/s3_buckets/0/policy/Statement/0/Resource", "arn:aws:s3:::other/*")], ["3.1.1"]),
        _case("s3_account_block_excuses_bucket", [add("/s3_buckets/0/public_access_block", None),
                                                  add("/s3_account_public_access_block", ALL_BLOCK)], [], ["3.1.4"]),
        _case("s3_no_block_anywhere_fails", [add("/s3_buckets/0/public_access_block", None)], ["3.1.4"]),
        _case("trail_basic_selector_all_buckets_write_only", _trail_sel({"EventSelectors": [
            {"ReadWriteType": "WriteOnly", "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]}), ["4.9"], ["4.8"]),
        _case("trail_basic_selector_one_bucket_fails", _trail_sel({"EventSelectors": [
            {"ReadWriteType": "All", "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::one/"]}]}]}), ["4.8", "4.9"]),
        _case("trail_advanced_read_only_selector", _trail_sel({"AdvancedEventSelectors": [{"Name": "r", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
            {"Field": "readOnly", "Equals": ["true"]}]}]}), ["4.8"], ["4.9"]),
        _case("trail_advanced_narrowed_by_arn_fails", _trail_sel({"AdvancedEventSelectors": [{"Name": "n", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
            {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::one/"]}]}]}), ["4.8", "4.9"]),
        _case("trail_single_region_fails", [add("/cloudtrail_trails/0/IsMultiRegionTrail", False)], ["4.8", "4.9"]),
        _case("kms_aws_managed_key_ignored", [add("/kms_keys/-", {"KeyId": "k2", "region": R, "KeySpec": "SYMMETRIC_DEFAULT",
                                                                  "KeyManager": "AWS", "KeyRotationEnabled": False})], [], ["4.6"]),
        _case("kms_asymmetric_key_ignored", [add("/kms_keys/-", {"KeyId": "k3", "region": R, "KeySpec": "RSA_2048",
                                                                 "KeyManager": "CUSTOMER", "KeyRotationEnabled": False})], [], ["4.6"]),
        _case("terminated_instance_ignored", [add("/ec2_instances/-", {"InstanceId": "i-2", "State": {"Name": "terminated"}})], [], ["2.16", "6.7"]),
        _case("instance_profile_without_role", [add("/iam_instance_profiles/0/Roles", [])], ["2.16"]),
        _case("imds_pending_state_fails", [add("/ec2_instances/0/MetadataOptions/State", "pending")], ["6.7"]),
        _case("default_sg_outbound_rule", [add("/security_groups/1/IpPermissionsEgress/-", {"IpProtocol": "-1"})], ["6.5"]),
        _case("role_source_arn_wildcard_fails", [add("/iam_roles/0/AssumeRolePolicyDocument/Statement/0/Condition/ArnLike/aws:SourceArn", "*")], ["7.1.5"]),
        _case("role_source_arn_other_account_fails", [add("/iam_roles/0/AssumeRolePolicyDocument/Statement/0/Condition/ArnLike/aws:SourceArn",
                                                          f"arn:aws:bedrock:{R}:999999999999:agent/*")], ["7.1.5"]),
        _case("role_source_arn_account_wildcard_fails", [add("/iam_roles/0/AssumeRolePolicyDocument/Statement/0/Condition/ArnLike/aws:SourceArn",
                                                             f"arn:aws:bedrock:{R}:*:*")], ["7.1.5"]),
        _case("role_source_account_mismatch_fails", [add("/iam_roles/0/AssumeRolePolicyDocument/Statement/0/Condition/StringEquals/aws:SourceAccount",
                                                         "999999999999")], ["7.1.5"]),
        _case("role_agentcore_principal_in_scope", [add("/iam_roles/1/AssumeRolePolicyDocument/Statement/0/Principal/Service",
                                                        ["bedrock-agentcore.amazonaws.com"])], ["7.1.5"]),
        _case("service_linked_role_skipped", [add("/iam_roles/1/Path", "/aws-service-role/x/"), add("/iam_roles/1/AssumeRolePolicyDocument/Statement/0/Principal/Service",
                                                                                                    "bedrock.amazonaws.com")], [], ["7.1.5"]),
        _case("bedrock_key_inactive_ignored", [add("/bedrock_api_keys/0/Status", "Inactive"), add("/bedrock_api_keys/0/CreateDate", "2020-01-01T00:00:00Z")],
              [], ["7.1.6"]),
        _case("bedrock_key_without_expiry", [rm("/bedrock_api_keys/0/ExpirationDate")], ["7.1.6"]),
        _case("guardrail_category_none_on_output", [add("/bedrock_guardrails/0/contentPolicy/filters/0/outputStrength", "NONE")], ["7.2.4"]),
        _case("guardrail_no_content_policy", [rm("/bedrock_guardrails/0/contentPolicy")], ["7.2.4"]),
        _case("guardrail_empty_message", [add("/bedrock_guardrails/0/blockedInputMessaging", " ")], ["7.2.4"]),
        _case("no_bedrock_regions_passes", [add("/bedrock_regions", [])], [], ["7.4.1", "7.4.2"]),
        _case("bedrock_basic_selectors_fail", _trail_sel({"EventSelectors": [{"ReadWriteType": "All", "DataResources": []}]}), ["7.4.1"]),
        _case("bedrock_trail_not_logging", [add("/cloudtrail_trails/0/status/IsLogging", False)], ["7.4.1"]),
        _case("bedrock_single_region_trail_other_region", [add("/cloudtrail_trails/0/IsMultiRegionTrail", False), add("/cloudtrail_trails/0/HomeRegion", "eu-west-1")],
              ["7.4.1"]),
        _case("invocation_logging_disabled", [add("/bedrock_invocation_logging/0/loggingConfig", None)], ["7.4.2"]),
        _case("invocation_logging_no_destination", [add("/bedrock_invocation_logging/0/loggingConfig/cloudWatchConfig", {"logGroupName": "x"})], ["7.4.2"]),
        _case("invocation_logging_s3_destination_passes", [add("/bedrock_invocation_logging/0/loggingConfig/cloudWatchConfig", None),
                                                           add("/bedrock_invocation_logging/0/loggingConfig/s3Config", {"bucketName": "b"})], [], ["7.4.2"]),
        _case("invocation_logging_unneeded_modality_ok", [add("/bedrock_invocation_logging/0/loggingConfig/videoDataDeliveryEnabled", False)], [], ["7.4.2"]),
        _case("endpoint_default_policy_fails", [add("/vpc_endpoints/0/PolicyDocument", json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}))], ["7.5.1"]),
        _case("endpoint_private_dns_off_excused_by_attestation", [add("/vpc_endpoints/0/PrivateDnsEnabled", False),
                                                                  add("/attest/bedrock_endpoint_specific_dns_used", True)], [], ["7.5.1"]),
        _case("endpoint_not_available_fails", [add("/vpc_endpoints/0/State", "pending")], ["7.5.1"]),
        _case("no_endpoint_requirements_passes", [add("/bedrock_endpoint_requirements", []), add("/vpc_endpoints", [])], [], ["7.5.1"]),
        _case("job_without_vpc_config", [add("/bedrock_jobs/0/vpcConfig", None)], ["7.5.2"]),
        _case("job_subnet_uses_main_route_table_with_igw", [add("/route_tables/0/Associations", [{"Main": True}]),
                                                          add("/route_tables/0/Routes/-", {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-9"})], ["7.5.2"]),
        _case("job_subnet_nat_default_route_fails", [add("/route_tables/0/Routes/-", {"DestinationIpv6CidrBlock": "::/0", "NatGatewayId": "nat-1"})], ["7.5.2"]),
        _case("job_subnet_endpoint_route_passes", [add("/route_tables/0/Routes/-", {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "vgw-1"})], [], ["7.5.2"]),
        _case("job_subnet_without_route_table", [add("/route_tables", [])], ["7.5.2"]),
        _case("kb_other_store_needs_attestation", [add("/bedrock_knowledge_bases/0/storageConfiguration", {"type": "PINECONE"})], ["7.5.3"]),
        _case("kb_other_store_attested", [add("/bedrock_knowledge_bases/0/storageConfiguration", {"type": "PINECONE"}),
                                          add("/attest/bedrock_other_vector_stores_private", True)], [], ["7.5.3"]),
        _case("collection_public_wins", [add("/opensearch_serverless_network_policies/-", {"region": R, "name": "p2", "policy": json.dumps([
            {"Rules": [{"ResourceType": "collection", "Resource": ["collection/kb*"]}], "AllowFromPublic": True}])})], ["7.5.3"]),
        _case("collection_without_network_policy", [add("/opensearch_serverless_network_policies", [])], ["7.5.3"]),
        _case("marketplace_vpc_missing", [add("/bedrock_marketplace_endpoints/0/models/0/VpcConfig", {"SecurityGroupIds": [], "Subnets": []})], ["7.5.4"]),
        _case("marketplace_no_models", [add("/bedrock_marketplace_endpoints/0/models", [])], ["7.5.4"]),
        _case("kb_log_source_other_type", [add("/log_delivery_sources/0/logType", "EVENT_LOGS")], ["7.4.4"]),
        _case("kb_log_source_unpaired", [add("/log_deliveries/0/deliverySourceName", "other")], ["7.4.4"]),
    ]
    out.append('''test_absent_list_is_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/rds_instances"}])
	vs := b.violations with input as inp
	"3.2.1: evidence missing — input.rds_instances not collected" in vs
}

test_object_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/password_policy"}])
	vs := b.violations with input as inp
	"2.8: evidence missing — input.password_policy not collected" in vs
}

test_missing_property_is_a_finding if {
	inp := json.patch(green, [{"op": "remove", "path": "/rds_instances/0/StorageEncrypted"}])
	vs := b.violations with input as inp
	_has_id(vs, "3.2.1")
	not "3.2.1: evidence missing — input.rds_instances not collected" in vs
}

test_age_checks_use_the_clock_without_assessment_time if {
	inp := json.patch(green, [
		{"op": "remove", "path": "/assessment_time"},
		{"op": "add", "path": "/credential_report/1/access_key_1_last_rotated", "value": "2026-01-01T00:00:00+00:00"},
	])
	vs := b.violations with input as inp
	_has_id(vs, "2.12")
}
''')
    return "\n".join(out)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    wb = load(sys.argv[1])
    verify(wb)
    out = sys.argv[2]
    os.makedirs(os.path.join(out, "tests"), exist_ok=True)
    files = {"cis_aws_foundations.rego": engine(wb), "cis_aws_main.rego": main_module(wb), "l2_validation.rego": l2_module(wb),
             "tests/test_cis_aws_v7_controls.rego": control_tests(wb), "tests/test_cis_aws_v7_reports.rego": report_tests(wb),
             "tests/test_cis_aws_v7_logic.rego": logic_tests(), "tests/test_cis_aws_v7_l2.rego": l2_tests(wb)}
    assert sorted(files) == sorted(OWNED)
    paths = []
    for name, text in files.items():
        p = os.path.join(out, name)
        with open(p, "w") as fh:
            fh.write(text)
        paths.append(p)
    subprocess.run(["opa", "fmt", "-w"] + paths, check=True)
    n1 = sum(1 for w in wb.values() if w["level"] == 1)
    print(f"ok {len(C)} recommendations; L1 {n1}, L2 {len(C) - n1}; attest {sum(c['kind'] == 'attest' for c in C)}")


if __name__ == "__main__":
    main()
