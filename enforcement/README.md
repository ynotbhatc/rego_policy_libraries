# AAC Enforcement Policies

Policy-as-Code gates for Ansible, Terraform, Dockerfiles, and Kubernetes manifests.
Integrated with AAP EDA for real-time enforcement on every commit and deployment.

---

## Sentinel — Ansible Enforcement

**File:** `ansible/sentinel_ansible.rego`  
**Package:** `sentinel.ansible`  
**OPA container:** `:8182` (opa-compliance)

Evaluates an Ansible playbook (converted to JSON) and blocks deployment if any violation is found.

### What it checks

| Rule ID | Check |
|---------|-------|
| `SENTINEL-ANS-001` | Every play must have a non-empty `name` |
| `SENTINEL-ANS-002` | Production plays must not target bare `hosts: all` |
| `SENTINEL-ANS-003` | `become: yes` tasks must include justification in `tags` |
| `SENTINEL-ANS-004` | No hardcoded secrets in `vars` (password, token, secret, key patterns) |
| `SENTINEL-ANS-005` | `shell`/`command` tasks must have a `name` and a `changed_when` guard |

### OPA endpoint

```
POST http://<host>:8182/v1/data/sentinel/ansible/result
```

### Input format

```json
{
  "input": {
    "environment": "production",
    "plays": [
      {
        "name": "Configure web servers",
        "hosts": "web_servers",
        "become": true,
        "vars": {},
        "tasks": [
          {
            "name": "Install nginx",
            "tags": ["web", "nginx"],
            "ansible.builtin.package": {
              "name": "nginx",
              "state": "present"
            }
          }
        ]
      }
    ]
  }
}
```

### Example query

```bash
# Convert playbook to JSON, then evaluate
python3 -c "import sys,yaml,json; print(json.dumps({'input': {'environment':'production','plays': yaml.safe_load(open('site.yml'))}}))" \
  | curl -s -X POST http://192.168.4.62:8182/v1/data/sentinel/ansible/result \
         -H 'Content-Type: application/json' -d @- | jq '.result'
```

### Example response

```json
{
  "allow": true,
  "violations": [],
  "violation_count": 0,
  "risk_score": 0,
  "compliant": true
}
```

If violations are present:

```json
{
  "allow": false,
  "violations": [
    "SENTINEL-ANS-004: Play 'Deploy app' contains hardcoded secret in vars: 'db_password'"
  ],
  "violation_count": 1,
  "risk_score": 85,
  "compliant": false
}
```

### AAP EDA integration

The `sentinel_github_webhook.yml` rulebook listens on port **5003** for GitHub push events.
When a `.yml` playbook is pushed, EDA automatically triggers `AAC_Comply_AnsibleDeny` (blocks)
or `AAC_Comply_AnsibleAllow` (passes) based on OPA result.

```
GitHub push → EDA :5003 → AAP job template → OPA :8182 → ALLOW / DENY
```

---

## Sentinel — Terraform Enforcement

**File:** `terraform/sentinel_terraform.rego`  
**Package:** `sentinel.terraform`  
**OPA container:** `:8182`  
**OPA endpoint:** `POST /v1/data/sentinel/terraform/result`

Evaluates a Terraform plan JSON for policy violations before `apply`.

### What it checks
- Unencrypted S3 buckets / storage resources
- Public exposure of storage or compute
- Missing required tags (`environment`, `owner`, `cost_center`)
- Disallowed resource types in production

### Example query

```bash
terraform plan -out=tfplan.bin && terraform show -json tfplan.bin \
  | jq '{input: {environment: "production", plan: .}}' \
  | curl -s -X POST http://192.168.4.62:8182/v1/data/sentinel/terraform/result \
         -H 'Content-Type: application/json' -d @- | jq '.result'
```

---

## Sentinel — Dockerfile Enforcement

**File:** `dockerfile/sentinel_dockerfile.rego`  
**Package:** `sentinel.dockerfile`  
**OPA container:** `:8182`  
**OPA endpoint:** `POST /v1/data/sentinel/dockerfile/result`

---

## Sentinel — Kubernetes Enforcement

**File:** `kubernetes/sentinel_kubernetes.rego`  
**Package:** `sentinel.kubernetes`  
**OPA container:** `:8182`  
**OPA endpoint:** `POST /v1/data/sentinel/kubernetes/result`

---

## Running Sentinel in CI/CD

Add this step to any pipeline to gate on policy compliance before deployment:

```bash
#!/bin/bash
# sentinel_check.sh — fail build if OPA returns allow=false
RESULT=$(curl -sf -X POST "$OPA_URL/v1/data/sentinel/ansible/result" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "import sys,yaml,json; print(json.dumps({'input': {'environment':'${ENV:-staging}','plays': yaml.safe_load(open('$1'))}}))")")

ALLOW=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('result',{}).get('allow', False)).lower())")

if [ "$ALLOW" != "true" ]; then
  echo "❌ Sentinel DENY — policy violations detected:"
  echo "$RESULT" | python3 -m json.tool
  exit 1
fi
echo "✅ Sentinel ALLOW"
```

---

## Related AAP Job Templates

| Template | Purpose |
|----------|---------|
| `AAC_Comply_AnsibleDeny` | Validate playbook → expected DENY result (non-compliant demo) |
| `AAC_Comply_AnsibleAllow` | Validate playbook → expected ALLOW result (compliant demo) |
| `AAC_Comply_TerraformDeny` | Validate Terraform plan → DENY |
| `AAC_Comply_TerraformAllow` | Validate Terraform plan → ALLOW |
| `AAC_Comply_RuntimeBlock` | OPA intercepts live execution at runtime |
| `AAC_Comply_SeedEDA` | Seed EDA Sentinel GitHub webhook activation on port 5003 |
