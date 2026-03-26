# CIS Oracle Database 19c Benchmark - OPA Policies

OPA Rego policies for validating CIS Oracle Database 19c Benchmark compliance.

## Overview

These policies validate Oracle Database 19c configurations against the CIS Oracle Database 19c Benchmark v1.2.0. The policies are organized into modules covering different sections of the benchmark.

## Coverage

### Section 1: Installation and Patches (Module: `installation_patches`)
- **CIS 1.1**: Oracle version and patch validation
- Critical Patch Updates (CPU) verification
- ORACLE_HOME permissions and ownership
- Oracle inventory security

**Controls Covered**: 5+

### Section 2.1: Listener Configuration (Module: `listener_configuration`)
- **CIS 2.1.1**: Ensure 'EXTPROC' is not present in listener.ora
- **CIS 2.1.2**: Ensure 'ADMIN_RESTRICTIONS' is set to 'ON'
- **CIS 2.1.3**: Ensure listener logging is configured
- **CIS 2.1.4**: Ensure listener is not using default port
- **CIS 2.1.5**: Ensure listener security settings
- **CIS 2.1.6**: Ensure VALID_NODE_CHECKING is enabled
- Listener file permissions

**Controls Covered**: 10+

### Section 2.2: Database Parameters (Module: `database_parameters`)
- **CIS 2.2.1**: AUDIT_SYS_OPERATIONS = TRUE
- **CIS 2.2.2**: AUDIT_TRAIL = DB/XML/OS
- **CIS 2.2.3**: GLOBAL_NAMES = TRUE
- **CIS 2.2.4**: OS_ROLES = FALSE
- **CIS 2.2.5**: REMOTE_LISTENER = empty
- **CIS 2.2.6**: REMOTE_LOGIN_PASSWORDFILE = NONE/EXCLUSIVE
- **CIS 2.2.7**: REMOTE_OS_AUTHENT = FALSE ⚠️ CRITICAL
- **CIS 2.2.8**: REMOTE_OS_ROLES = FALSE
- **CIS 2.2.9**: SEC_CASE_SENSITIVE_LOGON = TRUE
- **CIS 2.2.10**: SEC_MAX_FAILED_LOGIN_ATTEMPTS ≤ 10
- **CIS 2.2.11**: SEC_RETURN_SERVER_RELEASE_BANNER = FALSE
- **CIS 2.2.12**: SQL92_SECURITY = TRUE
- **CIS 2.2.13**: O7_DICTIONARY_ACCESSIBILITY = FALSE ⚠️ CRITICAL
- Network encryption configuration
- Unified auditing (Oracle 12c+)

**Controls Covered**: 20+

### Section 3: User Account Management (Module: `user_account_management`)
- **CIS 3.1**: Default account security
- **CIS 3.2**: Password profiles and policies
- **CIS 3.3**: Privileged account management
- **CIS 3.4**: Account lockout and inactive accounts
- **CIS 3.5**: Anonymous access
- **CIS 3.6**: PUBLIC privileges

**Controls Covered**: 15+

## Total Coverage

**~50+ CIS Oracle Database 19c controls validated**

## Risk Levels

- **CRITICAL**: Immediate security threat (e.g., REMOTE_OS_AUTHENT=TRUE, EXTPROC enabled, default passwords)
- **HIGH**: Significant security risk (e.g., weak password policies, unnecessary privileges)
- **MEDIUM**: Configuration issues (e.g., suboptimal settings)
- **LOW**: Informational (e.g., recommendations)

## Usage

### Query All Violations

```bash
curl -X POST http://localhost:8181/v1/data/cis_oracle/all_violations \
  -H "Content-Type: application/json" \
  -d @oracle_facts.json
```

### Get Complete Report

```bash
curl -X POST http://localhost:8181/v1/data/cis_oracle/report \
  -H "Content-Type: application/json" \
  -d @oracle_facts.json | jq '.'
```

### Check Specific Section

```bash
# Installation & Patches
curl -X POST http://localhost:8181/v1/data/cis_oracle/installation_patches/violations \
  -d @oracle_facts.json | jq '.result'

# Listener Configuration
curl -X POST http://localhost:8181/v1/data/cis_oracle/listener_configuration/violations \
  -d @oracle_facts.json | jq '.result'

# Database Parameters
curl -X POST http://localhost:8181/v1/data/cis_oracle/database_parameters/violations \
  -d @oracle_facts.json | jq '.result'

# User Account Management
curl -X POST http://localhost:8181/v1/data/cis_oracle/user_account_management/violations \
  -d @oracle_facts.json | jq '.result'
```

### Check Overall Compliance

```bash
curl -X POST http://localhost:8181/v1/data/cis_oracle/compliant \
  -d @oracle_facts.json | jq '.result'
```

## Expected Input Structure

The policies expect JSON input with the following structure:

```json
{
  "oracle_version": {
    "version": "19c",
    "supported": true,
    "end_of_support": "2027-04-30"
  },
  "database_info": {
    "db_name": "ORCL",
    "instance_name": "orcl1",
    "platform": "Linux x86_64"
  },
  "critical_patches": {
    "last_patch_date": "2025-01-15",
    "days_since_last_patch": 30,
    "critical_missing": 0,
    "missing_patches": []
  },
  "listeners": [
    {
      "name": "LISTENER",
      "port": 1521,
      "admin_restrictions": "ON",
      "services": ["ORCL"],
      "logging_enabled": true
    }
  ],
  "parameters": {
    "AUDIT_SYS_OPERATIONS": "TRUE",
    "AUDIT_TRAIL": "DB",
    "REMOTE_OS_AUTHENT": "FALSE",
    "SEC_CASE_SENSITIVE_LOGON": "TRUE"
  },
  "all_accounts": [...],
  "default_accounts": [...],
  "password_profiles": [...]
}
```

## Example Output

```json
{
  "result": {
    "metadata": {
      "benchmark": "CIS Oracle Database 19c Benchmark",
      "benchmark_version": "v1.2.0",
      "oracle_version": "19c",
      "database_name": "ORCL"
    },
    "compliance": {
      "overall_compliant": false,
      "compliant_sections": 2,
      "total_sections": 4,
      "compliance_percentage": 50,
      "overall_risk_level": "high"
    },
    "violations": {
      "total_count": 8,
      "critical_count": 2,
      "all_violations": [
        "CIS 2.2.7: REMOTE_OS_AUTHENT is 'TRUE' (should be 'FALSE' - CRITICAL)",
        "CIS 3.1: Default account 'SCOTT' is OPEN (should be LOCKED)",
        ...
      ]
    },
    "recommendations": [
      {
        "priority": "critical",
        "section": "Database Parameters",
        "action": "Set REMOTE_OS_AUTHENT=FALSE immediately"
      }
    ]
  }
}
```

## Fact Collection

To collect facts from an Oracle database, you can use SQL queries or the provided Ansible roles.

### SQL Queries for Fact Collection

```sql
-- Database version
SELECT * FROM v$version;

-- Database parameters
SELECT name, value FROM v$parameter WHERE name IN (
  'AUDIT_SYS_OPERATIONS',
  'AUDIT_TRAIL',
  'REMOTE_OS_AUTHENT',
  'REMOTE_OS_ROLES',
  'SEC_CASE_SENSITIVE_LOGON'
);

-- User accounts
SELECT username, account_status, lock_date, expiry_date
FROM dba_users;

-- Default accounts
SELECT username, account_status, created, default_tablespace
FROM dba_users
WHERE oracle_maintained = 'Y';

-- Password profiles
SELECT * FROM dba_profiles
WHERE resource_name LIKE 'PASSWORD%';

-- Listener status (from OS)
lsnrctl status
```

## Integration with Ansible

See the main repository documentation for Ansible integration examples.

## Testing

```bash
# Test policies
opa test policies/cis_oracle/

# Evaluate with mock data
opa eval --data policies/cis_oracle/ \
  --input test_data/oracle_compliant.json \
  'data.cis_oracle.report'
```

## References

- [CIS Oracle Database 19c Benchmark](https://www.cisecurity.org/benchmark/oracle_database)
- [Oracle Database Security Guide](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/)
- [Oracle Critical Patch Updates](https://www.oracle.com/security-alerts/)

## License

Same as parent repository.

## Contributing

Contributions welcome! Please ensure:
1. Follow existing Rego style
2. Add tests for new controls
3. Update this README with coverage
4. Include references to CIS control numbers
