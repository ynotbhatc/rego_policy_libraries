package corporate.git_approval

# Git Change Approval Policy
# Ensures changes to critical paths require proper approval

import rego.v1

# Protected paths that require approval
protected_paths := {
    "policies/",
    "opa/",
    ".github/workflows/",
    "aap-integration/",
    "ansible/",
}

# Users authorized to approve changes
authorized_approvers := {
    "tcoulter@example.com",
    "john.doe@example.com",
    "security-team@example.com",
    "compliance-admin@example.com",
}

# Default: changes are not approved
default approved := false

# Changes are approved if:
# 1. Commit message contains "Approved-By:" with authorized approver
# 2. Changes don't affect protected paths, OR
# 3. Pull request has required approvals
approved if {
    input.commit_message
    contains(input.commit_message, "Approved-By:")
    approver := extract_approver(input.commit_message)
    approver in authorized_approvers
}

# Allow changes to non-protected paths without approval
approved if {
    not affects_protected_paths
}

# Check if changes affect protected paths
affects_protected_paths if {
    some file in input.changed_files
    some path in protected_paths
    startswith(file, path)
}

# Extract approver email from commit message
extract_approver(msg) := approver if {
    lines := split(msg, "\n")
    some line in lines
    contains(line, "Approved-By:")
    parts := split(line, ":")
    approver := trim_space(parts[1])
}

# Validation: Check if approval is required but missing
default requires_approval := false

requires_approval if {
    affects_protected_paths
    not approved
}

# Generate approval requirement message
approval_message := msg if {
    requires_approval
    affected := [file |
        some file in input.changed_files
        some path in protected_paths
        startswith(file, path)
    ]
    msg := sprintf("Changes to protected paths require approval: %v", [affected])
}

# Policy decision
decision := {
    "approved": approved,
    "requires_approval": requires_approval,
    "affected_protected_paths": affected_protected_paths,
    "message": "Check complete",
}

# Helper: Get affected protected paths
default affected_protected_paths := []

affected_protected_paths := paths if {
    paths := [file |
        some file in input.changed_files
        some path in protected_paths
        startswith(file, path)
    ]
}

# Test data helpers
test_approved_change if {
    approved with input as {
        "commit_message": "Update policies\n\nApproved-By: john.doe@example.com",
        "changed_files": ["policies/cis_rhel9/test.rego"],
    }
}

test_unapproved_change if {
    requires_approval with input as {
        "commit_message": "Update policies",
        "changed_files": ["policies/cis_rhel9/test.rego"],
    }
}

test_non_protected_change if {
    approved with input as {
        "commit_message": "Update documentation",
        "changed_files": ["docs/README.md"],
    }
}
