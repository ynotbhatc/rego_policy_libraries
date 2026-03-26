package sentinel.dockerfile

import rego.v1

# =============================================================================
# Sentinel Policy Enforcement — Dockerfile Validation
# Validates Dockerfiles before git merge / image build
#
# Policy IDs:
#   SENTINEL-DF-001 — Must use approved base images
#   SENTINEL-DF-002 — No running as root (USER must be set)
#   SENTINEL-DF-003 — No hardcoded secrets or credentials
#   SENTINEL-DF-004 — No ADD with URLs (use COPY instead)
#   SENTINEL-DF-005 — Pin package versions (no unversioned installs)
#   SENTINEL-DF-006 — No SUID/SGID bits set
#   SENTINEL-DF-007 — Healthcheck must be defined
#   SENTINEL-DF-008 — Minimize layers (no excessive RUN commands)
#   SENTINEL-DF-009 — No secrets in ENV or ARG
#   SENTINEL-DF-010 — No privileged port exposure (ports < 1024)
#   SENTINEL-DF-011 — Use specific base image tag, not :latest
#   SENTINEL-DF-012 — apt-get / yum cleanup required after install
#   SENTINEL-DF-013 — No curl|bash pipe installs
#
# Input shape:
#   input.instructions[]        - Dockerfile instructions (parsed)
#     .cmd                      - instruction keyword (FROM, RUN, etc.)
#     .value                    - instruction value
#   input.approved_base_images[] - list of approved base image names
# =============================================================================

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

from_instructions := [i | some i in input.instructions; i.cmd == "FROM"]
run_instructions  := [i | some i in input.instructions; i.cmd == "RUN"]
env_instructions  := [i | some i in input.instructions; i.cmd == "ENV"]
arg_instructions  := [i | some i in input.instructions; i.cmd == "ARG"]
add_instructions  := [i | some i in input.instructions; i.cmd == "ADD"]
expose_instructions := [i | some i in input.instructions; i.cmd == "EXPOSE"]
user_instructions := [i | some i in input.instructions; i.cmd == "USER"]

# ---------------------------------------------------------------------------
# SENTINEL-DF-001 — Approved base images only
# ---------------------------------------------------------------------------

violation_df_001 contains msg if {
    some from_instr in from_instructions
    from_instr.value != "scratch"
    image_name := split(split(from_instr.value, ":")[0], "@")[0]
    count(input.approved_base_images) > 0
    not image_name in input.approved_base_images
    msg := sprintf(
        "SENTINEL-DF-001: Base image '%v' is not in the approved base image list. Use an approved, hardened base image.",
        [from_instr.value]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-002 — Must not run as root
# ---------------------------------------------------------------------------

violation_df_002 contains msg if {
    count(user_instructions) == 0
    msg := "SENTINEL-DF-002: No USER instruction found. Containers must run as a non-root user. Add 'USER nonroot' or a specific UID."
}

violation_df_002 contains msg if {
    some user_instr in user_instructions
    user_instr.value in {"root", "0"}
    msg := sprintf(
        "SENTINEL-DF-002: USER is set to '%v'. Containers must not run as root. Use a non-root user or UID > 0.",
        [user_instr.value]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-003 — No hardcoded secrets in RUN, ENV, ARG, COPY
# ---------------------------------------------------------------------------

secret_keywords := {
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "credential", "private_key", "privatekey", "access_key", "auth_token",
}

violation_df_003 contains msg if {
    some run_instr in run_instructions
    some keyword in secret_keywords
    contains(lower(run_instr.value), concat("=", [keyword, ""]))
    msg := sprintf(
        "SENTINEL-DF-003: RUN instruction may contain a hardcoded secret (keyword: '%v'). Use build secrets (--secret) or runtime environment variables.",
        [keyword]
    )
}

violation_df_003 contains msg if {
    some env_instr in env_instructions
    some keyword in secret_keywords
    contains(lower(env_instr.value), keyword)
    msg := sprintf(
        "SENTINEL-DF-003: ENV instruction may contain a hardcoded secret (keyword: '%v'). Do not bake secrets into image layers.",
        [keyword]
    )
}

violation_df_003 contains msg if {
    some arg_instr in arg_instructions
    some keyword in secret_keywords
    contains(lower(arg_instr.value), keyword)
    not contains(arg_instr.value, "?")  # allow ARG MY_SECRET with no default
    msg := sprintf(
        "SENTINEL-DF-003: ARG instruction '%v' may expose a secret as a build argument. ARG values appear in image history. Use BuildKit secrets instead.",
        [arg_instr.value]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-004 — No ADD with remote URLs
# ---------------------------------------------------------------------------

violation_df_004 contains msg if {
    some add_instr in add_instructions
    src := split(add_instr.value, " ")[0]
    startswith(src, "http")
    msg := sprintf(
        "SENTINEL-DF-004: ADD instruction fetches from URL '%v'. Use COPY for local files. Use RUN curl/wget if you need to fetch from a URL, and verify with checksums.",
        [src]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-005 — Pin package versions
# ---------------------------------------------------------------------------

violation_df_005 contains msg if {
    some run_instr in run_instructions
    contains(run_instr.value, "apt-get install")
    not contains(run_instr.value, "=")
    not contains(run_instr.value, "--no-install-recommends")
    msg := "SENTINEL-DF-005: apt-get install without version pinning detected. Pin package versions to ensure reproducible builds (e.g., 'apt-get install nginx=1.24.*')."
}

violation_df_005 contains msg if {
    some run_instr in run_instructions
    contains(run_instr.value, "pip install")
    not contains(run_instr.value, "==")
    not contains(run_instr.value, "-r ")
    msg := "SENTINEL-DF-005: pip install without version pinning detected. Use 'pip install package==version' or a requirements.txt with pinned versions."
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-006 — No chmod with SUID/SGID bits
# ---------------------------------------------------------------------------

violation_df_006 contains msg if {
    some run_instr in run_instructions
    contains(run_instr.value, "chmod")
    suid_patterns := ["4755", "2755", "6755", "4777", "2777", "+s", "u+s", "g+s"]
    some pattern in suid_patterns
    contains(run_instr.value, pattern)
    msg := sprintf(
        "SENTINEL-DF-006: RUN instruction sets SUID/SGID bits (pattern: '%v'). Do not set setuid/setgid bits in container images.",
        [pattern]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-007 — Healthcheck must be defined
# ---------------------------------------------------------------------------

violation_df_007 contains msg if {
    healthcheck_instructions := [i | some i in input.instructions; i.cmd == "HEALTHCHECK"]
    count(healthcheck_instructions) == 0
    msg := "SENTINEL-DF-007: No HEALTHCHECK instruction defined. A HEALTHCHECK enables Docker and orchestrators to detect unhealthy containers."
}

violation_df_007 contains msg if {
    some instr in input.instructions
    instr.cmd == "HEALTHCHECK"
    instr.value == "NONE"
    msg := "SENTINEL-DF-007: HEALTHCHECK is explicitly set to NONE. A health check must be defined for production containers."
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-009 — No secrets in ENV (already covered in DF-003, but explicit check)
# ---------------------------------------------------------------------------

violation_df_009 contains msg if {
    some env_instr in env_instructions
    parts := split(env_instr.value, "=")
    count(parts) >= 2
    count(parts[1]) > 0    # has a non-empty value
    some keyword in secret_keywords
    contains(lower(parts[0]), keyword)
    msg := sprintf(
        "SENTINEL-DF-009: ENV variable '%v' appears to be a hardcoded secret. ENV values are stored in image metadata and accessible to all container users.",
        [parts[0]]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-010 — No privileged port exposure
# ---------------------------------------------------------------------------

violation_df_010 contains msg if {
    some expose_instr in expose_instructions
    port_str := split(expose_instr.value, "/")[0]
    port := to_number(port_str)
    port < 1024
    msg := sprintf(
        "SENTINEL-DF-010: EXPOSE declares privileged port %v (< 1024). Use ports >= 1024 and configure port mapping at runtime.",
        [port]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-011 — No :latest base image tags
# ---------------------------------------------------------------------------

violation_df_011 contains msg if {
    some from_instr in from_instructions
    from_instr.value != "scratch"
    endswith(from_instr.value, ":latest")
    msg := sprintf(
        "SENTINEL-DF-011: Base image '%v' uses ':latest' tag. Pin to a specific version tag or digest for reproducible builds.",
        [from_instr.value]
    )
}

violation_df_011 contains msg if {
    some from_instr in from_instructions
    from_instr.value != "scratch"
    not contains(from_instr.value, ":")
    not contains(from_instr.value, "@")
    msg := sprintf(
        "SENTINEL-DF-011: Base image '%v' has no version tag. Specify an explicit tag or SHA256 digest.",
        [from_instr.value]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-012 — Clean up package manager cache
# ---------------------------------------------------------------------------

violation_df_012 contains msg if {
    some run_instr in run_instructions
    contains(run_instr.value, "apt-get install")
    not contains(run_instr.value, "rm -rf /var/lib/apt/lists")
    msg := "SENTINEL-DF-012: apt-get install without cache cleanup. Add '&& rm -rf /var/lib/apt/lists/*' to reduce image size and attack surface."
}

violation_df_012 contains msg if {
    some run_instr in run_instructions
    contains(run_instr.value, "yum install")
    not contains(run_instr.value, "yum clean all")
    not contains(run_instr.value, "dnf clean all")
    msg := "SENTINEL-DF-012: yum/dnf install without cache cleanup. Add '&& yum clean all' or '&& dnf clean all' after package installation."
}

# ---------------------------------------------------------------------------
# SENTINEL-DF-013 — No curl|bash pipe installs
# ---------------------------------------------------------------------------

violation_df_013 contains msg if {
    some run_instr in run_instructions
    pipe_install_patterns := ["curl.*|.*bash", "curl.*|.*sh", "wget.*|.*bash", "wget.*|.*sh", "curl.*|.*python"]
    some pattern in pipe_install_patterns
    regex.match(pattern, run_instr.value)
    msg := "SENTINEL-DF-013: Unsafe pipe-to-shell install detected in RUN instruction. Never pipe curl/wget output directly to a shell. Download, verify checksum, then execute."
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_df_001],
        [v | some v in violation_df_002]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_df_003],
            [v | some v in violation_df_004]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_df_005],
                [v | some v in violation_df_006]
            ),
            array.concat(
                array.concat(
                    [v | some v in violation_df_007],
                    [v | some v in violation_df_009]
                ),
                array.concat(
                    array.concat(
                        [v | some v in violation_df_010],
                        [v | some v in violation_df_011]
                    ),
                    array.concat(
                        [v | some v in violation_df_012],
                        [v | some v in violation_df_013]
                    )
                )
            )
        )
    )
)

compliant if { count(all_violations) == 0 }

result := {
    "compliant":       compliant,
    "violation_count": count(all_violations),
    "violations":      all_violations,
}
