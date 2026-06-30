# Automation Plan — Monthly Snowflake Access Review

**Goal:** Automate the recurring monthly access review by reconciling **actual** Snowflake access
against **expected** access (from Entra ID group membership + an approved role matrix), producing
auditor-ready evidence and a controlled, approval-gated remediation workflow. The automation runs on
**metadata only** — it never reads PHI — and **never revokes access automatically**.

**Compliance drivers:** HIPAA Security Rule §164.308(a)(3)–(a)(4) (workforce access management),
§164.312(b) (audit controls); SOC 2 CC6.1–CC6.3.
**Cadence:** first day of each month (the `0 6 1 * *` schedule in §5), plus on-demand re-runs.
**Related components:** consumes the `ACCOUNT_USAGE` patterns in
`audit_queries.sql` and the `FR_*` role model in `snowflake_rbac.sql`; the "expected" side is the
Entra-group → `FR_*` mapping defined there.

## 1. Inputs

| # | Input | Source | Notes |
|---|---|---|---|
| 1 | **Snowflake access metadata** | `ACCOUNT_USAGE` (`GRANTS_TO_USERS`, `GRANTS_TO_ROLES`, `USERS`, `ROLES`, `LOGIN_HISTORY`) + `SHOW GRANTS` for current truth before any change | `ACCOUNT_USAGE` lags (varies by view); fine for monthly, but re-confirm with `SHOW GRANTS` before remediating. |
| 2 | **Entra ID groups & membership** | Microsoft Graph (`/groups/{id}/transitiveMembers`, `/users`) via an app registration with read-only `Group.Read.All`, `User.Read.All`, certificate auth | Transitive members resolve nested groups; capture `accountEnabled` + last sign-in. |
| 3 | **Expected role matrix** | Version-controlled YAML in Git, PR-reviewed (CODEOWNERS = security + data owner) | Maps Entra group → `FR_*` role(s) and role → data-sensitivity. This is the policy; it changes only via reviewed PR. |
| 4 | **Service-account inventory** | Git/CMDB registry + Snowflake `USERS WHERE TYPE='SERVICE'` | Per account: owner, justification, expected roles, key rotation date, break-glass flag. Reconciled both ways. |
| 5 | **Prior run state** | `GOVERNANCE.ACCESS_REVIEW_HISTORY` (Snowflake) / object storage | Enables month-over-month diff and exception aging. |

**Identity correlation:** Snowflake users carry their Entra UPN/`objectId` (ideally SCIM-provisioned,
`LOGIN_NAME` = UPN). A Snowflake human user that can't be correlated to an active Entra identity is
itself an exception (orphan).

## 2. Process — actual vs. expected

```
EXPECTED(user) = ⋃ over Entra groups g the user belongs to: role_matrix[g].fr_roles
               ⋃ service_account_inventory[user].expected_roles
ACTUAL(user)   = effective FR_* roles from GRANTS_TO_USERS, hierarchy-expanded
```

Diff → exception classes:
- **OVER_PROVISIONED** = actual − expected → *revoke candidate*.
- **UNDER_PROVISIONED** = expected − actual → provisioning gap, ticket only (never a revoke).
- **ORPHAN** = Snowflake user with no active correlating Entra identity → **critical**.
- **STALE** = enabled, no login in N days (default 90).
- **UNMANAGED_SVC** = non-human login absent from the inventory.

Each exception is **risk-scored** by data sensitivity (PHI tag) × account state × privilege level;
PHI-scoped or admin-role exceptions auto-escalate to CRITICAL.

## 3. Outputs

1. **Exception report** (`CSV` + `HTML`) — one row per exception with severity, sensitivity, account
   status, recommended action, and "first seen" (aging).
2. **Audit evidence package** — immutable, SHA-256-hashed snapshot: raw extracts, the role-matrix
   commit SHA, run params, operator identity, timestamps, and reviewer sign-off. Written to WORM
   storage (S3 Object Lock / Blob immutability), retained ≥ 6 years (HIPAA).
3. **Notifications** — summary to the security channel; per-owner emails containing **only their
   team's** exceptions (least disclosure); a ticket per remediation item.
4. **Remediation plan** — generated `REVOKE` statements, **held for approval, not executed**, each
   paired with its inverse `GRANT` (rollback).
5. **Metrics** — exception counts by type/severity/team over time, mean-time-to-remediate, % within
   SLA.

## 4. Safety controls (non-negotiable in a PHI environment)

| Control | Implementation |
|---|---|
| **Dry-run by default** | No `--apply` → detect and propose only; zero changes. |
| **Approval before revoke** | Each revoke needs a signed approval entry (GitHub Environment / Azure DevOps / ServiceNow). **Separation of duties:** approver ≠ runner; PHI/admin revokes need a second approver. |
| **Never auto-revoke privileged** | `ACCOUNTADMIN`, `SECURITYADMIN`, `FR_BREAKGLASS`, and `protected`-tagged roles are report-only, always. |
| **Rollback** | Capture the inverse `GRANT` for every revoke **before** applying; store with evidence; `--rollback --run-id` restores in minutes. |
| **Re-confirm live** | Re-check `SHOW GRANTS` immediately before each revoke (`ACCOUNT_USAGE` lags); skip if already gone (idempotent). |
| **Blast-radius cap** | Abort if approved revokes exceed `--max-revokes`; a bad matrix edit must not mass-revoke. |
| **Least-privilege automation identity** | Dedicated role: `SELECT` on `ACCOUNT_USAGE` + scoped `MANAGE GRANTS`; never `ACCOUNTADMIN`. Key-pair auth, secret in a vault, rotated. Graph app is read-only. |
| **Comprehensive logging** | Every extract/compare/propose/approve/execute logged with run-id + actor to an append-only, tamper-evident store (SIEM); `QUERY_HISTORY` independently corroborates executed DDL. |
| **Change-control the matrix** | The role matrix is the only thing that drives revokes — PR-reviewed, signed commits, CODEOWNERS. |

## 5. Tools

| Layer | Tool | Why |
|---|---|---|
| Orchestration | **GitHub Actions** (cron `0 6 1 * *`) with protected Environments for the approval gate; **Azure DevOps** equivalent; **Airflow** only if already in use | Auditable, version-controlled runs; OIDC, no long-lived creds. |
| Extraction & glue | **Python** (`snowflake-connector-python`, `msgraph-sdk`/`requests`, `pydantic` for matrix validation) | Pull metadata, build sets, render reports, notify. |
| Reconciliation | **dbt** (tested SQL models for expected-vs-actual + sensitivity tagging) | Version-controlled, testable, documented. |
| Evidence store | **Snowflake** `GOVERNANCE` schema (append-only) + WORM bucket | Trend store + immutable evidence. |
| Secrets / identity | **Azure Key Vault** + **GitHub OIDC / Azure Workload Identity**; read-only Entra app | No static credentials. |
| IaC | **Terraform** (`snowflake` + `azuread` providers) — see `terraform_or_iac_example.tf` | The reviewer/enforcement roles + governance schema as reviewable code. |
| Notifications / workflow | Teams/Outlook (M365 tenant) + Jira/ServiceNow | Reports, approvals, ticketing. |

**Recommended minimal stack:** Python + dbt + Snowflake + Terraform + GitHub Actions (protected
Environments for approval). Add Airflow only if richer scheduling/backfill is needed.

## 6. Rollout

1. **Report-only (2 cycles):** dry-run; hand-validate exceptions with owners; tune the matrix and
   sensitivity tags. No revokes.
2. **Assisted remediation:** approvals + manual execution of generated SQL; build the evidence
   package and sign-off flow.
3. **Gated enforcement:** enable `--apply` for *low-risk, high-confidence* classes (e.g. orphaned
   disabled accounts) with blast-radius caps; keep admin/PHI revokes manual.
4. **Continuous assurance:** quarterly control self-test (inject a known over-grant, confirm it's
   caught), annual auditor walkthrough using the evidence package.

A runnable, safety-first reference implementation of the comparison + gated remediation is in
**`access_review.py`**.
