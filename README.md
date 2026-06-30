# Secure Snowflake Data & AI Platform — Operating Model

Operating model for a HIPAA-regulated healthcare data platform on **Microsoft Entra ID** (identity),
**Snowflake** (warehouse), **dbt** (transformations), **Power BI** (reporting), Python ETL, and
**Snowflake Cortex** AI. It establishes Entra-driven least-privilege roles, secured service accounts,
auditable access, and PHI protected by default — with a phased rollout to reach that state without
breaking existing access.

The plan is sequenced to **assess → design → implement in parallel → cut over safely → automate**.
Each phase produces evidence, and nothing destructive happens without a reviewed, reversible step.

---

## What's in this repository

### Platform foundation

| Path | What it is |
|---|---|
| `rbac/snowflake_rbac.sql` | Two-layer RBAC model: roles, grants, service users, PHI masking/row-access, managed schemas, resource monitors, break-glass, safe migration. |
| `audit/audit_queries.sql` | `ACCOUNT_USAGE` audit pack: recursive role-closure, entitlement-vs-actual, monthly evidence package, PHI gap-check. |
| `automation/automation_plan.md` | Monthly access-review automation (inputs, diff, outputs, safety controls, tools). |
| `automation/access_review.py` | Safety-first reference implementation: reconcile, gated apply, blast-radius cap, key rotation check. |
| `governance/ai_governance_notes.md` | Governance for using AI tools against a HIPAA-sensitive environment. |
| `infra/terraform_or_iac_example.tf` | IaC sketch for the governance/automation roles + evidence schema. |
| `docs/VALIDATION.md` | Evidence the controls were verified on a live Snowflake Enterprise account. |

### Platform hardening

| Path | What it is |
|---|---|
| `security/network_policies.sql` | Network policies (corporate VPN, CI/CD runner, break-glass overrides) + PrivateLink configuration guide. |
| `security/auth_session_policies.sql` | `AUTHENTICATION POLICY` (MFA enforcement) and `SESSION POLICY` (idle timeouts) for human and service identities. |
| `security/snowflake_alerts.sql` | Native Snowflake `ALERT` objects: break-glass login, PHI masking-policy detach, PHI tag removal, ACCOUNTADMIN session. |
| `audit/anomaly_detection.sql` | Behavioral anomaly detection: data-volume spikes, off-hours PHI access, novel client IPs, mass export, cross-facility probing, auto-classification gap discovery. |
| `governance/cortex_ai_governance.md` | Per-surface governance for Snowflake Cortex: LLM functions, Cortex Analyst, Cortex Search, Document AI, and ML functions — each with a distinct PHI risk profile and control set. |
| `tests/test_access_review.py` | pytest unit tests for the pure reconcile / build_expected / approval-valid core of `access_review.py`. |
| `.github/workflows/ci.yml` | CI pipeline: SQLFluff lint (Snowflake dialect), pytest, Terraform fmt + validate. |
| `dbt/` | dbt project scaffold: profiles example, source definitions for `RAW_MASKED.GOV`, staging + mart models, schema tests, and masking-behavior documentation. |
| `infra/modules/snowflake-platform/` | Full Terraform module managing the complete `AR_*`/`FR_*` role model, warehouses, schemas, service accounts, and network policies as state-tracked code. |

The role names (`FR_*` / `AR_*`) are reused verbatim across the RBAC model, audit queries,
automation, Terraform module, and dbt source definitions — the components form **one coherent
system** where a change in one layer is visible in every other.

---

## Phase 0 — Days 1–7: Assess the current state (measure before you change)

Baseline everything read-only first; you cannot tighten access safely without knowing what exists.
Capture each as an exported snapshot (this is also your "before" audit evidence).

- **Users** — `SNOWFLAKE.ACCOUNT_USAGE.USERS`: who exists, human vs `TYPE=SERVICE`, MFA/key-pair
  posture, last login, who owns each, disabled/never-logged-in accounts.
- **Roles & grants** — `GRANTS_TO_ROLES` / `GRANTS_TO_USERS`, expanded through the role hierarchy
  (access is transitive — see `audit_queries.sql` §1–2). Identify direct grants to users, use of
  `ACCOUNTADMIN`/`SECURITYADMIN` for daily work, and any role sprawl.
- **Warehouses** — sizes, auto-suspend, and whether resource monitors exist (cost guardrails).
- **Service accounts** — inventory every non-human login, its auth method (password vs key-pair),
  owner, and justification. Password-auth service accounts are an early finding to fix.
- **Network policies & integrations** — `SHOW NETWORK POLICIES`, `SHOW INTEGRATIONS` (SCIM, OAuth,
  storage, external functions): what's configured, what's unused, what's over-scoped.
- **PHI exposure** — which schemas/objects hold PHI, and whether any masking/row-access policies or
  classification tags exist today (likely none).

**Output:** a current-state inventory + a gap list, ranked by risk (e.g. password service accounts,
direct admin grants, unmasked PHI) — the input to the target design.

## Phase 1 — Days 5–12: Design Entra-driven, least-privilege RBAC

Design the target model (implemented in `snowflake_rbac.sql`) on two principles:

- **Identity-provider-driven.** Entra ID security groups are the source of truth. Via **SCIM**,
  each group is provisioned into Snowflake as a role; we grant the matching **functional role**
  (`FR_*`) to that group-role. Joiner/mover/leaver becomes a group change in Entra — **no Snowflake
  SQL per person**. Humans never receive direct `GRANT … TO USER`.
- **Two-layer roles (least privilege).** *Access roles* (`AR_*`) hold object privileges on one
  scope and are the only roles with grants on data; *functional roles* (`FR_*`) are composed from
  access roles and granted to people/services. Adding a schema means editing one access role, not
  every persona — and "who can do what" stays separate from "what privileges exist on an object."

The platform's functional roles, each backed by an Entra group:
`FR_PLATFORM_ADMIN`, `FR_DBT_TRANSFORM`, `FR_BI_REPORTING`, `FR_CLINICAL_ANALYTICS`, `FR_ANALYST`,
`FR_BREAKGLASS`.

## Phase 2 — Days 8–18: Implement, with clean separation of identities

Build the model (parallel to existing access — see Phase 3). The separations that matter:

- **Human vs. service.** Humans come only from Entra/SCIM. Service accounts (`SVC_DBT`,
  `SVC_POWERBI`) are `TYPE=SERVICE` with **key-pair auth** (no passwords, no MFA prompts), one
  least-privilege functional role each, and are the *only* direct user→role grants.
- **Admin vs. transform vs. reporting vs. analyst.** Platform admins manage the platform but are
  granted **neither** PHI clear-text (`AR_PHI_UNMASK`) **nor** policy authorship (`AR_GOV_ADMIN`), so an
  admin cannot both detach a masking policy and read the column — policy authorship is a separate
  governance role, and any policy change is logged and alerted. dbt reads masked source and owns
  builds in staging/marts/KPIs. BI/reporting and general analysts get **read-only on curated marts +
  KPIs**, masked. Clinical analysts additionally get masked clinical source **plus** the PHI-unmask
  access role.
- **Break-glass.** A sealed, **disabled** emergency role wired to `ACCOUNTADMIN` one direction only
  (avoiding the role-cycle Snowflake rejects), kept **outside** the SYSADMIN tree so it's never
  inherited, vault-stored, MFA-required, and **alert-on-use**.
- **Cost guardrails.** Per-workload warehouses, each with a **resource monitor** that notifies then
  suspends — so a looping service account can't burn unbounded credits.

## Phase 3 — Throughout: Protect PHI by default

PHI protection is built into the model, not bolted on later (`snowflake_rbac.sql` §3, §12):

- **Default-deny + masking.** PHI columns are masked at the column level via **tag-based dynamic
  masking** — tag a column once and the masking policy applies automatically to it and any future
  column with that tag. Even a granted reader sees `***REDACTED***` unless their session carries the
  `AR_PHI_UNMASK` access role (held only by clinical analysts).
- **Row-level segmentation.** A **row-access policy** limits PHI rows by facility entitlement.
- **Managed-access schemas.** PHI schemas are `WITH MANAGED ACCESS`, so only the schema owner grants
  — object owners cannot make side grants.
- **Classification.** Object **tags** (`DATA_CLASSIFICATION = 'PHI'`) make PHI discoverable and
  provide audit evidence (which columns are protected — `audit_queries.sql` §7d).

*(Masking, row-access, and tags require Snowflake **Enterprise** edition.)*

## Phase 4 — Days 12–22: Avoid breaking existing access (safe migration)

The new model is deployed **in parallel** with whatever exists today; nothing is revoked until the
new path is proven (`snowflake_rbac.sql` §14):

1. Build the new `AR_*`/`FR_*` roles alongside legacy roles (no revokes).
2. Grant the new functional roles **additively** to a pilot cohort / Entra groups — existing access
   keeps working.
3. **Verify**: pilot users run real workloads under `FR_*`; confirm masking behavior (general analyst
   sees redacted, clinical analyst sees real), row-access, and service-account key-pair auth; diff
   new-vs-legacy effective privileges via `ACCOUNT_USAGE`.
4. **Cut over** Entra group membership / default roles; monitor `LOGIN_HISTORY` / `QUERY_HISTORY`
   for failures over a soak period.
5. **Revoke legacy last**, reversibly — keep legacy roles defined (empty) for the rollback window.

Rollback at any step is a single re-grant of the still-defined legacy role.

## Phase 5 — Days 1–30: Documentation & audit evidence (continuous)

Evidence is produced as a by-product of the work, not reconstructed later:

- **Versioned change records** — the RBAC model, role matrix, and IaC live in Git; every access
  change is a reviewed PR (the matrix is change-controlled because it drives access).
- **Monthly access-review pack** — `audit_queries.sql` §7 produces a stamped evidence package: full
  user roster, PHI entitlement extract, privileged-access attestation list, control-existence
  evidence (`POLICY_REFERENCES` proving PHI columns are masked), and login anomalies. Materialize it
  to an immutable `GOVERNANCE.ACCESS_REVIEW` schema (`ACCOUNT_USAGE` only retains ~365 days; HIPAA
  evidence retention is longer).
- **AI governance** — `ai_governance_notes.md` defines how AI tools are evaluated, approved, and
  validated before use against the platform.

## Phase 6 — Days 18–30: Automate first what is highest-risk and repetitive

Automate in this order — safety and audit value first:

1. **The monthly access review** (`automation_plan.md` + `access_review.py`). It's recurring,
   error-prone by hand, and directly serves HIPAA workforce-access requirements. It reconciles actual
   vs. expected access and reports exceptions — **dry-run by default, never auto-revoking**; any
   revoke needs approval (separation of duties), a rollback plan, a live re-check, and a
   blast-radius cap.
2. **Drift detection on PHI controls** — alert if a PHI column loses its masking policy or a PHI
   schema stops being managed-access.
3. **Break-glass alerting** — page on any use of `FR_BREAKGLASS`.
4. **SCIM provisioning hardening** — once Entra→Snowflake group sync is the norm, deprecation of
   direct grants can be enforced in CI.

---

## Validation

The SQL and automation are validated, not assumed:

- **No real PHI, credentials, or secrets** — every value is a synthetic placeholder.
- Snowflake specifics (`ACCOUNT_USAGE` views/columns, masking/row-access/resource-monitor syntax,
  edition requirements, latency) are **verified against the official Snowflake documentation**.
- `snowflake_rbac.sql` and `audit_queries.sql` are **syntax-linted with SQLFluff**
  (`--dialect snowflake`); `access_review.py` compiles and its comparison core is unit-tested.
- The model was **deployed on a Snowflake Enterprise account** and masking, row-access, and
  least-privilege were verified with live query output. See **`docs/VALIDATION.md`** for the
  evidence, including screenshots of the live simulation.
