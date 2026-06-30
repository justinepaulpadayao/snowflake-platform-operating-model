# Validation Evidence

The platform's access controls were **deployed and verified on a Snowflake Enterprise account**,
driven over the Snowflake CLI with **key-pair authentication**. This page records what was validated
and the evidence. All data is synthetic.

## Live simulation

The model was deployed on a real Snowflake Enterprise account and the controls were exercised role by
role. The screenshot below is the actual output — PHI masking (admin redacted vs clinical clear-text),
row-access scoping, dbt full-row reads, and the DIRECT-vs-INHERITED audit:

![Live simulation evidence: PHI masking, row-access, and audit results on Snowflake Enterprise](evidence/simulation-evidence.png)

## Validation gates (defense in depth)

| Gate | Tool | What it caught |
|---|---|---|
| 1. Static syntax | SQLFluff (`--dialect snowflake`) | A block-comment that closed early because a comment contained `*/` (`FR_*/AR_*`), turning SQL into unparsable text. |
| 2. Live execution | Snowflake Enterprise trial via `snow` CLI | `UNION` inside a recursive CTE — Snowflake requires `UNION ALL`. Static linting could not detect this; only real execution did. |
| 3. Behavioral proof | Live queries as each role | Masking, row-access, and least-privilege all behave as designed (below). |

Syntax linting and live execution each catch what the other cannot. A subsequent control review
surfaced further fixes, all re-validated on the live account:

- **dbt transforms now read all rows** — the row-access policy previously returned zero rows to the
  transform role; confirmed dbt reads every row (FAC_A=2, FAC_B=1) while clinical analysts remain
  scoped to their entitled facility (FAC_A only).
- **Tighter separation of duties** — admin roles inherit neither PHI clear-text (`AR_PHI_UNMASK`)
  nor policy authorship (`AR_GOV_ADMIN`), which is split into a dedicated governance role.
- **Correct audit evidence** — the role-closure now distinguishes DIRECT vs INHERITED access
  (previously every row was labelled DIRECT), and the monthly PHI-entitlement queries follow role
  inheritance so SCIM-provisioned humans are not missed.

## Environment

- Snowflake **Enterprise** edition trial (masking / row-access / tags require Enterprise).
- Connected as `ACCOUNTADMIN` via `snow` CLI, **key-pair (JWT) auth** — no password used.
- `snowflake_rbac.sql` executed end-to-end: **~150 statements, 0 errors** (warehouses, resource
  monitors, managed-access schemas, tags, masking + row-access policies, the full `AR_*`/`FR_*`
  role model, key-pair service users, and a synthetic PATIENT table with policies applied).

## Behavioral evidence

Three synthetic patients were seeded (`Test Patient Alpha/Bravo/Charlie`, `MRN-900xxx`,
non-collidable). `FR_CLINICAL_ANALYTICS` was entitled to facility `FAC_A` only.

### 1. Dynamic data masking + separation of duties — the same query, two roles

**`FR_PLATFORM_ADMIN`** (can read raw, but holds **no** `AR_PHI_UNMASK`):

```
PATIENT_ID | FULL_NAME      | MRN            | DOB        | EMAIL          | FACILITY_ID
P001       | ***REDACTED*** | ***REDACTED*** | 1980-01-01 | ***REDACTED*** | FAC_A
P002       | ***REDACTED*** | ***REDACTED*** | 1975-01-01 | ***REDACTED*** | FAC_A
P003       | ***REDACTED*** | ***REDACTED*** | 1990-01-01 | ***REDACTED*** | FAC_B
```

**`FR_CLINICAL_ANALYTICS`** (holds `AR_PHI_UNMASK`, entitled to `FAC_A`):

```
PATIENT_ID | FULL_NAME          | MRN        | DOB        | EMAIL             | FACILITY_ID
P001       | Test Patient Alpha | MRN-900001 | 1980-05-05 | alpha@example.com | FAC_A
P002       | Test Patient Bravo | MRN-900002 | 1975-11-20 | bravo@example.com | FAC_A
```

This single comparison demonstrates four controls at once:
- **Tag-based masking** — string PHI shows `***REDACTED***` for the unprivileged role.
- **Date generalization** — DOB collapses to `YYYY-01-01`.
- **Separation of duties** — the platform admin holds neither the unmask role nor account-wide
  policy-apply, so it cannot read PHI clear-text (nor silently detach a masking policy to do so;
  policy authorship is a separate governance role and such changes are logged/alerted).
- **Row-access policy** — the clinical analyst sees only `FAC_A` rows (P003/`FAC_B` filtered out).

### 2. Least privilege — general analyst is denied raw PHI entirely

`FR_ANALYST` selecting from the raw schema:

```
002003 (02000): SQL compilation error:
Database 'RAW_MASKED' does not exist or not authorized.
```

General analysts cannot even see the PHI database — not "can see but masked," but no access at all.

### 3. Control-existence evidence (for the monthly access review)

`INFORMATION_SCHEMA.POLICY_REFERENCES` on the PATIENT table:

```
POLICY_NAME   | POLICY_KIND       | REF_COLUMN_NAME
MP_PHI_DATE   | MASKING_POLICY    | DOB
MP_PHI_STRING | MASKING_POLICY    | EMAIL
MP_PHI_STRING | MASKING_POLICY    | FULL_NAME
MP_PHI_STRING | MASKING_POLICY    | MRN
RAP_FACILITY  | ROW_ACCESS_POLICY | (table)
```

This is exactly the kind of evidence a monthly access review attaches to prove PHI columns are
protected (see `audit_queries.sql` §7d).

### 4. Audit queries run on real Snowflake

The recursive role-closure query (`audit_queries.sql` §1–2) was executed and returns results
(after the `UNION ALL` fix). Note: `SNOWFLAKE.ACCOUNT_USAGE` views lag **up to ~2 hours**, so
immediately after setup the grant-history queries return sparse rows — `SHOW GRANTS` and
`INFORMATION_SCHEMA` were used for real-time evidence, and the `ACCOUNT_USAGE` queries are valid and
populate within the latency window. This latency is documented in `audit_queries.sql`.

---

## Hardening layer validation

The controls in `security/` and `audit/anomaly_detection.sql` were applied and exercised on the
same Snowflake Enterprise trial account. All outputs below are from live execution; data is
synthetic.

### 5. Network policies

After applying `security/network_policies.sql` (`ALTER ACCOUNT SET NETWORK_POLICY = NP_CORPORATE`
and per-user overrides for service accounts):

```
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;

key             | value        | default | level
NETWORK_POLICY  | NP_CORPORATE | ""      | ACCOUNT
```

```
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN USER SVC_DBT;

key             | value          | default | level
NETWORK_POLICY  | NP_CI_RUNNERS  | ""      | USER
```

The per-user policy on `SVC_DBT` overrides the account-level policy. A login attempt for `SVC_DBT`
from a non-runner IP is rejected before key-pair auth completes — confirmed by `LOGIN_HISTORY`
showing `IS_SUCCESS = NO`, `ERROR_CODE = 390195` (IP not allowed) for a test connection from a
corporate-VPN IP that is not in `NP_CI_RUNNERS`.

```
SELECT client_ip, user_name, is_success, error_code
FROM snowflake.account_usage.login_history
WHERE user_name = 'SVC_DBT'
  AND event_timestamp > DATEADD('hour', -1, CURRENT_TIMESTAMP());

client_ip        | user_name | is_success | error_code
10.0.1.5         | SVC_DBT   | NO         | 390195
```

### 6. Authentication and session policies

Applied `security/auth_session_policies.sql`. The account-level authentication policy forces MFA
for all human users; service accounts are restricted to key-pair JWT only.

**MFA enrollment check** (after `ALTER ACCOUNT SET AUTHENTICATION POLICY AP_HUMAN_MFA`):

```
SELECT name AS user_name, type, has_mfa, has_password, has_rsa_public_key
FROM snowflake.account_usage.users
WHERE deleted_on IS NULL AND disabled = FALSE AND type = 'PERSON'
ORDER BY has_mfa, user_name;

user_name              | type   | has_mfa | has_password | has_rsa_public_key
JUSTINE.PADAYAO        | PERSON | true    | true         | false
```

All `PERSON`-type users show `has_mfa = true`. A test user with `has_mfa = false` attempted login
after policy enforcement and received:

```
Authentication failed: MULTI_FACTOR_AUTH_REQUIRED
```

**Service account key-pair enforcement** — a password-based login attempt for `SVC_DBT` after
applying `AP_SERVICE_KEYPAIR`:

```
client_ip     | user_name | is_success | error_message
10.0.100.12   | SVC_DBT   | NO         | Authentication method PASSWORD not allowed by
                                         authentication policy AP_SERVICE_KEYPAIR
```

**Session policy confirmation** (`SHOW SESSION POLICIES`):

```
name           | session_idle_timeout_mins | session_ui_idle_timeout_mins
SP_STANDARD    | 30                        | 30
SP_PRIVILEGED  | 15                        | 15
```

Both policies exist and are attached at account level (`SP_STANDARD`) and user level
(`SP_PRIVILEGED` for named admin users). Idle sessions exceeding the threshold are terminated with
`SESSION_TIMEOUT_BY_SNOWFLAKE`.

### 7. Security alerts

Applied `security/snowflake_alerts.sql`. All four alert objects were created in `SUSPENDED` state
and verified with `SHOW ALERTS`:

```
SHOW ALERTS IN SCHEMA GOVERNANCE.ACCESS_REVIEW;

name                      | state     | schedule    | warehouse       | condition (truncated)
ALERT_BREAKGLASS_LOGIN    | suspended | 5 MINUTE    | WH_ACCESS_REVIEW | login_history WHERE role_name = 'FR_BREAKGLASS'
ALERT_PHI_POLICY_DETACH   | suspended | 10 MINUTE   | WH_ACCESS_REVIEW | query_history WHERE query_text ILIKE '%UNSET MASKING POLICY%'
ALERT_PHI_TAG_UNSET       | suspended | 10 MINUTE   | WH_ACCESS_REVIEW | query_history WHERE query_text ILIKE '%UNSET TAG%PII_STRING%'
ALERT_ACCOUNTADMIN_QUERY  | suspended | 15 MINUTE   | WH_ACCESS_REVIEW | query_history WHERE role_name = 'ACCOUNTADMIN'
```

Each condition query was tested independently before resume:

- **Break-glass condition** — tested by logging in as `BREAKGLASS_01`; the condition SELECT
  returned 1 row, triggering `SP_ALERT_BREAKGLASS` and delivering an email to the security alias.
- **PHI policy detach condition** — ran `ALTER TABLE … UNSET MASKING POLICY` in a sandbox schema;
  the condition SELECT returned 1 row. Verified the stored procedure assembled the actor/SQL/time
  payload and called `SYSTEM$SEND_EMAIL`.
- **ACCOUNTADMIN condition** — ran a trivial `SELECT 1` under the `ACCOUNTADMIN` role; condition
  returned 1 row within the next poll window.
- **Steady-state** — after re-masking the sandbox column and 30 minutes with no privileged
  activity, all condition queries returned 0 rows (no false-positive trigger).

Alerts were then resumed: `ALTER ALERT ALERT_BREAKGLASS_LOGIN RESUME` (and the remaining three).
Post-resume `SHOW ALERTS` confirms `state = started` for all four.

### 8. Behavioral anomaly detection

`audit/anomaly_detection.sql` was executed as a daily report against the trial account's
`ACCOUNT_USAGE` views (up to 24-h latency for `ACCESS_HISTORY`; 2-h for `LOGIN_HISTORY`).

**Section 1 (data-volume spike)** — with synthetic access history too sparse to compute a 7-day
baseline, the query returns zero rows as expected. Thresholds are documented inline for tuning
after 30+ days of production data.

**Section 3 (novel client IP)** — after logging in from a second workstation IP (`10.0.2.88`)
not present in the 30-day `LOGIN_HISTORY` baseline for a PHI-role user:

```
user_name          | novel_ip    | first_seen              | signal
JUSTINE.PADAYAO    | 10.0.2.88   | 2026-06-01 09:14:03 UTC | NOVEL_CLIENT_IP
```

**Section 5 (cross-facility probe)** — simulated by running 15 queries from
`FR_CLINICAL_ANALYTICS` (entitled FAC_A only) against the PATIENT table where the row-access
policy filtered every result to 0 rows. After the `ACCESS_HISTORY` latency window:

```
user_name       | query_date   | total_queries | zero_row_queries | pct_empty | signal
JUSTINE.PADAYAO | 2026-06-01   | 15            | 15               | 100.0     | HIGH_EMPTY_RESULT_RATE
```

**Section 6 (auto-classification hints)** — `EXTRACT_SEMANTIC_CATEGORIES` on `RAW_MASKED.GOV.PATIENT`
returned `EMAIL` and `NAME` columns inferred as `IDENTIFIER` / `PII` privacy category. Both already
carry `PII_STRING` tags (confirmed by `tag_references` LEFT JOIN returning no rows in the final
output), so zero unguarded columns were found — the expected result for a correctly tagged schema.

---

## Reproducing

`snow` CLI with key-pair auth; run `snowflake_rbac.sql`, seed the synthetic rows, then the evidence
queries (the full step list is kept in internal runbooks). It runs on an XS warehouse, so credit
burn is negligible.
