/* ============================================================================
   audit_queries.sql
   Access & PHI audit pack for the Snowflake RBAC model in snowflake_rbac.sql.
   Identity: Microsoft Entra ID (SSO/SCIM). Data class: PHI (HIPAA).

   SOURCE: SNOWFLAKE.ACCOUNT_USAGE (the audit system of record).
   RUN AS: a role with IMPORTED PRIVILEGES on the SNOWFLAKE database
           (ACCOUNTADMIN, or a dedicated AUDITOR role granted that privilege).

   CAVEATS (verified against docs.snowflake.com, 2026):
     - ACCOUNT_USAGE latency varies by view (typically 1-6 h; LOGIN_HISTORY up to
       ~120 min). Treat results as "as of up to the latency window ago".
     - Retention ~365 days. For HIPAA's longer evidence window, materialize the
       monthly package (section 7) to an immutable REVIEW.YYYY_MM schema.
     - Soft deletes: these views keep dropped rows. We filter DELETED_ON IS NULL
       everywhere except the change-history query (section 5), where a non-null
       DELETED_ON is the revoke signal. PHI is identified by the RAW_MASKED.GOV
       schema and the DATA_CLASSIFICATION = 'PHI' tag.
     - ACCESS_HISTORY (section 6c) requires ENTERPRISE edition.
     - Role names below match snowflake_rbac.sql (FR_ and AR_ roles). PHI is
       by the RAW_MASKED.GOV schema and the DATA_CLASSIFICATION = 'PHI' tag.
   ============================================================================ */


/* ============================================================================
   (1) WHO CAN ACCESS PHI-SENSITIVE SCHEMAS OR ROLES
   Snowflake access is transitive (role -> role -> user). A flat GRANTS_TO_USERS
   query under-reports access. The recursive CTE walks USAGE-on-ROLE edges so
   inherited access is caught, and each row is tagged DIRECT vs INHERITED.
   ============================================================================ */

-- 1a. Roles holding any privilege on PHI objects, expanded to effective roles.
WITH phi_roles AS (
    SELECT DISTINCT grantee_name AS role_name
    FROM snowflake.account_usage.grants_to_roles
    WHERE deleted_on IS NULL
      AND (table_catalog = 'RAW_MASKED'    -- all RAW_MASKED schemas (PHI source)
           OR name ILIKE '%PHI%')          -- EDIT: extend to your PHI naming
),

role_edges AS (   -- child role -> parent role that inherits it
    SELECT name AS child_role, grantee_name AS parent_role
    FROM snowflake.account_usage.grants_to_roles
    WHERE granted_on = 'ROLE' AND privilege = 'USAGE' AND deleted_on IS NULL
),

closure (top_role, reachable_role) AS (
    SELECT role_name, role_name FROM phi_roles
    UNION ALL  -- Snowflake requires UNION ALL in a recursive CTE; outer DISTINCT dedups
    SELECT e.parent_role, c.reachable_role
    FROM role_edges e
    INNER JOIN closure c ON e.child_role = c.top_role
)

SELECT DISTINCT
    gu.grantee_name AS user_name,
    c.top_role      AS effective_role,
    CASE WHEN c.top_role = c.reachable_role THEN 'DIRECT' ELSE 'INHERITED' END AS access_path
FROM closure c
INNER JOIN snowflake.account_usage.grants_to_users gu
    ON gu.role = c.top_role AND gu.deleted_on IS NULL
ORDER BY user_name, effective_role;


/* ============================================================================
   (2) WHO HOLDS POWERFUL / ADMIN ROLES (direct + inherited)
   Same closure pattern seeded with the built-in privileged roles plus the
   custom break-glass role.
   ============================================================================ */
WITH admin_roles (role_name) AS (
    SELECT * FROM VALUES
        ('ACCOUNTADMIN'), ('SECURITYADMIN'), ('SYSADMIN'),
        ('USERADMIN'), ('ORGADMIN'), ('FR_BREAKGLASS'), ('FR_PLATFORM_ADMIN')
),

role_edges AS (
    SELECT name AS child_role, grantee_name AS parent_role
    FROM snowflake.account_usage.grants_to_roles
    WHERE granted_on = 'ROLE' AND privilege = 'USAGE' AND deleted_on IS NULL
),

closure (top_role, reachable_role) AS (
    SELECT role_name, role_name FROM admin_roles
    UNION ALL  -- Snowflake requires UNION ALL in a recursive CTE; outer DISTINCT dedups
    SELECT e.parent_role, c.reachable_role
    FROM role_edges e
    INNER JOIN closure c ON e.child_role = c.top_role
)

SELECT DISTINCT
    gu.grantee_name AS user_name,
    c.top_role      AS privileged_role,
    CASE WHEN c.top_role = c.reachable_role THEN 'DIRECT' ELSE 'INHERITED' END AS access_path,
    u.disabled,
    u.has_mfa,
    u.last_success_login
FROM closure c
INNER JOIN snowflake.account_usage.grants_to_users gu
    ON gu.role = c.top_role AND gu.deleted_on IS NULL
LEFT JOIN snowflake.account_usage.users u
    ON u.name = gu.grantee_name AND u.deleted_on IS NULL
ORDER BY privileged_role, user_name;


/* ============================================================================
   (3) SERVICE USERS AND THEIR ROLES
   Prefer USERS.TYPE = 'SERVICE'; fall back to key-pair + no-password and
   naming convention. No single flag is definitive.
   ============================================================================ */
SELECT
    u.name AS service_user,
    u.type,
    u.has_password,
    u.has_rsa_public_key,
    u.has_mfa,
    u.disabled,
    u.default_role,
    u.default_warehouse,
    u.owner,
    u.last_success_login,
    LISTAGG(DISTINCT gu.role, ', ') WITHIN GROUP (ORDER BY gu.role) AS roles_held
FROM snowflake.account_usage.users u
LEFT JOIN snowflake.account_usage.grants_to_users gu
    ON gu.grantee_name = u.name AND gu.deleted_on IS NULL
WHERE u.deleted_on IS NULL
  AND (u.type = 'SERVICE'
       OR (u.has_rsa_public_key = TRUE AND u.has_password = FALSE)
       OR u.name ILIKE ANY ('SVC_%', '%_SVC', '%SERVICE%'))
GROUP BY ALL
ORDER BY service_user;


/* ============================================================================
   (4) USERS WHO HAVE NOT LOGGED IN RECENTLY (dormant / never used)
   Window: 90 days (EDIT). Only enabled accounts matter for remediation.
   ============================================================================ */
SELECT
    name AS user_name,
    type,
    disabled,
    created_on,
    last_success_login,
    DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) AS days_since_login,
    default_role,
    owner
FROM snowflake.account_usage.users
WHERE deleted_on IS NULL
  AND disabled = FALSE
  AND (last_success_login IS NULL  -- never logged in
       OR last_success_login < DATEADD('day', -90, CURRENT_TIMESTAMP()))
ORDER BY days_since_login DESC NULLS FIRST;


/* ============================================================================
   (5) GRANTS ADDED OR CHANGED RECENTLY (last 30 days, incl. revokes)
   CREATED_ON = granted; DELETED_ON = revoked.
   ============================================================================ */
-- 5a. Privileges granted to / revoked from roles.
SELECT
    'GRANT_TO_ROLE' AS change_scope,
    created_on,
    deleted_on,
    CASE WHEN deleted_on IS NULL THEN 'ADDED' ELSE 'REVOKED' END AS action,
    grantee_name AS role_name,
    privilege,
    granted_on   AS object_type,
    name         AS object_name,
    granted_by
FROM snowflake.account_usage.grants_to_roles
WHERE created_on >= DATEADD('day', -30, CURRENT_TIMESTAMP())
   OR deleted_on >= DATEADD('day', -30, CURRENT_TIMESTAMP())

UNION ALL

-- 5b. Roles granted to / revoked from users.
SELECT
    'GRANT_TO_USER' AS change_scope,
    created_on,
    deleted_on,
    CASE WHEN deleted_on IS NULL THEN 'ADDED' ELSE 'REVOKED' END AS action,
    grantee_name AS role_name,
    'ROLE'       AS privilege,
    'USER'       AS object_type,
    role         AS object_name,
    granted_by
FROM snowflake.account_usage.grants_to_users
WHERE created_on >= DATEADD('day', -30, CURRENT_TIMESTAMP())
   OR deleted_on >= DATEADD('day', -30, CURRENT_TIMESTAMP())
ORDER BY created_on DESC;


/* ============================================================================
   (6) ROLES THAT APPEAR UNUSED OR OVER-PRIVILEGED
   ============================================================================ */
-- 6a. FUNCTIONAL roles never used to run a query in 90 days (unused candidates).
--     AR_* access roles are excluded: by design they are only ever INHERITED by
--     functional roles, never a session's active role, so they would otherwise
--     all appear here as false positives.
WITH used_roles AS (
    SELECT DISTINCT role_name
    FROM snowflake.account_usage.query_history
    WHERE start_time >= DATEADD('day', -90, CURRENT_TIMESTAMP())
      AND role_name IS NOT NULL
)

SELECT r.name AS role_name, 'NO QUERIES IN 90 DAYS' AS finding
FROM snowflake.account_usage.roles r
LEFT JOIN used_roles ur ON ur.role_name = r.name
WHERE r.deleted_on IS NULL
  AND ur.role_name IS NULL
  AND NOT STARTSWITH(r.name, 'AR_')  -- access roles are inherited by design, not session roles
ORDER BY r.name;

-- 6b. Roles holding broad/dangerous privileges (over-provisioned indicator).
SELECT
    grantee_name AS role_name,
    COUNT(*)     AS privilege_count,
    LISTAGG(DISTINCT privilege, ', ') WITHIN GROUP (ORDER BY privilege) AS privileges
FROM snowflake.account_usage.grants_to_roles
WHERE deleted_on IS NULL
  AND privilege IN (
      'MANAGE GRANTS', 'CREATE ROLE', 'CREATE USER', 'OWNERSHIP',
      'APPLY MASKING POLICY', 'APPLY ROW ACCESS POLICY', 'CREATE INTEGRATION',
      'CREATE DATABASE'
  )
GROUP BY grantee_name
ORDER BY privilege_count DESC;

-- 6c. STRONGEST signal (Enterprise): PHI granted but NEVER read in 90 days.
--     phi_role_members uses the recursive role-closure so users who receive a PHI
--     role THROUGH a SCIM Entra group-role are included. A flat GRANTS_TO_USERS
--     filter would miss every human (they hold the group-role, not FR_* directly)
--     and catch only service accounts.
WITH phi_readers AS (
    SELECT DISTINCT ah.user_name
    FROM snowflake.account_usage.access_history ah,
         LATERAL FLATTEN(input => ah.base_objects_accessed) f
    WHERE ah.query_start_time >= DATEADD('day', -90, CURRENT_TIMESTAMP())
      AND f.value:objectName::string ILIKE 'RAW_MASKED.GOV.%'  -- EDIT to PHI scope
),

phi_seed (role_name) AS (
    SELECT * FROM VALUES ('FR_CLINICAL_ANALYTICS'), ('AR_PHI_UNMASK')
),
role_edges AS (
    SELECT name AS child_role, grantee_name AS parent_role
    FROM snowflake.account_usage.grants_to_roles
    WHERE granted_on = 'ROLE' AND privilege = 'USAGE' AND deleted_on IS NULL
),
phi_closure (top_role) AS (
    SELECT role_name FROM phi_seed
    UNION ALL
    SELECT e.parent_role
    FROM role_edges e INNER JOIN phi_closure c ON e.child_role = c.top_role
),
phi_role_members AS (
    SELECT DISTINCT gu.grantee_name AS user_name
    FROM snowflake.account_usage.grants_to_users gu
    INNER JOIN phi_closure c ON gu.role = c.top_role
    WHERE gu.deleted_on IS NULL
)

SELECT m.user_name, 'HAS PHI ROLE, NO PHI ACCESS IN 90 DAYS' AS finding
FROM phi_role_members m
LEFT JOIN phi_readers r ON r.user_name = m.user_name
WHERE r.user_name IS NULL
ORDER BY m.user_name;


/* ============================================================================
   (7) MONTHLY ACCESS REVIEW -- EVIDENCE PACKAGE
   Export each result and attach to the signed review. Stamp every export.
   ============================================================================ */
-- 7a. Stamped attestation header (proves "reviewed on date X by Y").
SELECT
    CURRENT_ACCOUNT()   AS account,
    CURRENT_REGION()    AS region,
    CURRENT_TIMESTAMP() AS review_run_at,
    CURRENT_USER()      AS reviewer,
    'HIPAA Monthly Access Review' AS review_type;

-- 7b. Full user roster + auth posture (master attestation list).
SELECT
    name AS user_name, type, disabled, created_on, last_success_login,
    has_password, has_rsa_public_key, has_mfa, default_role, email, owner
FROM snowflake.account_usage.users
WHERE deleted_on IS NULL
ORDER BY disabled, user_name;

-- 7c. PHI entitlement extract (users who can reach PHI-relevant roles) for sign-off.
--     Uses the recursive closure so SCIM-inherited entitlements are included, and
--     reports both the role the user holds and the PHI role it reaches.
WITH phi_seed (role_name) AS (
    SELECT * FROM VALUES ('FR_CLINICAL_ANALYTICS'), ('AR_PHI_UNMASK'), ('FR_PLATFORM_ADMIN')
),
role_edges AS (
    SELECT name AS child_role, grantee_name AS parent_role
    FROM snowflake.account_usage.grants_to_roles
    WHERE granted_on = 'ROLE' AND privilege = 'USAGE' AND deleted_on IS NULL
),
phi_closure (top_role, phi_role) AS (
    SELECT role_name, role_name FROM phi_seed
    UNION ALL
    SELECT e.parent_role, c.phi_role
    FROM role_edges e INNER JOIN phi_closure c ON e.child_role = c.top_role
)
SELECT DISTINCT
    gu.grantee_name AS user_name,
    c.phi_role      AS phi_role_reached,
    gu.role         AS granted_via_role,
    u.disabled,
    u.last_success_login
FROM phi_closure c
INNER JOIN snowflake.account_usage.grants_to_users gu
    ON gu.role = c.top_role AND gu.deleted_on IS NULL
INNER JOIN snowflake.account_usage.users u
    ON u.name = gu.grantee_name AND u.deleted_on IS NULL
ORDER BY phi_role_reached, user_name;

-- 7d. Control-existence evidence: PHI columns actually protected by policies.
SELECT
    policy_name, policy_kind, ref_database_name, ref_schema_name,
    ref_entity_name, ref_column_name
FROM snowflake.account_usage.policy_references
WHERE policy_kind IN ('MASKING_POLICY', 'ROW_ACCESS_POLICY')
ORDER BY ref_database_name, ref_schema_name, ref_entity_name;

-- 7e. Failed-login summary (anomaly / brute-force signal) over the period.
SELECT
    user_name,
    COUNT(*)                  AS failed_logins,
    COUNT(DISTINCT client_ip) AS distinct_ips,
    MIN(event_timestamp)      AS first_failure,
    MAX(event_timestamp)      AS last_failure
FROM snowflake.account_usage.login_history
WHERE event_timestamp >= DATEADD('day', -30, CURRENT_TIMESTAMP())
  AND is_success = 'NO'
GROUP BY user_name
HAVING COUNT(*) >= 5
ORDER BY failed_logins DESC;

-- 7f. GAP CHECK: PHI/PII-tagged COLUMNS with NO masking policy attached.
--     Positive-only policy evidence (7d) proves what IS protected; this proves
--     nothing is MISSED. A non-empty result is a control gap -- a tagged PHI
--     column exposed in clear text -- and should fail the review.
--     (Verify TAG_REFERENCES / POLICY_REFERENCES column names on your account.)
SELECT
    t.object_database, t.object_schema, t.object_name, t.column_name,
    t.tag_name, t.tag_value
FROM snowflake.account_usage.tag_references t
LEFT JOIN snowflake.account_usage.policy_references p
    ON  p.ref_database_name = t.object_database
    AND p.ref_schema_name   = t.object_schema
    AND p.ref_entity_name   = t.object_name
    AND p.ref_column_name   = t.column_name
    AND p.policy_kind       = 'MASKING_POLICY'
WHERE t.tag_name IN ('PII_STRING', 'PII_DATE')   -- the PHI tags from snowflake_rbac.sql
  AND t.column_name IS NOT NULL
  AND p.policy_name IS NULL                       -- tagged PHI column, no mask
ORDER BY t.object_database, t.object_schema, t.object_name, t.column_name;

/* ----------------------------------------------------------------------------
   CAVEAT: GRANTS_TO_ROLES does not fully represent FUTURE grants or database
   roles. If PHI schemas use future grants (this model does), add to the monthly
   run:  SHOW FUTURE GRANTS IN SCHEMA RAW_MASKED.GOV;  (a SHOW command, not
   ACCOUNT_USAGE) to capture entitlements that will apply to new objects.
   -------------------------------------------------------------------------- */
