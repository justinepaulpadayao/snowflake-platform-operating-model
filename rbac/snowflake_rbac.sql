/* ============================================================================
   snowflake_rbac.sql
   Secure RBAC model for a HIPAA / PHI healthcare data platform on Snowflake.
   Identity: Microsoft Entra ID -> Snowflake via SCIM provisioning.

   DESIGN (two-layer RBAC, Snowflake-recommended):
     AR_*  ACCESS roles      -> hold object privileges on ONE scope. Never
                                granted to people. The only roles with grants
                                on databases/schemas/objects.
     FR_*  FUNCTIONAL roles  -> granted to Entra groups (via SCIM) and service
                                users. Composed from AR_* roles. Hold no object
                                privileges directly.
   This separates "what privileges exist on an object" from "who can do what",
   so adding a schema means editing one access role, not every persona.

   EXECUTION ROLES:
     SYSADMIN      - warehouses, databases, schemas, governance objects.
     USERADMIN     - role and user creation.
     SECURITYADMIN - grants between roles, role hierarchy.
     ACCOUNTADMIN  - resource monitors, break-glass wiring (minimal use).

   EDITION: masking policies, row-access policies, and object tags require
            Snowflake ENTERPRISE edition or higher (verify in your account:
            SHOW PARAMETERS LIKE 'edition' IN ACCOUNT). Core RBAC works on all
            editions. Verified against docs.snowflake.com (2026); some syntax is
            approximate where noted -- validate on the target account.

   SAFETY: all identifiers, group names, and RSA keys below are SYNTHETIC
           PLACEHOLDERS. Replace <...> tokens before running. No real PHI or
           secrets appear in this file. See section 14 for non-breaking rollout.

   VALIDATION: syntax-linted with `sqlfluff lint --dialect snowflake` (0 parse
           errors except CREATE RESOURCE MONITOR in section 1, which is a known
           SQLFluff dialect gap, not a syntax error -- the statement matches the
           current CREATE RESOURCE MONITOR grammar in the Snowflake docs).
           True validation is on a Snowflake Enterprise trial (masking/row-access
           require Enterprise); an XS warehouse keeps credit burn negligible.
   ============================================================================ */


/* ============================================================================
   SECTION 1 -- WAREHOUSES + RESOURCE MONITORS (run as SYSADMIN / ACCOUNTADMIN)
   Separate compute per workload so cost and concurrency are isolated. Resource
   monitors cap runaway spend (a service account looping a query, etc.).
   ============================================================================ */
USE ROLE SYSADMIN;

CREATE WAREHOUSE IF NOT EXISTS WH_ADMIN
    WAREHOUSE_SIZE = 'XSMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE COMMENT = 'Platform admin / break-glass';

CREATE WAREHOUSE IF NOT EXISTS WH_TRANSFORM
    WAREHOUSE_SIZE = 'SMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE COMMENT = 'dbt transformation runs';

CREATE WAREHOUSE IF NOT EXISTS WH_BI
    WAREHOUSE_SIZE = 'SMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE COMMENT = 'Power BI / reporting';

CREATE WAREHOUSE IF NOT EXISTS WH_ANALYST
    WAREHOUSE_SIZE = 'SMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE COMMENT = 'Ad-hoc + clinical analytics';

USE ROLE ACCOUNTADMIN;  -- resource monitors require ACCOUNTADMIN

CREATE RESOURCE MONITOR IF NOT EXISTS RM_TRANSFORM
    WITH CREDIT_QUOTA = 200 FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY
    TRIGGERS ON 80 PERCENT DO NOTIFY
             ON 100 PERCENT DO SUSPEND
             ON 110 PERCENT DO SUSPEND_IMMEDIATE;

CREATE RESOURCE MONITOR IF NOT EXISTS RM_BI
    WITH CREDIT_QUOTA = 150 FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY
    TRIGGERS ON 80 PERCENT DO NOTIFY
             ON 100 PERCENT DO SUSPEND;

CREATE RESOURCE MONITOR IF NOT EXISTS RM_ANALYST
    WITH CREDIT_QUOTA = 150 FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY
    TRIGGERS ON 80 PERCENT DO NOTIFY
             ON 100 PERCENT DO SUSPEND;

ALTER WAREHOUSE WH_TRANSFORM SET RESOURCE_MONITOR = RM_TRANSFORM;
ALTER WAREHOUSE WH_BI        SET RESOURCE_MONITOR = RM_BI;
ALTER WAREHOUSE WH_ANALYST   SET RESOURCE_MONITOR = RM_ANALYST;


/* ============================================================================
   SECTION 2 -- DATABASES + MANAGED-ACCESS SCHEMAS (run as SYSADMIN)
   WITH MANAGED ACCESS: only the schema owner grants on objects in the schema;
   object owners cannot make side grants. Critical control for PHI.
   ============================================================================ */
USE ROLE SYSADMIN;

CREATE DATABASE IF NOT EXISTS RAW_MASKED COMMENT = 'Masked PHI source layer';
CREATE DATABASE IF NOT EXISTS ANALYTICS  COMMENT = 'Modeled analytics layer';
CREATE DATABASE IF NOT EXISTS KPIS       COMMENT = 'Curated KPI / metrics layer';

CREATE SCHEMA IF NOT EXISTS RAW_MASKED.GOV       WITH MANAGED ACCESS
    COMMENT = 'Governance: tags, masking + row-access policies, clinical source';
CREATE SCHEMA IF NOT EXISTS RAW_MASKED.METADATA  WITH MANAGED ACCESS
    COMMENT = 'Lineage / catalog / operational metadata';
CREATE SCHEMA IF NOT EXISTS ANALYTICS.STAGING    WITH MANAGED ACCESS
    COMMENT = 'dbt staging / intermediate (internal only)';
CREATE SCHEMA IF NOT EXISTS ANALYTICS.MARTS      WITH MANAGED ACCESS
    COMMENT = 'Consumption-ready marts';
CREATE SCHEMA IF NOT EXISTS KPIS.REPORTING       WITH MANAGED ACCESS
    COMMENT = 'Published KPI tables/views for reporting';


/* ============================================================================
   SECTION 3 -- GOVERNANCE OBJECTS: TAGS, MASKING + ROW-ACCESS POLICIES
   (run as SYSADMIN). Centralized in RAW_MASKED.GOV. PHI is masked at the
   column level so even a granted reader sees redacted values unless their
   session carries the AR_PHI_UNMASK access role.
   ============================================================================ */
USE ROLE SYSADMIN;

-- 3a. Classification + PII tags ------------------------------------------------
CREATE TAG IF NOT EXISTS RAW_MASKED.GOV.DATA_CLASSIFICATION
    ALLOWED_VALUES 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'PHI'
    COMMENT = 'Object/column data classification';

CREATE TAG IF NOT EXISTS RAW_MASKED.GOV.PII_STRING
    COMMENT = 'String PHI (name, MRN, address, email) -> string mask';

CREATE TAG IF NOT EXISTS RAW_MASKED.GOV.PII_DATE
    COMMENT = 'Date PHI (DOB, admit/discharge) -> date generalization';

-- 3b. Masking policies (one per data type) ------------------------------------
-- PREDICATE CHOICE: IS_GRANTED_TO_INVOKER_ROLE (not IS_ROLE_IN_SESSION).
--   IS_GRANTED_TO_INVOKER_ROLE evaluates ONLY the invoker's PRIMARY role and its
--   inheritance -- it excludes activated SECONDARY roles. IS_ROLE_IN_SESSION also
--   counts secondary roles, so under `USE SECONDARY ROLES ALL` (the Snowsight
--   default) a user who holds AR_PHI_UNMASK merely as a secondary role would see
--   cleartext PHI. For a PHI gate we want the fail-closed, primary-role-only
--   semantics. Verified live: with the unmask role active only as a SECONDARY
--   role the column stays REDACTED; it unmasks when reached through the PRIMARY
--   role's inheritance. See governance/adr_phi_masking_predicate.md.
-- OPERATIONAL DEPENDENCY: PHI-cleared users MUST have DEFAULT_ROLE set to the
--   role that carries AR_PHI_UNMASK (FR_CLINICAL_ANALYTICS) so the unmask role is
--   their PRIMARY role at query time. SCIM does not set DEFAULT_ROLE; it is set
--   out-of-band (Section 11). DEFAULT_SECONDARY_ROLES = ('ALL') does NOT satisfy
--   this predicate -- auto-activated secondaries are exactly what it ignores.
-- DEPLOY NOTE: a masking policy already ATTACHED to a tag/column cannot be
--   CREATE OR REPLACE'd (Snowflake: "associated with one or more entities").
--   The CREATE ... IF NOT EXISTS handles a fresh account; the ALTER ... SET BODY
--   immediately after enforces/updates the predicate IN PLACE on any re-run or
--   when migrating an existing deployment off the older IS_ROLE_IN_SESSION body.
CREATE MASKING POLICY IF NOT EXISTS RAW_MASKED.GOV.MP_PHI_STRING
    AS (val STRING) RETURNS STRING ->
        CASE
            WHEN IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK') THEN val
            ELSE '***REDACTED***'
        END
    COMMENT = 'Masks string PHI unless the invoker PRIMARY role holds AR_PHI_UNMASK';
ALTER MASKING POLICY RAW_MASKED.GOV.MP_PHI_STRING SET BODY ->
    CASE
        WHEN IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK') THEN val
        ELSE '***REDACTED***'
    END;

CREATE MASKING POLICY IF NOT EXISTS RAW_MASKED.GOV.MP_PHI_DATE
    AS (val DATE) RETURNS DATE ->
        CASE
            WHEN IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK') THEN val
            ELSE DATE_FROM_PARTS(YEAR(val), 1, 1)  -- generalize to Jan-1 of year
        END
    COMMENT = 'Generalizes DOB unless the invoker PRIMARY role holds AR_PHI_UNMASK';
ALTER MASKING POLICY RAW_MASKED.GOV.MP_PHI_DATE SET BODY ->
    CASE
        WHEN IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK') THEN val
        ELSE DATE_FROM_PARTS(YEAR(val), 1, 1)
    END;

-- 3c. Tag-based masking: attach policy to the TAG, not each column. Any column
--     carrying the tag (now or in future) inherits the mask automatically.
ALTER TAG RAW_MASKED.GOV.PII_STRING SET MASKING POLICY RAW_MASKED.GOV.MP_PHI_STRING;
ALTER TAG RAW_MASKED.GOV.PII_DATE   SET MASKING POLICY RAW_MASKED.GOV.MP_PHI_DATE;

-- 3d. Row-access policy: clinical/facility row segmentation -------------------
CREATE TABLE IF NOT EXISTS RAW_MASKED.GOV.ROW_ENTITLEMENTS (
    role_name   STRING,
    facility_id STRING
) COMMENT = 'Maps a role to the facilities it may see (governance-owned)';

-- The argument is named distinctly (arg_facility_id) so the correlated subquery
-- cannot accidentally resolve `facility_id` to ROW_ENTITLEMENTS.facility_id.
--
-- PREDICATE CHOICE (deliberate, and different from the masking policies above):
--   Row-access uses IS_ROLE_IN_SESSION; masking uses IS_GRANTED_TO_INVOKER_ROLE.
--   This is NOT an oversight. The entitlement branch is DATA-DRIVEN -- it checks
--   a role name pulled from a column (e.role_name) -- and IS_GRANTED_TO_INVOKER_ROLE
--   accepts only a STRING LITERAL argument (verified live: a column argument
--   raises "invalid argument for function"). So the invoker-role predicate cannot
--   express a table-driven entitlement check; IS_ROLE_IN_SESSION is the only
--   option here.
--   Coherence: this makes row visibility (secondary-role-aware) potentially
--   BROADER than column visibility (primary-role-only). The mismatch FAILS CLOSED
--   -- the only possible divergence is "rows visible, PHI columns still masked",
--   never the reverse -- so it cannot leak PHI. And once PHI-cleared users carry
--   DEFAULT_ROLE = FR_CLINICAL_ANALYTICS (Section 11), the clinical role is their
--   PRIMARY role and both predicates agree, so the distinction is moot on the
--   intended path. See governance/adr_phi_masking_predicate.md.
CREATE ROW ACCESS POLICY IF NOT EXISTS RAW_MASKED.GOV.RAP_FACILITY
    AS (arg_facility_id STRING) RETURNS BOOLEAN ->
        -- Full-row roles: platform admin, break-glass, and dbt (transforms must
        -- read every row of source; they operate on already-masked columns).
        -- These are deterministic-primary identities (service users / a named
        -- break-glass user with a fixed DEFAULT_ROLE), so IS_ROLE_IN_SESSION and
        -- primary-role semantics coincide for them.
        IS_ROLE_IN_SESSION('FR_PLATFORM_ADMIN')
        OR IS_ROLE_IN_SESSION('FR_BREAKGLASS')
        OR IS_ROLE_IN_SESSION('FR_DBT_TRANSFORM')
        OR EXISTS (
            SELECT 1 FROM RAW_MASKED.GOV.ROW_ENTITLEMENTS e
            WHERE e.facility_id = arg_facility_id
              AND IS_ROLE_IN_SESSION(e.role_name)  -- must be a column; invoker-role fn rejects non-literals
        )
    COMMENT = 'Row-level facility entitlement for PHI tables';


/* ============================================================================
   SECTION 4 -- ACCESS ROLES (AR_*) (run as USERADMIN)
   Hold object privileges only. Named AR_<scope>_<R|RW>.
   ============================================================================ */
USE ROLE USERADMIN;

CREATE ROLE IF NOT EXISTS AR_RAW_GOV_R        COMMENT = 'Read RAW_MASKED.GOV (masked clinical source)';
CREATE ROLE IF NOT EXISTS AR_RAW_METADATA_R   COMMENT = 'Read RAW_MASKED.METADATA';
CREATE ROLE IF NOT EXISTS AR_STAGING_RW       COMMENT = 'Read/write/DDL ANALYTICS.STAGING (dbt)';
CREATE ROLE IF NOT EXISTS AR_MARTS_RW         COMMENT = 'Read/write/DDL ANALYTICS.MARTS (dbt)';
CREATE ROLE IF NOT EXISTS AR_MARTS_R          COMMENT = 'Read ANALYTICS.MARTS';
CREATE ROLE IF NOT EXISTS AR_KPIS_RW          COMMENT = 'Read/write/DDL KPIS.REPORTING (dbt)';
CREATE ROLE IF NOT EXISTS AR_KPIS_R           COMMENT = 'Read KPIS.REPORTING';
CREATE ROLE IF NOT EXISTS AR_PHI_UNMASK       COMMENT = 'Clear-text PHI gate (referenced by masking policies)';
CREATE ROLE IF NOT EXISTS AR_GOV_ADMIN        COMMENT = 'Manage tags / masking / row-access policies';

-- Object-privilege access roles live in the SYSADMIN tree so SYSADMIN can manage
-- object grants. The two CAPABILITY roles are deliberately EXCLUDED so SYSADMIN
-- (and ACCOUNTADMIN above it) does not inherit them:
--   AR_PHI_UNMASK -- clear-text PHI; kept only on clinical roles
--   AR_GOV_ADMIN  -- masking/row-access policy authorship; kept only on FR_GOV_ADMIN
USE ROLE SECURITYADMIN;
GRANT ROLE AR_RAW_GOV_R      TO ROLE SYSADMIN;
GRANT ROLE AR_RAW_METADATA_R TO ROLE SYSADMIN;
GRANT ROLE AR_STAGING_RW     TO ROLE SYSADMIN;
GRANT ROLE AR_MARTS_RW       TO ROLE SYSADMIN;
GRANT ROLE AR_MARTS_R        TO ROLE SYSADMIN;
GRANT ROLE AR_KPIS_RW        TO ROLE SYSADMIN;
GRANT ROLE AR_KPIS_R         TO ROLE SYSADMIN;


/* ============================================================================
   SECTION 5 -- OBJECT PRIVILEGES ON ACCESS ROLES (run as SYSADMIN)
   ALL + FUTURE grants paired, so objects dbt creates later are auto-covered.
   ============================================================================ */
USE ROLE SYSADMIN;

-- 5a. RAW_MASKED.GOV read (clinical analytics, platform admin) -----------------
GRANT USAGE ON DATABASE RAW_MASKED      TO ROLE AR_RAW_GOV_R;
GRANT USAGE ON SCHEMA RAW_MASKED.GOV    TO ROLE AR_RAW_GOV_R;
GRANT SELECT ON ALL TABLES    IN SCHEMA RAW_MASKED.GOV TO ROLE AR_RAW_GOV_R;
GRANT SELECT ON FUTURE TABLES IN SCHEMA RAW_MASKED.GOV TO ROLE AR_RAW_GOV_R;
GRANT SELECT ON ALL VIEWS     IN SCHEMA RAW_MASKED.GOV TO ROLE AR_RAW_GOV_R;
GRANT SELECT ON FUTURE VIEWS  IN SCHEMA RAW_MASKED.GOV TO ROLE AR_RAW_GOV_R;

-- 5b. RAW_MASKED.METADATA read -------------------------------------------------
GRANT USAGE ON DATABASE RAW_MASKED         TO ROLE AR_RAW_METADATA_R;
GRANT USAGE ON SCHEMA RAW_MASKED.METADATA  TO ROLE AR_RAW_METADATA_R;
GRANT SELECT ON ALL TABLES    IN SCHEMA RAW_MASKED.METADATA TO ROLE AR_RAW_METADATA_R;
GRANT SELECT ON FUTURE TABLES IN SCHEMA RAW_MASKED.METADATA TO ROLE AR_RAW_METADATA_R;

-- 5c. ANALYTICS.STAGING read/write/DDL (dbt) -----------------------------------
GRANT USAGE ON DATABASE ANALYTICS       TO ROLE AR_STAGING_RW;
GRANT USAGE, CREATE TABLE, CREATE VIEW  ON SCHEMA ANALYTICS.STAGING TO ROLE AR_STAGING_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES    IN SCHEMA ANALYTICS.STAGING TO ROLE AR_STAGING_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ANALYTICS.STAGING TO ROLE AR_STAGING_RW;

-- 5d. ANALYTICS.MARTS read/write/DDL (dbt) + read-only role --------------------
GRANT USAGE ON DATABASE ANALYTICS     TO ROLE AR_MARTS_RW;
GRANT USAGE, CREATE TABLE, CREATE VIEW ON SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES    IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_RW;

GRANT USAGE ON DATABASE ANALYTICS     TO ROLE AR_MARTS_R;
GRANT USAGE ON SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_R;
GRANT SELECT ON ALL TABLES    IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_R;
GRANT SELECT ON FUTURE TABLES IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_R;
GRANT SELECT ON ALL VIEWS     IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_R;
GRANT SELECT ON FUTURE VIEWS  IN SCHEMA ANALYTICS.MARTS TO ROLE AR_MARTS_R;

-- 5e. KPIS read/write/DDL (dbt) + read-only role -------------------------------
GRANT USAGE ON DATABASE KPIS          TO ROLE AR_KPIS_RW;
GRANT USAGE, CREATE TABLE, CREATE VIEW ON SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES    IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_RW;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_RW;

GRANT USAGE ON DATABASE KPIS          TO ROLE AR_KPIS_R;
GRANT USAGE ON SCHEMA KPIS.REPORTING  TO ROLE AR_KPIS_R;
GRANT SELECT ON ALL TABLES    IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_R;
GRANT SELECT ON FUTURE TABLES IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_R;
GRANT SELECT ON ALL VIEWS     IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_R;
GRANT SELECT ON FUTURE VIEWS  IN SCHEMA KPIS.REPORTING TO ROLE AR_KPIS_R;

-- 5f. Governance admin: manage policies + tags (no data privileges) -----------
GRANT USAGE ON SCHEMA RAW_MASKED.GOV TO ROLE AR_GOV_ADMIN;
GRANT CREATE TAG, CREATE MASKING POLICY, CREATE ROW ACCESS POLICY
    ON SCHEMA RAW_MASKED.GOV TO ROLE AR_GOV_ADMIN;
GRANT APPLY MASKING POLICY    ON ACCOUNT TO ROLE AR_GOV_ADMIN;
GRANT APPLY ROW ACCESS POLICY ON ACCOUNT TO ROLE AR_GOV_ADMIN;
GRANT APPLY TAG               ON ACCOUNT TO ROLE AR_GOV_ADMIN;


/* ============================================================================
   SECTION 6 -- FUNCTIONAL ROLES (FR_*) (run as USERADMIN)
   Granted to Entra groups (via SCIM) and service users. Composed from AR_*.
   ============================================================================ */
USE ROLE USERADMIN;

CREATE ROLE IF NOT EXISTS FR_PLATFORM_ADMIN     COMMENT = 'Data platform admins (manage objects; read masked PHI only)';
CREATE ROLE IF NOT EXISTS FR_GOV_ADMIN          COMMENT = 'Security/governance: authors masking + row-access policies; no raw PHI read';
CREATE ROLE IF NOT EXISTS FR_DBT_TRANSFORM      COMMENT = 'dbt transformation service';
CREATE ROLE IF NOT EXISTS FR_BI_REPORTING       COMMENT = 'BI / reporting users (incl. Power BI)';
CREATE ROLE IF NOT EXISTS FR_CLINICAL_ANALYTICS COMMENT = 'Clinical analytics (PHI-cleared)';
CREATE ROLE IF NOT EXISTS FR_ANALYST            COMMENT = 'General analysts (no PHI)';
CREATE ROLE IF NOT EXISTS FR_BREAKGLASS         COMMENT = 'Break-glass admin (sealed, audited)';


/* ============================================================================
   SECTION 7 -- COMPOSE FUNCTIONAL ROLES FROM ACCESS ROLES (run as SECURITYADMIN)
   ============================================================================ */
USE ROLE SECURITYADMIN;

-- Platform admin: manage all data layers, read only MASKED PHI. Deliberately
-- NOT granted AR_PHI_UNMASK (no clear-text PHI) and NOT granted AR_GOV_ADMIN
-- (policy authorship). Separating these means an admin cannot both detach a
-- masking policy and read the cleartext column.
GRANT ROLE AR_RAW_GOV_R      TO ROLE FR_PLATFORM_ADMIN;
GRANT ROLE AR_RAW_METADATA_R TO ROLE FR_PLATFORM_ADMIN;
GRANT ROLE AR_STAGING_RW     TO ROLE FR_PLATFORM_ADMIN;
GRANT ROLE AR_MARTS_RW       TO ROLE FR_PLATFORM_ADMIN;
GRANT ROLE AR_KPIS_RW        TO ROLE FR_PLATFORM_ADMIN;

-- Governance/security: authors tags + masking + row-access policies. Holds
-- APPLY ... ON ACCOUNT but NO raw-data read role, so it cannot read the PHI it
-- governs (the counterpart to platform admin's no-policy-authorship).
GRANT ROLE AR_GOV_ADMIN      TO ROLE FR_GOV_ADMIN;

-- dbt transform: read masked source, own build in staging/marts/kpis.
GRANT ROLE AR_RAW_GOV_R      TO ROLE FR_DBT_TRANSFORM;
GRANT ROLE AR_RAW_METADATA_R TO ROLE FR_DBT_TRANSFORM;
GRANT ROLE AR_STAGING_RW     TO ROLE FR_DBT_TRANSFORM;
GRANT ROLE AR_MARTS_RW       TO ROLE FR_DBT_TRANSFORM;
GRANT ROLE AR_KPIS_RW        TO ROLE FR_DBT_TRANSFORM;

-- BI / reporting (incl. Power BI service): marts + KPIs read only, masked.
GRANT ROLE AR_MARTS_R TO ROLE FR_BI_REPORTING;
GRANT ROLE AR_KPIS_R  TO ROLE FR_BI_REPORTING;

-- Clinical analytics: marts + KPIs + masked clinical source, PHI cleared.
GRANT ROLE AR_MARTS_R     TO ROLE FR_CLINICAL_ANALYTICS;
GRANT ROLE AR_KPIS_R      TO ROLE FR_CLINICAL_ANALYTICS;
GRANT ROLE AR_RAW_GOV_R   TO ROLE FR_CLINICAL_ANALYTICS;
GRANT ROLE AR_PHI_UNMASK  TO ROLE FR_CLINICAL_ANALYTICS;  -- sees unmasked PHI

-- General analysts: marts + KPIs only, masked. No raw, no PHI clear-text.
GRANT ROLE AR_MARTS_R TO ROLE FR_ANALYST;
GRANT ROLE AR_KPIS_R  TO ROLE FR_ANALYST;

-- Chain functional roles to SYSADMIN for manageability. FR_CLINICAL_ANALYTICS,
-- FR_GOV_ADMIN, and FR_BREAKGLASS are deliberately EXCLUDED so SYSADMIN (and
-- ACCOUNTADMIN) never inherit clear-text PHI (AR_PHI_UNMASK) or policy authorship
-- (AR_GOV_ADMIN). They are managed via SECURITYADMIN/USERADMIN and mapped to Entra
-- groups, not reached by admin inheritance.
GRANT ROLE FR_PLATFORM_ADMIN     TO ROLE SYSADMIN;
GRANT ROLE FR_DBT_TRANSFORM      TO ROLE SYSADMIN;
GRANT ROLE FR_BI_REPORTING       TO ROLE SYSADMIN;
GRANT ROLE FR_ANALYST            TO ROLE SYSADMIN;


/* ============================================================================
   SECTION 8 -- WAREHOUSE USAGE GRANTS (run as SECURITYADMIN)
   ============================================================================ */
USE ROLE SECURITYADMIN;
GRANT USAGE ON WAREHOUSE WH_ADMIN     TO ROLE FR_PLATFORM_ADMIN;
GRANT USAGE ON WAREHOUSE WH_ADMIN     TO ROLE FR_GOV_ADMIN;
GRANT USAGE ON WAREHOUSE WH_ADMIN     TO ROLE FR_BREAKGLASS;
GRANT USAGE ON WAREHOUSE WH_TRANSFORM TO ROLE FR_DBT_TRANSFORM;
GRANT USAGE ON WAREHOUSE WH_BI        TO ROLE FR_BI_REPORTING;
GRANT USAGE ON WAREHOUSE WH_ANALYST   TO ROLE FR_ANALYST;
GRANT USAGE ON WAREHOUSE WH_ANALYST   TO ROLE FR_CLINICAL_ANALYTICS;

-- Platform admin may operate/resize the workload warehouses.
GRANT OPERATE, MONITOR ON WAREHOUSE WH_TRANSFORM TO ROLE FR_PLATFORM_ADMIN;
GRANT OPERATE, MONITOR ON WAREHOUSE WH_BI        TO ROLE FR_PLATFORM_ADMIN;
GRANT OPERATE, MONITOR ON WAREHOUSE WH_ANALYST   TO ROLE FR_PLATFORM_ADMIN;


/* ============================================================================
   SECTION 9 -- SERVICE USERS (run as USERADMIN)
   TYPE = SERVICE: key-pair auth, no password, no MFA prompt, not federated.
   Replace <...RSA_PUBLIC_KEY...> with the PEM body (no header/footer) and store
   the matching PRIVATE key only in a secrets manager -- never in this repo.
   ============================================================================ */
USE ROLE USERADMIN;

CREATE USER IF NOT EXISTS SVC_DBT
    TYPE = SERVICE
    DEFAULT_ROLE = FR_DBT_TRANSFORM
    DEFAULT_WAREHOUSE = WH_TRANSFORM
    RSA_PUBLIC_KEY = '<SVC_DBT_RSA_PUBLIC_KEY>'
    COMMENT = 'dbt transformation service account (key-pair auth)';

CREATE USER IF NOT EXISTS SVC_POWERBI
    TYPE = SERVICE
    DEFAULT_ROLE = FR_BI_REPORTING
    DEFAULT_WAREHOUSE = WH_BI
    RSA_PUBLIC_KEY = '<SVC_POWERBI_RSA_PUBLIC_KEY>'
    COMMENT = 'Power BI service account (key-pair auth)';

USE ROLE SECURITYADMIN;
GRANT ROLE FR_DBT_TRANSFORM TO USER SVC_DBT;
GRANT ROLE FR_BI_REPORTING  TO USER SVC_POWERBI;


/* ============================================================================
   SECTION 10 -- BREAK-GLASS ADMIN (run as ACCOUNTADMIN)
   Emergency identity. DISABLED by default; enabled only during an incident and
   disabled after. Owned OUTSIDE the SYSADMIN tree so it is never inherited.
   ACCOUNTADMIN is granted INTO the break-glass role one direction only -- do
   NOT also grant the break-glass role into ACCOUNTADMIN (that is a role cycle
   Snowflake rejects).
   ============================================================================ */
USE ROLE ACCOUNTADMIN;
GRANT ROLE ACCOUNTADMIN TO ROLE FR_BREAKGLASS;  -- one direction only

USE ROLE USERADMIN;
CREATE USER IF NOT EXISTS BREAKGLASS_01
    TYPE = PERSON
    DEFAULT_ROLE = FR_BREAKGLASS
    DEFAULT_WAREHOUSE = WH_ADMIN
    MUST_CHANGE_PASSWORD = TRUE
    DISABLED = TRUE  -- enable only during a declared incident
    COMMENT = 'BREAK-GLASS ONLY. Vault-stored, MFA required, alert on use.';

USE ROLE SECURITYADMIN;
GRANT ROLE FR_BREAKGLASS TO USER BREAKGLASS_01;
-- To activate during an incident:  ALTER USER BREAKGLASS_01 SET DISABLED = FALSE;
-- Operational control: alert on any login/query where ROLE_NAME = 'FR_BREAKGLASS'.


/* ============================================================================
   SECTION 11 -- ENTRA ID / SCIM GROUP -> FUNCTIONAL ROLE MAPPING
   (run as SECURITYADMIN). With SCIM, Entra security groups are provisioned into
   Snowflake as roles; grant the functional role to the provisioned group-role
   so joiner/mover/leaver is a group change in Entra, with no SQL. Rename the
   quoted group-roles to your real SCIM group names and uncomment.

   Service accounts (SVC_DBT, SVC_POWERBI) are the ONLY direct user->role grants
   -- machine identities are not provisioned through Entra.
   ============================================================================ */
-- One-time SCIM integration (run as ACCOUNTADMIN; token stored in Entra):
-- CREATE SECURITY INTEGRATION IF NOT EXISTS ENTRA_SCIM
--     TYPE = SCIM SCIM_CLIENT = 'AZURE' RUN_AS_ROLE = 'AAD_PROVISIONER';

-- GRANT ROLE FR_PLATFORM_ADMIN     TO ROLE "AAD-SF-DATA-PLATFORM-ADMINS";
-- GRANT ROLE FR_GOV_ADMIN          TO ROLE "AAD-SF-SECURITY-GOVERNANCE";
-- GRANT ROLE FR_BI_REPORTING       TO ROLE "AAD-SF-BI-USERS";
-- GRANT ROLE FR_CLINICAL_ANALYTICS TO ROLE "AAD-SF-CLINICAL-ANALYTICS";
-- GRANT ROLE FR_ANALYST            TO ROLE "AAD-SF-GENERAL-ANALYSTS";
-- Break-glass is assigned to a named user out-of-band, never mapped to a group.

-- REQUIRED for PHI unmasking: the masking policies use IS_GRANTED_TO_INVOKER_ROLE,
-- which only honors the invoker's PRIMARY role. A clinical analyst who also sits
-- in another group (e.g. general analyst / BI) may have FR_CLINICAL_ANALYTICS
-- activated only as a SECONDARY role, in which case PHI is masked FROM THEM. SCIM
-- provisions role grants but does NOT set DEFAULT_ROLE, so it must be set
-- out-of-band for every PHI-cleared user so the clinical role is their PRIMARY:
-- ALTER USER "<clinician_login>" SET DEFAULT_ROLE = FR_CLINICAL_ANALYTICS;
-- Snowsight/interactive fallback: run `USE ROLE FR_CLINICAL_ANALYTICS;` before
-- querying PHI. NOTE: DEFAULT_SECONDARY_ROLES = ('ALL') does NOT help here --
-- auto-activated secondary roles are exactly what the invoker predicate ignores.
-- Driver/Power BI/dbt connections set the role explicitly, so they are unaffected.


/* ============================================================================
   SECTION 12 -- APPLY PHI PROTECTION TO A SAMPLE TABLE (illustrative)
   Shows masking + row-access actually applied (not deferred). Replace with real
   PHI tables. All values synthetic.
   ============================================================================ */
USE ROLE SYSADMIN;
-- patient_id is a non-reversible SURROGATE key (not a HIPAA identifier), so it
-- is left unmasked for joins. Every DIRECT identifier (name, MRN, SSN, email,
-- DOB, addresses, etc.) MUST carry a PII tag below. Audit for gaps with the
-- "PHI columns with no policy" query in audit_queries.sql.
CREATE TABLE IF NOT EXISTS RAW_MASKED.GOV.PATIENT (
    patient_id  STRING,  -- surrogate key, not PHI
    full_name   STRING,
    mrn         STRING,
    dob         DATE,
    email       STRING,
    facility_id STRING
) COMMENT = 'Synthetic example PHI table for policy demonstration';

ALTER TABLE RAW_MASKED.GOV.PATIENT SET TAG RAW_MASKED.GOV.DATA_CLASSIFICATION = 'PHI';

-- Tag PHI columns -> masking applied automatically via tag-based masking (3c).
ALTER TABLE RAW_MASKED.GOV.PATIENT MODIFY
    COLUMN full_name SET TAG RAW_MASKED.GOV.PII_STRING = 'name',
    COLUMN mrn       SET TAG RAW_MASKED.GOV.PII_STRING = 'mrn',
    COLUMN email     SET TAG RAW_MASKED.GOV.PII_STRING = 'email',
    COLUMN dob       SET TAG RAW_MASKED.GOV.PII_DATE   = 'dob';

ALTER TABLE RAW_MASKED.GOV.PATIENT
    ADD ROW ACCESS POLICY RAW_MASKED.GOV.RAP_FACILITY ON (facility_id);


/* ============================================================================
   SECTION 13 -- VERIFICATION (run after deploy)
   ============================================================================ */
-- SHOW GRANTS TO ROLE FR_ANALYST;             -- expect marts + kpis read only
-- SHOW GRANTS TO ROLE FR_CLINICAL_ANALYTICS;  -- adds raw read + AR_PHI_UNMASK
-- SHOW GRANTS TO ROLE FR_DBT_TRANSFORM;       -- raw read + staging/marts/kpis RW
-- SHOW GRANTS TO USER SVC_DBT;
-- SELECT * FROM TABLE(INFORMATION_SCHEMA.POLICY_REFERENCES(
--     REF_ENTITY_NAME => 'RAW_MASKED.GOV.PATIENT', REF_ENTITY_DOMAIN => 'TABLE'));
--
-- PHI UNMASK -- MUST test BOTH role-activation modes (the masking predicate is
-- primary-role-only, so activation mode is the variable that decides the result):
--   (a) clinical role as PRIMARY  -> expect CLEARTEXT PHI:
--         USE ROLE FR_CLINICAL_ANALYTICS; USE SECONDARY ROLES NONE;
--         SELECT full_name, mrn, dob FROM RAW_MASKED.GOV.PATIENT;   -- real values
--   (b) clinical role as SECONDARY under a non-PHI primary -> expect MASKED
--       (this is the misconfiguration that DEFAULT_ROLE prevents):
--         USE ROLE FR_ANALYST; USE SECONDARY ROLES ALL;
--         SELECT full_name, mrn, dob FROM RAW_MASKED.GOV.PATIENT;   -- ***REDACTED***
--   (c) ACCOUNTADMIN / break-glass -> expect MASKED (no admin bypass).
-- Post-cutover, monitor for a spike in ***REDACTED*** / Jan-1 dates returned to
-- clinical analysts -- that is the early signal that DEFAULT_ROLE was not set.


/* ============================================================================
   SECTION 14 -- SAFE, NON-BREAKING MIGRATION (don't break existing access)
   ----------------------------------------------------------------------------
   0. AUDIT current state (export, change nothing):
        SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE DELETED_ON IS NULL;
        SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE DELETED_ON IS NULL;
        SHOW GRANTS TO ROLE <each legacy role>;   -- snapshot to a baseline table.
   1. PARALLEL BUILD: run sections 1-12. New AR_/FR_ roles coexist with legacy
      roles; nothing legacy is revoked yet.
   2. ADDITIVE GRANT: map Entra groups (or a pilot cohort) to the new FR_* roles
      in addition to legacy access. Existing access keeps working.
   3. VERIFY: pilot users/services run under FR_* roles; confirm masking,
      row-access, and dbt/Power BI key-pair auth. For masking, test BOTH modes
      (see Section 13): clinical role as PRIMARY -> cleartext; clinical role as a
      SECONDARY under a non-PHI primary -> ***REDACTED*** (proves the invoker
      predicate + why DEFAULT_ROLE matters). A soak that only tests the clinical
      role as primary WILL pass and then break in production for multi-group
      users on secondaries -- test the secondary case explicitly. Diff new vs
      legacy effective privileges via ACCOUNT_USAGE.GRANTS_TO_ROLES.
   4. CUTOVER: switch Entra group membership to FR_*, AND set DEFAULT_ROLE =
      FR_CLINICAL_ANALYTICS for every PHI-cleared user (SCIM will not). Monitor
      LOGIN_HISTORY / QUERY_HISTORY for failures, and QUERY_HISTORY for a spike
      in masked PHI returned to clinical analysts, over a soak period.
   5. REVOKE LEGACY LAST (reversible): revoke legacy roles from users, then
      groups; keep legacy roles defined (empty) for the rollback window.
   ROLLBACK at any step: re-grant the still-defined legacy role to the affected
   group/user -- instantly restores prior access. Drop legacy only after a clean
   soak window.
   ============================================================================ */
