/* ============================================================================
   security/snowflake_alerts.sql
   Native Snowflake ALERT objects for real-time security event detection.

   The monthly audit pack (audit_queries.sql) and anomaly queries
   (audit/anomaly_detection.sql) are retrospective.  These ALERT objects fire
   immediately when a condition is met, closing the detection window from
   "discovered at month-end" to "paged within minutes."

   Alerts defined here:
     ALERT_BREAKGLASS_LOGIN   — any successful login with FR_BREAKGLASS role.
     ALERT_PHI_POLICY_DETACH  — any DDL removing a masking or row-access policy
                                 from a PHI table/column (control drift).
     ALERT_PHI_TAG_UNSET      — any DDL removing a PII_STRING or PII_DATE tag
                                 from a column.
     ALERT_ACCOUNTADMIN_QUERY — any query run under the ACCOUNTADMIN role
                                 (ACCOUNTADMIN should never be the session role
                                 for routine work).

   Prerequisites:
     - NI_SECURITY_EMAIL notification integration (created in network_policies.sql).
     - WH_ACCESS_REVIEW warehouse (created in terraform_or_iac_example.tf).
     - GOVERNANCE.ACCESS_REVIEW schema for alert audit logging.

   HIPAA relevance:
     §164.312(b) audit controls — automated, near-real-time detection of
     privileged access and control tampering.
     §164.308(a)(6)(ii) response and reporting — alerts trigger the incident-
     response workflow without relying on a human to notice the event in logs.

   EDITION: ALERT requires Enterprise edition or higher.
   SAFETY: ALERTs start in SUSPENDED state.  Resume each explicitly after
           testing the condition query independently to avoid false-positive
           floods.  Run:  ALTER ALERT <name> RESUME;
   ============================================================================ */


/* ============================================================================
   SECTION 1 -- NOTIFICATION STORED PROCEDURES
   Each alert THEN clause calls a stored procedure that emits a rich email.
   A stored procedure allows multi-statement logic (gather context, format body)
   that cannot be expressed as a single SQL statement in the THEN clause.
   ============================================================================ */
USE ROLE SYSADMIN;
USE DATABASE GOVERNANCE;
USE SCHEMA ACCESS_REVIEW;

-- 1a. Break-glass login notifier.
CREATE OR REPLACE PROCEDURE SP_ALERT_BREAKGLASS()
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body STRING;
BEGIN
    SELECT LISTAGG(
        'User: '    || user_name
        || ' | IP: '  || client_ip
        || ' | Time: ' || event_timestamp::STRING,
        '\n'
    )
    INTO body
    FROM snowflake.account_usage.login_history
    WHERE role_name = 'FR_BREAKGLASS'
      AND is_success = 'YES'
      AND event_timestamp > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME();

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        '[CRITICAL] Snowflake Break-Glass Login Detected',
        'Break-glass account activation detected.  Verify this is an approved'
        || ' incident.\n\n' || COALESCE(body, '(no rows — possible false trigger)')
    );
    RETURN 'notified';
END;
$$;

-- 1b. PHI policy detach / tag removal notifier.
CREATE OR REPLACE PROCEDURE SP_ALERT_PHI_CONTROL_TAMPER(event_type STRING)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body  STRING;
    subj  STRING;
BEGIN
    SELECT LISTAGG(
        'Actor: '    || user_name
        || ' | SQL: '  || LEFT(query_text, 200)
        || ' | Time: ' || start_time::STRING,
        '\n'
    )
    INTO body
    FROM snowflake.account_usage.query_history
    WHERE execution_status = 'SUCCESS'
      AND start_time > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
      AND (
          (event_type = 'POLICY_DETACH'
           AND query_text ILIKE ANY ('%UNSET MASKING POLICY%', '%UNSET ROW ACCESS POLICY%'))
          OR
          (event_type = 'TAG_REMOVAL'
           AND query_text ILIKE ANY ('%UNSET TAG%PII_STRING%', '%UNSET TAG%PII_DATE%'))
      );

    subj := CASE event_type
        WHEN 'POLICY_DETACH' THEN '[CRITICAL] PHI Masking or Row-Access Policy Removed'
        ELSE                      '[CRITICAL] PHI Classification Tag Removed from Column'
    END;

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        subj,
        'A PHI data control was altered.  Verify the change is authorized'
        || ' and that the affected column is still protected.\n\n'
        || COALESCE(body, '(no rows — possible false trigger)')
    );
    RETURN 'notified';
END;
$$;

-- 1c. ACCOUNTADMIN session notifier.
CREATE OR REPLACE PROCEDURE SP_ALERT_ACCOUNTADMIN_QUERY()
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body STRING;
BEGIN
    SELECT LISTAGG(
        'User: '      || user_name
        || ' | Query: ' || LEFT(query_text, 150)
        || ' | Time: '  || start_time::STRING,
        '\n'
    )
    INTO body
    FROM snowflake.account_usage.query_history
    WHERE role_name       = 'ACCOUNTADMIN'
      AND execution_status = 'SUCCESS'
      AND start_time > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME();

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        '[HIGH] Snowflake ACCOUNTADMIN Role Used for Query',
        'ACCOUNTADMIN should be reserved for break-glass only.'
        || '  Verify the session is authorized.\n\n'
        || COALESCE(body, '(no rows — possible false trigger)')
    );
    RETURN 'notified';
END;
$$;


/* ============================================================================
   SECTION 2 -- ALERT OBJECTS
   All ALERTs start SUSPENDED; resume only after testing the IF condition
   independently to confirm it returns rows for a known event and no rows
   in the steady state.
   ============================================================================ */
USE ROLE SYSADMIN;

-- 2a. Break-glass login alert — poll every 5 minutes.
--     Condition: any successful login using the FR_BREAKGLASS role since the
--     last successful scheduled run of this alert.
CREATE OR REPLACE ALERT ALERT_BREAKGLASS_LOGIN
    WAREHOUSE = WH_ACCESS_REVIEW
    SCHEDULE  = '5 MINUTE'
    IF (EXISTS (
        SELECT 1
        FROM snowflake.account_usage.login_history
        WHERE role_name   = 'FR_BREAKGLASS'
          AND is_success  = 'YES'
          AND event_timestamp > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
    ))
    THEN
        CALL GOVERNANCE.ACCESS_REVIEW.SP_ALERT_BREAKGLASS();

-- 2b. PHI masking / row-access policy removal alert.
--     Detects DDL that unsets a masking or row-access policy from any object.
--     A legitimate change is always a reviewed PR through CI; any change here
--     without a corresponding PR is an unauthorized control removal.
CREATE OR REPLACE ALERT ALERT_PHI_POLICY_DETACH
    WAREHOUSE = WH_ACCESS_REVIEW
    SCHEDULE  = '10 MINUTE'
    IF (EXISTS (
        SELECT 1
        FROM snowflake.account_usage.query_history
        WHERE execution_status = 'SUCCESS'
          AND start_time > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
          AND query_text ILIKE ANY (
              '%UNSET MASKING POLICY%',
              '%UNSET ROW ACCESS POLICY%'
          )
    ))
    THEN
        CALL GOVERNANCE.ACCESS_REVIEW.SP_ALERT_PHI_CONTROL_TAMPER('POLICY_DETACH');

-- 2c. PHI classification tag removal alert.
--     A column tagged PII_STRING or PII_DATE is masked automatically via
--     tag-based masking.  Removing the tag silently removes the mask.
CREATE OR REPLACE ALERT ALERT_PHI_TAG_UNSET
    WAREHOUSE = WH_ACCESS_REVIEW
    SCHEDULE  = '10 MINUTE'
    IF (EXISTS (
        SELECT 1
        FROM snowflake.account_usage.query_history
        WHERE execution_status = 'SUCCESS'
          AND start_time > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
          AND (
              query_text ILIKE '%UNSET TAG%PII_STRING%'
              OR query_text ILIKE '%UNSET TAG%PII_DATE%'
          )
    ))
    THEN
        CALL GOVERNANCE.ACCESS_REVIEW.SP_ALERT_PHI_CONTROL_TAMPER('TAG_REMOVAL');

-- 2d. ACCOUNTADMIN session query alert — poll every 15 minutes.
--     Fires only on DML/DDL/SELECT — SHOW, DESCRIBE, and USE commands run
--     under ACCOUNTADMIN every time the monitoring queries in Section 4 run,
--     and would cause alert fatigue that trains responders to ignore the alert.
CREATE OR REPLACE ALERT ALERT_ACCOUNTADMIN_QUERY
    WAREHOUSE = WH_ACCESS_REVIEW
    SCHEDULE  = '15 MINUTE'
    IF (EXISTS (
        SELECT 1
        FROM snowflake.account_usage.query_history
        WHERE role_name       = 'ACCOUNTADMIN'
          AND execution_status = 'SUCCESS'
          AND start_time > SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
          AND query_type NOT IN ('SHOW', 'DESCRIBE', 'USE')
    ))
    THEN
        CALL GOVERNANCE.ACCESS_REVIEW.SP_ALERT_ACCOUNTADMIN_QUERY();


/* ============================================================================
   SECTION 3 -- RESUME ALERTS (after testing)
   Run these after verifying each condition query returns the expected rows
   for a synthetic test event and zero rows in the steady state.
   ============================================================================ */
-- ALTER ALERT ALERT_BREAKGLASS_LOGIN   RESUME;
-- ALTER ALERT ALERT_PHI_POLICY_DETACH  RESUME;
-- ALTER ALERT ALERT_PHI_TAG_UNSET      RESUME;
-- ALTER ALERT ALERT_ACCOUNTADMIN_QUERY RESUME;


/* ============================================================================
   SECTION 4 -- MONITORING AND ALERT HISTORY
   ============================================================================ */
-- Check alert execution history and any errors:
SELECT
    name               AS alert_name,
    scheduled_time,
    completed_time,
    state,
    error_message
FROM snowflake.account_usage.alert_history
WHERE scheduled_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY scheduled_time DESC;

-- Confirm alerts are STARTED (RESUMED), not SUSPENDED:
SHOW ALERTS IN SCHEMA GOVERNANCE.ACCESS_REVIEW;

-- Test the break-glass condition manually (should return 0 rows in steady state):
SELECT 1
FROM snowflake.account_usage.login_history
WHERE role_name   = 'FR_BREAKGLASS'
  AND is_success  = 'YES'
  AND event_timestamp > DATEADD('hour', -1, CURRENT_TIMESTAMP());
