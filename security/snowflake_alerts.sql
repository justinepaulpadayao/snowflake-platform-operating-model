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

   LATE-DATA CORRECTNESS (important):
   ACCOUNT_USAGE views are populated with LATENCY (LOGIN_HISTORY up to ~2 h,
   QUERY_HISTORY up to ~45 min), but SNOWFLAKE.ALERT.LAST_SUCCESSFUL_SCHEDULED_TIME()
   advances in REAL time.  A break-glass login at 09:58 that only becomes
   queryable at 11:58 has an event_timestamp (09:58) BELOW the watermark
   (~11:53) — so a naive `event_timestamp > LAST_SUCCESSFUL_SCHEDULED_TIME()`
   filter silently NEVER matches it, and the event goes undetected.

   Fix (two parts):
     1. The ALERT IF condition and these procedures look back a fixed window
        WIDER than the maximum view latency (LATENCY_LOOKBACK below), not just
        since the last run, so late-arriving rows are still seen.
     2. A widened window re-sees already-notified events every run, so each
        procedure DEDUPES against ALERT_STATE by a stable event key and emails
        only genuinely new events.  This converts "poll since watermark" (loses
        late data) into "poll a latency-safe window, dedupe" (no loss, no flood).
   ============================================================================ */
USE ROLE SYSADMIN;
USE DATABASE GOVERNANCE;
USE SCHEMA ACCESS_REVIEW;

-- Dedup ledger: one row per already-notified event, keyed by a stable hash.
CREATE TABLE IF NOT EXISTS GOVERNANCE.ACCESS_REVIEW.ALERT_STATE (
    alert_name   STRING,
    event_key    STRING,      -- stable identity of the event (e.g. query_id, or user||ts)
    notified_at  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    CONSTRAINT pk_alert_state PRIMARY KEY (alert_name, event_key)
);

-- Latency-safe lookback: each alert/procedure looks back a fixed 3 h (literal
-- in every query below), which exceeds the worst-case ACCOUNT_USAGE latency of
-- the view it reads (2 h for LOGIN_HISTORY).  Dedup against ALERT_STATE keeps
-- the wider window from re-notifying the same event.

-- 1a. Break-glass login notifier.
--     Reads a latency-safe 3 h window, dedupes NEW logins against ALERT_STATE
--     (key = user||event_timestamp), records them, and emails only new events.
CREATE OR REPLACE PROCEDURE SP_ALERT_BREAKGLASS()
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body     STRING;
    new_ct   NUMBER;
BEGIN
    -- LOGIN_HISTORY records the USER and login outcome, not the role activated
    -- (there is no role_name column).  Break-glass is a dedicated, normally
    -- DISABLED user, so a successful login BY that user is the signal.  Match
    -- the break-glass login name(s); adjust the pattern to your account.
    -- New = not already in ALERT_STATE for this alert (dedup over the wide window).
    CREATE OR REPLACE TEMPORARY TABLE _bg_new AS
        SELECT
            MD5(lh.user_name || '|' || lh.event_timestamp::STRING) AS event_key,
            lh.user_name,
            lh.client_ip,
            lh.event_timestamp
        FROM snowflake.account_usage.login_history lh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_BREAKGLASS_LOGIN'
         AND s.event_key  = MD5(lh.user_name || '|' || lh.event_timestamp::STRING)
        WHERE lh.user_name ILIKE 'BREAKGLASS%'
          AND lh.is_success = 'YES'
          AND lh.event_timestamp > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND s.event_key IS NULL;

    SELECT COUNT(*) INTO new_ct FROM _bg_new;
    IF (new_ct = 0) THEN
        RETURN 'no new events';
    END IF;

    INSERT INTO GOVERNANCE.ACCESS_REVIEW.ALERT_STATE (alert_name, event_key)
        SELECT 'ALERT_BREAKGLASS_LOGIN', event_key FROM _bg_new;

    SELECT LISTAGG('User: ' || user_name || ' | IP: ' || client_ip
                   || ' | Time: ' || event_timestamp::STRING, '\n')
    INTO body FROM _bg_new;

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        '[CRITICAL] Snowflake Break-Glass Login Detected',
        'Break-glass account activation detected.  Verify this is an approved'
        || ' incident.\n\n' || body
    );
    RETURN 'notified: ' || new_ct::STRING || ' new event(s)';
END;
$$;

-- 1b. PHI policy detach / tag removal notifier.
--     Same latency-safe + dedup pattern; event_key = query_id (unique per stmt).
CREATE OR REPLACE PROCEDURE SP_ALERT_PHI_CONTROL_TAMPER(event_type STRING)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body    STRING;
    subj    STRING;
    new_ct  NUMBER;
    aname   STRING := 'ALERT_PHI_CONTROL_TAMPER_' || event_type;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE _pt_new AS
        SELECT qh.query_id AS event_key, qh.user_name, qh.query_text, qh.start_time
        FROM snowflake.account_usage.query_history qh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = :aname AND s.event_key = qh.query_id
        WHERE qh.execution_status = 'SUCCESS'
          AND qh.start_time > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND s.event_key IS NULL
          AND (
              (event_type = 'POLICY_DETACH'
               AND qh.query_text ILIKE ANY ('%UNSET MASKING POLICY%', '%UNSET ROW ACCESS POLICY%'))
              OR
              (event_type = 'TAG_REMOVAL'
               AND qh.query_text ILIKE ANY ('%UNSET TAG%PII_STRING%', '%UNSET TAG%PII_DATE%'))
          );

    SELECT COUNT(*) INTO new_ct FROM _pt_new;
    IF (new_ct = 0) THEN
        RETURN 'no new events';
    END IF;

    INSERT INTO GOVERNANCE.ACCESS_REVIEW.ALERT_STATE (alert_name, event_key)
        SELECT :aname, event_key FROM _pt_new;

    SELECT LISTAGG('Actor: ' || user_name || ' | SQL: ' || LEFT(query_text, 200)
                   || ' | Time: ' || start_time::STRING, '\n')
    INTO body FROM _pt_new;

    subj := CASE event_type
        WHEN 'POLICY_DETACH' THEN '[CRITICAL] PHI Masking or Row-Access Policy Removed'
        ELSE                      '[CRITICAL] PHI Classification Tag Removed from Column'
    END;

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        subj,
        'A PHI data control was altered.  Verify the change is authorized'
        || ' and that the affected column is still protected.\n\n' || body
    );
    RETURN 'notified: ' || new_ct::STRING || ' new event(s)';
END;
$$;

-- 1c. ACCOUNTADMIN session notifier.
--     Same latency-safe + dedup pattern; event_key = query_id.
CREATE OR REPLACE PROCEDURE SP_ALERT_ACCOUNTADMIN_QUERY()
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    body    STRING;
    new_ct  NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE _aa_new AS
        SELECT qh.query_id AS event_key, qh.user_name, qh.query_text, qh.start_time
        FROM snowflake.account_usage.query_history qh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_ACCOUNTADMIN_QUERY' AND s.event_key = qh.query_id
        WHERE qh.role_name = 'ACCOUNTADMIN'
          AND qh.execution_status = 'SUCCESS'
          AND qh.start_time > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND qh.query_type NOT IN ('SHOW', 'DESCRIBE', 'USE')
          AND s.event_key IS NULL;

    SELECT COUNT(*) INTO new_ct FROM _aa_new;
    IF (new_ct = 0) THEN
        RETURN 'no new events';
    END IF;

    INSERT INTO GOVERNANCE.ACCESS_REVIEW.ALERT_STATE (alert_name, event_key)
        SELECT 'ALERT_ACCOUNTADMIN_QUERY', event_key FROM _aa_new;

    SELECT LISTAGG('User: ' || user_name || ' | Query: ' || LEFT(query_text, 150)
                   || ' | Time: ' || start_time::STRING, '\n')
    INTO body FROM _aa_new;

    CALL SYSTEM$SEND_EMAIL(
        'NI_SECURITY_EMAIL',
        '<security-team@example.com>',
        '[HIGH] Snowflake ACCOUNTADMIN Role Used for Query',
        'ACCOUNTADMIN should be reserved for break-glass only.'
        || '  Verify the session is authorized.\n\n' || body
    );
    RETURN 'notified: ' || new_ct::STRING || ' new event(s)';
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
--     Condition: a NEW successful login by the break-glass USER within a
--     latency-safe 3 h window (LOGIN_HISTORY has no role_name; break-glass is a
--     dedicated user).  Not since-last-run — that misses late-arriving
--     ACCOUNT_USAGE rows.  "New" = not already recorded in ALERT_STATE.
CREATE OR REPLACE ALERT ALERT_BREAKGLASS_LOGIN
    WAREHOUSE = WH_ACCESS_REVIEW
    SCHEDULE  = '5 MINUTE'
    IF (EXISTS (
        SELECT 1
        FROM snowflake.account_usage.login_history lh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_BREAKGLASS_LOGIN'
         AND s.event_key  = MD5(lh.user_name || '|' || lh.event_timestamp::STRING)
        WHERE lh.user_name ILIKE 'BREAKGLASS%'
          AND lh.is_success  = 'YES'
          AND lh.event_timestamp > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND s.event_key IS NULL
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
        FROM snowflake.account_usage.query_history qh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_PHI_CONTROL_TAMPER_POLICY_DETACH'
         AND s.event_key  = qh.query_id
        WHERE qh.execution_status = 'SUCCESS'
          AND qh.start_time > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND s.event_key IS NULL
          AND qh.query_text ILIKE ANY (
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
        FROM snowflake.account_usage.query_history qh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_PHI_CONTROL_TAMPER_TAG_REMOVAL'
         AND s.event_key  = qh.query_id
        WHERE qh.execution_status = 'SUCCESS'
          AND qh.start_time > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND s.event_key IS NULL
          AND (
              qh.query_text ILIKE '%UNSET TAG%PII_STRING%'
              OR qh.query_text ILIKE '%UNSET TAG%PII_DATE%'
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
        FROM snowflake.account_usage.query_history qh
        LEFT JOIN GOVERNANCE.ACCESS_REVIEW.ALERT_STATE s
          ON s.alert_name = 'ALERT_ACCOUNTADMIN_QUERY'
         AND s.event_key  = qh.query_id
        WHERE qh.role_name       = 'ACCOUNTADMIN'
          AND qh.execution_status = 'SUCCESS'
          AND qh.start_time > DATEADD('hour', -3, CURRENT_TIMESTAMP())
          AND qh.query_type NOT IN ('SHOW', 'DESCRIBE', 'USE')
          AND s.event_key IS NULL
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
