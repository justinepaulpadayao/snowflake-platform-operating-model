/* ============================================================================
   audit/anomaly_detection.sql
   Behavioral anomaly detection for PHI access on the Snowflake platform.

   The access-review pack (audit_queries.sql) answers "who is entitled to what"
   on a monthly cadence.  This file answers a different question: "is anyone
   behaving unusually with the access they have?"  Both are required for a
   mature HIPAA detection posture — entitlement reviews catch over-provisioning;
   behavioral baselines catch misuse within a valid entitlement.

   Sections:
     (1) Data-volume spike — rolling 7-day baseline vs. current day; a spike
         signals bulk extraction or a looping job.
     (2) Off-hours PHI access — queries on PHI schemas outside business hours.
     (3) Novel client IP — first appearance of an IP for a PHI-role user.
     (4) Mass-export detection — single query returning > N rows from PHI tables.
     (5) Cross-facility probe — users scoped to one facility repeatedly querying
         another (row-access policy returns empty; high-frequency empty results
         indicate probing).
     (6) Auto-classification hints — columns Snowflake infers as PHI/PII that
         do not yet carry a PII_STRING or PII_DATE tag (unguarded PHI).

   SOURCE: SNOWFLAKE.ACCOUNT_USAGE (1–6 h latency for most views; up to 24 h
           for ACCESS_HISTORY).  These queries are suitable for a daily
           scheduled report; for sub-hour detection use the ALERT objects in
           security/snowflake_alerts.sql.

   RUN AS: a role with IMPORTED PRIVILEGES on the SNOWFLAKE database and
           USAGE on GOVERNANCE schema.

   EDITION: ACCESS_HISTORY (sections 1, 3, 4, 5) requires Enterprise edition.
   ============================================================================ */


/* ============================================================================
   (1) DATA-VOLUME SPIKE DETECTION
   Compares each user's rows-produced today against their 7-day rolling mean.
   A spike > 3× the baseline is a potential bulk-extraction signal.
   Exclude automated service accounts (they have predictable, large volumes);
   focus on human FR_* role sessions.
   ============================================================================ */
WITH daily_volume AS (
    SELECT
        user_name,
        DATE(query_start_time) AS query_date,
        SUM(rows_produced)     AS rows_produced_day
    FROM snowflake.account_usage.access_history
    WHERE query_start_time >= DATEADD('day', -8, CURRENT_TIMESTAMP())
      AND user_name NOT ILIKE ANY ('SVC_%', '%_SVC', 'BREAKGLASS_%')
    GROUP BY user_name, DATE(query_start_time)
),

baseline AS (
    SELECT
        user_name,
        AVG(rows_produced_day)    AS avg_7d,
        STDDEV(rows_produced_day) AS stddev_7d
    FROM daily_volume
    WHERE query_date < CURRENT_DATE()
    GROUP BY user_name
),

today_volume AS (
    SELECT user_name, rows_produced_day
    FROM daily_volume
    WHERE query_date = CURRENT_DATE()
)

SELECT
    t.user_name,
    t.rows_produced_day          AS rows_today,
    ROUND(b.avg_7d, 0)           AS avg_7d_baseline,
    ROUND(t.rows_produced_day
          / NULLIF(b.avg_7d, 0), 2) AS multiple_of_baseline,
    'DATA_VOLUME_SPIKE'          AS signal
FROM today_volume t
INNER JOIN baseline b ON t.user_name = b.user_name
WHERE b.avg_7d > 0
  AND t.rows_produced_day > b.avg_7d * 3   -- EDIT: tune threshold
ORDER BY multiple_of_baseline DESC;


/* ============================================================================
   (2) OFF-HOURS PHI ACCESS
   Queries on PHI schemas (RAW_MASKED.GOV / RAW_MASKED) outside business
   hours (22:00–06:00 local time, or weekends).  Off-hours PHI access by a
   human is uncommon; a volume spike off-hours is a stronger signal than
   either indicator alone.
   ============================================================================ */
WITH phi_sessions AS (
    SELECT
        ah.user_name,
        ah.query_start_time,
        EXTRACT('hour' FROM CONVERT_TIMEZONE('<YOUR_TIMEZONE>', ah.query_start_time)) AS hour_local,
        DAYOFWEEK(CONVERT_TIMEZONE('<YOUR_TIMEZONE>', ah.query_start_time))           AS dow,
        SUM(ah.rows_produced) AS rows_produced
    FROM snowflake.account_usage.access_history ah,
         LATERAL FLATTEN(input => ah.base_objects_accessed) f
    WHERE ah.query_start_time >= DATEADD('day', -30, CURRENT_TIMESTAMP())
      AND f.value:objectName::string ILIKE 'RAW_MASKED.GOV.%'
      AND ah.user_name NOT ILIKE ANY ('SVC_%', 'BREAKGLASS_%')
    GROUP BY ah.user_name, ah.query_start_time, hour_local, dow
)

SELECT
    user_name,
    query_start_time,
    hour_local,
    DECODE(dow, 0, 'Sunday', 1, 'Monday', 2, 'Tuesday', 3, 'Wednesday',
                 4, 'Thursday', 5, 'Friday', 6, 'Saturday') AS day_of_week,
    rows_produced,
    'OFF_HOURS_PHI_ACCESS'   AS signal
FROM phi_sessions
WHERE hour_local NOT BETWEEN 6 AND 22   -- EDIT: adjust business-hours window
   OR dow IN (0, 6)                     -- weekend
ORDER BY query_start_time DESC;


/* ============================================================================
   (3) NOVEL CLIENT IP FOR PHI-ROLE USERS
   Detects a source IP that has never appeared before for a given user who
   holds a PHI-relevant role.  A familiar user suddenly connecting from a new
   country or cloud provider IP warrants investigation.
   ============================================================================ */
WITH ip_history AS (
    SELECT DISTINCT user_name, client_ip
    FROM snowflake.account_usage.login_history
    WHERE event_timestamp < DATEADD('day', -1, CURRENT_TIMESTAMP())
      AND is_success = 'YES'
),

recent_logins AS (
    SELECT user_name, client_ip, MAX(event_timestamp) AS first_seen_recent
    FROM snowflake.account_usage.login_history
    WHERE event_timestamp >= DATEADD('day', -1, CURRENT_TIMESTAMP())
      AND is_success = 'YES'
    GROUP BY user_name, client_ip
),

phi_users AS (
    SELECT DISTINCT gu.grantee_name AS user_name
    FROM snowflake.account_usage.grants_to_users gu
    WHERE gu.deleted_on IS NULL
      AND gu.role IN ('FR_CLINICAL_ANALYTICS', 'FR_PLATFORM_ADMIN', 'AR_PHI_UNMASK')
)

SELECT
    r.user_name,
    r.client_ip                  AS novel_ip,
    r.first_seen_recent          AS first_seen,
    'NOVEL_CLIENT_IP'            AS signal
FROM recent_logins r
INNER JOIN phi_users p ON r.user_name = p.user_name
LEFT JOIN ip_history h ON r.user_name = h.user_name AND r.client_ip = h.client_ip
WHERE h.client_ip IS NULL   -- IP is new for this user
ORDER BY r.first_seen_recent DESC;


/* ============================================================================
   (4) MASS-EXPORT DETECTION
   A single query returning an unusually large number of rows from a PHI schema
   is a potential data-exfiltration signal — copy/download of a patient list.
   Threshold: 10 000 rows in a single query (EDIT to a value appropriate for
   your dataset size).
   ============================================================================ */
SELECT
    ah.user_name,
    ah.query_start_time,
    ah.rows_produced,
    LEFT(qh.query_text, 300)   AS query_text_excerpt,
    qh.query_id,
    'MASS_EXPORT'              AS signal
FROM snowflake.account_usage.access_history ah
INNER JOIN snowflake.account_usage.query_history qh
    ON ah.query_id = qh.query_id
   AND ah.query_start_time = qh.start_time,
LATERAL FLATTEN(input => ah.base_objects_accessed) f
WHERE ah.query_start_time >= DATEADD('day', -30, CURRENT_TIMESTAMP())
  AND f.value:objectName::string ILIKE 'RAW_MASKED.GOV.%'
  AND ah.rows_produced > 10000         -- EDIT: tune to data volume
  AND ah.user_name NOT ILIKE ANY ('SVC_%', 'BREAKGLASS_%')
ORDER BY ah.rows_produced DESC;


/* ============================================================================
   (5) HIGH-FREQUENCY EMPTY RESULT ON PHI TABLE (cross-facility probe)
   The row-access policy returns 0 rows when a user queries rows outside their
   facility entitlement.  A user querying a PHI table repeatedly and receiving
   0 rows suggests systematic probing for data they are not entitled to see.
   This query detects users with > 10 zero-row queries on PHI tables in a day
   (EDIT the threshold).
   ============================================================================ */
WITH phi_queries AS (
    SELECT
        qh.user_name,
        DATE(qh.start_time)   AS query_date,
        COUNT(*)              AS total_queries,
        SUM(CASE WHEN ah.rows_produced = 0 THEN 1 ELSE 0 END) AS zero_row_queries
    FROM snowflake.account_usage.query_history qh
    INNER JOIN snowflake.account_usage.access_history ah
        ON qh.query_id = ah.query_id
       AND qh.start_time = ah.query_start_time,
    LATERAL FLATTEN(input => ah.base_objects_accessed) f
    WHERE qh.start_time >= DATEADD('day', -30, CURRENT_TIMESTAMP())
      AND f.value:objectName::string ILIKE 'RAW_MASKED.GOV.%'
    GROUP BY qh.user_name, DATE(qh.start_time)
)

SELECT
    user_name,
    query_date,
    total_queries,
    zero_row_queries,
    ROUND(100.0 * zero_row_queries / NULLIF(total_queries, 0), 1) AS pct_empty,
    'HIGH_EMPTY_RESULT_RATE'  AS signal
FROM phi_queries
WHERE zero_row_queries > 10          -- EDIT: absolute count threshold
  AND zero_row_queries::float / NULLIF(total_queries, 0) > 0.5  -- > 50% empty
ORDER BY zero_row_queries DESC, query_date DESC;


/* ============================================================================
   (6) AUTO-CLASSIFICATION HINTS (unguarded PHI columns)
   SNOWFLAKE.DATA_PRIVACY.EXTRACT_SEMANTIC_CATEGORIES uses sampling and column
   metadata to infer sensitive data types.  This query surfaces columns that
   Snowflake infers as PHI/PII but that do not yet carry a PII_STRING or
   PII_DATE tag — candidate gaps in the tagging model.

   Note: EXTRACT_SEMANTIC_CATEGORIES is a TABLE function; call it once per
   table.  The example below targets RAW_MASKED.GOV; extend the table list
   or wrap in a stored procedure to sweep all schemas.

   EDITION: DATA PRIVACY features require Enterprise edition or higher.
   Verify the exact function path on your account:
     SHOW FUNCTIONS LIKE '%SEMANTIC_CATEGORIES%' IN DATABASE SNOWFLAKE;
   ============================================================================ */
WITH tagged_columns AS (
    -- Columns that already have a PHI classification tag.
    SELECT object_database, object_schema, object_name, column_name
    FROM snowflake.account_usage.tag_references
    WHERE tag_name IN ('PII_STRING', 'PII_DATE')
      AND column_name IS NOT NULL
)

SELECT
    sc.table_catalog,
    sc.table_schema,
    sc.table_name,
    sc.column_name,
    sc.semantic_category,
    sc.privacy_category,
    'UNTAGGED_PHI_CANDIDATE'  AS signal
FROM (
    -- Call EXTRACT_SEMANTIC_CATEGORIES per table; the JSON keys are column names.
    SELECT
        'RAW_MASKED'                              AS table_catalog,
        'GOV'                                     AS table_schema,
        'PATIENT'                                 AS table_name,   -- EDIT: sweep all PHI tables
        f.key                                     AS column_name,
        f.value:semantic_category::string         AS semantic_category,
        f.value:privacy_category::string          AS privacy_category
    FROM TABLE(
        SNOWFLAKE.DATA_PRIVACY.EXTRACT_SEMANTIC_CATEGORIES('RAW_MASKED.GOV.PATIENT')
    ) AS cat_out,
    LATERAL FLATTEN(input => cat_out.$1) f
    WHERE f.value:privacy_category::string IS NOT NULL   -- Snowflake infers as sensitive
) sc
LEFT JOIN tagged_columns tc
    ON  sc.table_catalog = tc.object_database
    AND sc.table_schema   = tc.object_schema
    AND sc.table_name     = tc.object_name
    AND sc.column_name     = tc.column_name
WHERE tc.column_name IS NULL   -- inferred sensitive but not yet tagged
ORDER BY sc.table_name, sc.column_name;

/* ----------------------------------------------------------------------------
   USAGE NOTES:
   - Sections 1–5 can be run as a daily scheduled task (GitHub Actions cron +
     Python reporting, or a dbt model in GOVERNANCE schema).
   - Section 6 is best run after schema changes or new dbt model deployments
     to catch newly created columns.
   - All findings should feed back into the monthly access-review exception
     report (access_review.py) or the SIEM for trend correlation.
   - Tune all numeric thresholds (rows, days, frequencies) to baseline values
     measured from at least 30 days of production ACCESS_HISTORY before
     enabling automated alerting on these signals.
   -------------------------------------------------------------------------- */
