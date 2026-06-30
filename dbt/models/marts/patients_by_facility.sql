{{
    config(
        materialized = 'table',
        schema       = 'MARTS'
    )
}}

/*
  patients_by_facility: facility-level patient count mart.

  Aggregates patient records by facility.  Because the staging model runs under
  FR_DBT_TRANSFORM (no AR_PHI_UNMASK and full-row row-access), the aggregate
  counts reflect ALL patients across ALL facilities — the intended behavior for
  a platform-wide reporting metric.

  The mart itself contains no PHI identifiers; patient_count is a safe metric
  for all consumers (FR_ANALYST, FR_BI_REPORTING) without requiring the AR_MARTS_R
  grant to carry any additional PHI controls.
*/

SELECT
    facility_id,
    COUNT(DISTINCT patient_id)  AS patient_count,
    CURRENT_TIMESTAMP()         AS mart_refreshed_at

FROM {{ ref('stg_patients') }}

GROUP BY facility_id
