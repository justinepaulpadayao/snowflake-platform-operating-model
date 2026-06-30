{{
    config(
        materialized = 'view',
        schema       = 'STAGING'
    )
}}

/*
  stg_patients: staging model for the patient source.

  Rename columns to snake_case, add light typing, and document the masking
  behavior explicitly.  No transforms that depend on clear-text PHI values —
  the model is authored under FR_DBT_TRANSFORM which does not hold AR_PHI_UNMASK.

  Downstream models and consumers see:
    - full_name, mrn, email  → '***REDACTED***'     (MP_PHI_STRING)
    - dob                    → YYYY-01-01            (MP_PHI_DATE)
  Clinical analysts who need unmasked PHI must query RAW_MASKED.GOV.PATIENT
  directly with a session that holds AR_PHI_UNMASK.
*/

SELECT
    patient_id,

    -- PHI string columns: value returned depends on the caller's role.
    -- Under FR_DBT_TRANSFORM (no AR_PHI_UNMASK), these are always REDACTED.
    full_name                     AS patient_name,
    mrn,
    email                         AS patient_email,

    -- PHI date column: generalized to Jan 1 of the year for uncleared roles.
    dob                           AS date_of_birth,

    -- Non-PHI facility reference: safe for aggregation, joins, and filtering.
    facility_id

FROM {{ source('clinical_source', 'PATIENT') }}
