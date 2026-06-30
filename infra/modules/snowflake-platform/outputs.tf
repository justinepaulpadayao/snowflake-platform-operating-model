output "warehouse_names" {
  description = "Warehouse names for use in dbt profiles and CI pipeline configuration."
  value = {
    admin     = snowflake_warehouse.admin.name
    transform = snowflake_warehouse.transform.name
    bi        = snowflake_warehouse.bi.name
    analyst   = snowflake_warehouse.analyst.name
  }
}

output "functional_role_names" {
  description = "Functional role names for Entra SCIM group mapping and service account grants."
  value = {
    platform_admin     = snowflake_account_role.fr_platform_admin.name
    gov_admin          = snowflake_account_role.fr_gov_admin.name
    dbt_transform      = snowflake_account_role.fr_dbt_transform.name
    bi_reporting       = snowflake_account_role.fr_bi_reporting.name
    clinical_analytics = snowflake_account_role.fr_clinical_analytics.name
    analyst            = snowflake_account_role.fr_analyst.name
    breakglass         = snowflake_account_role.fr_breakglass.name
  }
}

output "phi_gate_role" {
  description = "AR_PHI_UNMASK role name — referenced by masking policies. Do not grant widely."
  value       = snowflake_account_role.ar_phi_unmask.name
}

output "service_user_logins" {
  description = "Service account login names for CI/CD key-pair auth configuration."
  value = {
    dbt     = snowflake_user.svc_dbt.login_name
    powerbi = snowflake_user.svc_powerbi.login_name
  }
}

output "schema_names" {
  description = "Fully-qualified schema names for dbt profile, IaC, and documentation."
  value = {
    gov       = "${snowflake_database.raw_masked.name}.${snowflake_schema.raw_gov.name}"
    metadata  = "${snowflake_database.raw_masked.name}.${snowflake_schema.raw_metadata.name}"
    staging   = "${snowflake_database.analytics.name}.${snowflake_schema.staging.name}"
    marts     = "${snowflake_database.analytics.name}.${snowflake_schema.marts.name}"
    reporting = "${snowflake_database.kpis.name}.${snowflake_schema.reporting.name}"
  }
}
