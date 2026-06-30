#############################################################################
# infra/modules/snowflake-platform/main.tf
#
# Full Terraform module for the Snowflake platform RBAC and security layer.
# Manages the same objects as snowflake_rbac.sql as code — with state tracking,
# plan-before-apply, and drift detection.  Either the SQL or this module is
# the authority for a given environment; do not mix them.
#
# What this module manages:
#   - Warehouses + resource monitors
#   - Databases and managed-access schemas
#   - Access roles (AR_*) + functional roles (FR_*)
#   - Role hierarchy composition (role-to-role grants)
#   - Service accounts (SVC_DBT, SVC_POWERBI) with TYPE=SERVICE
#   - Network policies (account-level + per-user overrides)
#
# What is NOT managed here (kept in SQL for auditability or provider gaps):
#   - Authentication policies (AP_HUMAN_MFA, AP_SERVICE_KEYPAIR) — managed in
#     security/auth_session_policies.sql.
#   - Session policies (SP_STANDARD, SP_PRIVILEGED) — same file.
#   - Masking policies (CREATE MASKING POLICY) — provider support is limited;
#     validate policy DDL directly on the account.
#   - Row access policies — same reason.
#   - ALERT objects — managed in security/snowflake_alerts.sql.
#   - SCIM security integration — one-time, manual step in Snowflake console.
#
# Provider: Snowflake-Labs/snowflake (~> 0.95).
# Verify resource names against the provider changelog before applying — the
# provider's resource API evolves between major versions.
#############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    snowflake = {
      source  = "Snowflake-Labs/snowflake"
      version = "~> 0.95"
    }
  }
}

provider "snowflake" {
  organization_name = var.snowflake_org
  account_name      = var.snowflake_account
  user              = "SVC_TERRAFORM"
  authenticator     = "SNOWFLAKE_JWT"
  private_key       = var.snowflake_private_key
  role              = "SYSADMIN"
}

# SECURITYADMIN alias — required for NETWORK POLICY resources.
# CREATE / ALTER NETWORK POLICY requires SECURITYADMIN or ACCOUNTADMIN;
# the default SYSADMIN provider cannot create these objects.
provider "snowflake" {
  alias             = "securityadmin"
  organization_name = var.snowflake_org
  account_name      = var.snowflake_account
  user              = "SVC_TERRAFORM"
  authenticator     = "SNOWFLAKE_JWT"
  private_key       = var.snowflake_private_key
  role              = "SECURITYADMIN"
}

#############################################################################
# Warehouses + resource monitors
#############################################################################

resource "snowflake_warehouse" "admin" {
  name              = "WH_ADMIN"
  warehouse_size    = var.warehouse_sizes.admin
  auto_suspend      = 60
  auto_resume       = true
  initially_suspended = true
  comment           = "Platform admin / break-glass"
}

resource "snowflake_warehouse" "transform" {
  name              = "WH_TRANSFORM"
  warehouse_size    = var.warehouse_sizes.transform
  auto_suspend      = 60
  auto_resume       = true
  initially_suspended = true
  comment           = "dbt transformation runs"
}

resource "snowflake_warehouse" "bi" {
  name              = "WH_BI"
  warehouse_size    = var.warehouse_sizes.bi
  auto_suspend      = 60
  auto_resume       = true
  initially_suspended = true
  comment           = "Power BI / reporting"
}

resource "snowflake_warehouse" "analyst" {
  name              = "WH_ANALYST"
  warehouse_size    = var.warehouse_sizes.analyst
  auto_suspend      = 60
  auto_resume       = true
  initially_suspended = true
  comment           = "Ad-hoc + clinical analytics"
}

resource "snowflake_resource_monitor" "transform" {
  name              = "RM_TRANSFORM"
  credit_quota      = var.resource_monitor_credits.transform
  frequency         = "MONTHLY"
  notify_triggers   = [80]
  suspend_trigger   = 100
  suspend_immediate_trigger = 110
}

resource "snowflake_resource_monitor" "bi" {
  name            = "RM_BI"
  credit_quota    = var.resource_monitor_credits.bi
  frequency       = "MONTHLY"
  notify_triggers = [80]
  suspend_trigger = 100
}

resource "snowflake_resource_monitor" "analyst" {
  name            = "RM_ANALYST"
  credit_quota    = var.resource_monitor_credits.analyst
  frequency       = "MONTHLY"
  notify_triggers = [80]
  suspend_trigger = 100
}

#############################################################################
# Databases + managed-access schemas
# WITH MANAGED ACCESS: only the schema owner can grant on objects inside.
# Critical control for PHI schemas.
#############################################################################

resource "snowflake_database" "raw_masked" {
  name    = "RAW_MASKED"
  comment = "Masked PHI source layer"
}

resource "snowflake_database" "analytics" {
  name    = "ANALYTICS"
  comment = "Modeled analytics layer"
}

resource "snowflake_database" "kpis" {
  name    = "KPIS"
  comment = "Curated KPI / metrics layer"
}

resource "snowflake_schema" "raw_gov" {
  database            = snowflake_database.raw_masked.name
  name                = "GOV"
  with_managed_access = true
  comment             = "Governance: tags, masking + row-access policies, clinical source"
}

resource "snowflake_schema" "raw_metadata" {
  database            = snowflake_database.raw_masked.name
  name                = "METADATA"
  with_managed_access = true
  comment             = "Lineage / catalog / operational metadata"
}

resource "snowflake_schema" "staging" {
  database            = snowflake_database.analytics.name
  name                = "STAGING"
  with_managed_access = true
  comment             = "dbt staging / intermediate (internal only)"
}

resource "snowflake_schema" "marts" {
  database            = snowflake_database.analytics.name
  name                = "MARTS"
  with_managed_access = true
  comment             = "Consumption-ready marts"
}

resource "snowflake_schema" "reporting" {
  database            = snowflake_database.kpis.name
  name                = "REPORTING"
  with_managed_access = true
  comment             = "Published KPI tables/views for reporting"
}

#############################################################################
# Access roles (AR_*) — hold object privileges only; never granted to people
#############################################################################

resource "snowflake_account_role" "ar_raw_gov_r" {
  name    = "AR_RAW_GOV_R"
  comment = "Read RAW_MASKED.GOV (masked clinical source)"
}

resource "snowflake_account_role" "ar_raw_metadata_r" {
  name    = "AR_RAW_METADATA_R"
  comment = "Read RAW_MASKED.METADATA"
}

resource "snowflake_account_role" "ar_staging_rw" {
  name    = "AR_STAGING_RW"
  comment = "Read/write/DDL ANALYTICS.STAGING (dbt)"
}

resource "snowflake_account_role" "ar_marts_rw" {
  name    = "AR_MARTS_RW"
  comment = "Read/write/DDL ANALYTICS.MARTS (dbt)"
}

resource "snowflake_account_role" "ar_marts_r" {
  name    = "AR_MARTS_R"
  comment = "Read ANALYTICS.MARTS"
}

resource "snowflake_account_role" "ar_kpis_rw" {
  name    = "AR_KPIS_RW"
  comment = "Read/write/DDL KPIS.REPORTING (dbt)"
}

resource "snowflake_account_role" "ar_kpis_r" {
  name    = "AR_KPIS_R"
  comment = "Read KPIS.REPORTING"
}

resource "snowflake_account_role" "ar_phi_unmask" {
  name    = "AR_PHI_UNMASK"
  comment = "Clear-text PHI gate (referenced by masking policies). NOT in SYSADMIN tree."
}

resource "snowflake_account_role" "ar_gov_admin" {
  name    = "AR_GOV_ADMIN"
  comment = "Manage tags / masking / row-access policies. NOT in SYSADMIN tree."
}

#############################################################################
# Functional roles (FR_*) — granted to Entra groups (SCIM) and service users
#############################################################################

resource "snowflake_account_role" "fr_platform_admin" {
  name    = "FR_PLATFORM_ADMIN"
  comment = "Data platform admins (manage objects; read masked PHI only)"
}

resource "snowflake_account_role" "fr_gov_admin" {
  name    = "FR_GOV_ADMIN"
  comment = "Security/governance: authors masking + row-access policies; no raw PHI read"
}

resource "snowflake_account_role" "fr_dbt_transform" {
  name    = "FR_DBT_TRANSFORM"
  comment = "dbt transformation service"
}

resource "snowflake_account_role" "fr_bi_reporting" {
  name    = "FR_BI_REPORTING"
  comment = "BI / reporting users (incl. Power BI)"
}

resource "snowflake_account_role" "fr_clinical_analytics" {
  name    = "FR_CLINICAL_ANALYTICS"
  comment = "Clinical analytics (PHI-cleared)"
}

resource "snowflake_account_role" "fr_analyst" {
  name    = "FR_ANALYST"
  comment = "General analysts (no PHI)"
}

resource "snowflake_account_role" "fr_breakglass" {
  name    = "FR_BREAKGLASS"
  comment = "Break-glass admin (sealed, audited)"
}

#############################################################################
# Role composition — functional roles from access roles
# snowflake_role_grants was removed in provider 0.87; each grant is now an
# individual snowflake_grant_role_to_account_role resource.
# AR_PHI_UNMASK and AR_GOV_ADMIN are DELIBERATELY excluded from the SYSADMIN
# tree so ACCOUNTADMIN never inherits clear-text PHI or policy authorship.
#############################################################################

resource "snowflake_grant_role_to_account_role" "ar_raw_gov_r_to_platform_admin" {
  role_name        = snowflake_account_role.ar_raw_gov_r.name
  parent_role_name = snowflake_account_role.fr_platform_admin.name
}
resource "snowflake_grant_role_to_account_role" "ar_raw_metadata_r_to_platform_admin" {
  role_name        = snowflake_account_role.ar_raw_metadata_r.name
  parent_role_name = snowflake_account_role.fr_platform_admin.name
}
resource "snowflake_grant_role_to_account_role" "ar_staging_rw_to_platform_admin" {
  role_name        = snowflake_account_role.ar_staging_rw.name
  parent_role_name = snowflake_account_role.fr_platform_admin.name
}
resource "snowflake_grant_role_to_account_role" "ar_marts_rw_to_platform_admin" {
  role_name        = snowflake_account_role.ar_marts_rw.name
  parent_role_name = snowflake_account_role.fr_platform_admin.name
}
resource "snowflake_grant_role_to_account_role" "ar_kpis_rw_to_platform_admin" {
  role_name        = snowflake_account_role.ar_kpis_rw.name
  parent_role_name = snowflake_account_role.fr_platform_admin.name
}

resource "snowflake_grant_role_to_account_role" "ar_gov_admin_to_gov_admin" {
  role_name        = snowflake_account_role.ar_gov_admin.name
  parent_role_name = snowflake_account_role.fr_gov_admin.name
}

resource "snowflake_grant_role_to_account_role" "ar_raw_gov_r_to_dbt" {
  role_name        = snowflake_account_role.ar_raw_gov_r.name
  parent_role_name = snowflake_account_role.fr_dbt_transform.name
}
resource "snowflake_grant_role_to_account_role" "ar_raw_metadata_r_to_dbt" {
  role_name        = snowflake_account_role.ar_raw_metadata_r.name
  parent_role_name = snowflake_account_role.fr_dbt_transform.name
}
resource "snowflake_grant_role_to_account_role" "ar_staging_rw_to_dbt" {
  role_name        = snowflake_account_role.ar_staging_rw.name
  parent_role_name = snowflake_account_role.fr_dbt_transform.name
}
resource "snowflake_grant_role_to_account_role" "ar_marts_rw_to_dbt" {
  role_name        = snowflake_account_role.ar_marts_rw.name
  parent_role_name = snowflake_account_role.fr_dbt_transform.name
}
resource "snowflake_grant_role_to_account_role" "ar_kpis_rw_to_dbt" {
  role_name        = snowflake_account_role.ar_kpis_rw.name
  parent_role_name = snowflake_account_role.fr_dbt_transform.name
}

resource "snowflake_grant_role_to_account_role" "ar_marts_r_to_bi" {
  role_name        = snowflake_account_role.ar_marts_r.name
  parent_role_name = snowflake_account_role.fr_bi_reporting.name
}
resource "snowflake_grant_role_to_account_role" "ar_kpis_r_to_bi" {
  role_name        = snowflake_account_role.ar_kpis_r.name
  parent_role_name = snowflake_account_role.fr_bi_reporting.name
}

resource "snowflake_grant_role_to_account_role" "ar_marts_r_to_clinical" {
  role_name        = snowflake_account_role.ar_marts_r.name
  parent_role_name = snowflake_account_role.fr_clinical_analytics.name
}
resource "snowflake_grant_role_to_account_role" "ar_kpis_r_to_clinical" {
  role_name        = snowflake_account_role.ar_kpis_r.name
  parent_role_name = snowflake_account_role.fr_clinical_analytics.name
}
resource "snowflake_grant_role_to_account_role" "ar_raw_gov_r_to_clinical" {
  role_name        = snowflake_account_role.ar_raw_gov_r.name
  parent_role_name = snowflake_account_role.fr_clinical_analytics.name
}
resource "snowflake_grant_role_to_account_role" "ar_phi_unmask_to_clinical" {
  # clear-text PHI gate — deliberately not in the SYSADMIN tree
  role_name        = snowflake_account_role.ar_phi_unmask.name
  parent_role_name = snowflake_account_role.fr_clinical_analytics.name
}

resource "snowflake_grant_role_to_account_role" "ar_marts_r_to_analyst" {
  role_name        = snowflake_account_role.ar_marts_r.name
  parent_role_name = snowflake_account_role.fr_analyst.name
}
resource "snowflake_grant_role_to_account_role" "ar_kpis_r_to_analyst" {
  role_name        = snowflake_account_role.ar_kpis_r.name
  parent_role_name = snowflake_account_role.fr_analyst.name
}

#############################################################################
# Service users — key-pair auth (TYPE=SERVICE); no passwords
#############################################################################

resource "snowflake_user" "svc_dbt" {
  name          = "SVC_DBT"
  login_name    = "SVC_DBT"
  display_name  = "dbt Transform Service"
  user_type         = "SERVICE"
  default_role      = snowflake_account_role.fr_dbt_transform.name
  default_warehouse = snowflake_warehouse.transform.name
  rsa_public_key    = var.svc_dbt_rsa_public_key
  comment           = "dbt transformation service account (key-pair auth, TYPE=SERVICE)"

  lifecycle {
    ignore_changes = [password]
  }
}

resource "snowflake_user" "svc_powerbi" {
  name          = "SVC_POWERBI"
  login_name    = "SVC_POWERBI"
  display_name  = "Power BI Reporting Service"
  user_type         = "SERVICE"
  default_role      = snowflake_account_role.fr_bi_reporting.name
  default_warehouse = snowflake_warehouse.bi.name
  rsa_public_key    = var.svc_powerbi_rsa_public_key
  comment           = "Power BI service account (key-pair auth, TYPE=SERVICE)"

  lifecycle {
    ignore_changes = [password]
  }
}

resource "snowflake_grant_role_to_user" "svc_dbt_role" {
  role_name = snowflake_account_role.fr_dbt_transform.name
  user_name = snowflake_user.svc_dbt.name
}

resource "snowflake_grant_role_to_user" "svc_powerbi_role" {
  role_name = snowflake_account_role.fr_bi_reporting.name
  user_name = snowflake_user.svc_powerbi.name
}

#############################################################################
# Network policies
#############################################################################

resource "snowflake_network_policy" "corporate" {
  provider        = snowflake.securityadmin
  name            = "NP_CORPORATE"
  allowed_ip_list = var.corporate_vpn_cidrs
  comment         = "Corporate VPN + HQ egress — account-level default"
}

resource "snowflake_network_policy" "ci_runners" {
  provider        = snowflake.securityadmin
  name            = "NP_CI_RUNNERS"
  allowed_ip_list = var.ci_runner_cidrs
  comment         = "CI/CD runner IPs — service accounts only"
}

resource "snowflake_network_policy" "breakglass" {
  provider        = snowflake.securityadmin
  name            = "NP_BREAKGLASS"
  allowed_ip_list = var.breakglass_cidrs
  comment         = "Break-glass emergency user — includes IR workstation range"
}

resource "snowflake_network_policy_attachment" "account_default" {
  provider            = snowflake.securityadmin
  network_policy_name = snowflake_network_policy.corporate.name
  set_for_account     = true
}

resource "snowflake_network_policy_attachment" "svc_dbt" {
  provider            = snowflake.securityadmin
  network_policy_name = snowflake_network_policy.ci_runners.name
  users               = [snowflake_user.svc_dbt.name]
}

resource "snowflake_network_policy_attachment" "svc_powerbi" {
  provider            = snowflake.securityadmin
  network_policy_name = snowflake_network_policy.ci_runners.name
  users               = [snowflake_user.svc_powerbi.name]
}

resource "snowflake_network_policy_attachment" "breakglass_user" {
  provider            = snowflake.securityadmin
  network_policy_name = snowflake_network_policy.breakglass.name
  users               = ["BREAKGLASS_01"]
}
