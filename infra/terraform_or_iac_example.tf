#############################################################################
# terraform_or_iac_example.tf
#
# Infrastructure-as-code SKETCH for the governance layer of the Snowflake
# platform: the least-privilege roles the monthly access-review automation runs
# as, the governance schema where evidence is stored, and a warehouse + resource
# monitor. Managing these as code means a change to the *automation's* own
# privileges is itself a reviewed PR (drift in governance infra is reviewable).
#
# This is a sketch, not a full deployment. It intentionally manages only the
# governance/automation surface; the human/service FR_*/AR_* model is applied
# via snowflake_rbac.sql (which is clearer to read and review as SQL). All
# values are synthetic placeholders — wire real auth via a secrets backend.
#
# Provider: Snowflake-Labs/snowflake (verify the latest version + resource
# names against the provider docs before applying; the provider's resource API
# evolves between major versions).
#############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    snowflake = {
      source  = "Snowflake-Labs/snowflake"
      version = "~> 0.95" # pin to the version you validate against
    }
  }
}

# Authenticate as a dedicated Terraform service role via key-pair auth.
# Never hardcode the private key — load it from a secrets manager / TF_VAR.
provider "snowflake" {
  organization_name = var.snowflake_org
  account_name      = var.snowflake_account
  user              = "SVC_TERRAFORM"
  authenticator     = "SNOWFLAKE_JWT"
  private_key       = var.snowflake_private_key # from Vault / env, not VCS
  role              = "SYSADMIN"
}

variable "snowflake_org" { type = string }
variable "snowflake_account" { type = string }
variable "snowflake_private_key" {
  type      = string
  sensitive = true
}

#############################################################################
# Governance database/schema — append-only evidence store for access reviews
#############################################################################
resource "snowflake_database" "governance" {
  name    = "GOVERNANCE"
  comment = "Access-review evidence + history (managed by Terraform)"
}

resource "snowflake_schema" "access_review" {
  database            = snowflake_database.governance.name
  name                = "ACCESS_REVIEW"
  with_managed_access = true # only the owner grants on objects here
  comment             = "Monthly access-review results + immutable evidence"
}

#############################################################################
# Dedicated warehouse + resource monitor for the review job (cost guardrail)
#############################################################################
resource "snowflake_resource_monitor" "review" {
  name         = "RM_ACCESS_REVIEW"
  credit_quota = 20
  frequency    = "MONTHLY"
  notify_triggers         = [80]
  suspend_trigger         = 100
  suspend_immediate_trigger = 110
}

resource "snowflake_warehouse" "review" {
  name             = "WH_ACCESS_REVIEW"
  warehouse_size   = "XSMALL"
  auto_suspend     = 60
  auto_resume      = true
  resource_monitor = snowflake_resource_monitor.review.name
}

#############################################################################
# Least-privilege automation roles (separation of read vs. enforce)
#   - AUDITOR: read-only metadata access (the monthly report runs as this).
#   - ACCESS_REVIEW_ENFORCER: scoped MANAGE GRANTS, assumed ONLY by the gated
#     apply-job after human approval. Neither role is ACCOUNTADMIN.
#############################################################################
resource "snowflake_account_role" "auditor" {
  name    = "AUDITOR"
  comment = "Read-only access-review role (ACCOUNT_USAGE + SHOW)"
}

resource "snowflake_account_role" "enforcer" {
  name    = "ACCESS_REVIEW_ENFORCER"
  comment = "Scoped MANAGE GRANTS for approved revokes only (gated job)"
}

# Read on the SNOWFLAKE shared db (ACCOUNT_USAGE) for the auditor role.
resource "snowflake_grant_privileges_to_account_role" "auditor_imported" {
  account_role_name = snowflake_account_role.auditor.name
  privileges        = ["IMPORTED PRIVILEGES"]
  on_account_object {
    object_type = "DATABASE"
    object_name = "SNOWFLAKE"
  }
}

# Enforcer can manage grants account-wide but is NOT a system admin role; it is
# assumed only by the approved, logged apply-job (see access_review.py).
resource "snowflake_grant_privileges_to_account_role" "enforcer_manage_grants" {
  account_role_name = snowflake_account_role.enforcer.name
  privileges        = ["MANAGE GRANTS"]
  on_account        = true
}

#############################################################################
# Notes:
# - Apply with a plan/approval gate in CI (e.g. `terraform plan` posted to a PR,
#   `terraform apply` behind a protected environment) — same discipline the
#   access-review automation itself uses before any revoke.
# - Keep state in a remote backend with locking + encryption (S3+DynamoDB /
#   Azure Storage); never commit state or the private key.
#############################################################################
