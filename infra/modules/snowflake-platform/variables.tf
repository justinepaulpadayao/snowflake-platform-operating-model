variable "snowflake_org" {
  type        = string
  description = "Snowflake organization name (from Admin > Accounts in the console)."
}

variable "snowflake_account" {
  type        = string
  description = "Snowflake account name (not the full URL; the locator portion)."
}

variable "snowflake_private_key" {
  type        = string
  sensitive   = true
  description = "PEM-encoded RSA private key for SVC_TERRAFORM. Load from a vault; never hardcode."
}

variable "svc_dbt_rsa_public_key" {
  type        = string
  description = "RSA public key (PEM body, no headers) for SVC_DBT."
}

variable "svc_powerbi_rsa_public_key" {
  type        = string
  description = "RSA public key (PEM body, no headers) for SVC_POWERBI."
}

variable "corporate_vpn_cidrs" {
  type        = list(string)
  description = "Corporate VPN and HQ egress CIDR blocks for the account-level network policy."
}

variable "ci_runner_cidrs" {
  type        = list(string)
  description = "CI/CD runner IP ranges applied to service account network policies."
}

variable "security_alert_email" {
  type        = string
  description = "Email address for security alert notifications."
}

variable "warehouse_sizes" {
  type = object({
    admin     = string
    transform = string
    bi        = string
    analyst   = string
  })
  default = {
    admin     = "XSMALL"
    transform = "SMALL"
    bi        = "SMALL"
    analyst   = "SMALL"
  }
  description = "Warehouse sizes per workload. Override for environments with higher throughput needs."
}

variable "resource_monitor_credits" {
  type = object({
    transform = number
    bi        = number
    analyst   = number
  })
  default = {
    transform = 200
    bi        = 150
    analyst   = 150
  }
  description = "Monthly credit quotas per workload resource monitor."
}
