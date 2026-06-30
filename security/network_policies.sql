/* ============================================================================
   security/network_policies.sql
   Network-layer access controls for the Snowflake platform.

   A valid key-pair credential is necessary but not sufficient for
   authentication: without a network policy, that credential is usable from
   any IP on the internet.  These policies form a second gate by scoping each
   identity class to known egress points.

   Policies defined here:
     NP_CORPORATE   — corporate VPN + HQ breakout; applied account-wide.
     NP_CI_RUNNERS  — CI/CD runner pool IPs applied to service accounts.
     NP_BREAKGLASS  — slightly wider for the emergency user; still scoped.

   Application order (Snowflake evaluates user-level policy first):
     1. Per-user policy (SVC_*, BREAKGLASS_01) — most restrictive for SVC.
     2. Account-level fallback (NP_CORPORATE) — catches all other users.

   HIPAA relevance:
     §164.312(a)(1) access control — reduces attack surface if a key is stolen.
     §164.312(b) audit controls — client_ip in LOGIN_HISTORY is now bounded to
     known ranges, making anomalous IPs stand out in anomaly_detection.sql.

   PrivateLink note — Section 3 documents how to replace the internet path
   entirely for production workloads.

   EDITION: NETWORK POLICY is available on all Snowflake editions.
   SAFETY: replace all <...> placeholders with real CIDRs before applying.
           Always test on a non-critical user first:
             ALTER USER <test_user> SET NETWORK_POLICY = NP_CORPORATE;
           Then verify you can still connect before setting the account policy.
   ============================================================================ */


/* ============================================================================
   SECTION 1 -- NOTIFICATION INTEGRATION (prerequisite for alerts)
   Place credentials/email config here so all policies + alerts share one
   integration object managed by a single SECURITYADMIN grant.
   ============================================================================ */
USE ROLE ACCOUNTADMIN;

CREATE NOTIFICATION INTEGRATION IF NOT EXISTS NI_SECURITY_EMAIL
    TYPE     = EMAIL
    ENABLED  = TRUE
    ALLOWED_RECIPIENTS = ('<security-team@example.com>')
    COMMENT  = 'Outbound security alerts: break-glass, policy drift, anomalies';


/* ============================================================================
   SECTION 2 -- NETWORK POLICY DEFINITIONS
   ============================================================================ */
USE ROLE SECURITYADMIN;

-- 2a. Corporate / VPN egress — applied as the account-level default.
--     Add every CIDR used by corporate VPN concentrators, HQ internet breakouts,
--     and any regional office NAT IPs.  This is the broadest policy; keep it
--     as narrow as possible.
CREATE NETWORK POLICY IF NOT EXISTS NP_CORPORATE
    ALLOWED_IP_LIST = (
        '<CORPORATE_VPN_CIDR_1>',    -- primary VPN region  (e.g. '10.0.0.0/8')
        '<CORPORATE_VPN_CIDR_2>',    -- secondary VPN region
        '<HQ_EGRESS_IP>/32'          -- fixed HQ NAT gateway
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'Corporate VPN + HQ egress — default account policy';

-- 2b. CI/CD runner IPs — applied per service account.
--     For GitHub-hosted runners use the IP ranges published in the GitHub meta
--     API (actions section).  For self-hosted runners, use the runner pool CIDR.
--     Keeping this separate from NP_CORPORATE means a compromised key pair for
--     SVC_DBT is useless from a corporate laptop or any non-runner IP.
CREATE NETWORK POLICY IF NOT EXISTS NP_CI_RUNNERS
    ALLOWED_IP_LIST = (
        '<CI_RUNNER_CIDR>',          -- self-hosted runner pool
        '<GITHUB_ACTIONS_CIDR_1>',   -- from https://api.github.com/meta → actions
        '<GITHUB_ACTIONS_CIDR_2>'
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'CI/CD runner IPs — applied to service accounts only';

-- 2c. Break-glass override — intentionally slightly wider.
--     Incident responders may not be on the standard VPN path; this policy
--     adds the IR workstation pool.  Still scoped — not open to the internet.
CREATE NETWORK POLICY IF NOT EXISTS NP_BREAKGLASS
    ALLOWED_IP_LIST = (
        '<CORPORATE_VPN_CIDR_1>',
        '<CORPORATE_VPN_CIDR_2>',
        '<INCIDENT_RESPONSE_WORKSTATION_CIDR>'
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'Break-glass emergency user — includes IR workstation range';


/* ============================================================================
   SECTION 3 -- APPLY POLICIES
   Account-level = default for any user without a per-user override.
   ============================================================================ */

-- 3a. Account-level default: corporate network only.
ALTER ACCOUNT SET NETWORK_POLICY = NP_CORPORATE;

-- 3b. Service accounts: restricted to CI/CD runner IPs.
--     If a key is leaked, it is unusable from any non-runner source IP.
ALTER USER SVC_DBT     SET NETWORK_POLICY = NP_CI_RUNNERS;
ALTER USER SVC_POWERBI SET NETWORK_POLICY = NP_CI_RUNNERS;

-- 3c. Break-glass: wider but still bounded.
ALTER USER BREAKGLASS_01 SET NETWORK_POLICY = NP_BREAKGLASS;

/* Verification:
   SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;
   SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN USER SVC_DBT;
   SELECT client_ip, user_name, event_timestamp, is_success
   FROM snowflake.account_usage.login_history
   WHERE event_timestamp > DATEADD('hour', -1, CURRENT_TIMESTAMP())
   ORDER BY event_timestamp DESC;                                              */


/* ============================================================================
   SECTION 4 -- PRIVATE CONNECTIVITY (PrivateLink / Private Service Connect)
   Eliminates the public internet path entirely for production workloads.
   ============================================================================ */
-- Once PrivateLink is active, connections from Azure VNet or AWS VPC to
-- Snowflake traverse the cloud provider backbone only — no public endpoint.
--
-- AZURE (Private Link) setup:
--   1. Snowflake console (ACCOUNTADMIN) → Admin → Security → Private
--      Connectivity → Enable.  Note the Private Link Resource ID.
--   2. Azure portal → Private Endpoints → Create → target the Snowflake
--      resource ID from step 1.
--   3. DNS: add a private DNS zone for
--        <account>.privatelink.snowflakecomputing.com
--      resolving to the private endpoint NIC IP (RFC 1918).
--   4. Update NP_CORPORATE: replace public CIDRs with the Azure VNet range,
--      and optionally add the public Snowflake IPs to BLOCKED_IP_LIST to
--      enforce private-only access for all users.
--
-- AWS (PrivateLink) setup:
--   Identical pattern; create an Interface VPC Endpoint for
--   com.amazonaws.<region>.snowflake and update DNS accordingly.
--
-- Verify the path is private after setup:
SELECT SYSTEM$ALLOWLIST_PRIVATELINK();
-- client_ip in LOGIN_HISTORY should be a VNet RFC 1918 address, not a
-- Snowflake public egress IP.
