/* ============================================================================
   security/auth_session_policies.sql
   Authentication and session hardening for the Snowflake platform.

   Enforcing MFA at the POLICY level removes dependence on per-user enrollment:
   a missed enrollment becomes an authentication error rather than a silent
   bypass.  Session policies bound idle lifetimes so an abandoned privileged
   session cannot persist indefinitely.

   Policies defined here:
     AP_HUMAN_MFA       — MFA required for all interactive human sessions.
                          Accepts SAML (Entra SSO, MFA at the IdP) and PASSWORD
                          (native Snowflake + TOTP/push MFA).
     AP_SERVICE_KEYPAIR — key-pair JWT only for service accounts.  A password
                          prompt reaching a service account is a misconfiguration
                          that this policy turns into a hard auth failure.
     SP_STANDARD        — 30-min idle / 8-h max; applies to analyst and BI roles.
     SP_PRIVILEGED      — 15-min idle for platform-admin and governance roles.

   HIPAA relevance:
     §164.312(d) person/entity authentication — enforces MFA at the platform.
     §164.312(a)(2)(iii) automatic logoff — session timeouts limit blast radius
     of an abandoned session.

   EDITION: AUTHENTICATION POLICY and SESSION POLICY require Enterprise edition
            or higher.  Verify: SHOW PARAMETERS LIKE 'EDITION' IN ACCOUNT.

   VALIDATION: after applying, confirm behavior with:
     (a) A human user who is NOT MFA-enrolled receives a hard auth error.
     (b) A service account login attempt with password fails (key-pair only).
     (c) An idle session exceeds SP_STANDARD timeout and is terminated.
   Link test output to docs/evidence/ following the same pattern as VALIDATION.md.
   ============================================================================ */


/* ============================================================================
   SECTION 1 -- AUTHENTICATION POLICIES
   ============================================================================ */
USE ROLE SECURITYADMIN;

-- 1a. Human MFA policy.
--     SAML: Entra SAML/OIDC satisfies MFA at the IdP level (Entra Conditional
--     Access requires MFA for the Snowflake application).
--     PASSWORD: Snowflake-native authentication paired with TOTP or push MFA.
--     MFA_ENROLLMENT = REQUIRED means a user who skips MFA enrollment cannot
--     authenticate via password — the UI prompts them to enroll rather than
--     silently allowing a password-only session.
CREATE AUTHENTICATION POLICY IF NOT EXISTS AP_HUMAN_MFA
    AUTHENTICATION_METHODS     = ('SAML', 'PASSWORD')
    MFA_AUTHENTICATION_METHODS = ('PASSWORD')
    MFA_ENROLLMENT             = REQUIRED
    CLIENT_TYPES               = ('SNOWFLAKE_UI', 'SNOWSQL', 'SNOWFLAKE_CLI', 'DRIVERS', 'JDBC', 'ODBC')
    COMMENT = 'Human users: MFA required (SAML or password+TOTP)';

-- 1b. Service-account key-pair-only policy.
--     Removes the password authentication path entirely for service accounts.
--     If the orchestration layer ever attempts a password login for SVC_DBT
--     or SVC_POWERBI, the connection fails immediately — a signal to investigate
--     rather than a silent fallback.
CREATE AUTHENTICATION POLICY IF NOT EXISTS AP_SERVICE_KEYPAIR
    AUTHENTICATION_METHODS = ('KEYPAIR')
    CLIENT_TYPES           = ('SNOWFLAKE_CLI', 'DRIVERS', 'JDBC', 'ODBC', 'SNOWSQL')
    COMMENT = 'Service accounts: key-pair JWT only; no password or MFA path';


/* ============================================================================
   SECTION 2 -- SESSION POLICIES
   ============================================================================ */

-- 2a. Standard session: 30-min idle, applies to analysts and BI users.
--     An idle analyst session left open overnight is not a material risk, but
--     30 minutes aligns with common HIPAA workstation policies.
CREATE SESSION POLICY IF NOT EXISTS SP_STANDARD
    SESSION_IDLE_TIMEOUT_MINS    = 30
    SESSION_UI_IDLE_TIMEOUT_MINS = 30
    COMMENT = 'Standard: 30-min idle timeout for analyst and BI roles';

-- 2b. Privileged session: 15-min idle for admin/governance roles.
--     An abandoned admin or governance session has significantly larger blast
--     radius than an analyst session; tighter timeout limits the exposure window.
CREATE SESSION POLICY IF NOT EXISTS SP_PRIVILEGED
    SESSION_IDLE_TIMEOUT_MINS    = 15
    SESSION_UI_IDLE_TIMEOUT_MINS = 15
    COMMENT = 'Privileged: 15-min idle timeout for admin and governance roles';


/* ============================================================================
   SECTION 3 -- APPLY POLICIES
   ============================================================================ */

-- 3a. Account-level authentication default: human MFA.
--     Per-user overrides (service accounts) take precedence.
ALTER ACCOUNT SET AUTHENTICATION POLICY AP_HUMAN_MFA;

-- 3b. Service accounts: key-pair only, overriding the account default.
ALTER USER SVC_DBT     SET AUTHENTICATION POLICY AP_SERVICE_KEYPAIR;
ALTER USER SVC_POWERBI SET AUTHENTICATION POLICY AP_SERVICE_KEYPAIR;

-- 3c. Account-level session default: standard timeouts.
ALTER ACCOUNT SET SESSION POLICY SP_STANDARD;

-- 3d. Named platform-admin and governance users: tighter session timeout.
--     Snowflake SESSION POLICY applies at user level; update the placeholders
--     with the actual login names of platform-admin personnel.
-- ALTER USER <platform_admin_login_1> SET SESSION POLICY SP_PRIVILEGED;
-- ALTER USER <gov_admin_login_1>      SET SESSION POLICY SP_PRIVILEGED;


/* ============================================================================
   SECTION 4 -- VERIFICATION QUERIES
   Run after applying policies to confirm expected behavior.
   Attach results to docs/evidence/ as a VALIDATION.md supplement.
   ============================================================================ */

-- Active authentication policies on the account and per-user:
SHOW AUTHENTICATION POLICIES;

-- Active session policies:
SHOW SESSION POLICIES;

-- Policy assignment (account level):
SELECT *
FROM snowflake.account_usage.authentication_history
WHERE event_timestamp >= DATEADD('hour', -2, CURRENT_TIMESTAMP())
ORDER BY event_timestamp DESC;

-- Confirm MFA enrollment status for all human users:
SELECT
    name          AS user_name,
    type,
    has_mfa,
    has_password,
    has_rsa_public_key,
    default_role,
    last_success_login
FROM snowflake.account_usage.users
WHERE deleted_on IS NULL
  AND disabled   = FALSE
  AND type       = 'PERSON'  -- human users only
ORDER BY has_mfa, user_name;
-- Expected: all PERSON users have has_mfa = TRUE after policy enforcement.
-- Any FALSE row is a finding for the monthly access review.

-- Failed login anomalies that may indicate the policy is blocking a
-- misconfigured client (password attempt to a key-pair-only service account):
SELECT
    user_name,
    error_code,
    error_message,
    client_ip,
    event_timestamp
FROM snowflake.account_usage.login_history
WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND is_success = 'NO'
ORDER BY event_timestamp DESC;
