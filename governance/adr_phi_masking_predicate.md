# ADR: PHI masking predicate — invoker-role vs in-session

**Status:** Accepted
**Scope:** `rbac/snowflake_rbac.sql` masking policies `MP_PHI_STRING`, `MP_PHI_DATE`
**Decision owner:** Security / Governance

## Context

The dynamic masking policies gate cleartext PHI on membership of the `AR_PHI_UNMASK`
access role. Snowflake offers two role-membership predicates for a policy body, and they
differ in how they treat **secondary roles**:

| Predicate | Evaluates | Secondary roles |
|---|---|---|
| `IS_ROLE_IN_SESSION('AR_PHI_UNMASK')` | primary role inheritance **and** all activated secondary roles | **counted** |
| `IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK')` | invoker's **primary** role and its inheritance only | **ignored** |

Identity is Entra ID → Snowflake via SCIM. Two documented defaults make the secondary-role
path the *common* case, not an edge case:

- **`DEFAULT_SECONDARY_ROLES` defaults to `('ALL')`** since Snowflake behavior-change bundle
  `2024_08` (`bcr-1692`); before that it was `NULL`. So every role granted to a user
  auto-activates as a secondary role at login (Snowflake docs, `CREATE USER`).
- **Entra SCIM provisions all roles as `primary = false`**, and `DEFAULT_ROLE` is a *custom
  extension attribute* not in the default mapping (Microsoft Learn, Snowflake provisioning
  tutorial). So SCIM alone does not make any role a user's primary.

Together: a user who holds `AR_PHI_UNMASK` only through a **secondary** role (the default for
a multi-group SCIM user) would see cleartext PHI under `IS_ROLE_IN_SESSION`. Snowflake's own
docs frame the distinction: use `IS_ROLE_IN_SESSION` "to evaluate the role hierarchy for the
current session" (includes secondaries); `IS_GRANTED_TO_INVOKER_ROLE` evaluates the invoker
(primary) role only.

## Decision

Use **`IS_GRANTED_TO_INVOKER_ROLE('AR_PHI_UNMASK')`**. For a PHI gate we want fail-closed,
primary-role-only semantics: a role that is merely a secondary in the session must not
unmask PHI.

This decision is **bundled with an operational requirement**: PHI-cleared users must have
`DEFAULT_ROLE = FR_CLINICAL_ANALYTICS` (the role carrying `AR_PHI_UNMASK`) set out-of-band,
because SCIM does not set `DEFAULT_ROLE`. Without primary-role discipline the strict
predicate masks PHI *from users who are entitled to see it*. `DEFAULT_SECONDARY_ROLES =
('ALL')` does **not** satisfy the predicate — auto-activated secondaries are exactly what
it ignores.

## Evidence (verified live on a Snowflake Enterprise account, tag-based masking)

| Scenario | Predicate | Role activation | Result |
|---|---|---|---|
| Entitled, correct | `IS_GRANTED_TO_INVOKER_ROLE` | clinical = **primary** | cleartext ✓ |
| Entitled, misconfigured | `IS_GRANTED_TO_INVOKER_ROLE` | clinical = **secondary** | `***REDACTED***` (masked) |
| via view | `IS_GRANTED_TO_INVOKER_ROLE` | clinical = secondary | masked (propagates) |
| break-glass | `IS_GRANTED_TO_INVOKER_ROLE` | ACCOUNTADMIN | masked (no bypass) |
| leak contrast | `IS_ROLE_IN_SESSION` | clinical = secondary | cleartext (**the leak**) |

Three implementation constraints were confirmed live and shaped the design:

1. **Context sensitivity.** `IS_GRANTED_TO_INVOKER_ROLE` returns TRUE for a secondary role
   in a bare `SELECT`, but correctly EXCLUDES secondary roles when evaluated **inside a
   policy** — the only context that matters here. Predicates must be tested in the policy,
   not in isolation.
2. **Literal-only argument.** `IS_GRANTED_TO_INVOKER_ROLE` accepts a **string literal**
   only; a column argument raises `invalid argument for function`. This is why the
   row-access policy `RAP_FACILITY` (which checks a role name from a column in a data-driven
   `ROW_ENTITLEMENTS` table) **cannot** use it and retains `IS_ROLE_IN_SESSION`.
3. **Replace-while-attached.** A masking policy attached to a tag/column cannot be
   `CREATE OR REPLACE`d ("associated with one or more entities"); the body is changed in
   place with `ALTER MASKING POLICY ... SET BODY`. The deploy script uses
   `CREATE ... IF NOT EXISTS` + `ALTER ... SET BODY` so it is idempotent for both fresh
   installs and in-place migration off the old `IS_ROLE_IN_SESSION` body.

## Consequence: masking (invoker) vs row-access (in-session) mismatch

Masking is primary-role-only; row-access counts secondary roles. The only possible
divergence is **rows visible but PHI columns still masked** — it **fails closed** and
cannot leak PHI. Once `DEFAULT_ROLE` discipline is in place, the clinical role is primary
and both predicates agree, so the distinction is moot on the intended path. Documented in
`rbac/snowflake_rbac.sql` Section 3d.

## When `IS_ROLE_IN_SESSION` would be the better choice

If an organization **deliberately** grants PHI-unmask through secondary roles (e.g. a
multi-role session model where the clinical capability is intentionally additive and never
the primary), or where no one uses secondary roles at all (the two predicates are then
equivalent), `IS_ROLE_IN_SESSION` is simpler and avoids the `DEFAULT_ROLE` dependency. That
is a looser posture and was rejected here in favor of fail-closed PHI protection.

## Rollback

Revert the two `ALTER MASKING POLICY ... SET BODY` statements to the
`IS_ROLE_IN_SESSION('AR_PHI_UNMASK')` body. No object needs detaching; the change is
in-place and immediate.

## Sources

Documentation (grounded this review):
- `IS_GRANTED_TO_INVOKER_ROLE` and the IS_ROLE_IN_SESSION distinction —
  https://docs.snowflake.com/en/sql-reference/functions/is_granted_to_invoker_role
- `IS_ROLE_IN_SESSION` — https://docs.snowflake.com/en/sql-reference/functions/is_role_in_session
- `DEFAULT_SECONDARY_ROLES` default is `('ALL')` —
  https://docs.snowflake.com/en/sql-reference/sql/create-user and behavior-change bundle
  https://docs.snowflake.com/en/release-notes/bcr-bundles/2024_08/bcr-1692
- Entra SCIM provisions roles as `primary = false`; `DEFAULT_ROLE` is a custom extension
  attribute — https://learn.microsoft.com/entra/identity/saas-apps/snowflake-provisioning-tutorial

Live-verified on a Snowflake Enterprise trial this session (not from docs): the in-policy
masking behavior under tag-based attachment (primary unmask / secondary mask / view
propagation / ACCOUNTADMIN mask), the literal-only argument to IS_GRANTED_TO_INVOKER_ROLE,
the context-sensitivity vs a bare SELECT, and that an attached policy cannot be
CREATE OR REPLACE'd but ALTER ... SET BODY migrates it in place.
