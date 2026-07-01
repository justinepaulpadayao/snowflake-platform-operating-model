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

Identity is Entra ID → Snowflake via SCIM. Snowsight activates non-primary roles with
`USE SECONDARY ROLES ALL` by default. So a user who holds `AR_PHI_UNMASK` only through a
**secondary** role would see cleartext PHI under `IS_ROLE_IN_SESSION`.

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
