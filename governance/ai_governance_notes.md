# AI Governance Notes — AI Tools in a HIPAA-Sensitive Snowflake Platform

**Scope:** All AI tools (chat assistants, IDE copilots, agents, MCP servers, SaaS-embedded AI,
Snowflake Cortex) used against or near systems that touch electronic PHI (ePHI) on our
Snowflake / dbt / Power BI stack.
**Owner:** Security / Privacy Office (HIPAA Security Officer) with Data Platform leads.
**Status:** Living document — review quarterly and whenever a new tool or use case is proposed.

> **Guiding principle:** Treat an AI tool like any third-party subprocessor. If we would not let an
> unvetted external vendor see the data, log, ticket, or schema, we do not let an AI tool see it —
> until that tool is evaluated and approved. **No BAA → no PHI. Not on the register → prohibited.**

---

## 1. Evaluating whether an AI tool is safe for a HIPAA environment

A tool must pass **all** mandatory gates before it touches anything connected to ePHI. The
Security/Privacy Officer owns the decision; engineers gather the evidence.

**Legal / contractual (mandatory)**
- **Business Associate Agreement (BAA)** covering the *exact* product, tier, and API in use. A
  vendor may offer a BAA only on specific paid plans — confirm it covers what you will actually use.
- **Subprocessor chain.** Identify who actually runs the model. A wrapper tool that forwards prompts
  to a third-party foundation model needs that model host covered by the BAA / flow-down terms.
- **Data residency** meets our regulatory commitments.

**Data handling**
- Inputs/outputs are **not used to train or improve** models — contractual, not just a UI toggle.
- Retention minimized/zero; deletion on request; no human review of PHI-bearing prompts; tenant
  isolation confirmed.

**Security**
- SOC 2 Type II / HITRUST / ISO 27001; current HIPAA attestation. Encryption in transit + at rest.
- SSO/SAML, MFA, SCIM deprovisioning; **central admin enforcement** of config (so "training off"
  doesn't depend on each engineer's personal settings).
- Egress surface understood — for IDE plugins/agents, what is sent upstream by default (open files,
  env vars, terminal output) and can it be scoped/disabled.

**Decision outcomes:** `Approved for PHI` · `Approved, no PHI (synthetic/de-identified only)` ·
`Prohibited`. Default is **Prohibited until evaluated** and on the register (§4). Prefer, in order:
(a) AI inside our covered boundary (e.g. **Snowflake Cortex** under our Snowflake BAA), (b) enterprise
SaaS with BAA + zero-retention, (c) anything else.

## 2. Information that must NEVER be pasted into unapproved AI tools

- **PHI / the 18 HIPAA identifiers** — names, geographic detail < state, all dates except year, MRN,
  SSN, account/health-plan numbers, device IDs, IPs, biometrics, full-face photos, and any other
  unique identifier; plus diagnoses/labs/claims tied to an individual.
- **Real data rows or query results** — including a "few rows to debug" and query output in error
  messages.
- **Credentials & secrets** — passwords, Snowflake key-pairs, OAuth tokens, API keys, `profiles.yml`,
  `.env`, connection strings.
- **Unredacted logs and tickets** — they routinely embed PHI, record IDs, and internal hostnames.
- **Security-sensitive material** — vulnerability findings, architecture, masking-policy definitions,
  key references.
- **Re-identifiable "de-identified" data** — small cohorts, rare diagnoses, ZIP+DOB+gender
  quasi-identifiers. Removing names is **not** enough.

**Platform-specific leak zones on our stack:** Snowflake `SELECT *` output / failing-query rows;
dbt seeds, compiled SQL, test-failure rows; Power BI screenshots, `.pbix` files, row-level-security
definitions; and **sensitive metadata** — a column named `hiv_status` or `substance_abuse_dx`
discloses context by itself.

## 3. Controls required before AI tools touch data, logs, tickets, code, or metadata

Access is a grant, not a default. Apply per surface; prefer de-identified/synthetic inputs everywhere.

| Surface | Required controls |
|---|---|
| **Data** (Snowflake/dbt/Power BI) | PHI-approved tools only; point AI at **masked/synthetic** datasets; never paste live results; rely on our **dynamic masking + row-access policies** (see `snowflake_rbac.sql`) so even an authorized AI session cannot read raw PHI; prefer Cortex in-boundary over exporting data out; connect via a dedicated least-privilege role, never `ACCOUNTADMIN`. |
| **Logs** | Scrub PHI/secrets/IPs before sharing; do not wire unapproved "AI ops" tools to Snowflake query history / dbt run logs. |
| **Tickets** | Redact before ingestion; vet AI ticket-summarizers and meeting notetakers; exclude patient-correspondence queues. |
| **Code** | Approved copilots only; no real PHI/secrets in code, tests, fixtures, or commits; exclude sensitive paths (`.env`, `profiles.yml`, seeds) via ignore files; treat AI-generated code as **untrusted** — review, SAST, secret-scan, watch for hallucinated/typosquatted dependencies. |
| **Metadata** | Don't dump full `information_schema` / dbt `manifest.json`; sensitive names disclose context; lineage reveals architecture. |
| **Cross-cutting** | Least-privilege scoped service identity; no standing prod write; audit logging to SIEM; DLP/egress control; **human-in-the-loop** for any action that changes data, permissions, or infra; minimum-necessary even to approved tools. |

## 4. Documenting approved vs. prohibited AI use cases

Maintain a single, version-controlled **AI Use Register** (default-deny — anything not listed is
prohibited).

**Approved tools table:** tool/tier · BAA status & date · training disabled? · retention ·
classification (PHI / no-PHI) · allowed use cases · constraints · owner/approver · next review.

**Use-case matrix (starter):**

| Use case | Status | Conditions |
|---|---|---|
| Draft docs/runbooks from non-sensitive notes | Approved | No PHI/secrets/hostnames |
| Write/refactor dbt SQL on genericized schema | Approved w/ conditions | No real rows; review + test |
| Generate Snowflake admin scripts (no creds in prompt) | Approved w/ conditions | Human review before run; no prod write without approval |
| Troubleshoot with **redacted** errors/logs | Approved w/ conditions | Strip PHI/secrets/IPs first |
| Summarize **redacted** tickets in BAA-covered tool | Approved w/ conditions | Redaction verified |
| Security review of code/config in an approved tool | Approved w/ conditions | No secrets in prompt; findings stay internal |
| Paste real patient data / query results | **Prohibited** | HIPAA breach risk |
| Paste credentials / keys / `.env` | **Prohibited** | Always |
| Consumer/unapproved AI for anything sensitive | **Prohibited** | Synthetic, non-sensitive only |
| Auto-execute AI actions on prod data/permissions | **Prohibited** | Requires human approval |
| Feed raw security/audit logs to an agent | **Prohibited** | Sanitized exports only |

**Process:** lightweight intake ticket → Security/Privacy review against §1 → register entry;
re-review on T&C / model / subprocessor / tier / data-category change; periodic (quarterly)
revalidation; record decision, approver, and date; log incidents and near-misses back into the rules.

## 5. Using AI personally while validating correctness and avoiding risk

You are accountable for anything you ship with AI help. The AI is a fast junior assistant, not an
authority. *(This is the same discipline our `phi-safe-authoring` and `snowflake-doc-grounding`
engineering skills enforce at the artifact level.)*

**Protect data/secrets (every prompt):** approved tools for work content; sanitize before pasting
(no PHI, no secrets, no internal hostnames, no real rows — use synthetic/genericized examples);
secrets stay in a vault; disable chat history/training where available.

**Validate output (trust nothing by default):**
- Read and understand **every line**; if you can't explain it, don't ship it.
- Verify facts and platform specifics (view names, grant syntax, editions, latency) against
  **authoritative docs** — assume the model can be confidently wrong.
- Test on **synthetic/dev** data: check SQL grain/fan-out, null handling, dedup, incremental logic,
  date/timezone boundaries; run `dbt build`/tests; review query plans for cost.
- Watch for hallucinated functions/columns/macros and **prompt injection** when AI reads
  tickets/logs/web/repos.
- Ensure AI suggestions don't **weaken controls** — over-broad grants, disabled masking,
  `SELECT *` on PHI, hardcoded creds. Reject and rewrite.
- Keep AI-assisted changes in normal **change control**: PRs, review, CI, audit trail; note material
  AI assistance for reviewer awareness.

**If something goes wrong:** if PHI or a secret reaches an unapproved tool, **report immediately**
per the incident-response process and **rotate** any exposed secret — do not quietly delete and move
on.

**Quick self-check before send / merge:** (1) PHI, secrets, or sensitive metadata in this prompt? →
redact/synthetic/stop. (2) Tool approved for this data class? → if not, switch. (3) Minimum necessary?
→ trim. (4) Output read, verified, and tested on safe data? → if not, don't ship.

*This document is operational guidance and does not replace the organization's formal HIPAA
policies, Business Associate Agreements, or the Security/Privacy Officer's authority.*
