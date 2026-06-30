#!/usr/bin/env python3
"""
access_review.py — Monthly Snowflake access review for a HIPAA / ePHI platform.

Reconciles ACTUAL Snowflake grants against EXPECTED access derived from Entra ID
group membership + an approved role matrix + a service-account inventory, then
reports exceptions and (only when explicitly told to) applies APPROVED revokes.

SAFETY MODEL (see automation_plan.md §4):
  * Dry-run by default — nothing is revoked unless BOTH --apply AND a matching
    signed approval are present.
  * Separation of duties — the approver must differ from the runner.
  * Protected roles (ACCOUNTADMIN/SECURITYADMIN/FR_BREAKGLASS/...) are never
    auto-revoked.
  * Every revoke is re-confirmed against live `SHOW GRANTS` first (ACCOUNT_USAGE
    lags) and a rollback (inverse GRANT) is written BEFORE the revoke.
  * A blast-radius cap aborts oversized change sets.
  * Operates on METADATA ONLY — no PHI is ever read.

The comparison core (build_expected / reconcile) is pure and unit-testable
without live credentials. The SnowflakeClient / EntraClient `_query` methods are
the only places that need real SDK wiring. All example identifiers are synthetic.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import yaml  # PyYAML

logger = logging.getLogger("access_review")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

DEFAULT_STALE_DAYS = 90
DEFAULT_MAX_REVOKES = 50
KEY_ROTATION_DAYS = 365
# Never auto-revoked, even if approved — defense in depth (overlaps matrix config).
# Every privileged system role plus the PHI/policy capability roles.
HARD_PROTECTED_ROLES = {
    "ACCOUNTADMIN",
    "SECURITYADMIN",
    "SYSADMIN",
    "USERADMIN",
    "ORGADMIN",
    "FR_BREAKGLASS",
    "FR_PLATFORM_ADMIN",
    "FR_GOV_ADMIN",
    "AR_PHI_UNMASK",
    "AR_GOV_ADMIN",
}

SEVERITY = {
    "ORPHAN": "CRITICAL",
    "OVER_PROVISIONED": "HIGH",
    "UNMANAGED_SVC": "HIGH",
    "STALE": "MEDIUM",
    "STALE_KEY": "HIGH",
    "UNDER_PROVISIONED": "LOW",
}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# --------------------------------------------------------------------------- #
# Domain models
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Grant:
    identity: str  # Snowflake login (upper-cased)
    role: str  # role name (upper-cased)


@dataclass
class Identity:
    login: str
    is_service: bool = False
    entra_object_id: str | None = None
    account_enabled: bool = True
    last_login: dt.date | None = None
    key_last_set: dt.date | None = None  # for service accounts: RSA key set date


@dataclass
class Exception_:
    exception_id: str
    kind: str
    identity: str
    role: str | None
    severity: str
    sensitivity: str
    detail: str
    revoke_sql: str | None = None
    rollback_sql: str | None = None


def _exc_id(kind: str, identity: str, role: str | None) -> str:
    return hashlib.sha256(f"{kind}|{identity}|{role or ''}".encode()).hexdigest()[:16]


def _q(identifier: str) -> str:
    """Quote a Snowflake identifier safely (double-quote; escape embedded quotes).
    Prevents breakage/misfire on UPN-style users (e.g. jdoe@example.com) or roles
    with special characters, and removes any identifier-injection foothold."""
    return '"' + str(identifier).replace('"', '""') + '"'


# --------------------------------------------------------------------------- #
# Pure comparison core (unit-testable — no I/O)
# --------------------------------------------------------------------------- #
def build_expected(
    role_matrix: dict,
    group_membership: dict[str, list[str]],  # entra_group_id -> [login, ...]
    svc_inventory: dict,
) -> tuple[set[Grant], dict[str, str]]:
    """Return EXPECTED (identity, role) grants and a role->sensitivity map."""
    expected: set[Grant] = set()
    sensitivity: dict[str, str] = {}
    for entry in role_matrix.get("entra_groups", []):
        roles = [r.upper() for r in entry.get("fr_roles", [])]
        for r in roles:
            sensitivity[r] = entry.get("data_sensitivity", "internal")
        for login in group_membership.get(entry["entra_group_id"], []):
            for r in roles:
                expected.add(Grant(login.upper(), r))
    for sa in svc_inventory.get("service_accounts", []):
        for r in sa.get("expected_roles", []):
            expected.add(Grant(sa["login_name"].upper(), r.upper()))
    return expected, sensitivity


def reconcile(
    actual: set[Grant],
    expected: set[Grant],
    identities: dict[str, Identity],
    svc_logins: set[str],
    sensitivity: dict[str, str],
    stale_days: int = DEFAULT_STALE_DAYS,
    key_rotation_days: int = KEY_ROTATION_DAYS,
    today: dt.date | None = None,
) -> list[Exception_]:
    """Set diff + identity checks -> exceptions. Pure function."""
    today = today or dt.date.today()
    out: list[Exception_] = []

    def mk(kind, identity, role, detail):
        sev = SEVERITY[kind]
        sens = sensitivity.get(role or "", "unknown")
        if sens == "phi" or (role or "") in HARD_PROTECTED_ROLES:
            sev = "CRITICAL"
        exc = Exception_(
            _exc_id(kind, identity, role), kind, identity, role, sev, sens, detail
        )
        if kind == "OVER_PROVISIONED" and role:
            exc.revoke_sql = f"REVOKE ROLE {_q(role)} FROM USER {_q(identity)};"
            exc.rollback_sql = f"GRANT ROLE {_q(role)} TO USER {_q(identity)};"
        return exc

    for g in actual - expected:  # over-provisioned
        out.append(
            mk(
                "OVER_PROVISIONED",
                g.identity,
                g.role,
                "Grant present in Snowflake but not authorized by policy.",
            )
        )
    for g in expected - actual:  # under-provisioned
        out.append(
            mk(
                "UNDER_PROVISIONED",
                g.identity,
                g.role,
                "Policy grants role but it is missing in Snowflake.",
            )
        )

    for login in {g.identity for g in actual}:
        ident = identities.get(login)
        if login not in identities and login not in svc_logins:
            out.append(
                mk(
                    "UNMANAGED_SVC",
                    login,
                    None,
                    "Non-human login absent from the service-account inventory.",
                )
            )
            continue
        if ident is None or ident.is_service:
            if ident is not None and ident.is_service and ident.key_last_set:
                age = (today - ident.key_last_set).days
                if age > key_rotation_days:
                    out.append(
                        mk(
                            "STALE_KEY",
                            login,
                            None,
                            f"RSA key not rotated in {age} days (last set {ident.key_last_set}).",
                        )
                    )
            continue
        if ident.entra_object_id is None or not ident.account_enabled:
            out.append(
                mk(
                    "ORPHAN",
                    login,
                    None,
                    "Snowflake human account has no active correlating Entra identity.",
                )
            )
        elif ident.last_login and (today - ident.last_login).days > stale_days:
            out.append(
                mk(
                    "STALE",
                    login,
                    None,
                    f"No login in > {stale_days} days (last {ident.last_login}).",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# I/O clients (wire `_query` to the real SDKs in production)
# --------------------------------------------------------------------------- #
class SnowflakeClient:
    def __init__(self, conn=None):
        self._conn = conn

    def _query(self, sql: str) -> list[dict]:
        if self._conn is None:
            raise RuntimeError(
                "No live Snowflake connection; inject test data instead."
            )
        cur = self._conn.cursor(dict_cursor=True)
        try:
            cur.execute(sql)
            return cur.fetchall()
        finally:
            cur.close()

    def actual_grants(self) -> set[Grant]:
        """DIRECT role grants to users. NOTE: humans receive FR_* roles via SCIM
        Entra group-roles (role-to-role), so production must EXPAND each user's
        effective roles through a recursive GRANTS_TO_ROLES closure (see
        audit_queries.sql §1) before comparison — otherwise SCIM-inherited access
        is misclassified. This reference returns direct grants only."""
        rows = self._query(
            "SELECT GRANTEE_NAME AS identity, ROLE AS role "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE DELETED_ON IS NULL"
        )
        return {Grant(r["IDENTITY"].upper(), r["ROLE"].upper()) for r in rows}

    def live_grant_exists(self, identity: str, role: str) -> bool:
        rows = self._query(f"SHOW GRANTS TO USER {_q(identity)}")
        return any(str(r.get("role", "")).upper() == role for r in rows)

    def revoke(self, identity: str, role: str) -> None:
        self._query(f"REVOKE ROLE {_q(role)} FROM USER {_q(identity)}")


# --------------------------------------------------------------------------- #
# Outputs + gated remediation
# --------------------------------------------------------------------------- #
def write_outputs(
    exceptions: list[Exception_], out_dir: Path, run_id: str, matrix_sha: str
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = [
        "exception_id",
        "kind",
        "severity",
        "sensitivity",
        "identity",
        "role",
        "detail",
    ]
    with (out_dir / f"exception_report_{run_id}.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for e in sorted(exceptions, key=lambda x: SEV_RANK.get(x.severity, 99)):
            row = dataclasses.asdict(e)
            w.writerow({k: row[k] for k in fields})

    snapshot = {
        "run_id": run_id,
        "role_matrix_commit": matrix_sha,
        "exception_count": len(exceptions),
        "exceptions": [dataclasses.asdict(e) for e in exceptions],
    }
    body = json.dumps(snapshot, indent=2, sort_keys=True).encode()
    digest = hashlib.sha256(body).hexdigest()
    (out_dir / f"audit_evidence_{run_id}.json").write_bytes(body)
    (out_dir / f"audit_evidence_{run_id}.sha256").write_text(f"{digest}\n")
    logger.info(
        "evidence written run_id=%s sha256=%s exceptions=%d",
        run_id,
        digest,
        len(exceptions),
    )


def _approval_valid(appr: dict, e: Exception_, run_id: str, runner: str) -> bool:
    """Reject replayed, forged, mismatched, or expired approvals. The approval must
    (a) be by someone other than the runner (separation of duties), (b) name THIS
    run, (c) match the exact identity/role/action, and (d) not be expired.
    Production: also verify a cryptographic signature over these bound fields."""
    if appr.get("approver", "").lower() == runner.lower():
        logger.error("separation-of-duties violation exc=%s", e.exception_id)
        return False
    if appr.get("run_id") != run_id:
        logger.error("approval not bound to this run exc=%s", e.exception_id)
        return False
    if appr.get("identity", "").upper() != e.identity or appr.get(
        "role", ""
    ).upper() != (e.role or ""):
        logger.error("approval identity/role mismatch exc=%s", e.exception_id)
        return False
    if appr.get("action", "REVOKE").upper() != "REVOKE":
        return False
    expires = appr.get("expires")
    if expires and str(expires) < dt.date.today().isoformat():
        logger.error("approval expired exc=%s", e.exception_id)
        return False
    return True


def apply_remediation(
    exceptions: list[Exception_],
    approvals: dict[str, dict],
    sf: SnowflakeClient,
    out_dir: Path,
    runner: str,
    max_revokes: int,
    run_id: str,
) -> None:
    candidates = [
        e
        for e in exceptions
        if e.kind == "OVER_PROVISIONED"
        and e.role
        and e.role not in HARD_PROTECTED_ROLES
        and e.severity != "CRITICAL"
    ]  # PHI/admin = manual only
    approved = [e for e in candidates if e.exception_id in approvals]
    if len(approved) > max_revokes:
        raise SystemExit(
            f"blast-radius guard: {len(approved)} > {max_revokes}; manual review"
        )

    # Persist each inverse GRANT to disk BEFORE its revoke executes, so a crash
    # mid-loop never leaves an executed revoke without a recorded rollback.
    rollback_path = out_dir / f"rollback_{run_id}.sql"
    with rollback_path.open("w") as rb:
        rb.write(f"-- Rollback for run {run_id}: re-grants every role revoked below.\n")
        for e in approved:
            appr = approvals[e.exception_id]
            if not _approval_valid(appr, e, run_id, runner):
                continue
            if not sf.live_grant_exists(e.identity, e.role):  # re-confirm vs live
                logger.info("grant already absent, skipping %s/%s", e.identity, e.role)
                continue
            rb.write(e.rollback_sql + "\n")
            rb.flush()  # rollback line is durable BEFORE the revoke runs
            sf.revoke(e.identity, e.role)
            logger.warning(
                "revoked %s FROM %s (approver=%s)",
                e.role,
                e.identity,
                appr.get("approver"),
            )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _load_yaml(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text()) or {}


def run(
    args,
    sf: SnowflakeClient,
    identities: dict[str, Identity],
    group_membership: dict[str, list[str]],
) -> int:
    role_matrix = _load_yaml(args.role_matrix)
    svc_inventory = _load_yaml(args.inventory)
    svc_logins = {
        sa["login_name"].upper() for sa in svc_inventory.get("service_accounts", [])
    }
    for login in svc_logins:
        if login in identities:
            identities[login].is_service = True

    actual = sf.actual_grants()
    expected, sensitivity = build_expected(role_matrix, group_membership, svc_inventory)
    exceptions = reconcile(
        actual,
        expected,
        identities,
        svc_logins,
        sensitivity,
        args.stale_days,
        args.key_rotation_days,
    )

    run_id = args.run_id
    out_dir = Path(args.out_dir)
    write_outputs(exceptions, out_dir, run_id, args.matrix_sha)

    crit = sum(1 for e in exceptions if e.severity == "CRITICAL")
    logger.info(
        "review complete exceptions=%d critical=%d mode=%s",
        len(exceptions),
        crit,
        "apply" if args.apply else "dry-run",
    )

    if args.apply:
        if not args.approvals:
            raise SystemExit("--apply requires --approvals")
        approvals = {
            a["exception_id"]: a for a in json.loads(Path(args.approvals).read_text())
        }
        apply_remediation(
            exceptions, approvals, sf, out_dir, args.runner, args.max_revokes, run_id
        )
    else:
        logger.info("DRY-RUN: %d exceptions proposed, nothing revoked", len(exceptions))

    return 2 if crit else 0  # non-zero so CI surfaces CRITICAL


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monthly Snowflake access review (dry-run by default)."
    )
    p.add_argument("--role-matrix", required=True)
    p.add_argument("--inventory", required=True)
    p.add_argument("--out-dir", default="./review_output")
    p.add_argument("--run-id", default=dt.date.today().strftime("%Y-%m"))
    p.add_argument("--matrix-sha", default="<git-sha>")
    p.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    p.add_argument(
        "--apply",
        action="store_true",
        help="Execute APPROVED revokes. Omit for dry-run (default).",
    )
    p.add_argument(
        "--approvals", help="Path to signed approvals.json. Required with --apply."
    )
    p.add_argument("--max-revokes", type=int, default=DEFAULT_MAX_REVOKES)
    p.add_argument(
        "--key-rotation-days",
        type=int,
        default=KEY_ROTATION_DAYS,
        help="Flag service-account RSA keys older than this many days as STALE_KEY.",
    )
    p.add_argument(
        "--runner", default="ci-bot", help="Identity running the job (for SoD)."
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # Production wiring (kept out so the module imports cleanly for unit tests):
    #   conn = snowflake.connector.connect(... key-pair auth from a vault ...)
    #   sf = SnowflakeClient(conn)
    #   identities = load_identities_from_account_usage(conn)
    #   group_membership = resolve_entra_transitive_membership(graph_client)
    #   return run(args, sf, identities, group_membership)
    raise SystemExit(
        "Wire SnowflakeClient + Entra Graph clients, then call run(...). "
        "The build_expected/reconcile core is import-and-unit-testable as-is."
    )


if __name__ == "__main__":
    raise SystemExit(main())
