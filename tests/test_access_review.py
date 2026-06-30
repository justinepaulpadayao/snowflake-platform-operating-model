"""
Unit tests for the pure, I/O-free functions in automation/access_review.py.

The build_expected and reconcile functions drive every revoke decision the
platform makes.  Tests here are the safety net that catches logic regressions
before they reach a PHI environment: a misclassified OVER_PROVISIONED finding
causes an unnecessary revoke; a missed ORPHAN or STALE_KEY finding leaves a
real risk undetected.

Run:  pytest tests/ -v
"""

import datetime as dt
import sys
from pathlib import Path


# Add project root to import path so 'automation.access_review' resolves
# without an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from automation.access_review import (
    Exception_,
    Grant,
    Identity,
    _approval_valid,
    _exc_id,
    _q,
    build_expected,
    reconcile,
    HARD_PROTECTED_ROLES,
    SEVERITY,
)


# =========================================================================== #
# Shared fixtures
# =========================================================================== #

ROLE_MATRIX = {
    "entra_groups": [
        {
            "entra_group_id": "grp-analysts",
            "fr_roles": ["FR_ANALYST"],
            "data_sensitivity": "internal",
        },
        {
            "entra_group_id": "grp-clinical",
            "fr_roles": ["FR_CLINICAL_ANALYTICS"],
            "data_sensitivity": "phi",
        },
    ]
}

SVC_INVENTORY = {
    "service_accounts": [
        {"login_name": "SVC_DBT", "expected_roles": ["FR_DBT_TRANSFORM"]},
        {"login_name": "SVC_POWERBI", "expected_roles": ["FR_BI_REPORTING"]},
    ]
}

GROUP_MEMBERSHIP = {
    "grp-analysts": ["alice", "bob"],
    "grp-clinical": ["charlie"],
}


def _identity(
    login,
    *,
    entra_id="oid-x",
    enabled=True,
    last_login=None,
    is_service=False,
    key_last_set=None,
):
    return Identity(
        login=login.upper(),
        is_service=is_service,
        entra_object_id=entra_id,
        account_enabled=enabled,
        last_login=last_login,
        key_last_set=key_last_set,
    )


def _exc(kind="OVER_PROVISIONED", identity="ALICE", role="FR_ANALYST"):
    return Exception_(
        exception_id=_exc_id(kind, identity, role),
        kind=kind,
        identity=identity,
        role=role,
        severity=SEVERITY.get(kind, "HIGH"),
        sensitivity="internal",
        detail="unit-test fixture",
    )


# =========================================================================== #
# build_expected
# =========================================================================== #


class TestBuildExpected:
    def test_entra_group_members_get_fr_role(self):
        expected, _ = build_expected(ROLE_MATRIX, GROUP_MEMBERSHIP, SVC_INVENTORY)
        assert Grant("ALICE", "FR_ANALYST") in expected
        assert Grant("BOB", "FR_ANALYST") in expected

    def test_phi_group_member_gets_phi_role(self):
        expected, _ = build_expected(ROLE_MATRIX, GROUP_MEMBERSHIP, SVC_INVENTORY)
        assert Grant("CHARLIE", "FR_CLINICAL_ANALYTICS") in expected

    def test_service_accounts_are_included(self):
        expected, _ = build_expected(ROLE_MATRIX, GROUP_MEMBERSHIP, SVC_INVENTORY)
        assert Grant("SVC_DBT", "FR_DBT_TRANSFORM") in expected
        assert Grant("SVC_POWERBI", "FR_BI_REPORTING") in expected

    def test_no_cross_contamination(self):
        expected, _ = build_expected(ROLE_MATRIX, GROUP_MEMBERSHIP, SVC_INVENTORY)
        assert Grant("CHARLIE", "FR_ANALYST") not in expected
        assert Grant("ALICE", "FR_CLINICAL_ANALYTICS") not in expected

    def test_sensitivity_map(self):
        _, sensitivity = build_expected(ROLE_MATRIX, GROUP_MEMBERSHIP, SVC_INVENTORY)
        assert sensitivity["FR_ANALYST"] == "internal"
        assert sensitivity["FR_CLINICAL_ANALYTICS"] == "phi"

    def test_login_names_uppercased(self):
        membership = {"grp-analysts": ["alice_lowercase"]}
        expected, _ = build_expected(ROLE_MATRIX, membership, {})
        assert Grant("ALICE_LOWERCASE", "FR_ANALYST") in expected

    def test_empty_matrix_returns_empty_set(self):
        expected, sensitivity = build_expected({}, {}, {})
        assert expected == set()
        assert sensitivity == {}


# =========================================================================== #
# reconcile — over-provisioned
# =========================================================================== #


class TestReconcileOverProvisioned:
    def test_extra_role_flagged(self):
        actual = {Grant("ALICE", "FR_ANALYST"), Grant("ALICE", "FR_CLINICAL_ANALYTICS")}
        expected = {Grant("ALICE", "FR_ANALYST")}
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), {})
        over = [e for e in excs if e.kind == "OVER_PROVISIONED"]
        assert len(over) == 1
        assert over[0].role == "FR_CLINICAL_ANALYTICS"

    def test_revoke_sql_generated(self):
        actual = {Grant("ALICE", "FR_ANALYST")}
        expected = set()
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), {})
        over = [e for e in excs if e.kind == "OVER_PROVISIONED"]
        assert over[0].revoke_sql is not None
        assert over[0].rollback_sql is not None

    def test_phi_sensitivity_escalates_to_critical(self):
        actual = {Grant("ALICE", "FR_CLINICAL_ANALYTICS")}
        expected = set()
        sensitivity = {"FR_CLINICAL_ANALYTICS": "phi"}
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), sensitivity)
        over = [e for e in excs if e.kind == "OVER_PROVISIONED"]
        assert over[0].severity == "CRITICAL"

    def test_hard_protected_role_escalates_to_critical(self):
        protected_role = "ACCOUNTADMIN"
        assert protected_role in HARD_PROTECTED_ROLES
        actual = {Grant("ALICE", protected_role)}
        expected = set()
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), {})
        over = [e for e in excs if e.kind == "OVER_PROVISIONED"]
        assert over[0].severity == "CRITICAL"

    def test_all_hard_protected_roles_escalate(self):
        for role in HARD_PROTECTED_ROLES:
            actual = {Grant("ALICE", role)}
            expected = set()
            identities = {"ALICE": _identity("ALICE")}
            excs = reconcile(actual, expected, identities, set(), {})
            over = [e for e in excs if e.kind == "OVER_PROVISIONED"]
            assert all(e.severity == "CRITICAL" for e in over), (
                f"{role} did not escalate to CRITICAL"
            )


# =========================================================================== #
# reconcile — under-provisioned
# =========================================================================== #


class TestReconcileUnderProvisioned:
    def test_missing_role_flagged(self):
        actual = set()
        expected = {Grant("ALICE", "FR_ANALYST")}
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), {})
        under = [e for e in excs if e.kind == "UNDER_PROVISIONED"]
        assert len(under) == 1
        assert under[0].identity == "ALICE"

    def test_under_provisioned_has_no_revoke_sql(self):
        actual = set()
        expected = {Grant("ALICE", "FR_ANALYST")}
        identities = {"ALICE": _identity("ALICE")}
        excs = reconcile(actual, expected, identities, set(), {})
        under = [e for e in excs if e.kind == "UNDER_PROVISIONED"]
        assert under[0].revoke_sql is None


# =========================================================================== #
# reconcile — orphan
# =========================================================================== #


class TestReconcileOrphan:
    def test_no_entra_id_is_orphan(self):
        actual = {Grant("DAVE", "FR_ANALYST")}
        expected = {Grant("DAVE", "FR_ANALYST")}
        identities = {"DAVE": _identity("DAVE", entra_id=None)}
        excs = reconcile(actual, expected, identities, set(), {})
        assert any(e.kind == "ORPHAN" for e in excs)

    def test_disabled_entra_account_is_orphan(self):
        actual = {Grant("EVE", "FR_ANALYST")}
        expected = {Grant("EVE", "FR_ANALYST")}
        identities = {"EVE": _identity("EVE", enabled=False)}
        excs = reconcile(actual, expected, identities, set(), {})
        assert any(e.kind == "ORPHAN" for e in excs)

    def test_orphan_severity_critical(self):
        actual = {Grant("FRANK", "FR_ANALYST")}
        expected = {Grant("FRANK", "FR_ANALYST")}
        identities = {"FRANK": _identity("FRANK", entra_id=None)}
        excs = reconcile(actual, expected, identities, set(), {})
        orphan = next(e for e in excs if e.kind == "ORPHAN")
        assert orphan.severity == "CRITICAL"


# =========================================================================== #
# reconcile — stale
# =========================================================================== #


class TestReconcileStale:
    _today = dt.date(2024, 6, 1)

    def test_stale_user_flagged(self):
        last = self._today - dt.timedelta(days=100)
        actual = {Grant("GRACE", "FR_ANALYST")}
        expected = {Grant("GRACE", "FR_ANALYST")}
        identities = {"GRACE": _identity("GRACE", last_login=last)}
        excs = reconcile(actual, expected, identities, set(), {}, today=self._today)
        assert any(e.kind == "STALE" for e in excs)

    def test_recent_user_not_stale(self):
        last = self._today - dt.timedelta(days=10)
        actual = {Grant("HENRY", "FR_ANALYST")}
        expected = {Grant("HENRY", "FR_ANALYST")}
        identities = {"HENRY": _identity("HENRY", last_login=last)}
        excs = reconcile(actual, expected, identities, set(), {}, today=self._today)
        assert not any(e.kind == "STALE" for e in excs)

    def test_never_logged_in_not_stale(self):
        # No last_login — cannot compute staleness without a date; no STALE raised.
        actual = {Grant("IVY", "FR_ANALYST")}
        expected = {Grant("IVY", "FR_ANALYST")}
        identities = {"IVY": _identity("IVY", last_login=None)}
        excs = reconcile(actual, expected, identities, set(), {}, today=self._today)
        assert not any(e.kind == "STALE" for e in excs)


# =========================================================================== #
# reconcile — unmanaged service account
# =========================================================================== #


class TestReconcileUnmanagedSvc:
    def test_unknown_non_human_flagged(self):
        actual = {Grant("MYSTERY_BOT", "FR_ANALYST")}
        excs = reconcile(actual, set(), {}, set(), {})
        assert any(e.kind == "UNMANAGED_SVC" for e in excs)

    def test_known_svc_in_inventory_not_flagged(self):
        actual = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        expected = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        svc_logins = {"SVC_DBT"}
        identities = {"SVC_DBT": _identity("SVC_DBT", is_service=True)}
        excs = reconcile(actual, expected, identities, svc_logins, {})
        assert not any(e.kind == "UNMANAGED_SVC" for e in excs)


# =========================================================================== #
# reconcile — stale key (service account RSA key rotation)
# =========================================================================== #


class TestReconcileStaleKey:
    _today = dt.date(2024, 7, 1)

    def test_old_key_flagged(self):
        old_key = self._today - dt.timedelta(days=400)
        actual = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        expected = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        svc_logins = {"SVC_DBT"}
        identities = {
            "SVC_DBT": _identity("SVC_DBT", is_service=True, key_last_set=old_key)
        }
        excs = reconcile(
            actual, expected, identities, svc_logins, {}, today=self._today
        )
        assert any(e.kind == "STALE_KEY" for e in excs)

    def test_recent_key_not_flagged(self):
        recent_key = self._today - dt.timedelta(days=90)
        actual = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        expected = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        svc_logins = {"SVC_DBT"}
        identities = {
            "SVC_DBT": _identity("SVC_DBT", is_service=True, key_last_set=recent_key)
        }
        excs = reconcile(
            actual, expected, identities, svc_logins, {}, today=self._today
        )
        assert not any(e.kind == "STALE_KEY" for e in excs)

    def test_no_key_date_no_exception(self):
        actual = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        expected = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        svc_logins = {"SVC_DBT"}
        identities = {
            "SVC_DBT": _identity("SVC_DBT", is_service=True, key_last_set=None)
        }
        excs = reconcile(
            actual, expected, identities, svc_logins, {}, today=self._today
        )
        assert not any(e.kind == "STALE_KEY" for e in excs)

    def test_stale_key_severity_is_high(self):
        old_key = self._today - dt.timedelta(days=400)
        actual = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        expected = {Grant("SVC_DBT", "FR_DBT_TRANSFORM")}
        svc_logins = {"SVC_DBT"}
        identities = {
            "SVC_DBT": _identity("SVC_DBT", is_service=True, key_last_set=old_key)
        }
        excs = reconcile(
            actual, expected, identities, svc_logins, {}, today=self._today
        )
        sk = next(e for e in excs if e.kind == "STALE_KEY")
        assert sk.severity == "HIGH"


# =========================================================================== #
# _approval_valid
# =========================================================================== #


class TestApprovalValid:
    _base = {
        "approver": "manager",
        "run_id": "2024-06",
        "identity": "ALICE",
        "role": "FR_ANALYST",
        "action": "REVOKE",
        "expires": "2099-12-31",
    }

    def _exc(self):
        return _exc(kind="OVER_PROVISIONED", identity="ALICE", role="FR_ANALYST")

    def test_valid_approval_accepted(self):
        assert _approval_valid(self._base, self._exc(), "2024-06", "ci-bot") is True

    def test_sod_violation_rejected(self):
        appr = {**self._base, "approver": "ci-bot"}  # same as runner
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_wrong_run_id_rejected(self):
        appr = {**self._base, "run_id": "2024-05"}
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_expired_approval_rejected(self):
        appr = {**self._base, "expires": "2020-01-01"}
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_identity_mismatch_rejected(self):
        appr = {**self._base, "identity": "BOB"}
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_role_mismatch_rejected(self):
        appr = {**self._base, "role": "FR_DBT_TRANSFORM"}
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_wrong_action_rejected(self):
        appr = {**self._base, "action": "GRANT"}
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False

    def test_case_insensitive_approver_comparison(self):
        appr = {**self._base, "approver": "CI-BOT"}  # same as runner, different case
        assert _approval_valid(appr, self._exc(), "2024-06", "ci-bot") is False


# =========================================================================== #
# _q (identifier quoting — prevents injection on UPN-style logins)
# =========================================================================== #


class TestIdentifierQuoting:
    def test_plain_identifier(self):
        assert _q("FR_ANALYST") == '"FR_ANALYST"'

    def test_upn_style_login(self):
        assert _q("jdoe@example.com") == '"jdoe@example.com"'

    def test_escaped_embedded_double_quote(self):
        assert _q('role"embedded"') == '"role""embedded"""'

    def test_empty_string(self):
        assert _q("") == '""'

    def test_snowflake_reserved_word(self):
        # Quoting a reserved word makes it safe as an identifier.
        result = _q("SELECT")
        assert result == '"SELECT"'

    def test_role_with_slash(self):
        result = _q("AR_PHI/UNMASK")
        assert result.startswith('"') and result.endswith('"')
