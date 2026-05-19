import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from notebooks.Includes.custom_checks import identity, _audit  # noqa: E402


class _Member:
    type = "user"
    value = "alice@example.com"
    display = "alice"


class _Group:
    members = [_Member()]


class _User:
    user_name = "alice@example.com"
    display_name = "alice"
    active = True
    id = "u-1"


class _WSClient:
    @property
    def groups(self):
        return self

    def list(self, filter=None):
        return [_Group()]

    @property
    def users(self):
        return self

    def get(self, _id):
        return _User()


class _Acct:
    def get_workspace_client(self, _ws):
        return _WSClient()


def _ws():
    return SimpleNamespace(workspace_id=7, workspace_name="w", deployment_name="d")


def test_c06_returns_audit_not_available_when_warehouse_id_missing(monkeypatch):
    def stub(_ws_client, _warehouse_id, _sql):
        return [], "no audit_warehouse_id configured"
    monkeypatch.setattr(_audit, "run_audit_query", stub)
    rows = identity.run_c06(_Acct(), [_ws()], central_ws_client=None,
                            audit_warehouse_id=None)
    assert len(rows) == 1
    _, score, details = rows[0]
    assert score == 1
    assert "audit_warehouse_id" in details["summary"] or "audit not available" in details["findings_json"]


def test_c08_returns_audit_not_available_when_warehouse_id_missing(monkeypatch):
    class _AcctWithSp(_Acct):
        @property
        def service_principals(self):
            return self

        def list(self):
            return [SimpleNamespace(display_name="sp-1", application_id="aid-1", active=True)]

    def stub(_ws_client, _warehouse_id, _sql):
        return [], "no audit_warehouse_id configured"
    monkeypatch.setattr(_audit, "run_audit_query", stub)
    rows = identity.run_c08(_AcctWithSp(), central_ws_client=None, audit_warehouse_id=None)
    assert len(rows) == 1
    cid, score, details = rows[0]
    assert cid == "908"
    assert "audit not available" in details["summary"]
