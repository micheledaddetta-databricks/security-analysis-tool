import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from notebooks.Includes.custom_checks import (  # noqa: E402
    governance, identity, secrets, workloads,
)


class _EmptyWS:
    """Workspace client where every list() call yields no items."""

    def __getattr__(self, _name):
        return self

    def __call__(self, *a, **kw):
        return iter([])

    def get(self, *a, **kw):
        raise Exception("not implemented in stub")

    def list(self, *a, **kw):
        return iter([])

    def list_acls(self, *a, **kw):
        return iter([])

    def list_scopes(self, *a, **kw):
        return iter([])

    def list_endpoints(self, *a, **kw):
        return iter([])

    def list_pipelines(self, *a, **kw):
        return iter([])

    def list_experiments(self, *a, **kw):
        return iter([])

    def list_database_instances(self, *a, **kw):
        return iter([])


class _MetastoreAssignments:
    """Stub that returns a valid metastore assignment so C05 emits PASS."""

    def get(self, workspace_id):
        inner = SimpleNamespace(metastore_id="m-stub")
        return SimpleNamespace(metastore_assignment=inner)


class _Acct:
    def __init__(self, ws_client):
        self._ws = ws_client
        self.metastore_assignments = _MetastoreAssignments()

    def get_workspace_client(self, _ws):
        return self._ws


def _ws():
    return SimpleNamespace(workspace_id=99, workspace_name="ws-99",
                           deployment_name="adb-99.0")


def test_round1_controls_all_return_pass_on_empty_workspace():
    acct = _Acct(_EmptyWS())
    targets = [_ws()]
    for fn, cid in [
        (secrets.run_c01, "901"), (secrets.run_c02, "902"),
        (identity.run_c03, "903"),
        (governance.run_c04, "904"), (governance.run_c05, "905"),
        (workloads.run_c07, "907"), (governance.run_c09, "909"),
        (workloads.run_c11, "911"), (workloads.run_c12, "912"),
        (governance.run_c13, "913"), (workloads.run_c14, "914"),
    ]:
        rows = fn(acct, targets)
        assert len(rows) == 1, f"{cid} produced {len(rows)} rows"
        check_id, score, details = rows[0]
        assert check_id == cid, f"{cid} returned wrong check_id"
        assert score == 0, f"{cid} expected score=0 on empty workspace, got {score}"
