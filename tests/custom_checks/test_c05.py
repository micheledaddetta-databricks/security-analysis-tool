import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from notebooks.Includes.custom_checks import governance  # noqa: E402


class _AccountStub:
    def __init__(self, assignment_or_exc):
        self._assignment_or_exc = assignment_or_exc

    @property
    def metastore_assignments(self):
        return self

    def get(self, workspace_id):
        if isinstance(self._assignment_or_exc, Exception):
            raise self._assignment_or_exc
        return self._assignment_or_exc


def _ws(workspace_id=42, name="ws-42", deployment="adb-42.0"):
    return SimpleNamespace(workspace_id=workspace_id,
                           workspace_name=name,
                           deployment_name=deployment)


def test_c05_pass_when_metastore_assigned():
    inner = SimpleNamespace(metastore_id="m-abc")
    wrapper = SimpleNamespace(metastore_assignment=inner)
    acct = _AccountStub(wrapper)
    rows = governance.run_c05(acct, [_ws()])
    assert len(rows) == 1
    check_id, score, details = rows[0]
    assert check_id == "905"
    assert score == 0
    assert "Unity Catalog enabled" in details["summary"]


def test_c05_fail_when_no_metastore():
    wrapper = SimpleNamespace(metastore_assignment=None)
    acct = _AccountStub(wrapper)
    rows = governance.run_c05(acct, [_ws()])
    check_id, score, details = rows[0]
    assert check_id == "905"
    assert score == 1
    assert details["findings_count"] == "1"


def test_c05_fail_when_lookup_raises():
    acct = _AccountStub(Exception("404 not found"))
    rows = governance.run_c05(acct, [_ws()])
    check_id, score, details = rows[0]
    assert check_id == "905"
    assert score == 1
    assert "no assignment" in details["summary"]
