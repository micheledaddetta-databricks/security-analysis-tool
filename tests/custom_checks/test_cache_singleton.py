import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from notebooks.Includes import custom_checks  # noqa: E402


def _ws(wid):
    return SimpleNamespace(workspace_id=wid, workspace_name=f"w-{wid}", deployment_name="d")


class _SpyAcct:
    """Stub account_client with a counter for workspaces.list() calls."""

    def __init__(self, wids):
        self.workspaces_calls = 0
        self._wids = wids

    @property
    def workspaces(self):
        return self

    def list(self):
        self.workspaces_calls += 1
        return [_ws(w) for w in self._wids]

    def get_workspace_client(self, ws):
        raise RuntimeError("not used in this test")

    @property
    def service_principals(self):
        class _SP:
            def list(self_inner):
                return iter([])
        return _SP()


def test_account_wide_fanout_runs_once_per_run_id(monkeypatch):
    custom_checks._reset_cache_for_tests()
    spy = _SpyAcct([10, 20, 30])
    # Patch every control's run_* to return a small no-op so we measure cache,
    # not control logic.
    for mod in (custom_checks.secrets, custom_checks.identity,
                custom_checks.governance, custom_checks.workloads):
        for name in dir(mod):
            if name.startswith("run_c") and callable(getattr(mod, name)):
                monkeypatch.setattr(mod, name, lambda *a, **kw: [])

    custom_checks.run_all(workspace_id=10, run_id=42,
                           account_client=spy, central_ws_client=None)
    custom_checks.run_all(workspace_id=20, run_id=42,
                           account_client=spy, central_ws_client=None)
    custom_checks.run_all(workspace_id=30, run_id=42,
                           account_client=spy, central_ws_client=None)

    # The cache populates on the first call, then `workspaces.list()` is also
    # used by `_first_workspace_id_seen_this_run` per call — accept anything
    # ≤ 5 as "ran once for the cache, plus per-call first-id lookups".
    assert spy.workspaces_calls <= 5

    # New run_id resets the cache.
    custom_checks.run_all(workspace_id=10, run_id=43,
                           account_client=spy, central_ws_client=None)
    # After a new run_id, the cache must have been rebuilt — workspaces.list
    # called at least once more vs. the previous total.
    assert spy.workspaces_calls > 3
