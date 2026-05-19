"""custom_checks — account-wide controls ported from the Findings tool.

`run_all` is the SAT driver hook. It executes every account-wide control
exactly once per SAT run (keyed by `run_id`) and serves per-workspace rows
from an in-memory cache on subsequent invocations.
"""
from __future__ import annotations

from typing import Optional

from . import governance, identity, secrets, workloads

# Module-level singleton. Keyed on the SAT run_id; mismatch ⇒ rebuild.
_cache: dict = {"run_id": None, "rows_by_ws": {}}


def _build_rows_for_run(account_client, central_ws_client,
                        audit_warehouse_id: Optional[str]) -> dict[int, list[tuple]]:
    """Run every control account-wide once and partition the rows by workspace_id."""
    workspaces = list(account_client.workspaces.list())

    all_rows: list[tuple] = []
    all_rows.extend(secrets.run_c01(account_client, workspaces))
    all_rows.extend(secrets.run_c02(account_client, workspaces))
    all_rows.extend(identity.run_c03(account_client, workspaces))
    all_rows.extend(governance.run_c04(account_client, workspaces))
    all_rows.extend(governance.run_c05(account_client, workspaces))
    all_rows.extend(identity.run_c06(account_client, workspaces, central_ws_client,
                                     audit_warehouse_id))
    all_rows.extend(workloads.run_c07(account_client, workspaces))
    all_rows.extend(governance.run_c09(account_client, workspaces))
    all_rows.extend(workloads.run_c11(account_client, workspaces))
    all_rows.extend(workloads.run_c12(account_client, workspaces))
    all_rows.extend(governance.run_c13(account_client, workspaces))
    all_rows.extend(workloads.run_c14(account_client, workspaces))

    # C08 is account-only — bucket under workspace_id=0.
    c08_rows = identity.run_c08(account_client, central_ws_client, audit_warehouse_id)

    by_ws: dict[int, list[tuple]] = {}
    for cid, score, details in all_rows:
        ws_id = int(details.get("workspace_id", "0"))
        by_ws.setdefault(ws_id, []).append((cid, score, details))
    by_ws[0] = by_ws.get(0, []) + c08_rows
    return by_ws


def run_all(workspace_id: int,
            run_id: int,
            account_client,
            central_ws_client,
            audit_warehouse_id: Optional[str] = None) -> list[tuple]:
    """Return the SAT rows for `workspace_id` from the cached run."""
    if _cache["run_id"] != run_id:
        _cache["rows_by_ws"] = _build_rows_for_run(
            account_client, central_ws_client, audit_warehouse_id)
        _cache["run_id"] = run_id
    # Workspace-level rows plus the account-only C08 row (under key 0) for the
    # first workspace SAT iterates through. SAT calls run_all once per workspace;
    # we don't repeat C08 on subsequent calls.
    rows = list(_cache["rows_by_ws"].get(workspace_id, []))
    if workspace_id == _first_workspace_id_seen_this_run(account_client):
        rows.extend(_cache["rows_by_ws"].get(0, []))
        _cache["rows_by_ws"][0] = []  # prevent re-emit on subsequent workspace calls
    return rows


def _first_workspace_id_seen_this_run(account_client) -> int:
    workspaces = list(account_client.workspaces.list())
    if not workspaces:
        return -1
    return getattr(workspaces[0], "workspace_id", -1)


def _reset_cache_for_tests():
    """Test-only helper to clear the singleton between cases."""
    _cache["run_id"] = None
    _cache["rows_by_ws"] = {}
