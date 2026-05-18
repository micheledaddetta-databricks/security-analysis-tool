"""Governance-domain controls: C04, C05, C09, C13."""
from __future__ import annotations

from typing import Iterable

from . import _common


def _c05_workspace_row(account_client, ws) -> tuple:
    """Return one SAT row for this workspace, for check_id 905."""
    workspace_id = getattr(ws, "workspace_id", None)
    if workspace_id is None:
        return _common.emit_error(
            "905", 0, "workspace has no workspace_id",
            summary="cannot evaluate UC assignment", error_kind="missing_id")
    try:
        wrapper = account_client.metastore_assignments.get(workspace_id)
        inner = getattr(wrapper, "metastore_assignment", None)
        metastore_id = getattr(inner, "metastore_id", "") if inner else ""
        if metastore_id:
            return _common.emit_pass("905", workspace_id,
                                     f"Unity Catalog enabled (metastore {metastore_id})")
        return _common.emit_finding("905", workspace_id,
                                    "Unity Catalog not enabled",
                                    [{"workspace_name": getattr(ws, "workspace_name", ""),
                                      "deployment_name": getattr(ws, "deployment_name", "")}])
    except Exception as e:
        return _common.emit_finding("905", workspace_id,
                                    "Unity Catalog not enabled (no assignment)",
                                    [{"workspace_name": getattr(ws, "workspace_name", ""),
                                      "deployment_name": getattr(ws, "deployment_name", ""),
                                      "lookup_error": repr(e)[:200]}])


def run_c05(account_client, workspaces: Iterable) -> list[tuple]:
    """Run C05 (Unity Catalog enabled) across the supplied account workspaces.
    Returns a list of (check_id, score, additional_details) tuples — one per workspace."""
    return [_c05_workspace_row(account_client, ws) for ws in workspaces]
