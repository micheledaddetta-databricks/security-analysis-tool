"""custom_checks — account-wide governance controls ported from the Findings tool.

Entrypoint: ``run_all(workspace_id, run_id, account_client, central_ws_client,
                       audit_warehouse_id=None) -> list[tuple]``
"""
from __future__ import annotations

from typing import Optional

from . import governance


def run_all(workspace_id: int,
            run_id: int,
            account_client,
            central_ws_client,
            audit_warehouse_id: Optional[str] = None) -> list[tuple]:
    """Return the SAT rows for `workspace_id` across all custom_checks controls."""
    workspaces = list(account_client.workspaces.list())
    targets = [ws for ws in workspaces if getattr(ws, "workspace_id", None) == workspace_id]
    rows = []
    rows.extend(governance.run_c05(account_client, targets))
    return rows
