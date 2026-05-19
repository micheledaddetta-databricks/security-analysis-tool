"""custom_checks — account-wide controls ported from the Findings tool."""
from __future__ import annotations

from typing import Optional

from . import governance, identity, secrets, workloads


def run_all(workspace_id: int,
            run_id: int,
            account_client,
            central_ws_client,
            audit_warehouse_id: Optional[str] = None) -> list[tuple]:
    """Return the SAT rows for `workspace_id` across all custom_checks controls."""
    workspaces = list(account_client.workspaces.list())
    targets = [ws for ws in workspaces if getattr(ws, "workspace_id", None) == workspace_id]
    rows: list[tuple] = []
    rows.extend(secrets.run_c01(account_client, targets))
    rows.extend(secrets.run_c02(account_client, targets))
    rows.extend(identity.run_c03(account_client, targets))
    rows.extend(governance.run_c04(account_client, targets))
    rows.extend(governance.run_c05(account_client, targets))
    rows.extend(identity.run_c06(account_client, targets, central_ws_client, audit_warehouse_id))
    rows.extend(workloads.run_c07(account_client, targets))
    # C08 is account-only; only emit it once across the run — gate on first workspace id.
    first_ws_id = getattr(workspaces[0], "workspace_id", None) if workspaces else None
    if workspace_id == first_ws_id:
        rows.extend(identity.run_c08(account_client, central_ws_client, audit_warehouse_id))
    rows.extend(governance.run_c09(account_client, targets))
    rows.extend(workloads.run_c11(account_client, targets))
    rows.extend(workloads.run_c12(account_client, targets))
    rows.extend(governance.run_c13(account_client, targets))
    rows.extend(workloads.run_c14(account_client, targets))
    return rows
