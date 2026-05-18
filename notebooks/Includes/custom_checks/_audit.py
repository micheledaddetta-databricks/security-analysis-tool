"""Audit-warehouse helper. Stubbed until Task 4."""
from __future__ import annotations


def run_audit_query(ws_client, warehouse_id, sql) -> tuple[list[list], str]:
    """Execute SQL against an existing warehouse. Returns (rows, error_message)."""
    if not warehouse_id:
        return [], "no audit_warehouse_id configured"
    return [], "audit query not yet implemented"
