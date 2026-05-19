"""Audit-warehouse helper for controls that query system.access.audit."""
from __future__ import annotations

import time


def run_audit_query(ws_client, warehouse_id, sql) -> tuple[list[list], str]:
    """Execute SQL against an existing warehouse. Returns (rows, error_message)."""
    if not warehouse_id:
        return [], "no audit_warehouse_id configured"
    try:
        from databricks.sdk.service.sql import (
            Disposition, Format, StatementState,
        )
    except Exception as e:
        return [], f"sdk import failed: {e!r}"

    try:
        resp = ws_client.statement_execution.execute_statement(
            statement=sql,
            warehouse_id=warehouse_id,
            wait_timeout="30s",
            disposition=Disposition.INLINE,
            format=Format.JSON_ARRAY,
        )
        statement_id = resp.statement_id
        deadline = time.time() + 180
        state = resp.status.state if resp.status else None
        while state in (StatementState.PENDING, StatementState.RUNNING) and time.time() < deadline:
            time.sleep(2)
            resp = ws_client.statement_execution.get_statement(statement_id)
            state = resp.status.state if resp.status else None
        if state != StatementState.SUCCEEDED:
            err = (resp.status.error.message
                   if (resp.status and resp.status.error) else f"state={state}")
            return [], f"audit query did not succeed: {err}"
        return (resp.result.data_array if resp.result else []) or [], ""
    except Exception as e:
        return [], f"audit query failed: {e!r}"
