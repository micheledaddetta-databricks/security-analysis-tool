"""Secrets-domain controls: C01, C02."""
from __future__ import annotations

from typing import Iterable

from . import _common


def _scope_acl_rows(ws_client) -> tuple[list[dict], list[dict]]:
    """Returns (no_acl, with_acl) finding rows for DATABRICKS-backed scopes."""
    no_acl, with_acl = [], []
    for s in ws_client.secrets.list_scopes():
        backend = getattr(s, "backend_type", None)
        backend_str = backend.value if hasattr(backend, "value") else str(backend or "")
        if "DATABRICKS" not in backend_str.upper():
            continue
        try:
            acls = list(ws_client.secrets.list_acls(scope=s.name))
        except Exception:
            acls = []
        row = {"scope": s.name, "backend_type": backend_str, "acl_count": len(acls),
               "principals": ", ".join(getattr(a, "principal", "") for a in acls)}
        if len(acls) <= 1:
            no_acl.append(row)
        else:
            with_acl.append(row)
    return no_acl, with_acl


def run_c01(account_client, workspaces: Iterable) -> list[tuple]:
    """C01: secret scopes with no ACL configured."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            no_acl, _ = _scope_acl_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("901", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if no_acl:
            rows.append(_common.emit_finding("901", ws_id,
                                             f"{len(no_acl)} Databricks-backed scope(s) without ACL",
                                             no_acl))
        else:
            rows.append(_common.emit_pass("901", ws_id, "No DATABRICKS-backed scopes without ACL"))
    return rows


def run_c02(account_client, workspaces: Iterable) -> list[tuple]:
    """C02: Databricks-backed secret scopes with ACL (prefer AKV)."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            _, with_acl = _scope_acl_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("902", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if with_acl:
            rows.append(_common.emit_finding("902", ws_id,
                                             f"{len(with_acl)} Databricks-backed scope(s) with ACL — prefer AKV",
                                             with_acl, severity_note="review"))
        else:
            rows.append(_common.emit_pass("902", ws_id, "No Databricks-backed scopes with ACL"))
    return rows
