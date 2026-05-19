"""Identity-domain controls: C03 (this task), C06+C08 (Task 4)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from . import _common

THRESHOLD_DAYS = 30


def _ms_to_dt(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def _c03_workspace_rows(ws_client) -> list[dict]:
    """Returns list of finding dicts for tokens expiring > 30d from now."""
    now = datetime.now(timezone.utc)
    user_cache: dict[str, str] = {}

    def resolve_user(user_id):
        if not user_id:
            return ""
        key = str(user_id)
        if key in user_cache:
            return user_cache[key]
        try:
            u = ws_client.users.get(key)
            name = getattr(u, "user_name", "") or getattr(u, "display_name", "") or ""
        except Exception:
            name = ""
        user_cache[key] = name
        return name

    findings = []
    for t in ws_client.token_management.list():
        expiry = _ms_to_dt(getattr(t, "expiry_time", None))
        if expiry is None:
            days = float("inf")
        else:
            days = (expiry - now).days
        if days > THRESHOLD_DAYS:
            owner_id = getattr(t, "owner_id", None)
            owner_username = (getattr(t, "created_by_username", "")
                              or resolve_user(owner_id) or str(owner_id or ""))
            findings.append({
                "token_id": getattr(t, "token_id", ""),
                "owner": owner_username,
                "owner_id": str(owner_id or ""),
                "expiry": expiry.date().isoformat() if expiry else "no-expiry",
                "days_to_expiry": days if days != float("inf") else "∞",
                "comment": getattr(t, "comment", ""),
            })
    return findings


def run_c03(account_client, workspaces: Iterable) -> list[tuple]:
    """C03: PATs with expiry > 30 days."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c03_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("903", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("903", ws_id,
                                             f"{len(findings)} PAT(s) expire more than 30 days from now",
                                             findings))
        else:
            rows.append(_common.emit_pass("903", ws_id, "No PATs with expiry > 30 days"))
    return rows
