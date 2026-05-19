"""Identity-domain controls: C03 (this task), C06+C08 (Task 4)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from . import _audit, _common

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


# ---------------------------------------------------------------------------
# C06: Workspace admins + last_login from audit logs
# ---------------------------------------------------------------------------

LOOKBACK_DAYS_C06 = 90


def _build_login_map(central_ws_client, audit_warehouse_id) -> tuple[dict, str]:
    sql = f"""
        SELECT lower(user_identity.email) AS identity,
               MAX(event_date) AS last_login_date
        FROM system.access.audit
        WHERE event_date >= current_date() - INTERVAL {LOOKBACK_DAYS_C06} DAYS
          AND (lower(action_name) LIKE '%login%' OR
               lower(action_name) LIKE '%tokenauthorization%')
          AND user_identity.email IS NOT NULL
        GROUP BY user_identity.email
    """
    rows, err = _audit.run_audit_query(central_ws_client, audit_warehouse_id, sql)
    out = {str(r[0]).lower(): str(r[1]) for r in rows if len(r) >= 2 and r[0]}
    return out, err


_SP_TYPES = {"serviceprincipal", "service-principal", "sp", "service_principal"}


def _resolve_admin_member(ws_client, member) -> dict:
    value = getattr(member, "value", "") or ""
    declared_type = (getattr(member, "type", "") or "").lower()
    is_sp_hint = declared_type in _SP_TYPES

    def _load_sp():
        sp = ws_client.service_principals.get(value)
        return {"kind": "sp",
                "identifier": getattr(sp, "display_name", "") or getattr(sp, "application_id", "") or value,
                "application_id": getattr(sp, "application_id", "") or "",
                "active": bool(getattr(sp, "active", True)),
                "user_id": getattr(sp, "id", value)}

    def _load_user():
        u = ws_client.users.get(value)
        return {"kind": "user",
                "identifier": getattr(u, "user_name", "") or getattr(u, "display_name", "") or value,
                "application_id": "",
                "active": bool(getattr(u, "active", True)),
                "user_id": getattr(u, "id", value)}

    primary, secondary = (_load_sp, _load_user) if is_sp_hint else (_load_user, _load_sp)
    try:
        return primary()
    except Exception:
        try:
            return secondary()
        except Exception:
            return {"kind": "unknown",
                    "identifier": getattr(member, "display", "") or value,
                    "application_id": "", "active": True, "user_id": value}


def _c06_workspace_admins(ws_client, login_map, audit_unavailable):
    groups = list(ws_client.groups.list(filter='displayName eq "admins"'))
    if not groups:
        return []
    members = list(getattr(groups[0], "members", []) or [])
    findings = []
    for member in members:
        info = _resolve_admin_member(ws_client, member)
        if audit_unavailable:
            last_login = "audit not available"
        else:
            last_login = (login_map.get((info["identifier"] or "").lower())
                          or login_map.get((info["application_id"] or "").lower())
                          or "no login in last 90d")
        findings.append({"username": info["identifier"], "kind": info["kind"],
                         "application_id": info["application_id"],
                         "user_id": info["user_id"], "active": info["active"],
                         "last_login": last_login})
    return findings


def run_c06(account_client, workspaces, central_ws_client, audit_warehouse_id):
    """C06: admins per workspace + last_login from audit logs."""
    login_map, audit_err = _build_login_map(central_ws_client, audit_warehouse_id)
    audit_unavailable = bool(audit_err)
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            admins = _c06_workspace_admins(ws_client, login_map, audit_unavailable)
        except Exception as e:
            rows.append(_common.emit_error("906", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if not admins:
            rows.append(_common.emit_finding("906", ws_id, "workspace has no admins", [],
                                             severity_note="review"))
            continue
        details_summary = f"{len(admins)} admin(s)"
        if audit_unavailable:
            details_summary += " (audit_warehouse_id: not configured — last_login unavailable)"
        rows.append(_common.emit_finding("906", ws_id, details_summary, admins,
                                         severity_note="review" if audit_unavailable else ""))
    return rows


# ---------------------------------------------------------------------------
# C08: Unused service principals (account-level)
# ---------------------------------------------------------------------------

LOOKBACK_DAYS_C08 = 90
INACTIVE_THRESHOLD_DAYS_C08 = 30


def _build_activity_map(central_ws_client, audit_warehouse_id) -> tuple[dict, str]:
    sql = f"""
        SELECT lower(user_identity.email) AS identity,
               MAX(event_date) AS last_event_date
        FROM system.access.audit
        WHERE event_date >= current_date() - INTERVAL {LOOKBACK_DAYS_C08} DAYS
          AND user_identity.email IS NOT NULL
        GROUP BY user_identity.email
    """
    rows, err = _audit.run_audit_query(central_ws_client, audit_warehouse_id, sql)
    out = {str(r[0]).lower(): str(r[1]) for r in rows if len(r) >= 2 and r[0]}
    return out, err


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.split("T")[0]).date()
    except Exception:
        return None


def run_c08(account_client, central_ws_client, audit_warehouse_id) -> list[tuple]:
    """C08: account service principals unused > 30 days (account-only — emits one
    synthetic 'account' row keyed to workspace_id=0)."""
    activity_map, audit_err = _build_activity_map(central_ws_client, audit_warehouse_id)
    today = datetime.now(timezone.utc).date()
    findings = []
    for sp in account_client.service_principals.list():
        display = getattr(sp, "display_name", "") or ""
        app_id = getattr(sp, "application_id", "") or ""
        last_str = (activity_map.get(display.lower())
                    or activity_map.get(app_id.lower()) or "") if not audit_err else ""
        last = _parse_date(last_str)
        if audit_err:
            findings.append({"sp_name": display, "application_id": app_id,
                             "active": bool(getattr(sp, "active", True)),
                             "last_activity": "audit not available",
                             "days_inactive": "?"})
            continue
        if last is None:
            findings.append({"sp_name": display, "application_id": app_id,
                             "active": bool(getattr(sp, "active", True)),
                             "last_activity": "no activity in last 90d",
                             "days_inactive": ">90"})
            continue
        days_inactive = (today - last).days
        if days_inactive > INACTIVE_THRESHOLD_DAYS_C08:
            findings.append({"sp_name": display, "application_id": app_id,
                             "active": bool(getattr(sp, "active", True)),
                             "last_activity": last.isoformat(),
                             "days_inactive": days_inactive})
    if audit_err:
        return [_common.emit_finding("908", 0,
                                     "audit not available — cannot compute SP inactivity",
                                     findings, severity_note="review")]
    if findings:
        return [_common.emit_finding("908", 0,
                                     f"{len(findings)} SP(s) unused more than {INACTIVE_THRESHOLD_DAYS_C08} days",
                                     findings)]
    return [_common.emit_pass("908", 0,
                              "all account service principals active within 30 days")]
