"""Governance-domain controls: C04, C05, C09, C13."""
from __future__ import annotations

from typing import Iterable

from . import _common


_HOME_IGNORED_GROUPS = {"admins"}


def _c04_workspace_rows(ws_client) -> list[dict]:
    findings = []
    for obj in ws_client.workspace.list("/Users"):
        path = getattr(obj, "path", "") or ""
        object_id = getattr(obj, "object_id", None)
        object_type = getattr(obj, "object_type", None)
        type_str = object_type.value if hasattr(object_type, "value") else str(object_type or "")
        if type_str.upper() != "DIRECTORY" or object_id is None:
            continue
        owner = path.rsplit("/", 1)[-1].lower()
        try:
            perms = ws_client.workspace.get_permissions(
                workspace_object_type="directories",
                workspace_object_id=str(object_id))
        except Exception as e:
            findings.append({"home_folder": path, "owner": owner,
                             "issue": "could_not_read_permissions",
                             "error": str(e)[:200]})
            continue
        leaks = []
        for entry in (getattr(perms, "access_control_list", None) or []):
            principal = (getattr(entry, "user_name", None)
                         or getattr(entry, "group_name", None)
                         or getattr(entry, "service_principal_name", None) or "")
            kind = ("user" if getattr(entry, "user_name", None)
                    else "group" if getattr(entry, "group_name", None)
                    else "sp" if getattr(entry, "service_principal_name", None)
                    else "unknown")
            if not principal:
                continue
            if kind in ("user", "sp") and principal.lower() == owner:
                continue
            if kind == "group" and principal in _HOME_IGNORED_GROUPS:
                continue
            levels = [getattr(p.permission_level, "value", str(p.permission_level))
                      for p in (getattr(entry, "all_permissions", None) or [])
                      if getattr(p, "permission_level", None) is not None]
            if levels:
                leaks.append({"principal": principal, "kind": kind,
                              "levels": ",".join(levels)})
        if leaks:
            findings.append({"home_folder": path, "owner": owner,
                             "leak_count": len(leaks),
                             "shared_with": "; ".join(
                                 f"{l['principal']}({l['kind']}):{l['levels']}" for l in leaks)})
    return findings


def run_c04(account_client, workspaces: Iterable) -> list[tuple]:
    """C04: home folders accessible to non-owners."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c04_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("904", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("904", ws_id,
                                             f"{len(findings)} home folder(s) accessible to non-owners",
                                             findings))
        else:
            rows.append(_common.emit_pass("904", ws_id, "All home folders are owner-only"))
    return rows


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


def _read_disable_setting(api_root, name: str):
    try:
        api = getattr(api_root, name)
        result = api.get()
    except Exception:
        return None
    inner = getattr(result, name, None)
    if inner is None:
        return None
    val = getattr(inner, "value", None)
    return bool(val) if val is not None else None


def _hive_has_tables(ws_client) -> tuple:
    try:
        catalogs = list(ws_client.catalogs.list())
    except Exception:
        return None, False
    present = any(getattr(c, "name", "") == "hive_metastore" for c in catalogs)
    if not present:
        return False, False
    try:
        schemas = list(ws_client.schemas.list(catalog_name="hive_metastore"))
    except Exception:
        return True, False
    for schema in schemas:
        name = getattr(schema, "name", "") or ""
        if not name or name == "information_schema":
            continue
        try:
            it = ws_client.tables.list(catalog_name="hive_metastore", schema_name=name)
            if next(iter(it), None) is not None:
                return True, True
        except Exception:
            continue
    return True, False


def _c09_workspace_row_data(ws_client) -> dict:
    dbfs_disabled = _read_disable_setting(ws_client.settings, "disable_legacy_dbfs")
    hive_disabled = _read_disable_setting(ws_client.settings, "disable_legacy_access")
    hive_present, hive_has_tables_val = _hive_has_tables(ws_client)
    legacy_active = (dbfs_disabled is not True) or (hive_disabled is not True)
    return {
        "dbfs_legacy_disabled": dbfs_disabled,
        "hive_legacy_disabled": hive_disabled,
        "hive_metastore_present": hive_present,
        "hive_metastore_has_tables": hive_has_tables_val,
        "legacy_active": legacy_active,
    }


def run_c09(account_client, workspaces: Iterable) -> list[tuple]:
    """C09: DBFS or Hive legacy still enabled (uses workspace settings)."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            data = _c09_workspace_row_data(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("909", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if data["legacy_active"]:
            rows.append(_common.emit_finding("909", ws_id,
                                             "DBFS or Hive legacy still enabled", [data]))
        else:
            rows.append(_common.emit_pass("909", ws_id, "DBFS and Hive legacy disabled"))
    return rows


def _enum_value(v) -> str:
    if v is None:
        return ""
    return str(getattr(v, "value", v))


def _c13_workspace_rows(ws_client) -> list[dict]:
    findings = []
    try:
        for q in ws_client.queries.list():
            if _enum_value(getattr(q, "run_as_mode", None)).upper() != "OWNER":
                continue
            findings.append({"api": "queries (v2)",
                             "name": getattr(q, "display_name", "") or "",
                             "owner": getattr(q, "owner_user_name", "") or "",
                             "warehouse_id": getattr(q, "warehouse_id", "") or "",
                             "id": getattr(q, "id", "") or ""})
    except Exception:
        pass
    try:
        for q in ws_client.queries_legacy.list():
            if _enum_value(getattr(q, "run_as_role", None)).lower() != "owner":
                continue
            user = getattr(q, "user", None)
            owner = ""
            if user is not None:
                owner = getattr(user, "email", "") or getattr(user, "display_name", "")
            findings.append({"api": "queries (legacy)",
                             "name": getattr(q, "name", "") or "",
                             "owner": owner,
                             "id": getattr(q, "id", "") or ""})
    except Exception:
        pass
    return findings


def run_c13(account_client, workspaces: Iterable) -> list[tuple]:
    """C13: SQL queries configured to Run as OWNER."""
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c13_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("913", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("913", ws_id,
                                             f"{len(findings)} query(ies) configured to Run as OWNER",
                                             findings, severity_note="review"))
        else:
            rows.append(_common.emit_pass("913", ws_id, "No queries running as OWNER"))
    return rows
