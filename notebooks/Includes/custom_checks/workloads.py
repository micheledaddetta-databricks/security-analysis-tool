"""Workload-domain controls: C07, C11, C12, C14."""
from __future__ import annotations

from typing import Iterable

from . import _common


# -------- C07: apps deployed without a git repo --------

def _c07_app_info(detail) -> dict:
    out = {"git_backed": False, "git_url": "", "git_provider": "",
           "git_branch": "", "git_tag": "", "git_commit": "",
           "source_code_path": ""}
    app_repo = getattr(detail, "git_repository", None)
    if app_repo is not None:
        out["git_url"] = getattr(app_repo, "url", "") or ""
        out["git_provider"] = getattr(app_repo, "provider", "") or ""
    deployment = (getattr(detail, "active_deployment", None)
                  or getattr(detail, "default_deployment", None))
    if deployment is not None:
        gs = getattr(deployment, "git_source", None)
        if gs is not None:
            gr = getattr(gs, "git_repository", None)
            if gr is not None:
                out["git_url"] = out["git_url"] or (getattr(gr, "url", "") or "")
                out["git_provider"] = out["git_provider"] or (getattr(gr, "provider", "") or "")
            out["git_branch"] = getattr(gs, "branch", "") or ""
            out["git_tag"] = getattr(gs, "tag", "") or ""
            out["git_commit"] = (getattr(gs, "resolved_commit", "")
                                 or getattr(gs, "commit", "") or "")
            out["source_code_path"] = getattr(gs, "source_code_path", "") or ""
        if not out["source_code_path"]:
            out["source_code_path"] = getattr(deployment, "source_code_path", "") or ""
    out["git_backed"] = bool(out["git_url"])
    return out


def _c07_workspace_rows(ws_client) -> list[dict]:
    rows = []
    try:
        apps = list(ws_client.apps.list())
    except Exception:
        return rows
    for app in apps:
        try:
            detail = ws_client.apps.get(name=app.name)
        except Exception:
            detail = app
        info = _c07_app_info(detail)
        if not info["git_backed"]:
            rows.append({"app_name": getattr(detail, "name", ""), **info})
    return rows


def run_c07(account_client, workspaces: Iterable) -> list[tuple]:
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c07_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("907", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("907", ws_id,
                                             f"{len(findings)} App(s) deployed without a git repo",
                                             findings, severity_note="review"))
        else:
            rows.append(_common.emit_pass("907", ws_id, "All Apps git-backed (or none deployed)"))
    return rows


# -------- C11: inventory of in-use features --------

def _safe_iter_count(it) -> int:
    try:
        return sum(1 for _ in it)
    except Exception:
        return 0


def _c11_workspace_inventory(ws_client) -> list[dict]:
    rows = []

    def add(feature, n):
        if n > 0:
            rows.append({"feature": feature, "count": n})

    add("Apps", _safe_iter_count(ws_client.apps.list()))
    add("Vector Search Endpoints", _safe_iter_count(ws_client.vector_search_endpoints.list_endpoints()))
    add("Serving Endpoints", _safe_iter_count(ws_client.serving_endpoints.list()))
    add("DLT Pipelines", _safe_iter_count(ws_client.pipelines.list_pipelines()))
    add("Jobs", _safe_iter_count(ws_client.jobs.list()))
    add("MLflow Experiments", _safe_iter_count(ws_client.experiments.list_experiments()))
    add("Lakeview Dashboards", _safe_iter_count(ws_client.lakeview.list()))
    try:
        add("Genie Spaces", _safe_iter_count(ws_client.genie.list_spaces()))
    except AttributeError:
        pass
    try:
        add("Clean Rooms", _safe_iter_count(ws_client.clean_rooms.list()))
    except AttributeError:
        pass

    try:
        instances = list(ws_client.database.list_database_instances())
        prov, auto = 0, 0
        for inst in instances:
            pol = getattr(inst, "usage_policy_id", None) or getattr(inst, "effective_usage_policy_id", None)
            if pol:
                auto += 1
            else:
                prov += 1
        add("Lakebase (Provisioned)", prov)
        add("Lakebase (Autoscaling)", auto)
    except Exception:
        pass
    return rows


def run_c11(account_client, workspaces: Iterable) -> list[tuple]:
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            inventory = _c11_workspace_inventory(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("911", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        # C11 is informational — always PASS, payload carries the inventory.
        details_summary = ", ".join(f"{r['feature']}={r['count']}" for r in inventory[:6]) or "no features in use"
        rows.append(_common.emit_finding("911", ws_id, details_summary, inventory) if inventory
                    else _common.emit_pass("911", ws_id, "no features in use"))
    return rows


# -------- C12: LLM serving endpoints --------

def _c12_entity_summary(ep) -> tuple:
    config = getattr(ep, "config", None)
    if config is None:
        return ("", "unknown")
    served = (getattr(config, "served_entities", []) or getattr(config, "served_models", []) or [])
    if not served:
        return ("", "unknown")
    e = served[0]
    if getattr(e, "foundation_model", None) is not None:
        fm = e.foundation_model
        return (getattr(fm, "name", "") or getattr(fm, "display_name", ""), "foundation")
    if getattr(e, "external_model", None) is not None:
        return (getattr(e.external_model, "name", "") or getattr(e.external_model, "provider", ""), "external")
    return (getattr(e, "entity_name", "") or getattr(e, "model_name", ""), "custom")


def _c12_workspace_rows(ws_client) -> list[dict]:
    rows = []
    for ep in ws_client.serving_endpoints.list():
        model, kind = _c12_entity_summary(ep)
        if kind == "custom":
            continue
        rows.append({"endpoint": getattr(ep, "name", ""), "model": model, "type": kind,
                     "state": str(getattr(getattr(ep, "state", None), "ready", ""))})
    return rows


def run_c12(account_client, workspaces: Iterable) -> list[tuple]:
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c12_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("912", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("912", ws_id,
                                             f"{len(findings)} LLM-serving endpoint(s)",
                                             findings))
        else:
            rows.append(_common.emit_pass("912", ws_id, "no LLM-serving endpoints"))
    return rows


# -------- C14: apps not using OBO --------

def _c14_uses_obo(detail) -> bool:
    if getattr(detail, "user_api_scopes", None):
        return True
    auth_mode = (getattr(detail, "auth_mode", "") or
                 getattr(detail, "user_authorization", "") or
                 getattr(detail, "authorization_mode", ""))
    return "user" in str(auth_mode).lower() or "obo" in str(auth_mode).lower()


def _c14_workspace_rows(ws_client) -> list[dict]:
    rows = []
    try:
        apps = list(ws_client.apps.list())
    except Exception:
        return rows
    for app in apps:
        try:
            detail = ws_client.apps.get(name=app.name)
        except Exception:
            detail = app
        if not _c14_uses_obo(detail):
            rows.append({"app_name": getattr(detail, "name", ""),
                         "auth_mode": (getattr(detail, "auth_mode", "")
                                       or getattr(detail, "user_authorization", "")
                                       or "service-principal"),
                         "uses_obo": False})
    return rows


def run_c14(account_client, workspaces: Iterable) -> list[tuple]:
    rows = []
    for ws in workspaces:
        ws_id = getattr(ws, "workspace_id", 0)
        try:
            ws_client = account_client.get_workspace_client(ws)
            findings = _c14_workspace_rows(ws_client)
        except Exception as e:
            rows.append(_common.emit_error("914", ws_id, repr(e), error_kind="ws_client_failed"))
            continue
        if findings:
            rows.append(_common.emit_finding("914", ws_id,
                                             f"{len(findings)} App(s) not using OBO", findings))
        else:
            rows.append(_common.emit_pass("914", ws_id, "All Apps use OBO (or none deployed)"))
    return rows
