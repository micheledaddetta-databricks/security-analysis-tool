"""Shared helpers for translating ControlResult-shaped data into SAT rows.

The SAT `security_checks` Delta table expects rows of shape
``(check_id: str, score: int, additional_details: dict[str, str])``.
"""
from __future__ import annotations

import json
from typing import Any

ADDITIONAL_DETAILS_VALUE_CAP = 2048  # 2 KB per value


def _truncate(value: str) -> str:
    if len(value) <= ADDITIONAL_DETAILS_VALUE_CAP:
        return value
    return value[: ADDITIONAL_DETAILS_VALUE_CAP - 12] + "...[truncated]"


def emit_pass(check_id: str, workspace_id: int, summary: str) -> tuple:
    return check_id, 0, {
        "summary": _truncate(summary),
        "workspace_id": str(workspace_id),
    }


def emit_finding(check_id: str, workspace_id: int, summary: str,
                 findings: list[dict], severity_note: str = "") -> tuple:
    details = {
        "summary": _truncate(summary),
        "workspace_id": str(workspace_id),
        "findings_count": str(len(findings)),
        "findings_json": _truncate(json.dumps(findings, default=str)),
    }
    if severity_note:
        details["severity_note"] = severity_note
    return check_id, 1, details


def emit_error(check_id: str, workspace_id: int, error: str,
               summary: str = "audit incomplete",
               error_kind: str = "") -> tuple:
    details = {
        "summary": _truncate(summary),
        "workspace_id": str(workspace_id),
        "error": _truncate(error),
    }
    if error_kind:
        details["error_kind"] = error_kind
    return check_id, 1, details
