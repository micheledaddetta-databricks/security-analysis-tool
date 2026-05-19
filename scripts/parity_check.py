"""Compare the standalone Findings tool output to SAT's security_checks table.

Run the standalone tool first (produces `Findings/output/results.json`), then
this script — which loads that JSON, queries SAT's `security_checks` table,
and diffs the set of (check_id, workspace_id) -> score tuples.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# Our control IDs (Findings naming) → SAT check IDs.
ID_MAP = {
    "C01": "901", "C02": "902", "C03": "903", "C04": "904", "C05": "905",
    "C06": "906", "C07": "907", "C08": "908", "C09": "909",
    "C11": "911", "C12": "912", "C13": "913", "C14": "914",
}

# Our 5-state Status → expected SAT score in the parity comparison.
STATUS_TO_SCORE = {"pass": 0, "fail": 1, "warn": 1, "error": 1, "skipped": None}


def load_standalone(json_path: Path) -> dict[tuple[str, int], int]:
    """Return {(sat_check_id, workspace_id): expected_score}."""
    data = json.loads(json_path.read_text())
    expected: dict[tuple[str, int], int] = {}
    for r in data["results"]:
        cid = ID_MAP.get(r["control_id"])
        if not cid:
            continue
        score = STATUS_TO_SCORE.get(r["status"])
        if score is None:
            continue  # SKIPPED → no SAT row expected
        # In the standalone tool every items[] row carries a workspace_id.
        for item in r.get("items", []):
            ws_id = item.get("workspace_id")
            if ws_id is None:
                continue
            expected[(cid, int(ws_id))] = score
        for err in r.get("errors", []):
            ws_id = err.get("workspace_id")
            if ws_id is None:
                continue
            expected[(cid, int(ws_id))] = 1
    return expected


def load_sat(sql_query_output: Path) -> dict[tuple[str, int], int]:
    """Load (id, workspaceid, score) rows exported to JSON by Databricks CLI."""
    rows = json.loads(sql_query_output.read_text())
    out: dict[tuple[str, int], int] = {}
    for r in rows:
        cid = str(r.get("id") or r.get("ID") or r[0])
        ws_id = int(r.get("workspaceid") or r.get("WORKSPACEID") or r[1])
        score = int(r.get("score") or r.get("SCORE") or r[2])
        out[(cid, ws_id)] = score
    return out


def diff_results(expected, actual):
    only_in_expected = set(expected) - set(actual)
    only_in_actual = set(actual) - set(expected)
    score_mismatches = [
        (key, expected[key], actual[key])
        for key in set(expected) & set(actual)
        if expected[key] != actual[key]
    ]
    return only_in_expected, only_in_actual, score_mismatches


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--standalone-json", required=True,
                   type=Path, help="Findings/output/results.json")
    p.add_argument("--sat-json", required=True,
                   type=Path, help="JSON export of SELECT id,workspaceid,score FROM security_checks WHERE id IN (901..914)")
    args = p.parse_args(argv)

    expected = load_standalone(args.standalone_json)
    actual = load_sat(args.sat_json)

    only_e, only_a, mism = diff_results(expected, actual)
    print(f"only in standalone: {len(only_e)}")
    for key in sorted(only_e):
        print("  ", key, "expected_score=", expected[key])
    print(f"only in SAT: {len(only_a)}")
    for key in sorted(only_a):
        print("  ", key, "actual_score=", actual[key])
    print(f"score mismatches: {len(mism)}")
    for key, e, a in sorted(mism):
        print("  ", key, "expected=", e, "actual=", a)
    return 1 if (only_e or only_a or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
