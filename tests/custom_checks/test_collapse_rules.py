import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from notebooks.Includes.custom_checks import _common  # noqa: E402


def test_pass_emits_score_0_and_summary():
    cid, score, details = _common.emit_pass("905", 1, "looks good")
    assert (cid, score) == ("905", 0)
    assert details["summary"] == "looks good"


def test_finding_emits_score_1_and_json():
    cid, score, details = _common.emit_finding("901", 2, "found stuff",
                                               [{"k": "v"}, {"k": "w"}])
    assert (cid, score) == ("901", 1)
    assert details["findings_count"] == "2"
    assert "k" in details["findings_json"]


def test_warn_carries_severity_note():
    cid, score, details = _common.emit_finding("902", 3, "soft", [{"x": 1}],
                                               severity_note="review")
    assert details["severity_note"] == "review"


def test_error_emits_score_1_and_error_kind():
    cid, score, details = _common.emit_error("903", 4, "boom",
                                             error_kind="ws_client_failed")
    assert (cid, score) == ("903", 1)
    assert details["error"] == "boom"
    assert details["error_kind"] == "ws_client_failed"


def test_truncation_caps_large_values():
    huge = "x" * 4096
    cid, score, details = _common.emit_finding("911", 5, huge, [{"x": huge}])
    assert len(details["summary"]) <= _common.ADDITIONAL_DETAILS_VALUE_CAP
    assert len(details["findings_json"]) <= _common.ADDITIONAL_DETAILS_VALUE_CAP
