import pytest

from app.agent import (
    EvidenceValidationError,
    extract_tool_event_ids,
    validate_report_evidence,
)


EVENT_1 = "11111111-1111-4111-8111-111111111111"
EVENT_2 = "22222222-2222-4222-8222-222222222222"
INVENTED = "99999999-9999-4999-8999-999999999999"


def test_extract_tool_event_ids():
    result = {
        "events": [
            {"event_id": EVENT_1},
        ],
        "bursts": [
            {"event_ids": [EVENT_1, EVENT_2]},
        ],
    }

    assert extract_tool_event_ids(result) == {
        EVENT_1,
        EVENT_2,
    }


def test_accepts_returned_event_citation():
    validate_report_evidence(
        f"Python opened a connection [event:{EVENT_1}]",
        {EVENT_1},
    )


def test_rejects_invented_event_id():
    with pytest.raises(
        EvidenceValidationError,
        match="not returned by tools",
    ):
        validate_report_evidence(
            f"Unexpected activity [event:{INVENTED}]",
            {EVENT_1},
        )


def test_rejects_evidence_report_without_citations():
    with pytest.raises(
        EvidenceValidationError,
        match="without citing",
    ):
        validate_report_evidence(
            "Python opened many outbound connections.",
            {EVENT_1},
        )


def test_allows_no_evidence_response_when_tools_found_nothing():
    validate_report_evidence(
        "No connection events were found, so no conclusion can be made.",
        set(),
    )
