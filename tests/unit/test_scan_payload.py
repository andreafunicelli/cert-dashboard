"""Plan 2 Task 2: the scan/default payload contract shared by the web route and the registry."""

import pytest

from app.services.scans import validate_scan_payload


@pytest.mark.parametrize("payload", [{}, {"action": "default"}, {"endpoint_ids": [3, 1]}, {"certificate_id": 7}])
def test_valid_scan_payloads(payload):
    clean = validate_scan_payload(payload)
    assert "action" not in clean and clean.get("endpoint_ids", [1, 3]) == [1, 3]


@pytest.mark.parametrize(
    "payload",
    [
        {"endpoint_ids": []},
        {"endpoint_ids": [1, 1]},
        {"endpoint_ids": [0]},
        {"endpoint_ids": [True]},
        {"endpoint_ids": list(range(1, 1002))},
        {"certificate_id": "7"},
        {"endpoint_ids": [1], "certificate_id": 2},
        {"host": "example.internal"},
        {"action": "import_pull"},
    ],
)
def test_invalid_scan_payloads(payload):
    with pytest.raises(ValueError):
        validate_scan_payload(payload)


def test_scan_payload_boundaries_and_normalisation():
    assert validate_scan_payload({"endpoint_ids": list(range(1000, 0, -1))})["endpoint_ids"] == list(range(1, 1001))
    assert validate_scan_payload({"action": "default", "certificate_id": 7}) == {"certificate_id": 7}
    assert validate_scan_payload({}) == {}
    for bad in ({"certificate_id": 0}, {"certificate_id": True}, {"endpoint_ids": "1"}, {"endpoint_ids": [1.0]}):
        with pytest.raises(ValueError):
            validate_scan_payload(bad)
