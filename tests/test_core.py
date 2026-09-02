from nova.core.models import Finding, ScanResult


def test_finding_serialization():
    finding = Finding(
        category="TEST",
        key="name",
        value="nova",
        source="test",
    )

    data = finding.to_dict()

    assert data["category"] == "TEST"
    assert data["key"] == "name"
    assert data["value"] == "nova"
    assert data["source"] == "test"
    assert "timestamp" in data


def test_scan_result_add():
    result = ScanResult(target="example.com")

    result.add(
        category="DNS",
        key="A",
        value="93.184.216.34",
        source="DNS",
    )

    assert len(result.findings) == 1
    assert result.findings[0].category == "DNS"
    assert result.findings[0].key == "A"
    assert result.findings[0].value == "93.184.216.34"
    assert result.findings[0].source == "DNS"


def test_scan_result_serialization():
    result = ScanResult(target="example.com")

    result.add(
        category="TEST",
        key="status",
        value="ok",
        source="test",
    )

    data = result.to_dict()

    assert data["target"] == "example.com"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["value"] == "ok"

