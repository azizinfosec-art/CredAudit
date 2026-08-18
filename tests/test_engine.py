from credaudit import ScanResult, scan


def test_public_engine_api_returns_redacted_result():
    result = scan("tests/secrets.txt", mode="fast", no_cache=True)

    assert isinstance(result, ScanResult)
    assert result.files_scanned == 1
    assert result.findings
    assert result.version
    assert set(result.counts) == {"Critical", "High", "Medium", "Low"}


def test_engine_rejects_unknown_mode():
    try:
        scan("tests/secrets.txt", mode="unknown")
    except ValueError as exc:
        assert "mode" in str(exc)
    else:
        raise AssertionError("scan() accepted an unknown mode")
