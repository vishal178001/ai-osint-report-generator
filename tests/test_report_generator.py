from reports.report_generator import generate_markdown_report


def test_report_contains_collection_status(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "reports").mkdir()

    report_data = {
        "target": "example.com",
        "collector_status": {
            "dns": "success",
            "whois": "success",
            "theharvester": "failed",
            "http": "success",
            "ssl": "success",
            "subdomains": "success",
            "technologies": "success"
        },
        "security_analysis": {
            "findings": []
        }
    }

    report_file = generate_markdown_report(report_data)

    with open(report_file, "r") as file:
        content = file.read()

    assert "## Collection Status" in content
    assert "dns: success" in content
    assert "theharvester: failed" in content
