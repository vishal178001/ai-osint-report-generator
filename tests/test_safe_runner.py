import time
import utils.safe_runner as safe_runner_module
from utils.safe_runner import safe_collect


def successful_collector(target):
    return {"target": target, "data": "test"}


def failing_collector(target):
    raise RuntimeError("Test collector failure")


def test_successful_collector():
    result, status = safe_collect(
        "Test Success",
        successful_collector,
        "example.com"
    )

    assert status == "success"
    assert result["target"] == "example.com"


def test_failing_collector():
    result, status = safe_collect(
        "Test Failure",
        failing_collector,
        "example.com"
    )

def test_failing_collector():
    result, status = safe_collect(
        "Test Failure",
        failing_collector,
        "example.com"
    )

    assert status == "failed"
    assert result == {}


def slow_collector(target):
    time.sleep(2)
    return {"target": target}


def test_collector_timeout(monkeypatch):
    monkeypatch.setattr(
        safe_runner_module,
        "COLLECTOR_TIMEOUT",
        0.1
    )

    result, status = safe_runner_module.safe_collect(
        "Slow Collector",
        slow_collector,
        "example.com"
    )

    assert status == "timeout"
    assert result == {}
