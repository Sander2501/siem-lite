from app.alert_engine import detect_brute_force_attempts
from app.models import SecurityEvent


def test_detect_brute_force_attempt():
    events = [
        SecurityEvent("FAILED_SSH_LOGIN", "admin", "10.0.0.5", "log")
        for _ in range(5)
    ]

    alerts = detect_brute_force_attempts(events, threshold=5)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "BRUTE_FORCE_ATTEMPT"
    assert alerts[0]["source_ip"] == "10.0.0.5"
    assert alerts[0]["failed_attempts"] == 5


def test_no_brute_force_below_threshold():
    events = [
        SecurityEvent("FAILED_SSH_LOGIN", "admin", "10.0.0.5", "log")
        for _ in range(3)
    ]

    alerts = detect_brute_force_attempts(events, threshold=5)

    assert alerts == []
