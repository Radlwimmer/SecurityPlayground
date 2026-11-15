from datetime import datetime, timedelta

from src.detection import count_failed_logins

def test_detects_brute_force():
    events = [
        {
            "timestamp": datetime(2026, 11, 15, 10, 0, 0) + timedelta(minutes=i),
            "source_ip": "203.0.113.10",
            "username": "admin",
            "event_type": "FAILED"
        }
        for i in range(5)
    ]

    result = count_failed_logins(
        events,
        "203.0.113.10",
        timedelta(minutes=5)
    )

    assert result == 5

def test_does_not_reach_brute_force_threshold():
    events = [
        {
            "timestamp": datetime(2026, 11, 15, 10, 0, 0) + timedelta(minutes=i),
            "source_ip": "203.0.113.10",
            "username": "admin",
            "event_type": "FAILED"
        }
        for i in range(3)
    ]

    result = count_failed_logins(
        events,
        "203.0.113.10",
        timedelta(minutes=5)
    )

    assert result == 3
    assert result < 5


def test_detects_password_spraying():
    from src.detection import detect_password_spraying

    events = [
        {
            "timestamp": datetime(2026, 11, 15, 10, 0, 0) + timedelta(minutes=i),
            "source_ip": "203.0.113.10",
            "username": username,
            "event_type": "FAILED"
        }
        for i, username in enumerate(
            ["admin", "irene", "marcel", "karl", "peter"]
        )
    ]

    result = detect_password_spraying(
        events,
        "203.0.113.10",
        5,
        timedelta(minutes=5)
    )

    assert result is True

def test_detects_success_after_failures():
    from src.detection import detect_success_after_failures

    events = [
        {
            "timestamp": datetime(2026, 11, 15, 10, 0, 0) + timedelta(minutes=i),
            "source_ip": "203.0.113.10",
            "username": "admin",
            "event_type": "FAILED"
        }
        for i in range(5)
    ]

    events.append({
        "timestamp": datetime(2026, 11, 15, 10, 5, 30),
        "source_ip": "203.0.113.10",
        "username": "admin",
        "event_type": "SUCCESS"
    })

    result = detect_success_after_failures(
        events,
        "203.0.113.10",
        5,
        timedelta(minutes=10)
    )

    assert result == 5

def test_does_not_detect_success_after_fewer_failures():
    from src.detection import detect_success_after_failures

    events = [
        {
            "timestamp": datetime(2026, 11, 15, 10, 0, 0) + timedelta(minutes=i),
            "source_ip": "203.0.113.10",
            "username": "admin",
            "event_type": "FAILED"
        }
        for i in range(4)
    ]

    events.append({
        "timestamp": datetime(2026, 11, 15, 10, 5, 0),
        "source_ip": "203.0.113.10",
        "username": "admin",
        "event_type": "SUCCESS"
    })

    result = detect_success_after_failures(
        events,
        "203.0.113.10",
        5,
        timedelta(minutes=10)
    )

    assert result == 0