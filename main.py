
from datetime import datetime, timedelta

from src.database import create_tables, insert_alert, get_alerts, clear_alerts
from src.detection import (
    count_failed_logins,
    count_unique_usernames,
    detect_password_spraying,
    create_alert
)

from src.parser import parse_log_line

# security events
events = [
    {
        "timestamp": datetime(2026, 11, 15, 10, 0, 0),
        "source_ip": "203.0.113.10",
        "username": "admin",
        "event_type": "FAILED"
    },
    {
        "timestamp": datetime(2026, 11, 15, 10, 1, 0),
        "source_ip": "203.0.113.10",
        "username": "irene",
        "event_type": "FAILED"
    },
    {
        "timestamp": datetime(2026, 11, 15, 10, 2, 0),
        "source_ip": "203.0.113.10",
        "username": "marcel",
        "event_type": "FAILED"
    },
    {
        "timestamp": datetime(2026, 11, 15, 10, 3, 0),
        "source_ip": "203.0.113.10",
        "username": "karl",
        "event_type": "FAILED"
    },
    {
        "timestamp": datetime(2026, 11, 15, 10, 4, 0),
        "source_ip": "203.0.113.10",
        "username": "peter",
        "event_type": "FAILED"
    }
]


# config
brute_force_threshold = 5
brute_force_time_window = timedelta(minutes=5)
spraying_threshold = 5
spraying_time_window = timedelta(minutes=5)


# run
alerts = []

source_ips = set(event["source_ip"] for event in events)
create_tables()
clear_alerts()
for source_ip in source_ips:

    attempts_in_window = count_failed_logins(
        events,
        source_ip,
        brute_force_time_window
    )

    if attempts_in_window >= brute_force_threshold:
        alerts.append(
            create_alert(
                source_ip,
                "BRUTE_FORCE",
                "HIGH",
                "Multiple failed login attempts",
                attempts_in_window
            )
        )

    if detect_password_spraying(
        events,
        source_ip,
        spraying_threshold,
        spraying_time_window
    ):
        alerts.append(
            create_alert(
                source_ip,
                "PASSWORD_SPRAYING",
                "HIGH",
                "Multiple usernames targeted",
                count_unique_usernames(
                    events,
                    source_ip,
                    spraying_time_window
                )
            )
        )

# save alerts to SQLite
for alert in alerts:
    insert_alert(alert)

print("\nAlerts in database:")
print(alerts)
saved_alerts = get_alerts()
for alert in saved_alerts:
    print(alert)

# parser tests
test_line = "Nov 15 10:32:14 server sshd[1234]: Failed password for admin from 203.0.113.10 port 54321 ssh2"
parsed_event = parse_log_line(test_line)
print(parsed_event)

success_line = "Nov 15 10:35:20 server sshd[1235]: Accepted password for admin from 203.0.113.20 port 54322 ssh2"
parsed_success = parse_log_line(success_line)
print(parsed_success)

other_line = "Nov 15 10:40:00 server systemd[1]: Started system service"
parsed_other = parse_log_line(other_line)
print(parsed_other)

invalid_user_line = "Nov 15 10:40:00 server sshd[1236]: Failed password for invalid user testadmin from 203.0.113.30 port 54323 ssh2"
parsed_invalid = parse_log_line(invalid_user_line)
print(parsed_invalid)