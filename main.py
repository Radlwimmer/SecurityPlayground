
from datetime import datetime, timedelta

from src.database import (
    create_tables,
    insert_alert,
    get_alerts,
    clear_alerts,
    insert_event,
    get_events,
    clear_events
)

from src.detection import (
    count_failed_logins,
    count_unique_usernames,
    detect_password_spraying,
    detect_success_after_failures,
    create_alert
)

from src.parser import parse_log_line


# Create database
create_tables()
clear_alerts()
clear_events()


# Log samples
log_lines = [
    "Nov 15 10:00:00 server sshd[1001]: Failed password for admin from 203.0.113.10 port 54321 ssh2",
    "Nov 15 10:01:00 server sshd[1002]: Failed password for irene from 203.0.113.10 port 54322 ssh2",
    "Nov 15 10:02:00 server sshd[1003]: Failed password for marcel from 203.0.113.10 port 54323 ssh2",
    "Nov 15 10:03:00 server sshd[1004]: Failed password for karl from 203.0.113.10 port 54324 ssh2",
    "Nov 15 10:04:00 server sshd[1005]: Failed password for peter from 203.0.113.10 port 54325 ssh2",
    "Nov 15 10:05:00 server systemd[1]: Started system service",
    "Nov 15 10:05:30 server sshd[1006]: Accepted password for peter from 203.0.113.10 port 54326 ssh2",
]


# Parse logs and store valid events
for line in log_lines:
    parsed_event = parse_log_line(line)

    if parsed_event:
        insert_event(parsed_event)


# Load events
saved_events = get_events()

events = [
    {
        "timestamp": datetime.fromisoformat(event[1]),
        "username": event[2],
        "source_ip": event[3],
        "event_type": event[4]
    }
    for event in saved_events
]


# Config
brute_force_threshold = 5
brute_force_time_window = timedelta(minutes=5)

spraying_threshold = 5
spraying_time_window = timedelta(minutes=5)

success_after_failures_threshold = 5
success_after_failures_window = timedelta(minutes=10)


# Run
alerts = []

source_ips = set(event["source_ip"] for event in events)

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

    failures_before_success = detect_success_after_failures(
        events,
        source_ip,
        success_after_failures_threshold,
        success_after_failures_window
    )

    if failures_before_success:
        alerts.append(
            create_alert(
                source_ip,
                "SUCCESS_AFTER_FAILURES",
                "CRITICAL",
                "Successful login after multiple failed attempts",
                failures_before_success
            )
        )


# Store alerts
for alert in alerts:
    insert_alert(alert)


# 8. Display results
print("\nEvents stored in database:")
for event in get_events():
    print(event)

print("\nAlerts stored in database:")
for alert in get_alerts():
    print(alert)
