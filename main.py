
from datetime import datetime, timedelta

from src.database import create_tables, insert_alert, get_alerts, clear_alerts
from src.detection import (
    count_failed_logins,
    count_unique_usernames,
    detect_password_spraying,
    create_alert
)

# 2. Sample security events
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


# 3. Detection configuration
brute_force_threshold = 5
brute_force_time_window = timedelta(minutes=5)
spraying_threshold = 5
spraying_time_window = timedelta(minutes=5)


# 4. Run detection
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

# Save alerts to SQLite
for alert in alerts:
    insert_alert(alert)

print("\n===== ALERTS STORED IN DATABASE =====")

saved_alerts = get_alerts()

for alert in saved_alerts:
    print(alert)

print("Alerts saved to database!")

# 5. Display alerts
print("\n===== ALERT SUMMARY =====")

for alert in alerts:
    print(f"{alert['alert_type']}: {alert['severity']}")

print(f"Total alerts: {len(alerts)}")