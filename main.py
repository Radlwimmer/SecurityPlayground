import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path

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

from src.parser import parse_log_file

logging.basicConfig(
    filename="securityplayground.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info("SecurityPlayground started")

# Create database
create_tables()
clear_alerts()
clear_events()


# Log samples
argument_parser = argparse.ArgumentParser(
    description="Analyze SSH authentication logs."
)
argument_parser.add_argument(
    "--log-file",
    default="sample_logs/auth.log",
    help="Path to the SSH authentication log file."
)
args = argument_parser.parse_args()
log_file_path = args.log_file
if not Path(log_file_path).is_file():
    logging.error("Log file not found: %s", log_file_path)
    raise SystemExit(1)
parsed_events = parse_log_file(log_file_path)
for event in parsed_events:
    insert_event(event)

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
    # detecting brute force
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
        logging.warning(
            "Brute-force activity detected from %s (%s failed attempts)",
            source_ip,
            attempts_in_window
        )
    # detecting spraying
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
        logging.warning(
            "Password spraying detected from %s",
            source_ip
        )
    # detect failures before success
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
        logging.warning(
            "Successful login after repeated failures from %s (%s failures)",
            source_ip,
            failures_before_success
        )

# Store alerts
for alert in alerts:
    insert_alert(alert)


# 8. Display results
logging.info("Displaying events stored in database")
for event in get_events():
    print(event)

logging.info("Displaying alerts stored in database")
for alert in get_alerts():
    print(alert)
