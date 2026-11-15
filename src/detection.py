from datetime import datetime, timedelta

def count_failed_logins(events, source_ip, window):
    timestamps = sorted(
        event["timestamp"]
        for event in events
        if event["source_ip"] == source_ip
        and event["event_type"] == "FAILED"
    )

    max_count = 0
    left = 0

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        current_count = right - left + 1
        max_count = max(max_count, current_count)

    return max_count

def count_unique_usernames(events, source_ip, window):
    attempts = sorted(
        (event["timestamp"], event["username"])
        for event in events
        if event["source_ip"] == source_ip
        and event["event_type"] == "FAILED"
    )

    max_count = 0
    left = 0

    for right in range(len(attempts)):
        while attempts[right][0] - attempts[left][0] > window:
            left += 1

        usernames = {
            username
            for timestamp, username in attempts[left:right + 1]
        }

        max_count = max(max_count, len(usernames))

    return max_count

def detect_password_spraying(events, source_ip, threshold, window):
    username_count = count_unique_usernames(
        events,
        source_ip,
        window
    )

    return username_count >= threshold

def detect_success_after_failures(events, source_ip, threshold, window):
    ip_events = sorted(
        [
            event
            for event in events
            if event["source_ip"] == source_ip
        ],
        key=lambda event: event["timestamp"]
    )

    failed_timestamps = []

    for event in ip_events:
        if event["event_type"] == "FAILED":
            failed_timestamps.append(event["timestamp"])

        elif event["event_type"] == "SUCCESS":
            recent_failures = [
                timestamp
                for timestamp in failed_timestamps
                if timedelta(0) <= event["timestamp"] - timestamp <= window
            ]

            if len(recent_failures) >= threshold:
                return len(recent_failures)

    return 0


def create_alert(source_ip, alert_type, severity, description, count):
    return {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
        "count": count
    }
