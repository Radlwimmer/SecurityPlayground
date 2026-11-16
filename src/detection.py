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
    threshold_timestamp = None
    left = 0

    for right in range(len(attempts)):
        while attempts[right][0] - attempts[left][0] > window:
            left += 1

        usernames = {
            username
            for timestamp, username in attempts[left:right + 1]
        }

        current_count = len(usernames)

        if current_count > max_count:
            max_count = current_count
            threshold_timestamp = attempts[right][0]

    return max_count, threshold_timestamp

def detect_password_spraying(events, source_ip, threshold, window):
    username_count, spraying_timestamp = count_unique_usernames(
        events,
        source_ip,
        window
    )

    if username_count >= threshold:
        return username_count, spraying_timestamp

    return 0, None

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
                return len(recent_failures), event["timestamp"]

    return 0, None


def create_alert(source_ip, alert_type, severity, description, count, timestamp=None):
    return {
        "timestamp": (
            timestamp.isoformat()
            if timestamp
            else datetime.now().isoformat()
        ),
        "source_ip": source_ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
        "count": count
    }
