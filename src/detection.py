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

def create_alert(source_ip, alert_type, severity, description, count):
    return {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
        "count": count
    }
