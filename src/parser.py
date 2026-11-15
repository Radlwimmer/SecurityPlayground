import re
from datetime import datetime

def parse_log_line(line):
    timestamp_pattern = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

    timestamp_match = re.search(timestamp_pattern, line)

    if not timestamp_match:
        return None

    timestamp = datetime.strptime(
        f"{timestamp_match.group(1)} {datetime.now().year}",
        "%b %d %H:%M:%S %Y"
    )
    failed_pattern = r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"

    match = re.search(failed_pattern, line)

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        return {
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "event_type": "FAILED"
        }

    success_pattern = r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"

    match = re.search(success_pattern, line)

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        return {
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "event_type": "SUCCESS"
        }

    return None