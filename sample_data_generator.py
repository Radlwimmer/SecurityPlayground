
from datetime import datetime, timedelta
import random

random.seed(42)

start = datetime(2026, 11, 15, 8, 0, 0)

events = []

# Normal activity across 12 hours
usernames = [
    "alice", "bob", "charlie", "david", "emma",
    "frank", "grace", "henry", "admin", "service"
]

normal_ips = [
    f"203.0.113.{number}"
    for number in range(20, 32)
]

for minute in range(720):
    # Generate 1-3 normal login attempts per minute
    for _ in range(random.randint(1, 3)):
        timestamp = start + timedelta(
            minutes=minute,
            seconds=random.randint(0, 59)
        )

        username = random.choice(usernames)
        source_ip = random.choice(normal_ips)

        event_type = random.choices(
            ["Accepted", "Failed"],
            weights=[92, 8]
        )[0]

        events.append((
            timestamp, username, source_ip, event_type
        ))


# Brute-force attack: repeated failures
for minute in range(5):
    timestamp = start + timedelta(minutes=35 + minute)

    events.append((
        timestamp,
        "admin",
        "203.0.113.100",
        "Failed"
    ))

# Successful login after brute-force attempts
events.append((
    start + timedelta(minutes=41),
    "admin",
    "203.0.113.100",
    "Accepted"
))


# Password spraying: different usernames, same IP
for minute, username in enumerate([
    "alice", "bob", "charlie", "david", "admin"
]):
    timestamp = start + timedelta(minutes=300 + minute)

    events.append((
        timestamp,
        username,
        "203.0.113.101",
        "Failed"
    ))


# Another brute-force attack later in the day
for minute in range(5):
    timestamp = start + timedelta(minutes=600 + minute)

    events.append((
        timestamp,
        "service",
        "203.0.113.102",
        "Failed"
    ))

events.append((
    start + timedelta(minutes=606),
    "service",
    "203.0.113.102",
    "Accepted"
))


# Sort all events chronologically
events.sort(key=lambda event: event[0])


# Write synthetic SSH log file
with open("sample_logs/auth.log", "w", encoding="utf-8") as file:
    for timestamp, username, source_ip, event_type in events:
        if event_type == "Failed":
            message = f"Failed password for {username}"
        else:
            message = f"Accepted password for {username}"

        file.write(
            f"{timestamp.strftime('%b %d %H:%M:%S')} "
            f"server sshd[1001]: {message} from {source_ip} "
            "port 54321 ssh2\n"
        )

print(f"Generated {len(events)} synthetic SSH events.")