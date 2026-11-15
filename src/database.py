import sqlite3
from pathlib import Path

def connect_db():
    project_folder = Path(__file__).resolve().parent.parent
    database_path = project_folder / "security_events.db"
    connection = sqlite3.connect(database_path)
    return connection

def create_tables():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            count INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            source_ip TEXT,
            event_type TEXT
        )
    """)

    connection.commit()
    connection.close()

def insert_alert(alert):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            source_ip,
            alert_type,
            severity,
            description,
            count
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["source_ip"],
        alert["alert_type"],
        alert["severity"],
        alert["description"],
        alert["count"]
    ))

    connection.commit()
    connection.close()

def get_alerts():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
    """)

    alerts = cursor.fetchall()

    connection.close()
    return alerts


def clear_alerts():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")

    connection.commit()
    connection.close()

def insert_event(event):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events (
            timestamp,
            username,
            source_ip,
            event_type
        )
        VALUES (?, ?, ?, ?)
    """, (
        event["timestamp"].isoformat(),
        event["username"],
        event["source_ip"],
        event["event_type"]
    ))

    connection.commit()
    connection.close()

def get_events():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM events
        ORDER BY timestamp DESC
    """)

    events = cursor.fetchall()

    connection.close()
    return events

def clear_events():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='events'")

    connection.commit()
    connection.close()

if __name__ == "__main__":
    create_tables()

    test_alert = {
        "timestamp": "2026-11-15T14:30:00",
        "source_ip": "203.0.113.10",
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "description": "Multiple failed login attempts",
        "count": 5
    }

    saved_alerts = get_alerts()

    for alert in saved_alerts:
        print(alert)