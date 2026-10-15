
import json
import sqlite3
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs" / "auth.log"
DB_FILE = BASE_DIR / "soc_alerts.db"

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def load_logs():
    events = []

    if not LOG_FILE.exists():
        print("Log file not found:", LOG_FILE)
        return events

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                event["timestamp"] = datetime.fromisoformat(
                    event["timestamp"]
                )
                events.append(event)
            except (json.JSONDecodeError, KeyError, ValueError) as error:
                print(f"Skipping invalid line {line_number}: {error}")

    return events


def detect_brute_force(events):
    failed_attempts = defaultdict(deque)
    alerts = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    events.sort(key=lambda event: event["timestamp"])

    for event in events:
        if event.get("event") != "failed_login":
            continue

        source_ip = event.get("ip", "Unknown")
        timestamp = event["timestamp"]
        attempts = failed_attempts[source_ip]

        attempts.append(timestamp)

        while attempts and timestamp - attempts[0] > window:
            attempts.popleft()

        if len(attempts) == FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "source_ip": source_ip,
                "severity": "HIGH",
                "failed_attempts": len(attempts),
                "window_minutes": TIME_WINDOW_MINUTES,
                "first_seen": attempts[0].isoformat(),
                "last_seen": timestamp.isoformat(),
                "alert": (
                    f"Possible brute-force attack from {source_ip}: "
                    f"{len(attempts)} failed login attempts within "
                    f"{TIME_WINDOW_MINUTES} minutes."
                ),
                "created_at": datetime.now().isoformat(
                    timespec="seconds"
                )
            })

    return alerts


def initialize_database():
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                window_minutes INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                alert TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(source_ip, first_seen, last_seen, alert)
            )
        """)


def save_alerts(alerts):
    with sqlite3.connect(DB_FILE) as connection:
        for alert in alerts:
            connection.execute("""
                INSERT OR IGNORE INTO alerts (
                    source_ip, severity, failed_attempts,
                    window_minutes, first_seen, last_seen,
                    alert, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["source_ip"],
                alert["severity"],
                alert["failed_attempts"],
                alert["window_minutes"],
                alert["first_seen"],
                alert["last_seen"],
                alert["alert"],
                alert["created_at"]
            ))


def show_recent_alerts():
    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute("""
            SELECT id, severity, source_ip, failed_attempts, alert
            FROM alerts
            ORDER BY id DESC
        """).fetchall()

    print("\nAlerts saved in SQLite database:")

    if not rows:
        print("No alerts stored.")
        return

    for row in rows:
        print(
            f"ID: {row[0]} | Severity: {row[1]} | "
            f"IP: {row[2]} | Failures: {row[3]}"
        )
        print(f"Alert: {row[4]}")


def main():
    print("Mini SOC - Threat Detection Engine")
    print("-" * 40)

    initialize_database()

    events = load_logs()
    print(f"Log events loaded: {len(events)}")

    alerts = detect_brute_force(events)
    print(f"New alerts detected: {len(alerts)}")

    save_alerts(alerts)
    show_recent_alerts()


if __name__ == "__main__":
    main()
