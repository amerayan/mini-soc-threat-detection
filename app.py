
import sqlite3
import json
import ipaddress
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "soc_alerts.db"

app = Flask(__name__)


def get_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_dashboard_db():
    with get_connection() as connection:
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

        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)")
        }

        if "status" not in columns:
            connection.execute("""
                ALTER TABLE alerts
                ADD COLUMN status TEXT NOT NULL DEFAULT 'Open'
            """)


@app.route("/")
def dashboard():
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        high = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
        ).fetchone()[0]

        open_count = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'Open'"
        ).fetchone()[0]

        alerts = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "index.html",
        alerts=alerts,
        total=total,
        high=high,
        open_count=open_count
    )


@app.route("/update-status/<int:alert_id>", methods=["POST"])
def update_status(alert_id):
    status = request.form.get("status")

    if status not in {"Open", "Investigating", "Resolved"}:
        return "Invalid status", 400

    with get_connection() as connection:
        connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (status, alert_id)
        )

    return redirect(url_for("dashboard"))


def load_events_for_ip(source_ip):
    log_file = BASE_DIR / "sample_logs" / "auth.log"
    matching_events = []

    if not log_file.exists():
        return matching_events

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
                if event.get("ip") == source_ip:
                    matching_events.append(event)
            except json.JSONDecodeError:
                continue

    matching_events.sort(
        key=lambda event: event.get("timestamp", "")
    )

    return matching_events


@app.route("/investigate")
def investigate():
    source_ip = request.args.get("ip", "").strip()
    events = []
    related_alerts = []
    failed_count = 0
    successful_count = 0
    error = None

    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
            events = load_events_for_ip(source_ip)

            failed_count = sum(
                event.get("event") == "failed_login"
                for event in events
            )

            successful_count = sum(
                event.get("event") == "successful_login"
                for event in events
            )

            with get_connection() as connection:
                related_alerts = connection.execute(
                    "SELECT * FROM alerts WHERE source_ip = ?",
                    (source_ip,)
                ).fetchall()

        except ValueError:
            error = "Please enter a valid IP address."

    return render_template(
        "investigate.html",
        source_ip=source_ip,
        events=events,
        related_alerts=related_alerts,
        failed_count=failed_count,
        successful_count=successful_count,
        error=error
    )


if __name__ == "__main__":
    initialize_dashboard_db()
    print("Starting Mini SOC Dashboard...")
    app.run(host="127.0.0.1", port=5000, debug=False)
