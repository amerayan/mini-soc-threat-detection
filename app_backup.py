import sqlite3
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


if __name__ == "__main__":
    initialize_dashboard_db()
    print("Starting Mini SOC Dashboard...")
    app.run(host="127.0.0.1", port=5000, debug=False)