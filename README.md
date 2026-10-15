# Mini SOC — Threat Detection & Incident Response

A beginner-friendly Security Operations Center (SOC) project built with Python, Flask, and SQLite. It demonstrates authentication log analysis, brute-force detection, security alert storage, and incident management.

## Project Overview

A Security Operations Center monitors systems for suspicious activity and investigates potential security incidents. This project simulates part of that workflow using sample authentication logs and a web-based dashboard.

## Features

- **Brute-force detection:** Detects repeated failed login attempts from the same IP address within a defined time window.
- **Security alert storage:** Stores detected alerts in an SQLite database.
- **SOC dashboard:** Displays alert counts, severity, source IP addresses, and incident status.
- **Incident management:** Supports tracking incidents through status updates.
- **IP investigation:** Includes a page intended to review authentication events and related alerts for a selected IP address.

## Technologies Used

- Python
- Flask
- SQLite
- HTML and CSS
- JSON Lines sample log data

## Project Structure

```text
mini-soc-threat-detection/
├── main.py
├── app.py
├── requirements.txt
├── .gitignore
├── README.md
├── sample_logs/
│   └── auth.log
└── templates/
    ├── index.html
    └── investigate.html
```

## How Detection Works

1. The detection engine reads simulated authentication events.
2. It checks failed login attempts by source IP address.
3. It looks for five failed attempts within a five-minute window.
4. When the threshold is met, it generates a high-severity alert.
5. Alerts are stored in SQLite and displayed on the dashboard.

## Installation and Usage

### 1. Install Python

Install Python from https://www.python.org/downloads/.

### 2. Download the Project

Click **Code → Download ZIP** on this repository page and extract the downloaded ZIP file.

### 3. Open the Project Folder

Open Command Prompt inside the extracted project folder.

### 4. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run the Detection Engine

```bash
python main.py
```

### 6. Start the Dashboard

Open a second Command Prompt in the project folder and run:

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

Keep the dashboard's Command Prompt window open while using the application.

## Sample Data

The included authentication logs are simulated for demonstration. They do not represent evidence of a real attack.

## Limitations

- Uses sample logs rather than a live enterprise log source.
- Uses a basic detection threshold that may need tuning.
- Is intended for learning and demonstration, not production security monitoring.
- The IP investigation feature should be tested before relying on it.

## Future Improvements

- Add log upload and filtering.
- Improve alert visualization and reporting.
- Add investigation notes and incident history.
- Add automated tests and configurable detection thresholds.
- Test and refine IP investigation functionality.

## Learning Outcomes

This project provides practical experience with Python, log parsing, basic threat detection, Flask routing, SQLite database operations, and incident management concepts.

## Disclaimer

This project is for educational purposes only. All included security events are simulated. Do not upload real credentials or sensitive logs to a public repository.
