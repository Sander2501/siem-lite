# SIEM Lite

A lightweight Security Information and Event Management (SIEM) platform built with Python, FastAPI, SQLite, Prometheus, and Grafana.

## Features

* Real-time Linux auth.log monitoring
* Security event parsing
* SQLite event storage
* Duplicate event detection using SHA-256 hashes
* Severity classification
* REST API
* Prometheus metrics
* Grafana dashboards
* Brute-force attack detection
* Sudo command auditing
* Authentication failure detection

## Architecture

```text
Linux auth.log
      ↓
Log Parser
      ↓
SQLite Database
      ↓
Alert Engine
      ↓
FastAPI REST API
      ↓
Prometheus
      ↓
Grafana Dashboard
```

## Supported Event Types

| Event Type          | Severity |
| ------------------- | -------- |
| SUDO_COMMAND        | LOW      |
| SUDO_AUTH_FAILURE   | MEDIUM   |
| FAILED_SSH_LOGIN    | HIGH     |
| BRUTE_FORCE_ATTEMPT | CRITICAL |

## Dashboard Metrics

* Total Security Events
* Failed SSH Logins
* Brute Force Alerts
* Sudo Commands
* Sudo Authentication Failures

## API Endpoints

### Get Events

```http
GET /events
```

### Get Statistics

```http
GET /stats
```

### Get Alerts

```http
GET /alerts
```

### Get Top Source IPs

```http
GET /top-ips
```

### Prometheus Metrics

```http
GET /metrics
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/siem-lite.git
cd siem-lite
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Initialize the database:

```bash
python3 -m app.init_db
```

Import historical logs:

```bash
python3 -m app.main --file /var/log/auth.log
```

Run the API:

```bash
python3 -m uvicorn app.api:app --reload --host 0.0.0.0 --port 8002
```

Run the real-time monitor:

```bash
python3 -m app.realtime_monitor
```

## Grafana Dashboard

The dashboard provides real-time visibility into:

* Security events
* Failed authentication attempts
* Sudo activity
* Brute-force attack indicators

## Example Dashboard

Add a screenshot:

```text
screenshots/dashboard.png
```

## Future Improvements

* Dockerized deployment
* Email alerts
* Slack notifications
* Geo-IP enrichment
* User activity tracking
* Threat intelligence feeds
* Multiple log sources

## Technology Stack

* Python
* FastAPI
* SQLite
* SQLAlchemy
* Prometheus
* Grafana
* Linux
* Docker (planned)

## Author

Sander Meijer
