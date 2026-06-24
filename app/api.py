from collections import Counter

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.alert_engine import detect_brute_force_attempts
from app.metrics import (
    TOTAL_EVENTS,
    FAILED_SSH_LOGINS,
    SUDO_COMMANDS,
    SUDO_AUTH_FAILURES,
    BRUTE_FORCE_ALERTS,
)
from app.models import SecurityEvent
from app.repository import get_all_events

app = FastAPI(title="SIEM Lite")


def to_security_events(db_events):
    return [
        SecurityEvent(
            event_type=event.event_type,
            username=event.username,
            source_ip=event.source_ip,
            raw_log=event.raw_log,
            timestamp=event.timestamp,
            severity=event.severity,
        )
        for event in db_events
    ]


@app.get("/")
def root():
    return {"message": "SIEM Lite API Running"}


@app.get("/events")
def events():
    all_events = get_all_events()

    return [
        {
            "id": event.id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "username": event.username,
            "source_ip": event.source_ip,
            "severity": event.severity,
        }
        for event in all_events
    ]


@app.get("/stats")
def stats():
    all_events = get_all_events()

    return {
        "total_events": len(all_events),
        "failed_ssh_logins": len([e for e in all_events if e.event_type == "FAILED_SSH_LOGIN"]),
        "sudo_commands": len([e for e in all_events if e.event_type == "SUDO_COMMAND"]),
        "sudo_auth_failures": len([e for e in all_events if e.event_type == "SUDO_AUTH_FAILURE"]),
        "high_severity": len([e for e in all_events if e.severity == "HIGH"]),
        "medium_severity": len([e for e in all_events if e.severity == "MEDIUM"]),
        "low_severity": len([e for e in all_events if e.severity == "LOW"]),
    }


@app.get("/alerts")
def alerts():
    db_events = get_all_events()
    return detect_brute_force_attempts(to_security_events(db_events))


@app.get("/top-ips")
def top_ips():
    all_events = get_all_events()

    ip_counts = Counter(
        event.source_ip
        for event in all_events
        if event.source_ip != "LOCAL"
    )

    return [
        {"source_ip": ip, "count": count}
        for ip, count in ip_counts.most_common(10)
    ]


@app.get("/metrics")
def metrics():
    db_events = get_all_events()
    security_events = to_security_events(db_events)
    alerts = detect_brute_force_attempts(security_events)

    TOTAL_EVENTS.set(len(db_events))
    FAILED_SSH_LOGINS.set(len([e for e in db_events if e.event_type == "FAILED_SSH_LOGIN"]))
    SUDO_COMMANDS.set(len([e for e in db_events if e.event_type == "SUDO_COMMAND"]))
    SUDO_AUTH_FAILURES.set(len([e for e in db_events if e.event_type == "SUDO_AUTH_FAILURE"]))
    BRUTE_FORCE_ALERTS.set(len(alerts))

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
