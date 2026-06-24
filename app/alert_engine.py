from collections import Counter

from app.models import SecurityEvent


def detect_brute_force_attempts(
    events: list[SecurityEvent],
    threshold: int = 5,
) -> list[dict]:
    failed_login_ips = [
        event.source_ip
        for event in events
        if event.event_type == "FAILED_SSH_LOGIN"
    ]

    ip_counts = Counter(failed_login_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append(
                {
                    "alert_type": "BRUTE_FORCE_ATTEMPT",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "severity": "HIGH",
                    "message": f"Possible brute-force attack from {ip} with {count} failed login attempts.",
                }
            )

    return alerts
