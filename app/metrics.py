from prometheus_client import Gauge


TOTAL_EVENTS = Gauge(
    "siem_total_events",
    "Total number of stored security events",
)

FAILED_SSH_LOGINS = Gauge(
    "siem_failed_ssh_logins",
    "Total number of failed SSH login events",
)

SUDO_COMMANDS = Gauge(
    "siem_sudo_commands",
    "Total number of sudo command events",
)

SUDO_AUTH_FAILURES = Gauge(
    "siem_sudo_auth_failures",
    "Total number of sudo authentication failures",
)

BRUTE_FORCE_ALERTS = Gauge(
    "siem_brute_force_alerts",
    "Total number of detected brute-force alerts",
)
