import re

from app.models import SecurityEvent


TIMESTAMP_PATTERN = re.compile(r"^(?P<timestamp>\S+)")

FAILED_SSH_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<username>\w+) from (?P<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
)

SUDO_COMMAND_PATTERN = re.compile(
    r"sudo: (?P<username>\w+) : .*COMMAND=(?P<command>.+)"
)

SUDO_AUTH_FAILURE_PATTERN = re.compile(
    r"sudo: pam_unix\(sudo:auth\): authentication failure; .*ruser=(?P<username>\w+)"
)


def extract_timestamp(log_line: str) -> str:
    match = TIMESTAMP_PATTERN.search(log_line)
    return match.group("timestamp") if match else "UNKNOWN"


def parse_failed_ssh_login(log_line: str) -> SecurityEvent | None:
    match = FAILED_SSH_PATTERN.search(log_line)

    if not match:
        return None

    return SecurityEvent(
        event_type="FAILED_SSH_LOGIN",
        username=match.group("username"),
        source_ip=match.group("ip"),
        raw_log=log_line.strip(),
        timestamp=extract_timestamp(log_line),
        severity="HIGH",
    )


def parse_sudo_command(log_line: str) -> SecurityEvent | None:
    match = SUDO_COMMAND_PATTERN.search(log_line)

    if not match:
        return None

    return SecurityEvent(
        event_type="SUDO_COMMAND",
        username=match.group("username"),
        source_ip="LOCAL",
        raw_log=log_line.strip(),
        timestamp=extract_timestamp(log_line),
        severity="LOW",
    )


def parse_sudo_auth_failure(log_line: str) -> SecurityEvent | None:
    match = SUDO_AUTH_FAILURE_PATTERN.search(log_line)

    if not match:
        return None

    return SecurityEvent(
        event_type="SUDO_AUTH_FAILURE",
        username=match.group("username"),
        source_ip="LOCAL",
        raw_log=log_line.strip(),
        timestamp=extract_timestamp(log_line),
        severity="MEDIUM",
    )


def parse_log_line(log_line: str) -> SecurityEvent | None:
    parsers = [
        parse_failed_ssh_login,
        parse_sudo_command,
        parse_sudo_auth_failure,
    ]

    for parser in parsers:
        event = parser(log_line)

        if event:
            return event

    return None
