from dataclasses import dataclass


@dataclass
class SecurityEvent:
    event_type: str
    username: str
    source_ip: str
    raw_log: str
    timestamp: str
    severity: str
