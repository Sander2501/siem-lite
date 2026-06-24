import argparse
from pathlib import Path

from app.alert_engine import detect_brute_force_attempts
from app.database import Base, engine
from app.log_parser import parse_log_line
from app.repository import save_event


def read_log_file(path: str) -> list[str]:
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with open(log_path, "r") as file:
        return file.readlines()


def main():
    Base.metadata.create_all(bind=engine)

    parser = argparse.ArgumentParser(description="SIEM Lite Log Analyzer")
    parser.add_argument(
        "--file",
        default="logs/auth_sample.log",
        help="Path to the log file to analyze",
    )

    args = parser.parse_args()
    lines = read_log_file(args.file)

    parsed_events = []
    stored_events = []

    for line in lines:
        event = parse_log_line(line)

        if event is None:
            continue

        parsed_events.append(event)

        saved_event = save_event(event)

        if saved_event is not None:
            stored_events.append(event)

    alerts = detect_brute_force_attempts(parsed_events)

    print("=" * 50)
    print("SIEM Lite Report")
    print("=" * 50)
    print(f"Parsed security events: {len(parsed_events)}")
    print(f"New stored security events: {len(stored_events)}")
    print(f"Generated alerts: {len(alerts)}")
    print()

    for event in stored_events:
        print(f"[NEW EVENT] {event.event_type} user={event.username} ip={event.source_ip}")

    print()

    for alert in alerts:
        print(f"[ALERT] {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Message: {alert['message']}")
        print("-" * 50)


if __name__ == "__main__":
    main()
