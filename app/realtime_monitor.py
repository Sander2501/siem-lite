import time
from pathlib import Path

from app.database import Base, engine
from app.log_parser import parse_log_line
from app.repository import save_event


def follow_log_file(path: str):
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with open(log_path, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            yield line


def main():
    Base.metadata.create_all(bind=engine)

    log_file = "/var/log/auth.log"

    print("=" * 50)
    print("SIEM Lite Real-Time Monitor")
    print("=" * 50)
    print(f"Watching: {log_file}")
    print("Press CTRL+C to stop.")
    print()

    for line in follow_log_file(log_file):
        event = parse_log_line(line)

        if event is None:
            continue

        saved_event = save_event(event)

        if saved_event:
            print(
                f"[NEW EVENT] {event.event_type} "
                f"user={event.username} ip={event.source_ip}"
            )


if __name__ == "__main__":
    main()
