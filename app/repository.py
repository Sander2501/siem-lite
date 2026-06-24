import hashlib

from app.database import SessionLocal
from app.event_model import Event
from app.models import SecurityEvent


def create_log_hash(raw_log: str) -> str:
    return hashlib.sha256(raw_log.encode()).hexdigest()


def save_event(security_event: SecurityEvent) -> Event | None:
    db = SessionLocal()

    try:
        log_hash = create_log_hash(security_event.raw_log)

        existing_event = (
            db.query(Event)
            .filter(Event.log_hash == log_hash)
            .first()
        )

        if existing_event:
            return None

        event = Event(
            event_type=security_event.event_type,
            username=security_event.username,
            source_ip=security_event.source_ip,
            raw_log=security_event.raw_log,
            timestamp=security_event.timestamp,
            severity=security_event.severity,
            log_hash=log_hash,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    finally:
        db.close()


def get_all_events() -> list[Event]:
    db = SessionLocal()

    try:
        return db.query(Event).all()

    finally:
        db.close()


def clear_events() -> None:
    db = SessionLocal()

    try:
        db.query(Event).delete()
        db.commit()

    finally:
        db.close()
