from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String

from app.database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String)
    username = Column(String)
    source_ip = Column(String)
    raw_log = Column(String)
    timestamp = Column(String)
    severity = Column(String)
    log_hash = Column(String, unique=True, index=True)
