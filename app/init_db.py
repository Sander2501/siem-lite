from app.database import Base
from app.database import engine
from app.event_model import Event


def create_database():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    create_database()
