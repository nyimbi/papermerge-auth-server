# (c) Copyright Datacraft, 2026
import os
from typing import Generator
from sqlalchemy import create_engine, Engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession

from auth_server.config import get_settings

settings = get_settings()

engine = create_engine(str(settings.db_url), poolclass=NullPool)

Session = sessionmaker(engine, expire_on_commit=False)


def get_engine() -> Engine:
    return engine


def get_db() -> Generator[SQLAlchemySession, None, None]:
    """FastAPI dependency for database sessions."""
    db = Session()
    try:
        yield db
    finally:
        db.close()
