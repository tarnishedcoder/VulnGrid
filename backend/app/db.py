import os
from pathlib import Path
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

SQLITE_FILE = os.getenv("SQLITE_FILE", "/app/db/sqlite.db")


def _ensure_parent(path: str) -> None:
    parent = str(Path(path).parent)
    if parent and parent not in ("", "."):
        Path(parent).mkdir(parents=True, exist_ok=True)


_ensure_parent(SQLITE_FILE)
engine = create_engine(f"sqlite:///{SQLITE_FILE}", echo=False, connect_args={"check_same_thread": False})


def create_db_and_tables() -> None:
    _ensure_parent(SQLITE_FILE)
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
