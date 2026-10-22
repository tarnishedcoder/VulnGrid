from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FindingBase(SQLModel):
    tool: str
    title: str
    description: str = ""
    file_path: str = ""
    line: Optional[int] = None
    cve: Optional[str] = None
    cwe: Optional[int] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    severity: Optional[str] = None
    status: str = "new"
    remediation: Optional[str] = None
    tickets: List[str] = Field(default_factory=list, sa_column=Column(JSON))


class Finding(FindingBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: Optional[datetime] = None

    @property
    def risk_score(self) -> float:
        cvss = self.cvss or 0.0
        epss = self.epss or 0.0
        return round(cvss * epss * 10, 2)


class FindingCreate(FindingBase):
    pass


class FindingUpdate(SQLModel):
    tool: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    cve: Optional[str] = None
    cwe: Optional[int] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    remediation: Optional[str] = None
    tickets: Optional[List[str]] = None
