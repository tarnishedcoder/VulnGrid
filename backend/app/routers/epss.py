from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models.finding import Finding

router = APIRouter(prefix="/epss", tags=["epss"])


class EpssUpsert(BaseModel):
    cve: str
    epss: float


@router.post("/", status_code=201)
def upsert_epss(payload: EpssUpsert, session: Session = Depends(get_session)):
    """Attach an EPSS score to every finding with this CVE.

    Returns the number of findings updated. If no finding exists yet the
    score is accepted (count 0) so nightly syncs never fail on empty DBs.
    """
    stmt = select(Finding).where(Finding.cve == payload.cve)
    rows: List[Finding] = list(session.exec(stmt).all())
    for row in rows:
        row.epss = float(payload.epss)
        session.add(row)
    session.commit()
    return {"cve": payload.cve, "epss": payload.epss, "updated": len(rows)}


@router.get("/{cve}", response_model=float)
def get_epss(cve: str, session: Session = Depends(get_session)):
    stmt = select(Finding).where(Finding.cve == cve)
    row = session.exec(stmt).first()
    if not row or row.epss is None:
        raise HTTPException(status_code=404, detail="EPSS not found for this CVE")
    return float(row.epss)
