from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from ..db import get_session
from ..models.finding import Finding, FindingCreate, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("/", response_model=Finding, status_code=201)
def create_finding(finding: FindingCreate, session: Session = Depends(get_session)):
    db_finding = Finding.model_validate(finding)
    session.add(db_finding)
    session.commit()
    session.refresh(db_finding)
    return db_finding


@router.post("/bulk", response_model=List[Finding], status_code=201)
def create_findings_bulk(findings: List[FindingCreate], session: Session = Depends(get_session)):
    created: List[Finding] = []
    for item in findings:
        db_finding = Finding.model_validate(item)
        session.add(db_finding)
        created.append(db_finding)
    session.commit()
    for obj in created:
        session.refresh(obj)
    return created


@router.get("/", response_model=List[Finding])
def list_findings(
    session: Session = Depends(get_session),
    tool: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    min_cvss: Optional[float] = Query(default=None),
    min_epss: Optional[float] = Query(default=None),
):
    stmt = select(Finding)
    if tool:
        stmt = stmt.where(Finding.tool == tool)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    findings = list(session.exec(stmt).all())
    if min_cvss is not None:
        findings = [f for f in findings if (f.cvss or 0) >= min_cvss]
    if min_epss is not None:
        findings = [f for f in findings if (f.epss or 0) >= min_epss]
    return findings


@router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    db_finding = session.get(Finding, finding_id)
    if not db_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return db_finding


@router.patch("/{finding_id}", response_model=Finding)
def update_finding(finding_id: int, payload: FindingUpdate, session: Session = Depends(get_session)):
    db_finding = session.get(Finding, finding_id)
    if not db_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(db_finding, key, value)
    db_finding.updated_at = datetime.now(timezone.utc)
    session.add(db_finding)
    session.commit()
    session.refresh(db_finding)
    return db_finding


@router.delete("/{finding_id}", status_code=204)
def delete_finding(finding_id: int, session: Session = Depends(get_session)):
    db_finding = session.get(Finding, finding_id)
    if not db_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    session.delete(db_finding)
    session.commit()
    return None
