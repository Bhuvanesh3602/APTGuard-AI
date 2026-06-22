from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models.report import CertInReport, CertInReportRequest
from app.services.reporter import CertInReporter

router = APIRouter(prefix="/api/v1/report")
_reporter = CertInReporter()


@router.post("/submit", response_model=CertInReport)
async def submit_report(req: CertInReportRequest) -> CertInReport:
    """Generate and submit a CERT-In mandatory incident report."""
    return _reporter.generate_report(req)


@router.get("/list", response_model=list[CertInReport])
async def list_reports() -> list[CertInReport]:
    """List all generated CERT-In reports."""
    return _reporter.list_reports()


@router.get("/{report_id}", response_model=CertInReport)
async def get_report(report_id: str) -> CertInReport:
    """Retrieve a specific CERT-In report by ID."""
    report = _reporter.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return report


@router.get("/overdue/list", response_model=list[CertInReport])
async def get_overdue_reports() -> list[CertInReport]:
    """List all reports that have breached the 6-hour CERT-In deadline."""
    return _reporter.get_overdue_reports()
