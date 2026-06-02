"""
services/ — thin application service layer.

Each service encapsulates a domain's business logic and shields API routes from
direct dependency on scanner/agent classes.  Routes call services; services
call the domain objects.  No business logic belongs in route handlers.

Available services:
  ScanService         — orchestrates all security scanners
  RemediationService  — patch generation and findings triage
  ReportService       — report formatting and export
"""
from services.scan_service import ScanService
from services.remediation_service import RemediationService
from services.report_service import ReportService

__all__ = ["ScanService", "RemediationService", "ReportService"]
