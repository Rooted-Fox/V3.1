"""Shared data models for findings flowing through the pipeline."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class OwaspCategory(str, Enum):
    A01_ACCESS_CONTROL = "A01:broken_access_control"
    A02_CRYPTO_FAILURES = "A02:cryptographic_failures"
    A03_INJECTION = "A03:injection"
    A04_INSECURE_DESIGN = "A04:insecure_design"
    A05_MISCONFIGURATION = "A05:security_misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:vulnerable_components"
    A07_AUTH_FAILURES = "A07:auth_failures"
    A08_INTEGRITY_FAILURES = "A08:integrity_failures"
    A09_LOGGING_FAILURES = "A09:logging_failures"
    A10_SSRF = "A10:ssrf"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    PATCHED = "patched"
    DISMISSED = "dismissed"


class RawFinding(BaseModel):
    """A finding straight out of the DAST scanner, before agent triage."""

    tool: str
    category: OwaspCategory
    title: str
    url: Optional[str] = None
    app_name: Optional[str] = None  # stamped by the orchestrator, not the scanner
    raw_severity: Optional[str] = None
    description: str = ""
    evidence: str = ""  # HTTP request/response context from the live scan


class TriagedFinding(BaseModel):
    """A finding after an OWASP agent has reviewed it."""

    id: Optional[int] = None
    tool: str
    category: OwaspCategory
    title: str
    url: Optional[str] = None
    app_name: str = "unspecified"
    severity: Severity
    exploitable: bool
    rationale: str
    remediation: Optional[str] = None  # guidance on how to fix it
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
