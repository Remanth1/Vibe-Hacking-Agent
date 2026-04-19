"""
Pydantic data models shared across the entire application.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ── Enumerations ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


# ── Sub-models ────────────────────────────────────────────────────────────────

class ScopeConfig(BaseModel):
    """Defines what is in/out of scope for the assessment."""
    targets: List[str]
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_hours: Optional[str] = None   # e.g. "09:00-17:00 UTC"
    test_intensity: str = "low"           # low | medium | high
    active_testing: bool = False
    authorization_note: str = ""          # free-text e.g. "I own this domain"


class Finding(BaseModel):
    """A single security finding discovered during the assessment."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity
    confidence: Confidence
    affected_asset: str
    title: str
    description: str
    evidence: str
    remediation: str
    timestamp: datetime = Field(default_factory=_utcnow)


class AuditEntry(BaseModel):
    """One entry in the immutable audit trail."""
    timestamp: datetime = Field(default_factory=_utcnow)
    agent: str
    action: str
    command: Optional[str] = None
    output: Optional[str] = None


class AssetInventory(BaseModel):
    """Aggregated asset information collected by the Recon Agent."""
    hosts: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    open_ports: Dict[str, List[int]] = Field(default_factory=dict)
    dns_records: Dict[str, Any] = Field(default_factory=dict)
    tls_info: Dict[str, Any] = Field(default_factory=dict)
    http_headers: Dict[str, Any] = Field(default_factory=dict)
    robots_txt: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


# ── Top-level run result ──────────────────────────────────────────────────────

class RunResult(BaseModel):
    """Complete result of one assessment run, persisted to disk as JSON."""
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    scope: ScopeConfig
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.PENDING
    error: Optional[str] = None
    asset_inventory: AssetInventory = Field(default_factory=AssetInventory)
    findings: List[Finding] = Field(default_factory=list)
    audit_log: List[AuditEntry] = Field(default_factory=list)
    report_path: Optional[str] = None
    executive_summary: str = ""

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_audit(
        self,
        agent: str,
        action: str,
        command: Optional[str] = None,
        output: Optional[str] = None,
    ) -> None:
        self.audit_log.append(
            AuditEntry(agent=agent, action=action, command=command, output=output)
        )
