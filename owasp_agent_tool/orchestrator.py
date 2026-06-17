"""Runs the DAST scan and stamps every finding with an app name. This is
deliberately the only thing a scan does - it never touches the Anthropic
API, so no API key is required to run it. AI triage is a separate,
explicitly approved step - see triage_runner.py.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

from models import RawFinding
from pending_store import PendingFindingsStore
from scanners.zap_scanner import ZapScanner


def _default_app_name(target_url: str) -> str:
    """Falls back to the hostname when no app name is given explicitly."""
    return urlparse(target_url).hostname or target_url


class Orchestrator:
    def __init__(self, target_url: str, app_name: Optional[str] = None):
        self.target_url = target_url
        self.app_name = app_name or _default_app_name(target_url)
        self.pending_store = PendingFindingsStore()
        self.scanner = ZapScanner(target_url)

    def scan(self) -> List[RawFinding]:
        """Spiders + actively scans target_url, tags every finding with
        app_name, and queues them for triage. No Claude calls happen here."""
        findings = self.scanner.scan()
        for finding in findings:
            finding.app_name = self.app_name
        self.pending_store.save_many(findings)
        return findings
