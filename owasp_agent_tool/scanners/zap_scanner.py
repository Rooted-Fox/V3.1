"""DAST scanner: drives an existing OWASP ZAP instance against a live URL.

This wrapper only calls ZAP's documented REST API to spider a target, run
an active scan, and read back alerts plus the underlying HTTP request and
response for each one. It assumes ZAP is already running in daemon mode
and pointed at infrastructure you own and are authorized to test - never
point this at a target outside your own environment.
"""
from __future__ import annotations

import time
from typing import List, Optional

import requests

from models import OwaspCategory, RawFinding
from runtime_settings import get_settings
from scanners.base import BaseScanner

_RISK_TO_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

_ALERT_KEYWORDS = {
    OwaspCategory.A10_SSRF: ["server side request forgery", "ssrf"],
    OwaspCategory.A07_AUTH_FAILURES: ["authentication", "session"],
    OwaspCategory.A01_ACCESS_CONTROL: ["access control", "path traversal"],
    OwaspCategory.A03_INJECTION: ["sql injection", "cross site scripting", "command injection"],
    OwaspCategory.A02_CRYPTO_FAILURES: ["tls", "ssl", "certificate", "weak cipher"],
    OwaspCategory.A06_VULNERABLE_COMPONENTS: ["outdated", "known vulnerable", "deprecated"],
}


def _infer_category(alert_name: str) -> OwaspCategory:
    lowered = alert_name.lower()
    for category, keywords in _ALERT_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return category
    return OwaspCategory.A05_MISCONFIGURATION


class ZapScanner(BaseScanner):
    """Targets a live URL - configured at construction, not per scan() call."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        rt = get_settings()
        self.base = rt["zap_api_url"]
        self.params = {"apikey": rt["zap_api_key"]}

    def _get(self, path: str, **extra_params):
        response = requests.get(f"{self.base}{path}", params={**self.params, **extra_params}, timeout=30)
        response.raise_for_status()
        return response.json()

    def _message_context(self, message_id: Optional[str]) -> str:
        """Pull the actual HTTP request/response for an alert, so the agent
        reviews real traffic instead of just a one-line description."""
        if not message_id:
            return ""
        try:
            msg = self._get("/JSON/core/view/message/", id=message_id).get("message", {})
        except requests.RequestException:
            return ""
        request_part = f"{msg.get('requestHeader', '')}\n{msg.get('requestBody', '')}"
        response_part = f"{msg.get('responseHeader', '')}\n{msg.get('responseBody', '')}"
        combined = f"--- request ---\n{request_part}\n--- response ---\n{response_part}"
        return combined[:2000]

    def scan(self) -> List[RawFinding]:
        self._get("/JSON/spider/action/scan/", url=self.target_url)
        while int(self._get("/JSON/spider/view/status/")["status"]) < 100:
            time.sleep(2)

        scan_id = self._get("/JSON/ascan/action/scan/", url=self.target_url)["scan"]
        while int(self._get("/JSON/ascan/view/status/", scanId=scan_id)["status"]) < 100:
            time.sleep(5)

        alerts = self._get("/JSON/core/view/alerts/", baseurl=self.target_url).get("alerts", [])
        findings: List[RawFinding] = []
        for alert in alerts:
            evidence = self._message_context(alert.get("messageId")) or alert.get("evidence", "")
            findings.append(
                RawFinding(
                    tool="zap",
                    category=_infer_category(alert.get("alert", "")),
                    title=alert.get("alert", "zap finding"),
                    url=alert.get("url"),
                    raw_severity=_RISK_TO_SEVERITY.get(alert.get("risk"), "low"),
                    description=alert.get("description", ""),
                    evidence=evidence,
                )
            )
        return findings
