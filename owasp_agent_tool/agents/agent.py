"""The OwaspAgent: takes one raw DAST finding for one category and produces
a triaged, remediation-drafted finding using Claude - this is the only
place in the codebase that calls the Anthropic API, and every call's token
usage is returned alongside the result so the caller can log it."""
from __future__ import annotations

import json

import anthropic

from agents.prompts import PROMPTS
from knowledge import AppKnowledge
from models import OwaspCategory, RawFinding, TriagedFinding
from runtime_settings import get_settings


class OwaspAgent:
    def __init__(self, category: OwaspCategory, knowledge: AppKnowledge | None = None):
        self.category = category
        self.knowledge = knowledge or AppKnowledge()
        self.system_prompt = PROMPTS[category]
        context_block = self.knowledge.for_category(category)
        if context_block:
            self.system_prompt = f"{self.system_prompt}\n\n{context_block}"
        rt = get_settings()
        self.model = rt["agent_model"]
        self.client = anthropic.Anthropic(api_key=rt["anthropic_api_key"])

    def triage(self, finding: RawFinding) -> tuple[TriagedFinding, dict]:
        """Returns (triaged_finding, token_usage) - token_usage is
        {"input_tokens": int, "output_tokens": int} straight from the
        Anthropic response, for the caller to log against the budget."""
        user_message = (
            f"Tool: {finding.tool}\n"
            f"Title: {finding.title}\n"
            f"URL: {finding.url}\n"
            f"Scanner severity: {finding.raw_severity}\n"
            f"Description: {finding.description}\n\n"
            f"HTTP request/response evidence:\n{finding.evidence}"
        )
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=self.system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        parsed = json.loads(text)
        result = TriagedFinding(
            tool=finding.tool,
            category=finding.category,
            title=finding.title,
            url=finding.url,
            app_name=finding.app_name or "unspecified",
            severity=parsed["severity"],
            exploitable=parsed["exploitable"],
            rationale=parsed["rationale"],
            remediation=parsed.get("remediation"),
        )
        usage = {
            "input_tokens": getattr(response.usage, "input_tokens", 0),
            "output_tokens": getattr(response.usage, "output_tokens", 0),
        }
        return result, usage
