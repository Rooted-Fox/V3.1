"""Runs AI triage on the pending-findings queue for one app - the only
step in this tool that spends Anthropic tokens, which is why it's split
out from scanning and only runs when explicitly approved (POST /api/triage
in the UI, not anything scan-related).

Token governance lives here too: if a budget is set in Settings and
already exhausted, triage refuses to start at all. If it gets exhausted
partway through a batch, it stops after the finding in progress rather
than continuing to spend past the limit.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from agents.agent import OwaspAgent
from notifier import notify_new_critical_findings
from pending_store import PendingFindingsStore
from store import FindingsStore
from token_store import TokenStore


class TokenBudgetExceeded(RuntimeError):
    pass


def triage_app(app_name: Optional[str], token_limit: Optional[int]) -> dict:
    pending_store = PendingFindingsStore()
    token_store = TokenStore()
    store = FindingsStore()

    if not token_store.has_budget(token_limit):
        raise TokenBudgetExceeded(
            f"Token budget ({token_limit}) already reached. Raise the limit or reset usage in Settings."
        )

    raw_findings = pending_store.take_for_triage(app_name=app_name)
    by_category = defaultdict(list)
    for finding in raw_findings:
        by_category[finding.category].append(finding)

    triaged = []
    stopped_early = False
    for category, findings in by_category.items():
        if stopped_early:
            break
        agent = OwaspAgent(category)
        for finding in findings:
            if not token_store.has_budget(token_limit):
                stopped_early = True
                break
            result, usage = agent.triage(finding)
            token_store.record(category.value, usage["input_tokens"], usage["output_tokens"])
            store.save(result)
            triaged.append(result)

    notify_new_critical_findings(triaged)

    return {
        "triaged_count": len(triaged),
        "remaining_pending": len(pending_store.pending(app_name=app_name)),
        "stopped_early": stopped_early,
        "tokens_used_total": token_store.total_used(),
    }
