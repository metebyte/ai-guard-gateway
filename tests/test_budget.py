"""Daily budget store."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from aiguard.budget import BudgetStore, estimate_tokens


def test_estimate_tokens_scales_with_length():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 40) == 10


def test_request_cap_blocks_without_consuming():
    store = BudgetStore(1, 100)
    assert store.try_consume("alpha", 10).allowed
    denied = store.try_consume("alpha", 10)
    assert denied.allowed is False
    assert denied.reason == "requests"
    assert denied.retry_after >= 1
    assert store.try_consume("beta", 10).allowed


def test_token_cap_blocks_without_consuming():
    store = BudgetStore(10, 20)
    denied = store.try_consume("alpha", 21)
    assert denied.reason == "tokens"
    assert store.try_consume("alpha", 20).allowed
    store.add_tokens("alpha", 1)
    assert store.try_consume("alpha", 1).reason == "tokens"


def test_budget_resets_on_the_next_utc_day():
    now = datetime(2026, 11, 20, 23, 30, tzinfo=timezone.utc)
    clock = {"now": now}
    store = BudgetStore(1, 100, clock=lambda: clock["now"])
    assert store.try_consume("alpha", 5).allowed
    assert store.try_consume("alpha", 5).allowed is False
    clock["now"] = now + timedelta(hours=2)
    assert store.try_consume("alpha", 5).allowed


def test_completion_tokens_count_toward_the_same_day():
    store = BudgetStore(10, 30)
    assert store.try_consume("alpha", 20).allowed
    store.add_tokens("alpha", 10)
    assert store.try_consume("alpha", 1).reason == "tokens"


def test_concurrent_requests_stop_at_the_cap():
    store = BudgetStore(400, 10_000_000)
    errors: list[str] = []

    def worker() -> None:
        for _ in range(50):
            if not store.try_consume("same", 1).allowed:
                errors.append("denied")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert store.try_consume("same", 1).allowed is False
