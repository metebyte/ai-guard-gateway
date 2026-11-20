"""In-memory per-key daily request and token budgets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Callable


def estimate_tokens(text: str) -> int:
    """Rough token count used only for the local budget (about 4 characters each)."""

    if not text:
        return 0
    return (len(text) + 3) // 4


def _seconds_until_utc_midnight(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    midnight = datetime.combine(
        now.date() + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    return max(1, int((midnight - now).total_seconds()))


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str = ""
    retry_after: int = 0


class BudgetStore:
    """Daily counters keyed by gateway key id. State lives in this process only."""

    def __init__(
        self,
        requests_per_day: int,
        tokens_per_day: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if requests_per_day < 0 or tokens_per_day < 0:
            raise ValueError("budgets must be >= 0")
        self.requests_per_day = requests_per_day
        self.tokens_per_day = tokens_per_day
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = Lock()
        self._records: dict[str, dict[str, int | str]] = {}

    def try_consume(self, key_id: str, tokens: int) -> BudgetDecision:
        """Reserve one request and ``tokens`` if both daily caps allow it.

        A denied call leaves the counters unchanged.
        """

        if tokens < 0:
            raise ValueError("tokens must be >= 0")
        with self._lock:
            now = self._clock()
            retry_after = _seconds_until_utc_midnight(now)
            today = now.date().isoformat()
            record = self._records.get(key_id)
            if record is None or record["date"] != today:
                record = {"date": today, "requests": 0, "tokens": 0}
                self._records[key_id] = record
            requests = int(record["requests"])
            used_tokens = int(record["tokens"])
            if requests + 1 > self.requests_per_day:
                return BudgetDecision(False, "requests", retry_after)
            if used_tokens + tokens > self.tokens_per_day:
                return BudgetDecision(False, "tokens", retry_after)
            record["requests"] = requests + 1
            record["tokens"] = used_tokens + tokens
            return BudgetDecision(True)

    def add_tokens(self, key_id: str, tokens: int) -> None:
        """Add completion tokens after the upstream responds."""

        if tokens <= 0:
            return
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                return
            record["tokens"] = int(record["tokens"]) + tokens
