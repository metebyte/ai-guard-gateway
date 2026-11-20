"""JSON-lines audit log. Records types and counts, never raw personal data."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from aiguard.pii import ordered_counts


def key_id_for(api_key: str) -> str:
    """Stable id for a gateway credential. The raw key is not recoverable from it."""

    if not api_key:
        return "anonymous"
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    return f"key_{digest}"


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = Lock()

    def write(self, *, key_id: str, endpoint: str, pii_counts: dict[str, int], status: int) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "key_id": key_id,
            "endpoint": endpoint,
            "pii": ordered_counts(pii_counts),
            "status": status,
        }
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
