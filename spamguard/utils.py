from __future__ import annotations

import datetime as dt
import uuid
from typing import Any


def parse_value(current: Any, raw: str) -> Any:
    if isinstance(current, bool):
        return raw.lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int):
        return int(raw)
    if current is None:
        lowered = raw.lower()
        if lowered in {"none", "null"}:
            return None
        return int(raw)
    return raw


def make_event_id(prefix: str = "SEC") -> str:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = uuid.uuid4().hex[:6]
    return f"{prefix}-{now}-{suffix}"
