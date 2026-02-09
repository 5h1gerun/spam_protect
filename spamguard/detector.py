from __future__ import annotations

import collections
import datetime as dt
import re
from dataclasses import dataclass

from .config import SpamGuardConfig

URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
WS_RE = re.compile(r"\s+")


@dataclass
class MessageSnapshot:
    user_id: int
    content: str
    mention_count: int
    created_at: dt.datetime
    account_created_at: dt.datetime


@dataclass
class ScoringResult:
    score: int
    reasons: list[str]


class SpamDetector:
    def __init__(self, config: SpamGuardConfig) -> None:
        self.config = config
        self.user_messages: dict[int, collections.deque[dt.datetime]] = collections.defaultdict(collections.deque)
        self.user_duplicates: dict[int, collections.deque[tuple[dt.datetime, str]]] = collections.defaultdict(collections.deque)
        self.user_urls: dict[int, collections.deque[tuple[dt.datetime, str]]] = collections.defaultdict(collections.deque)

    def _normalize(self, content: str) -> str:
        normalized = content.strip().lower()
        normalized = WS_RE.sub(" ", normalized)
        return normalized

    def score(self, snapshot: MessageSnapshot) -> ScoringResult:
        now = snapshot.created_at
        score = 0
        reasons: list[str] = []

        self._prune(snapshot.user_id, now)

        msg_history = self.user_messages[snapshot.user_id]
        dup_history = self.user_duplicates[snapshot.user_id]
        url_history = self.user_urls[snapshot.user_id]

        msg_history.append(now)
        normalized = self._normalize(snapshot.content)
        dup_history.append((now, normalized))

        if len(msg_history) >= self.config.max_msg_in_window:
            score += 2
            reasons.append("rapid_posting")

        dup_count = sum(1 for _, text in dup_history if text and text == normalized)
        if normalized and dup_count >= self.config.dup_threshold:
            score += 3
            reasons.append("duplicate_messages")

        url_count = len(URL_RE.findall(snapshot.content))
        if url_count >= self.config.url_threshold:
            score += 3
            reasons.append("url_spam")
        urls = [url.lower() for url in URL_RE.findall(snapshot.content)]
        for url in urls:
            url_history.append((now, url))
        if urls:
            for url in set(urls):
                repeated = sum(1 for _, seen_url in url_history if seen_url == url)
                if repeated >= self.config.url_repeat_threshold:
                    score += 3
                    reasons.append("repeated_url_posts")
                    break

        if snapshot.mention_count >= self.config.mention_threshold:
            score += 3
            reasons.append("mention_spam")

        account_age = now - snapshot.account_created_at
        if account_age < dt.timedelta(hours=24):
            score += 1
            reasons.append("new_account")

        return ScoringResult(score=score, reasons=reasons)

    def _prune(self, user_id: int, now: dt.datetime) -> None:
        msg_cutoff = now - dt.timedelta(seconds=self.config.window_sec)
        dup_cutoff = now - dt.timedelta(seconds=self.config.duplicate_window_sec)
        url_cutoff = now - dt.timedelta(seconds=self.config.url_repeat_window_sec)

        msg_history = self.user_messages[user_id]
        while msg_history and msg_history[0] < msg_cutoff:
            msg_history.popleft()

        dup_history = self.user_duplicates[user_id]
        while dup_history and dup_history[0][0] < dup_cutoff:
            dup_history.popleft()

        url_history = self.user_urls[user_id]
        while url_history and url_history[0][0] < url_cutoff:
            url_history.popleft()
