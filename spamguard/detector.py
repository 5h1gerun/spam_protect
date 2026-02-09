from __future__ import annotations

import collections
import datetime as dt
import re
from dataclasses import dataclass
from urllib.parse import urlparse

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
    joined_at: dt.datetime | None = None


@dataclass
class ScoringResult:
    score: int
    reasons: list[str]


@dataclass
class EnforcementDecision:
    offense_count: int
    action: str


class SpamDetector:
    def __init__(self, config: SpamGuardConfig) -> None:
        self.config = config
        self.user_messages: dict[int, collections.deque[dt.datetime]] = collections.defaultdict(
            collections.deque
        )
        self.user_duplicates: dict[int, collections.deque[tuple[dt.datetime, str]]] = collections.defaultdict(
            collections.deque
        )
        self.user_urls: dict[int, collections.deque[tuple[dt.datetime, str]]] = collections.defaultdict(
            collections.deque
        )
        self.user_offenses: dict[int, collections.deque[dt.datetime]] = collections.defaultdict(
            collections.deque
        )
        self.recent_joins: collections.deque[tuple[dt.datetime, int]] = collections.deque()
        self.recent_new_user_messages: collections.deque[dt.datetime] = collections.deque()

    def register_join(self, user_id: int, joined_at: dt.datetime) -> None:
        self.recent_joins.append((joined_at, user_id))
        self._prune_joins(joined_at)

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

        urls = [url.lower() for url in URL_RE.findall(snapshot.content)]
        if len(urls) >= self.config.url_threshold:
            score += 3
            reasons.append("url_spam")

        for url in urls:
            url_history.append((now, url))

        if urls:
            for url in set(urls):
                repeated = sum(1 for _, seen_url in url_history if seen_url == url)
                if repeated >= self.config.url_repeat_threshold:
                    score += 3
                    reasons.append("repeated_url_posts")
                    break

            phishing_score, phishing_reasons = self._score_url_risk(urls)
            score += phishing_score
            reasons.extend(phishing_reasons)

        if snapshot.mention_count >= self.config.mention_threshold:
            score += 3
            reasons.append("mention_spam")

        account_age = now - snapshot.account_created_at
        if account_age < dt.timedelta(hours=24):
            score += 1
            reasons.append("new_account")

        if self._is_recent_join(snapshot, now):
            self.recent_new_user_messages.append(now)
        if self._is_raid_active(now):
            score += 2
            reasons.append("raid_join_surge")
            if (
                len(self.recent_new_user_messages)
                >= self.config.raid_new_user_message_threshold
            ):
                score += 5
                reasons.append("raid_activity")

        return ScoringResult(score=score, reasons=self._dedupe(reasons))

    def decide_enforcement(self, user_id: int, now: dt.datetime) -> EnforcementDecision:
        history = self.user_offenses[user_id]
        cutoff = now - dt.timedelta(seconds=self.config.offense_window_sec)
        while history and history[0] < cutoff:
            history.popleft()

        history.append(now)
        count = len(history)

        action = "warn"
        if self.config.ban_enabled and count >= self.config.ban_threshold:
            action = "ban"
        elif count >= self.config.timeout_threshold:
            action = "timeout"
        elif count < self.config.warning_threshold:
            action = "none"

        return EnforcementDecision(offense_count=count, action=action)

    def _normalize(self, content: str) -> str:
        normalized = content.strip().lower()
        normalized = WS_RE.sub(" ", normalized)
        return normalized

    def _score_url_risk(self, urls: list[str]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        blocked = {domain.lower() for domain in self.config.phishing_domains}
        allowed = {domain.lower() for domain in self.config.allow_domains}
        suspicious_tlds = {tld.lower().lstrip(".") for tld in self.config.suspicious_tlds}

        for url in urls:
            host = self._extract_host(url)
            if not host:
                continue
            if host in allowed:
                continue
            if host in blocked:
                score += 8
                reasons.append("phishing_domain")
                continue

            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in suspicious_tlds:
                score += 4
                reasons.append("suspicious_domain_tld")

        return score, reasons

    def _extract_host(self, url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        return host

    def _is_recent_join(self, snapshot: MessageSnapshot, now: dt.datetime) -> bool:
        if not snapshot.joined_at:
            return False
        return (now - snapshot.joined_at) <= dt.timedelta(
            seconds=self.config.new_member_window_sec
        )

    def _is_raid_active(self, now: dt.datetime) -> bool:
        self._prune_joins(now)
        self._prune_new_user_messages(now)
        return len(self.recent_joins) >= self.config.raid_join_threshold

    def _prune_joins(self, now: dt.datetime) -> None:
        join_cutoff = now - dt.timedelta(seconds=self.config.raid_join_window_sec)
        while self.recent_joins and self.recent_joins[0][0] < join_cutoff:
            self.recent_joins.popleft()

    def _prune_new_user_messages(self, now: dt.datetime) -> None:
        message_cutoff = now - dt.timedelta(seconds=self.config.raid_message_window_sec)
        while (
            self.recent_new_user_messages
            and self.recent_new_user_messages[0] < message_cutoff
        ):
            self.recent_new_user_messages.popleft()

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

    def _dedupe(self, reasons: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for reason in reasons:
            if reason in seen:
                continue
            seen.add(reason)
            out.append(reason)
        return out
