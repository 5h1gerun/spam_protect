import datetime as dt

from spamguard.config import SpamGuardConfig
from spamguard.detector import MessageSnapshot, SpamDetector


def build_snapshot(user_id: int, now: dt.datetime, content: str, mentions: int = 0, age_hours: int = 48) -> MessageSnapshot:
    return MessageSnapshot(
        user_id=user_id,
        content=content,
        mention_count=mentions,
        created_at=now,
        account_created_at=now - dt.timedelta(hours=age_hours),
    )


def test_rapid_posting_scores_after_threshold() -> None:
    detector = SpamDetector(SpamGuardConfig(max_msg_in_window=3, window_sec=12))
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    detector.score(build_snapshot(1, base, "a"))
    detector.score(build_snapshot(1, base + dt.timedelta(seconds=2), "b"))
    result = detector.score(build_snapshot(1, base + dt.timedelta(seconds=4), "c"))

    assert result.score >= 2
    assert "rapid_posting" in result.reasons


def test_duplicate_detection_scores() -> None:
    detector = SpamDetector(SpamGuardConfig(dup_threshold=3, duplicate_window_sec=120))
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    detector.score(build_snapshot(2, base, "same"))
    detector.score(build_snapshot(2, base + dt.timedelta(seconds=10), "same"))
    result = detector.score(build_snapshot(2, base + dt.timedelta(seconds=20), "same"))

    assert result.score >= 3
    assert "duplicate_messages" in result.reasons


def test_url_mention_and_new_account_combined() -> None:
    detector = SpamDetector(
        SpamGuardConfig(url_threshold=2, mention_threshold=4, score_threshold=6)
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    result = detector.score(
        build_snapshot(
            3,
            now,
            "https://a.example https://b.example",
            mentions=4,
            age_hours=1,
        )
    )

    assert result.score == 7
    assert "url_spam" in result.reasons
    assert "mention_spam" in result.reasons
    assert "new_account" in result.reasons


def test_repeated_url_posts_scores() -> None:
    detector = SpamDetector(
        SpamGuardConfig(
            url_threshold=2,
            url_repeat_threshold=3,
            url_repeat_window_sec=120,
        )
    )
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    detector.score(build_snapshot(9, base, "https://spam.example"))
    detector.score(
        build_snapshot(9, base + dt.timedelta(seconds=5), "text https://spam.example")
    )
    result = detector.score(
        build_snapshot(9, base + dt.timedelta(seconds=10), "https://spam.example")
    )

    assert result.score >= 3
    assert "repeated_url_posts" in result.reasons


def test_phishing_domain_is_high_risk() -> None:
    detector = SpamDetector(
        SpamGuardConfig(phishing_domains=["login-discord-security.example"])
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    result = detector.score(
        build_snapshot(20, now, "https://login-discord-security.example/path")
    )

    assert result.score >= 8
    assert "phishing_domain" in result.reasons


def test_suspicious_tld_detection() -> None:
    detector = SpamDetector(SpamGuardConfig(suspicious_tlds=["zip"]))
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    result = detector.score(build_snapshot(21, now, "https://safe-looking.zip"))

    assert result.score >= 4
    assert "suspicious_domain_tld" in result.reasons


def test_raid_detection_from_join_surge_and_new_user_posts() -> None:
    detector = SpamDetector(
        SpamGuardConfig(
            raid_join_window_sec=30,
            raid_join_threshold=3,
            raid_message_window_sec=30,
            raid_new_user_message_threshold=2,
            new_member_window_sec=1800,
        )
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    detector.register_join(101, now)
    detector.register_join(102, now + dt.timedelta(seconds=2))
    detector.register_join(103, now + dt.timedelta(seconds=4))

    detector.score(
        MessageSnapshot(
            user_id=101,
            content="hi",
            mention_count=0,
            created_at=now + dt.timedelta(seconds=5),
            account_created_at=now - dt.timedelta(days=3),
            joined_at=now,
        )
    )
    result = detector.score(
        MessageSnapshot(
            user_id=102,
            content="raid",
            mention_count=0,
            created_at=now + dt.timedelta(seconds=6),
            account_created_at=now - dt.timedelta(days=3),
            joined_at=now + dt.timedelta(seconds=2),
        )
    )

    assert "raid_join_surge" in result.reasons
    assert "raid_activity" in result.reasons


def test_enforcement_escalates_warn_timeout_ban() -> None:
    detector = SpamDetector(
        SpamGuardConfig(
            warning_threshold=1,
            timeout_threshold=2,
            ban_threshold=3,
            ban_enabled=True,
            offense_window_sec=3600,
        )
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    first = detector.decide_enforcement(user_id=10, now=now)
    second = detector.decide_enforcement(user_id=10, now=now + dt.timedelta(minutes=1))
    third = detector.decide_enforcement(user_id=10, now=now + dt.timedelta(minutes=2))

    assert first.action == "warn"
    assert second.action == "timeout"
    assert third.action == "ban"
