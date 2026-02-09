from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

import discord

from .config import ConfigStore
from .detector import MessageSnapshot, SpamDetector
from .utils import make_event_id

REASON_LABELS = {
    "rapid_posting": "短時間の連投",
    "duplicate_messages": "同文連投",
    "url_spam": "URL乱投",
    "repeated_url_posts": "同一URL連投",
    "mention_spam": "過剰メンション",
    "new_account": "新規アカウント加点",
    "phishing_domain": "フィッシング既知ドメイン",
    "suspicious_domain_tld": "危険TLD",
    "raid_join_surge": "Join急増",
    "raid_activity": "レイド活動",
}

ACTION_LABELS = {
    "none": "未実行",
    "warn": "警告",
    "timeout": "タイムアウト",
    "ban": "BAN",
}

EDITABLE_SECURITY_RULES = {
    "window_sec",
    "max_msg_in_window",
    "duplicate_window_sec",
    "dup_threshold",
    "url_threshold",
    "url_repeat_window_sec",
    "url_repeat_threshold",
    "mention_threshold",
    "score_threshold",
    "timeout_minutes",
    "warning_threshold",
    "timeout_threshold",
    "ban_threshold",
    "offense_window_sec",
    "ban_enabled",
    "raid_join_window_sec",
    "raid_join_threshold",
    "raid_message_window_sec",
    "raid_new_user_message_threshold",
    "new_member_window_sec",
    "log_channel_id",
    "verify_enabled",
    "verify_channel_id",
    "verify_timeout_minutes",
    "verify_max_attempts",
    "verify_fail_action",
    "verify_member_role_id",
}


@dataclass
class ModerationOutcome:
    enforced: bool
    event_id: str | None = None


class SecurityRuntime:
    def __init__(self, config_store: ConfigStore) -> None:
        self.config_store = config_store
        self.detectors: dict[int, SpamDetector] = {}

    def resolve_detector(self, guild_id: int) -> SpamDetector:
        config = self.config_store.get_guild_config(guild_id)
        detector = self.detectors.get(guild_id)
        if detector is None or detector.config is not config:
            detector = SpamDetector(config)
            self.detectors[guild_id] = detector
        return detector

    def format_reason_labels(self, reasons: list[str]) -> str:
        if not reasons:
            return "なし"
        return ", ".join(REASON_LABELS.get(reason, reason) for reason in reasons)

    def format_action_status(self, status: str) -> str:
        mapping = {
            "ok": "成功",
            "forbidden": "権限不足",
            "http_error": "APIエラー",
            "not_supported": "未対応",
            "not_attempted": "未実行",
        }
        return mapping.get(status, status)

    def is_exempt(self, message: discord.Message, config: Any) -> bool:
        if message.channel.id in config.ignore_channel_ids:
            return True
        if message.author.id in config.whitelist_user_ids:
            return True

        author_roles = {role.id for role in getattr(message.author, "roles", [])}
        if author_roles.intersection(config.ignore_role_ids):
            return True
        if author_roles.intersection(config.whitelist_role_ids):
            return True
        return False

    async def perform_action(
        self,
        message: discord.Message,
        action: str,
        timeout_minutes: int,
    ) -> str:
        if action == "none":
            return "not_attempted"

        if action == "warn":
            try:
                await message.channel.send(
                    f"{message.author.mention} スパム/セキュリティ違反を検知しました。"
                )
                return "ok"
            except (discord.Forbidden, discord.HTTPException):
                return "http_error"

        if action == "timeout":
            try:
                await message.author.timeout_for(
                    dt.timedelta(minutes=timeout_minutes),
                    reason="SpamGuard security auto-moderation",
                )
                return "ok"
            except discord.Forbidden:
                return "forbidden"
            except discord.HTTPException:
                return "http_error"
            except AttributeError:
                return "not_supported"

        if action == "ban":
            try:
                await message.guild.ban(
                    message.author,
                    reason="SpamGuard security escalation",
                )
                return "ok"
            except discord.Forbidden:
                return "forbidden"
            except discord.HTTPException:
                return "http_error"

        return "not_attempted"

    async def log_message_event(
        self,
        message: discord.Message,
        score: int,
        reasons: list[str],
        action: str,
        offense_count: int,
        delete_status: str,
        action_status: str,
    ) -> str:
        config = self.config_store.get_guild_config(message.guild.id)
        event_id = make_event_id("SEC")
        if not config.log_channel_id:
            return event_id

        channel = message.guild.get_channel(config.log_channel_id)
        if not channel or not isinstance(channel, discord.TextChannel):
            return event_id

        content_preview = message.content.strip() or "(本文なし)"
        if len(content_preview) > 300:
            content_preview = content_preview[:300] + "..."

        embed = discord.Embed(
            title="Security Event",
            description="自動モデレーションを実行しました。",
            color=discord.Color.red(),
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        avatar_url = message.author.display_avatar.url
        embed.set_author(name=str(message.author), icon_url=avatar_url)
        embed.add_field(name="event_id", value=event_id, inline=False)
        embed.add_field(
            name="対象ユーザー",
            value=f"{message.author.mention}\n`{message.author.id}`",
            inline=True,
        )
        embed.add_field(name="スコア", value=str(score), inline=True)
        embed.add_field(name="違反累積", value=str(offense_count), inline=True)
        embed.add_field(name="理由", value=self.format_reason_labels(reasons), inline=False)
        embed.add_field(name="処分", value=ACTION_LABELS.get(action, action), inline=True)
        embed.add_field(
            name="削除結果",
            value=self.format_action_status(delete_status),
            inline=True,
        )
        embed.add_field(
            name="処分結果",
            value=self.format_action_status(action_status),
            inline=True,
        )
        embed.add_field(name="投稿チャンネル", value=message.channel.mention, inline=True)
        embed.add_field(name="投稿内容(先頭300文字)", value=content_preview, inline=False)

        try:
            await channel.send(embed=embed)
        except (discord.Forbidden, discord.HTTPException):
            return event_id

        return event_id

    async def log_verification_event(
        self,
        guild: discord.Guild,
        member: discord.Member,
        phase: str,
        status: str,
        detail: str,
    ) -> str:
        config = self.config_store.get_guild_config(guild.id)
        event_id = make_event_id("VER")
        if not config.log_channel_id:
            return event_id

        channel = guild.get_channel(config.log_channel_id)
        if not channel or not isinstance(channel, discord.TextChannel):
            return event_id

        embed = discord.Embed(
            title="Verification Event",
            description="入室認証フローイベント",
            color=discord.Color.blue(),
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        embed.add_field(name="event_id", value=event_id, inline=False)
        embed.add_field(name="フェーズ", value=phase, inline=True)
        embed.add_field(name="結果", value=self.format_action_status(status), inline=True)
        embed.add_field(name="対象", value=f"{member.mention}\n`{member.id}`", inline=True)
        embed.add_field(name="詳細", value=detail[:1000], inline=False)

        try:
            await channel.send(embed=embed)
        except (discord.Forbidden, discord.HTTPException):
            return event_id

        return event_id

    async def handle_message(self, message: discord.Message) -> ModerationOutcome:
        config = self.config_store.get_guild_config(message.guild.id)
        if self.is_exempt(message, config):
            return ModerationOutcome(enforced=False)

        detector = self.resolve_detector(message.guild.id)
        now = dt.datetime.now(dt.timezone.utc)
        snapshot = MessageSnapshot(
            user_id=message.author.id,
            content=message.content,
            mention_count=len(message.mentions),
            created_at=now,
            account_created_at=message.author.created_at,
            joined_at=getattr(message.author, "joined_at", None),
        )
        result = detector.score(snapshot)

        force_reasons = {"phishing_domain", "raid_activity"}
        should_enforce = result.score >= config.score_threshold or bool(
            force_reasons.intersection(result.reasons)
        )
        if not should_enforce:
            return ModerationOutcome(enforced=False)

        decision = detector.decide_enforcement(message.author.id, now)
        delete_status = "not_attempted"
        try:
            await message.delete()
            delete_status = "ok"
        except discord.Forbidden:
            delete_status = "forbidden"
        except discord.HTTPException:
            delete_status = "http_error"

        action_status = await self.perform_action(
            message,
            decision.action,
            config.timeout_minutes,
        )

        event_id = await self.log_message_event(
            message=message,
            score=result.score,
            reasons=result.reasons,
            action=decision.action,
            offense_count=decision.offense_count,
            delete_status=delete_status,
            action_status=action_status,
        )
        return ModerationOutcome(enforced=True, event_id=event_id)
