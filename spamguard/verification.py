from __future__ import annotations

import asyncio
import datetime as dt
import secrets
from dataclasses import dataclass

import discord
from discord.ext import commands

from .config import ConfigStore, SpamGuardConfig
from .security_runtime import SecurityRuntime


@dataclass
class VerificationSession:
    guild_id: int
    user_id: int
    code: str
    expires_at: dt.datetime
    attempts: int = 0


class VerificationManager:
    PERMISSION_RETRY_DELAY_SECONDS = 120

    def __init__(
        self,
        bot: commands.Bot,
        config_store: ConfigStore,
        security_runtime: SecurityRuntime,
    ) -> None:
        self.bot = bot
        self.config_store = config_store
        self.security_runtime = security_runtime
        self.sessions: dict[tuple[int, int], VerificationSession] = {}
        self.timeout_tasks: dict[tuple[int, int], asyncio.Task[None]] = {}

    async def handle_member_join(self, member: discord.Member) -> None:
        if member.bot:
            return
        if member.guild_permissions.administrator:
            return
        if member.guild_permissions.manage_guild:
            return

        config = self.config_store.get_guild_config(member.guild.id)
        if not config.verify_enabled:
            return

        if member.id in config.whitelist_user_ids:
            return

        unverified_role = await self.ensure_unverified_role(member.guild, config)
        verified_role = await self.ensure_verified_role(member.guild, config)
        verify_channel = await self.ensure_verify_channel(member.guild, config)
        if verify_channel:
            await self.ensure_member_verify_access(member, verify_channel)

        isolation_detail = "未実施"
        if unverified_role:
            try:
                if verified_role and verified_role in member.roles:
                    await member.remove_roles(
                        verified_role,
                        reason="SpamGuard verification pending",
                    )
                await member.add_roles(
                    unverified_role, reason="SpamGuard verification pending"
                )
            except (discord.Forbidden, discord.HTTPException):
                pass
            if verify_channel and verified_role:
                applied, failed = await self.apply_verification_visibility(
                    member.guild, unverified_role, verified_role, verify_channel
                )
                isolation_detail = f"権限上書き 適用:{applied} 失敗:{failed}"
            elif verify_channel:
                isolation_detail = "Verifiedロール作成失敗のため権限制御を適用できませんでした"

        session = self.start_session(member, config)
        await self.notify_member(member, config, session, verify_channel)
        await self.security_runtime.log_verification_event(
            guild=member.guild,
            member=member,
            phase="join",
            status="ok",
            detail=(
                f"入室認証を開始しました。{isolation_detail}"
                if not verify_channel
                else (
                    f"入室認証を開始しました。案内チャンネル: #{verify_channel.name} "
                    f"/ {isolation_detail}"
                )
            ),
        )
        self.schedule_timeout(session, config)

    async def verify_code(
        self,
        member: discord.Member,
        code: str,
    ) -> tuple[bool, str]:
        if member.guild_permissions.administrator or member.guild_permissions.manage_guild:
            return True, "管理者権限ユーザーは認証対象外です。"

        config = self.config_store.get_guild_config(member.guild.id)
        key = (member.guild.id, member.id)
        session = self.sessions.get(key)
        now = dt.datetime.now(dt.timezone.utc)

        if not config.verify_enabled:
            return True, "このサーバーでは認証機能が無効です。"

        if not session:
            return False, "認証セッションがありません。再入室後にやり直してください。"

        if now > session.expires_at:
            self.clear_session(key)
            return False, "認証期限切れです。再入室して再試行してください。"

        if session.code != code.strip():
            session.attempts += 1
            max_attempts = max(1, config.verify_max_attempts)
            remaining = max_attempts - session.attempts
            if remaining <= 0:
                action_status = await self.apply_failure_action(member, config)
                await self.security_runtime.log_verification_event(
                    guild=member.guild,
                    member=member,
                    phase="verify",
                    status=action_status,
                    detail="認証コード誤入力の上限到達",
                )
                self.clear_session(key)
                return False, "認証失敗回数が上限に達しました。"
            return False, f"認証コードが違います。残り試行回数: {remaining}"

        unverified_role = member.guild.get_role(config.verify_unverified_role_id or 0)
        if unverified_role and unverified_role in member.roles:
            try:
                await member.remove_roles(unverified_role, reason="SpamGuard verification success")
            except (discord.Forbidden, discord.HTTPException):
                pass

        verified_role = await self.ensure_verified_role(member.guild, config)
        role_status = "not_attempted"
        if verified_role and verified_role not in member.roles:
            try:
                await member.add_roles(
                    verified_role, reason="SpamGuard verification success"
                )
                role_status = "ok"
            except discord.Forbidden:
                role_status = "forbidden"
            except discord.HTTPException:
                role_status = "http_error"
        elif verified_role and verified_role in member.roles:
            role_status = "ok"

        channel_applied, channel_failed = await self.grant_member_access_after_verify(
            member=member,
            log_channel_id=config.log_channel_id,
        )
        verify_channel = member.guild.get_channel(config.verify_channel_id or 0)
        if isinstance(verify_channel, discord.TextChannel):
            await self.clear_member_verify_access(member, verify_channel)

        await self.security_runtime.log_verification_event(
            guild=member.guild,
            member=member,
            phase="verify",
            status="ok",
            detail=(
                "認証成功 "
                f"(role:{role_status}, channel_overwrite:適用{channel_applied}/失敗{channel_failed})"
            ),
        )
        self.clear_session(key)
        return True, "認証に成功しました。"

    async def send_new_code(self, member: discord.Member) -> tuple[bool, str]:
        config = self.config_store.get_guild_config(member.guild.id)
        if not config.verify_enabled:
            return False, "このサーバーでは認証機能が無効です。"
        key = (member.guild.id, member.id)
        session = self.sessions.get(key)
        if not session:
            session = self.start_session(member, config)
        else:
            session.code = self.generate_code()
            session.expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                minutes=max(1, config.verify_timeout_minutes)
            )
        self.schedule_timeout(session, config)

        verify_channel = await self.ensure_verify_channel(member.guild, config)
        await self.notify_member(member, config, session, verify_channel)
        await self.security_runtime.log_verification_event(
            guild=member.guild,
            member=member,
            phase="resend",
            status="ok",
            detail="認証コードを再発行",
        )
        return True, "認証コードを再送しました。DMを確認してください。"

    def pending_count(self, guild_id: int) -> int:
        return sum(1 for key in self.sessions if key[0] == guild_id)

    def is_pending(self, guild_id: int, user_id: int) -> bool:
        return (guild_id, user_id) in self.sessions

    async def ensure_unverified_role(
        self,
        guild: discord.Guild,
        config: SpamGuardConfig,
    ) -> discord.Role | None:
        if config.verify_unverified_role_id:
            role = guild.get_role(config.verify_unverified_role_id)
            if role:
                return role

        role = discord.utils.get(guild.roles, name="Unverified")
        if role:
            config.verify_unverified_role_id = role.id
            self.config_store.save()
            return role

        try:
            role = await guild.create_role(
                name="Unverified",
                mentionable=False,
                hoist=False,
                reason="SpamGuard verification role",
            )
        except (discord.Forbidden, discord.HTTPException):
            return None

        config.verify_unverified_role_id = role.id
        self.config_store.save()
        return role

    async def ensure_verified_role(
        self,
        guild: discord.Guild,
        config: SpamGuardConfig,
    ) -> discord.Role | None:
        if config.verify_member_role_id:
            role = guild.get_role(config.verify_member_role_id)
            if role:
                return role

        role = discord.utils.get(guild.roles, name="Verified")
        if role:
            config.verify_member_role_id = role.id
            self.config_store.save()
            return role

        try:
            role = await guild.create_role(
                name="Verified",
                mentionable=False,
                hoist=False,
                reason="SpamGuard verification completed role",
            )
        except (discord.Forbidden, discord.HTTPException):
            return None

        config.verify_member_role_id = role.id
        self.config_store.save()
        return role

    async def ensure_verify_channel(
        self,
        guild: discord.Guild,
        config: SpamGuardConfig,
    ) -> discord.TextChannel | None:
        if config.verify_channel_id:
            channel = guild.get_channel(config.verify_channel_id)
            if isinstance(channel, discord.TextChannel):
                return channel

        existing = discord.utils.get(guild.text_channels, name="verify")
        if existing:
            config.verify_channel_id = existing.id
            self.config_store.save()
            return existing

        me = guild.me or guild.get_member(self.bot.user.id if self.bot.user else 0)
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(
                view_channel=True,
                send_messages=False,
                read_message_history=True,
                use_application_commands=True,
            ),
        }
        if me:
            overwrites[me] = discord.PermissionOverwrite(
                view_channel=True,
                send_messages=True,
                read_message_history=True,
                manage_messages=True,
                use_application_commands=True,
            )

        try:
            channel = await guild.create_text_channel(
                name="verify",
                reason="SpamGuard verification channel auto-create",
                overwrites=overwrites,
            )
        except (discord.Forbidden, discord.HTTPException):
            return None

        config.verify_channel_id = channel.id
        self.config_store.save()
        return channel

    async def apply_verification_visibility(
        self,
        guild: discord.Guild,
        unverified_role: discord.Role,
        verified_role: discord.Role,
        verify_channel: discord.TextChannel,
    ) -> tuple[int, int]:
        applied = 0
        failed = 0
        for channel in guild.channels:
            if channel.id == verify_channel.id:
                unverified_overwrite = discord.PermissionOverwrite(
                    view_channel=True,
                    read_messages=True,
                    send_messages=True,
                    read_message_history=True,
                    connect=True,
                    use_application_commands=True,
                )
                verified_overwrite = discord.PermissionOverwrite(
                    view_channel=True,
                    read_messages=True,
                    use_application_commands=True,
                )
                everyone_overwrite = discord.PermissionOverwrite(
                    view_channel=False,
                    read_messages=False,
                    use_application_commands=False,
                )
            else:
                unverified_overwrite = discord.PermissionOverwrite(
                    view_channel=False,
                    read_messages=False,
                    send_messages=False,
                    read_message_history=False,
                    connect=False,
                    use_application_commands=False,
                )
                everyone_public = channel.permissions_for(guild.default_role).view_channel
                if everyone_public:
                    everyone_overwrite = discord.PermissionOverwrite(
                        view_channel=False,
                        read_messages=False,
                    )
                    verified_overwrite = discord.PermissionOverwrite(
                        view_channel=True,
                        read_messages=True,
                    )
                else:
                    everyone_overwrite = None
                    verified_overwrite = None

            try:
                if everyone_overwrite is not None:
                    await self._set_permissions_with_retry(
                        channel,
                        guild.default_role,
                        overwrite=everyone_overwrite,
                        reason="SpamGuard verification isolation",
                    )
                    applied += 1

                await self._set_permissions_with_retry(
                    channel,
                    unverified_role,
                    overwrite=unverified_overwrite,
                    reason="SpamGuard verification isolation",
                )
                applied += 1

                if verified_overwrite is not None:
                    await self._set_permissions_with_retry(
                        channel,
                        verified_role,
                        overwrite=verified_overwrite,
                        reason="SpamGuard verification isolation",
                    )
                    applied += 1

                if self.bot.user:
                    bot_member = guild.get_member(self.bot.user.id)
                    if bot_member:
                        await self._set_permissions_with_retry(
                            channel,
                            bot_member,
                            overwrite=discord.PermissionOverwrite(
                                view_channel=True,
                                read_messages=True,
                                send_messages=True,
                                read_message_history=True,
                                manage_messages=True,
                                connect=True,
                            ),
                            reason="SpamGuard verification isolation",
                        )
                        applied += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
                continue

        return applied, failed

    async def ensure_member_verify_access(
        self,
        member: discord.Member,
        verify_channel: discord.TextChannel,
    ) -> None:
        try:
            await self._set_permissions_with_retry(
                verify_channel,
                member,
                overwrite=discord.PermissionOverwrite(
                    view_channel=True,
                    read_messages=True,
                    send_messages=True,
                    read_message_history=True,
                    use_application_commands=True,
                ),
                reason="SpamGuard verification temporary member access",
            )
        except (discord.Forbidden, discord.HTTPException):
            return

    async def clear_member_verify_access(
        self,
        member: discord.Member,
        verify_channel: discord.TextChannel,
    ) -> None:
        try:
            await self._set_permissions_with_retry(
                verify_channel,
                member,
                overwrite=None,
                reason="SpamGuard verification access cleanup",
            )
        except (discord.Forbidden, discord.HTTPException):
            return

    async def grant_member_access_after_verify(
        self,
        member: discord.Member,
        log_channel_id: int | None,
    ) -> tuple[int, int]:
        applied = 0
        failed = 0
        for channel in member.guild.channels:
            if log_channel_id and channel.id == log_channel_id:
                continue
            try:
                await self._set_permissions_with_retry(
                    channel,
                    member,
                    overwrite=discord.PermissionOverwrite(
                        view_channel=True,
                        read_messages=True,
                    ),
                    reason="SpamGuard verification completed member access",
                )
                applied += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
                continue
        return applied, failed

    async def _set_permissions_with_retry(
        self,
        channel: discord.abc.GuildChannel,
        target: discord.Role | discord.Member,
        *,
        overwrite: discord.PermissionOverwrite | None,
        reason: str,
    ) -> None:
        try:
            await channel.set_permissions(target, overwrite=overwrite, reason=reason)
            return
        except discord.Forbidden:
            raise
        except discord.HTTPException:
            await asyncio.sleep(self.PERMISSION_RETRY_DELAY_SECONDS)
            await channel.set_permissions(target, overwrite=overwrite, reason=reason)

    def start_session(
        self,
        member: discord.Member,
        config: SpamGuardConfig,
    ) -> VerificationSession:
        code = self.generate_code()
        expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            minutes=max(1, config.verify_timeout_minutes)
        )
        session = VerificationSession(
            guild_id=member.guild.id,
            user_id=member.id,
            code=code,
            expires_at=expires_at,
        )
        key = (member.guild.id, member.id)
        self.sessions[key] = session
        return session

    def schedule_timeout(self, session: VerificationSession, config: SpamGuardConfig) -> None:
        key = (session.guild_id, session.user_id)
        old_task = self.timeout_tasks.pop(key, None)
        if old_task:
            old_task.cancel()

        task = asyncio.create_task(self._timeout_job(session, config))
        self.timeout_tasks[key] = task

    async def _timeout_job(self, session: VerificationSession, config: SpamGuardConfig) -> None:
        key = (session.guild_id, session.user_id)
        seconds = max(1, int((session.expires_at - dt.datetime.now(dt.timezone.utc)).total_seconds()))

        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            return

        current = self.sessions.get(key)
        if not current:
            return

        guild = self.bot.get_guild(session.guild_id)
        if not guild:
            self.clear_session(key)
            return

        member = guild.get_member(session.user_id)
        if not member:
            self.clear_session(key)
            return

        status = await self.apply_failure_action(member, config)
        await self.security_runtime.log_verification_event(
            guild=guild,
            member=member,
            phase="timeout",
            status=status,
            detail="認証期限切れ",
        )
        self.clear_session(key)

    async def apply_failure_action(
        self,
        member: discord.Member,
        config: SpamGuardConfig,
    ) -> str:
        action = config.verify_fail_action
        if action == "none":
            return "not_attempted"

        if action == "kick":
            try:
                await member.kick(reason="SpamGuard verification failed")
                return "ok"
            except discord.Forbidden:
                return "forbidden"
            except discord.HTTPException:
                return "http_error"

        if action == "timeout":
            try:
                await member.timeout_for(
                    dt.timedelta(minutes=max(1, config.verify_timeout_minutes)),
                    reason="SpamGuard verification failed",
                )
                return "ok"
            except discord.Forbidden:
                return "forbidden"
            except discord.HTTPException:
                return "http_error"
            except AttributeError:
                return "not_supported"

        return "not_attempted"

    async def notify_member(
        self,
        member: discord.Member,
        config: SpamGuardConfig,
        session: VerificationSession,
        verify_channel: discord.TextChannel | None,
    ) -> None:
        expire_minutes = max(1, config.verify_timeout_minutes)
        channel_hint = (
            f"認証チャンネル {verify_channel.mention} で"
            if verify_channel
            else "サーバー内で"
        )
        dm_text = (
            f"{member.guild.name} に参加ありがとうございます。\n"
            f"認証コード: `{session.code}`\n"
            f"{expire_minutes}分以内に{channel_hint} `/verify code:<コード>` を実行してください。"
        )

        try:
            await member.send(dm_text)
        except (discord.Forbidden, discord.HTTPException):
            pass

        if verify_channel:
            try:
                await verify_channel.send(
                    f"{member.mention} 参加ありがとうございます。"
                    f" {expire_minutes}分以内に `/verify code:<DMで届いた6桁コード>` を入力してください。"
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

    def generate_code(self) -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    def clear_session(self, key: tuple[int, int]) -> None:
        self.sessions.pop(key, None)
        task = self.timeout_tasks.pop(key, None)
        if task:
            task.cancel()
