from typing import Any

import discord
from discord import Option
from discord.commands import SlashCommandGroup
from discord.ext import commands

from .config import ConfigStore
from .security_runtime import EDITABLE_SECURITY_RULES, SecurityRuntime
from .utils import parse_value
from .verification import VerificationManager


def can_manage(interaction: discord.ApplicationContext) -> bool:
    return bool(interaction.guild and interaction.user.guild_permissions.manage_guild)


async def ensure_manage_and_guild(
    ctx: discord.ApplicationContext,
    config_store: ConfigStore,
) -> tuple[discord.Guild | None, Any | None]:
    if not can_manage(ctx):
        await ctx.respond("サーバー管理権限(Manage Server)が必要です。", ephemeral=True)
        return None, None
    if not ctx.guild:
        await ctx.respond("サーバー内で実行してください。", ephemeral=True)
        return None, None
    return ctx.guild, config_store.get_guild_config(ctx.guild.id)


async def ensure_log_viewer_role(
    guild: discord.Guild,
    config: Any,
    config_store: ConfigStore,
) -> discord.Role | None:
    role = None
    if getattr(config, "log_viewer_role_id", None):
        role = guild.get_role(config.log_viewer_role_id)
    if role:
        return role

    try:
        role = await guild.create_role(
            name="SpamGuard-Log閲覧者",
            reason="SpamGuardログ閲覧用ロールの自動作成",
            mentionable=False,
            hoist=False,
        )
    except (discord.Forbidden, discord.HTTPException):
        return None

    config.log_viewer_role_id = role.id
    config_store.save()
    return role


async def apply_log_visibility_restriction(
    guild: discord.Guild,
    channel: discord.TextChannel,
    config: Any,
    config_store: ConfigStore,
) -> tuple[bool, str]:
    me = guild.me
    if not me:
        return False, "Botメンバー情報を取得できませんでした。"
    if not me.guild_permissions.manage_roles:
        return False, "Botに Manage Roles 権限が必要です。"
    if not me.guild_permissions.manage_channels:
        return False, "Botに Manage Channels 権限が必要です。"

    role = await ensure_log_viewer_role(guild, config, config_store)
    if not role:
        return False, "閲覧用ロールの作成に失敗しました。"

    overwrites = dict(channel.overwrites)
    overwrites[guild.default_role] = discord.PermissionOverwrite(
        view_channel=False,
        read_message_history=False,
    )
    overwrites[role] = discord.PermissionOverwrite(
        view_channel=True,
        read_message_history=True,
    )
    overwrites[me] = discord.PermissionOverwrite(
        view_channel=True,
        send_messages=True,
        read_message_history=True,
    )
    try:
        await channel.edit(overwrites=overwrites, reason="SpamGuardログ閲覧制限の適用")
    except discord.Forbidden:
        return False, "チャンネル権限の変更に失敗しました。"
    except discord.HTTPException:
        return False, "チャンネル更新中にAPIエラーが発生しました。"

    config.log_viewer_role_id = role.id
    return True, f"閲覧ロール: {role.mention}"


def resolve_role_input(guild: discord.Guild, raw: Any) -> discord.Role | None:
    if isinstance(raw, discord.Role):
        return raw
    if not isinstance(raw, str):
        return None

    text = raw.strip()
    if text.startswith("<@&") and text.endswith(">"):
        text = text[3:-1]

    if text.isdigit():
        return guild.get_role(int(text))

    return discord.utils.get(guild.roles, name=text)


def register_commands(
    bot: commands.Bot,
    config_store: ConfigStore,
    security_runtime: SecurityRuntime,
    verification_manager: VerificationManager,
) -> None:
    spamguard = SlashCommandGroup("spamguard", "SpamGuardの管理コマンド")
    security = SlashCommandGroup("security", "Security運用コマンド")

    @bot.slash_command(name="help", description="SpamGuardコマンド一覧を表示します")
    async def help_command(
        ctx: discord.ApplicationContext,
        category: Option(
            str,
            "表示カテゴリ",
            required=False,
            choices=["all", "spamguard", "security", "verify"],
            default="all",
        ) = "all",
    ) -> None:
        sections: list[str] = []

        if category in {"all", "spamguard"}:
            sections.append(
                "\n".join(
                    [
                        "[spamguard]",
                        "/spamguard status: 現在のスパム検知設定と関連値を表示します。",
                        "/spamguard set key value: 単一設定を変更します。",
                        "/spamguard setting bulk: スパム検知関連の値を一括更新します。",
                        "/spamguard setting log_setup: ログ出力チャンネル設定と閲覧制限をまとめて適用します。",
                        "/spamguard setting log_viewer: ログ閲覧ロールをユーザーへ付与/剥奪します。",
                        "/spamguard setting log_clear: ログチャンネル設定を解除します。",
                        "/spamguard ignore add: チャンネルまたはロールを検知対象から除外します。",
                        "/spamguard ignore remove: 除外を解除して検知対象に戻します。",
                    ]
                )
            )

        if category in {"all", "security"}:
            sections.append(
                "\n".join(
                    [
                        "[security]",
                        "/security status: セキュリティ機能全体の状態を表示します。",
                        "/security rule list: 更新可能なルールと現在値を表示します。",
                        "/security rule set: 指定ルールを1項目更新します。",
                        "/security whitelist add: 許可ユーザー/ロール/ドメインを追加します。",
                        "/security whitelist remove: 許可ユーザー/ロール/ドメインを削除します。",
                        "/security whitelist list: 現在のホワイトリスト一覧を表示します。",
                        "/security blocklist domain_add: 危険ドメインを追加します。",
                        "/security blocklist domain_remove: 危険ドメインを削除します。",
                        "/security blocklist tld_add: 危険TLDを追加します。",
                        "/security blocklist tld_remove: 危険TLDを削除します。",
                        "/security verify status: 入室認証設定と保留認証数を表示します。",
                        "/security verify configure: 入室認証設定を更新します。",
                        "/security verify unverified_role: 未認証ユーザー用ロールを設定します。",
                    ]
                )
            )

        if category in {"all", "verify"}:
            sections.append(
                "\n".join(
                    [
                        "[verify]",
                        "/verify code:<6桁コード>: DMで届いたコードを入力して認証を完了します。",
                        "/verify_resend: 認証コードを再発行して再送します。",
                    ]
                )
            )

        sections.append(
            "\n".join(
                [
                    "[note]",
                    "管理系コマンド（/spamguard, /security）はManage Server権限が必要です。",
                    "認証コードは入室時にDM送信され、認証チャンネルで `/verify` 実行を案内します。",
                    "認証チャンネルが未設定なら自動作成され、未認証ユーザーは認証チャンネルのみ閲覧可能です。",
                    "認証中の通常メッセージは削除されます。",
                ]
            )
        )

        await ctx.respond("\n\n".join(sections), ephemeral=True)

    @spamguard.command(description="現在のSpamGuard設定を表示します")
    async def spamguard_status(ctx: discord.ApplicationContext) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        lines = [
            f"window_sec={config.window_sec}",
            f"max_msg_in_window={config.max_msg_in_window}",
            f"duplicate_window_sec={config.duplicate_window_sec}",
            f"dup_threshold={config.dup_threshold}",
            f"url_threshold={config.url_threshold}",
            f"url_repeat_window_sec={config.url_repeat_window_sec}",
            f"url_repeat_threshold={config.url_repeat_threshold}",
            f"mention_threshold={config.mention_threshold}",
            f"score_threshold={config.score_threshold}",
            f"timeout_minutes={config.timeout_minutes}",
            f"warning_threshold={config.warning_threshold}",
            f"timeout_threshold={config.timeout_threshold}",
            f"ban_threshold={config.ban_threshold}",
            f"ban_enabled={config.ban_enabled}",
            f"offense_window_sec={config.offense_window_sec}",
            f"raid_join_window_sec={config.raid_join_window_sec}",
            f"raid_join_threshold={config.raid_join_threshold}",
            f"raid_message_window_sec={config.raid_message_window_sec}",
            f"raid_new_user_message_threshold={config.raid_new_user_message_threshold}",
            f"new_member_window_sec={config.new_member_window_sec}",
            f"verify_enabled={config.verify_enabled}",
            f"verify_channel_id={config.verify_channel_id}",
            f"verify_unverified_role_id={config.verify_unverified_role_id}",
            f"verify_member_role_id={config.verify_member_role_id}",
            f"verify_timeout_minutes={config.verify_timeout_minutes}",
            f"verify_max_attempts={config.verify_max_attempts}",
            f"verify_fail_action={config.verify_fail_action}",
            f"log_channel_id={config.log_channel_id}",
            f"log_viewer_role_id={getattr(config, 'log_viewer_role_id', None)}",
            f"ignore_role_ids={config.ignore_role_ids}",
            f"ignore_channel_ids={config.ignore_channel_ids}",
            f"whitelist_user_ids={config.whitelist_user_ids}",
            f"whitelist_role_ids={config.whitelist_role_ids}",
            f"allow_domains={config.allow_domains}",
            f"phishing_domains={config.phishing_domains}",
        ]
        await ctx.respond("\n".join(lines), ephemeral=True)

    @spamguard.command(description="設定値を変更します")
    async def spamguard_set(
        ctx: discord.ApplicationContext,
        key: Option(str, "設定キー"),
        value: Option(str, "新しい値"),
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        if not hasattr(config, key):
            await ctx.respond(f"不明なキーです: {key}", ephemeral=True)
            return

        if key in {
            "ignore_role_ids",
            "ignore_channel_ids",
            "whitelist_user_ids",
            "whitelist_role_ids",
            "allow_domains",
            "phishing_domains",
            "suspicious_tlds",
        }:
            await ctx.respond(
                f"{key} は専用サブコマンドを使ってください。", ephemeral=True
            )
            return

        try:
            parsed = parse_value(getattr(config, key), value)
        except ValueError:
            await ctx.respond(f"{key} の値が不正です: {value}", ephemeral=True)
            return

        config_store.set_guild_value(guild.id, key, parsed)
        await ctx.respond(f"更新しました: {key}={parsed}", ephemeral=True)

    setting = spamguard.create_subgroup("setting", "設定をDiscord UIで変更します")

    @setting.command(name="bulk", description="スパム検知の各種設定を一括更新します")
    async def setting_bulk(
        ctx: discord.ApplicationContext,
        window_sec: Option(int, "連投判定ウィンドウ秒数", required=False, min_value=1) = None,
        max_msg_in_window: Option(int, "連投判定の投稿数閾値", required=False, min_value=1) = None,
        duplicate_window_sec: Option(int, "同文判定ウィンドウ秒数", required=False, min_value=1) = None,
        dup_threshold: Option(int, "同文判定回数閾値", required=False, min_value=1) = None,
        url_threshold: Option(int, "1メッセージ内URL数閾値", required=False, min_value=1) = None,
        url_repeat_window_sec: Option(int, "同一URL監視秒数", required=False, min_value=1) = None,
        url_repeat_threshold: Option(int, "同一URL投稿回数閾値", required=False, min_value=1) = None,
        mention_threshold: Option(int, "メンション数閾値", required=False, min_value=1) = None,
        score_threshold: Option(int, "スパム判定スコア閾値", required=False, min_value=1) = None,
        timeout_minutes: Option(int, "タイムアウト分数", required=False, min_value=1) = None,
        timeout_threshold: Option(int, "タイムアウト開始違反回数", required=False, min_value=1) = None,
        ban_threshold: Option(int, "BAN開始違反回数", required=False, min_value=1) = None,
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        updates: list[str] = []
        values = {
            "window_sec": window_sec,
            "max_msg_in_window": max_msg_in_window,
            "duplicate_window_sec": duplicate_window_sec,
            "dup_threshold": dup_threshold,
            "url_threshold": url_threshold,
            "url_repeat_window_sec": url_repeat_window_sec,
            "url_repeat_threshold": url_repeat_threshold,
            "mention_threshold": mention_threshold,
            "score_threshold": score_threshold,
            "timeout_minutes": timeout_minutes,
            "timeout_threshold": timeout_threshold,
            "ban_threshold": ban_threshold,
        }

        for cfg_key, cfg_value in values.items():
            if cfg_value is None:
                continue
            setattr(config, cfg_key, cfg_value)
            updates.append(f"{cfg_key}={cfg_value}")

        if not updates:
            await ctx.respond(
                "更新する値が指定されていません。必要な項目だけ入力してください。",
                ephemeral=True,
            )
            return

        config_store.save()
        await ctx.respond("一括更新しました: " + ", ".join(updates), ephemeral=True)

    @setting.command(name="log_setup", description="ログチャンネル設定と閲覧制限をまとめて行います")
    async def setting_log_setup(
        ctx: discord.ApplicationContext,
        channel: Option(discord.TextChannel, "ログ出力チャンネル"),
        restrict: Option(bool, "管理者+専用ロールだけ閲覧可能にする", required=False) = True,
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        config.log_channel_id = channel.id
        message = f"ログチャンネルを設定しました: {channel.mention}"

        if restrict:
            ok, detail = await apply_log_visibility_restriction(
                guild,
                channel,
                config,
                config_store,
            )
            if not ok:
                await ctx.respond(detail, ephemeral=True)
                return
            message = f"{message}\n閲覧制限を適用しました（{detail}）"

        config_store.save()
        await ctx.respond(message, ephemeral=True)

    @setting.command(name="log_viewer", description="ログ閲覧ロールを付与/剥奪します")
    async def setting_log_viewer(
        ctx: discord.ApplicationContext,
        action: Option(str, "操作", choices=["add", "remove"]),
        member: Option(discord.Member, "対象ユーザー"),
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        role = guild.get_role(getattr(config, "log_viewer_role_id", 0))
        if action == "add" and not role:
            role = await ensure_log_viewer_role(guild, config, config_store)
        if not role:
            await ctx.respond(
                "閲覧ロールがありません。先に /spamguard setting log_setup を実行してください。",
                ephemeral=True,
            )
            return

        try:
            if action == "add":
                await member.add_roles(role, reason="SpamGuardログ閲覧権限の付与")
                await ctx.respond(
                    f"{member.mention} に {role.mention} を付与しました。", ephemeral=True
                )
            else:
                await member.remove_roles(role, reason="SpamGuardログ閲覧権限の剥奪")
                await ctx.respond(
                    f"{member.mention} から {role.mention} を剥奪しました。", ephemeral=True
                )
        except discord.Forbidden:
            await ctx.respond(
                "ロール操作に失敗しました。Botのロール階層を確認してください。",
                ephemeral=True,
            )
            return
        except discord.HTTPException:
            await ctx.respond("ロール操作時にAPIエラーが発生しました。", ephemeral=True)
            return

    @setting.command(name="log_clear", description="ログチャンネル設定を解除します")
    async def setting_log_clear(ctx: discord.ApplicationContext) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return
        config.log_channel_id = None
        config_store.save()
        await ctx.respond("ログチャンネル設定を解除しました。", ephemeral=True)

    ignore = spamguard.create_subgroup("ignore", "除外チャンネル・ロールを管理します")

    @ignore.command(description="除外するチャンネルまたはロールを追加します")
    async def ignore_add(
        ctx: discord.ApplicationContext,
        role: Option(discord.Role, required=False, description="除外するロール") = None,
        channel: Option(discord.TextChannel, required=False, description="除外するチャンネル") = None,
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        if bool(role) == bool(channel):
            await ctx.respond("role か channel のどちらか片方だけ指定してください。", ephemeral=True)
            return

        if role:
            if role.id not in config.ignore_role_ids:
                config.ignore_role_ids.append(role.id)
                config_store.save()
            await ctx.respond(f"除外ロールを追加しました: {role.name}", ephemeral=True)
            return

        if channel:
            if channel.id not in config.ignore_channel_ids:
                config.ignore_channel_ids.append(channel.id)
                config_store.save()
            await ctx.respond(f"除外チャンネルを追加しました: {channel.mention}", ephemeral=True)

    @ignore.command(description="除外中のチャンネルまたはロールを解除します")
    async def ignore_remove(
        ctx: discord.ApplicationContext,
        role: Option(discord.Role, required=False, description="除外解除するロール") = None,
        channel: Option(discord.TextChannel, required=False, description="除外解除するチャンネル") = None,
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        if bool(role) == bool(channel):
            await ctx.respond("role か channel のどちらか片方だけ指定してください。", ephemeral=True)
            return

        if role:
            if role.id in config.ignore_role_ids:
                config.ignore_role_ids.remove(role.id)
                config_store.save()
            await ctx.respond(f"除外ロールを解除しました: {role.name}", ephemeral=True)
            return

        if channel:
            if channel.id in config.ignore_channel_ids:
                config.ignore_channel_ids.remove(channel.id)
                config_store.save()
            await ctx.respond(f"除外チャンネルを解除しました: {channel.mention}", ephemeral=True)

    @security.command(description="セキュリティ機能の状態を表示します")
    async def security_status(ctx: discord.ApplicationContext) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        lines = [
            f"score_threshold={config.score_threshold}",
            f"warning_threshold={config.warning_threshold}",
            f"timeout_threshold={config.timeout_threshold}",
            f"ban_threshold={config.ban_threshold}",
            f"ban_enabled={config.ban_enabled}",
            f"offense_window_sec={config.offense_window_sec}",
            f"mention_threshold={config.mention_threshold}",
            f"raid_join_threshold={config.raid_join_threshold}",
            f"raid_new_user_message_threshold={config.raid_new_user_message_threshold}",
            f"phishing_domains={config.phishing_domains}",
            f"allow_domains={config.allow_domains}",
            f"whitelist_user_ids={config.whitelist_user_ids}",
            f"whitelist_role_ids={config.whitelist_role_ids}",
            f"verify_enabled={config.verify_enabled}",
            f"verify_channel_id={config.verify_channel_id}",
            f"verify_timeout_minutes={config.verify_timeout_minutes}",
            f"verify_max_attempts={config.verify_max_attempts}",
            f"verify_fail_action={config.verify_fail_action}",
        ]
        await ctx.respond("\n".join(lines), ephemeral=True)

    rules = security.create_subgroup("rule", "Securityルールの一覧/更新")

    @rules.command(name="list", description="更新可能なルール一覧を表示します")
    async def security_rule_list(ctx: discord.ApplicationContext) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        lines = [f"{key}={getattr(config, key)}" for key in sorted(EDITABLE_SECURITY_RULES)]
        await ctx.respond("\n".join(lines), ephemeral=True)

    @rules.command(name="set", description="Securityルールを更新します")
    async def security_rule_set(
        ctx: discord.ApplicationContext,
        key: Option(str, "設定キー"),
        value: Option(str, "新しい値"),
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        if key not in EDITABLE_SECURITY_RULES:
            await ctx.respond(f"更新できないキーです: {key}", ephemeral=True)
            return

        try:
            parsed = parse_value(getattr(config, key), value)
        except ValueError:
            await ctx.respond(f"{key} の値が不正です: {value}", ephemeral=True)
            return

        config_store.set_guild_value(guild.id, key, parsed)
        await ctx.respond(f"更新しました: {key}={parsed}", ephemeral=True)

    whitelist = security.create_subgroup("whitelist", "ホワイトリストを管理します")

    @whitelist.command(name="add", description="ユーザー/ロール/許可ドメインを追加します")
    async def whitelist_add(
        ctx: discord.ApplicationContext,
        user: Option(discord.Member, "許可ユーザー", required=False) = None,
        role: Option(discord.Role, "許可ロール", required=False) = None,
        domain: Option(str, "許可ドメイン", required=False) = None,
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        provided = sum(1 for item in [user, role, domain] if item)
        if provided != 1:
            await ctx.respond("user / role / domain のいずれか1つだけ指定してください。", ephemeral=True)
            return

        if user:
            if user.id not in config.whitelist_user_ids:
                config.whitelist_user_ids.append(user.id)
                config_store.save()
            await ctx.respond(f"許可ユーザーを追加しました: {user.mention}", ephemeral=True)
            return

        if role:
            if role.id not in config.whitelist_role_ids:
                config.whitelist_role_ids.append(role.id)
                config_store.save()
            await ctx.respond(f"許可ロールを追加しました: {role.name}", ephemeral=True)
            return

        normalized = domain.lower().strip()
        if normalized.startswith("www."):
            normalized = normalized[4:]
        if normalized and normalized not in config.allow_domains:
            config.allow_domains.append(normalized)
            config_store.save()
        await ctx.respond(f"許可ドメインを追加しました: {normalized}", ephemeral=True)

    @whitelist.command(name="remove", description="ユーザー/ロール/許可ドメインを削除します")
    async def whitelist_remove(
        ctx: discord.ApplicationContext,
        user: Option(discord.Member, "削除ユーザー", required=False) = None,
        role: Option(discord.Role, "削除ロール", required=False) = None,
        domain: Option(str, "削除ドメイン", required=False) = None,
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        provided = sum(1 for item in [user, role, domain] if item)
        if provided != 1:
            await ctx.respond("user / role / domain のいずれか1つだけ指定してください。", ephemeral=True)
            return

        if user:
            if user.id in config.whitelist_user_ids:
                config.whitelist_user_ids.remove(user.id)
                config_store.save()
            await ctx.respond(f"許可ユーザーを削除しました: {user.mention}", ephemeral=True)
            return

        if role:
            if role.id in config.whitelist_role_ids:
                config.whitelist_role_ids.remove(role.id)
                config_store.save()
            await ctx.respond(f"許可ロールを削除しました: {role.name}", ephemeral=True)
            return

        normalized = domain.lower().strip()
        if normalized.startswith("www."):
            normalized = normalized[4:]
        if normalized in config.allow_domains:
            config.allow_domains.remove(normalized)
            config_store.save()
        await ctx.respond(f"許可ドメインを削除しました: {normalized}", ephemeral=True)

    @whitelist.command(name="list", description="現在のホワイトリストを表示します")
    async def whitelist_list(ctx: discord.ApplicationContext) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        user_mentions: list[str] = []
        for user_id in config.whitelist_user_ids:
            member = guild.get_member(user_id)
            user_mentions.append(member.mention if member else str(user_id))

        role_mentions: list[str] = []
        for role_id in config.whitelist_role_ids:
            role = guild.get_role(role_id)
            role_mentions.append(role.mention if role else str(role_id))

        lines = [
            "whitelist users: " + (", ".join(user_mentions) if user_mentions else "(none)"),
            "whitelist roles: " + (", ".join(role_mentions) if role_mentions else "(none)"),
            "allow domains: "
            + (", ".join(sorted(config.allow_domains)) if config.allow_domains else "(none)"),
        ]
        await ctx.respond("\n".join(lines), ephemeral=True)

    blocklist = security.create_subgroup("blocklist", "危険ドメイン/TLDを管理します")

    @blocklist.command(name="domain_add", description="危険ドメインを追加します")
    async def blocklist_domain_add(
        ctx: discord.ApplicationContext,
        domain: Option(str, "危険ドメイン"),
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        normalized = domain.lower().strip()
        if normalized.startswith("www."):
            normalized = normalized[4:]
        if normalized and normalized not in config.phishing_domains:
            config.phishing_domains.append(normalized)
            config_store.save()
        await ctx.respond(f"危険ドメインを追加しました: {normalized}", ephemeral=True)

    @blocklist.command(name="domain_remove", description="危険ドメインを削除します")
    async def blocklist_domain_remove(
        ctx: discord.ApplicationContext,
        domain: Option(str, "危険ドメイン"),
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        normalized = domain.lower().strip()
        if normalized.startswith("www."):
            normalized = normalized[4:]
        if normalized in config.phishing_domains:
            config.phishing_domains.remove(normalized)
            config_store.save()
        await ctx.respond(f"危険ドメインを削除しました: {normalized}", ephemeral=True)

    @blocklist.command(name="tld_add", description="危険TLDを追加します")
    async def blocklist_tld_add(
        ctx: discord.ApplicationContext,
        tld: Option(str, "危険TLD(例: zip)"),
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        normalized = tld.lower().strip().lstrip(".")
        if normalized and normalized not in config.suspicious_tlds:
            config.suspicious_tlds.append(normalized)
            config_store.save()
        await ctx.respond(f"危険TLDを追加しました: .{normalized}", ephemeral=True)

    @blocklist.command(name="tld_remove", description="危険TLDを削除します")
    async def blocklist_tld_remove(
        ctx: discord.ApplicationContext,
        tld: Option(str, "危険TLD(例: zip)"),
    ) -> None:
        _, config = await ensure_manage_and_guild(ctx, config_store)
        if not config:
            return

        normalized = tld.lower().strip().lstrip(".")
        if normalized in config.suspicious_tlds:
            config.suspicious_tlds.remove(normalized)
            config_store.save()
        await ctx.respond(f"危険TLDを削除しました: .{normalized}", ephemeral=True)

    verify_group = security.create_subgroup("verify", "入室認証の設定")

    @verify_group.command(name="status", description="入室認証の状態を表示します")
    async def verify_status(ctx: discord.ApplicationContext) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        lines = [
            f"verify_enabled={config.verify_enabled}",
            f"verify_channel_id={config.verify_channel_id}",
            f"verify_unverified_role_id={config.verify_unverified_role_id}",
            f"verify_member_role_id={config.verify_member_role_id}",
            f"verify_timeout_minutes={config.verify_timeout_minutes}",
            f"verify_max_attempts={config.verify_max_attempts}",
            f"verify_fail_action={config.verify_fail_action}",
            f"pending_sessions={verification_manager.pending_count(guild.id)}",
        ]
        await ctx.respond("\n".join(lines), ephemeral=True)

    @verify_group.command(name="configure", description="入室認証設定を更新します")
    async def verify_configure(
        ctx: discord.ApplicationContext,
        enabled: Option(bool, "認証を有効にする", required=False) = None,
        channel: Option(discord.TextChannel, "案内チャンネル", required=False) = None,
        member_role: Option(discord.Role, "認証完了後に付与するロール", required=False) = None,
        timeout_minutes: Option(int, "認証期限(分)", required=False, min_value=1) = None,
        max_attempts: Option(int, "最大試行回数", required=False, min_value=1) = None,
        fail_action: Option(str, "失敗時アクション", required=False, choices=["kick", "timeout", "none"]) = None,
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        updates: list[str] = []
        if enabled is not None:
            config.verify_enabled = enabled
            updates.append(f"verify_enabled={enabled}")
        if channel is not None:
            config.verify_channel_id = channel.id
            updates.append(f"verify_channel_id={channel.id}")
        if member_role is not None:
            config.verify_member_role_id = member_role.id
            updates.append(f"verify_member_role_id={member_role.id}")
        if timeout_minutes is not None:
            config.verify_timeout_minutes = timeout_minutes
            updates.append(f"verify_timeout_minutes={timeout_minutes}")
        if max_attempts is not None:
            config.verify_max_attempts = max_attempts
            updates.append(f"verify_max_attempts={max_attempts}")
        if fail_action is not None:
            config.verify_fail_action = fail_action
            updates.append(f"verify_fail_action={fail_action}")

        if not updates:
            await ctx.respond("更新対象がありません。", ephemeral=True)
            return

        config_store.save()
        await ctx.respond("更新しました: " + ", ".join(updates), ephemeral=True)

    @verify_group.command(name="unverified_role", description="隔離ロールを設定します")
    async def verify_unverified_role(
        ctx: discord.ApplicationContext,
        role: Option(str, "未認証ユーザー用ロール"),
    ) -> None:
        guild, config = await ensure_manage_and_guild(ctx, config_store)
        if not guild or not config:
            return

        resolved_role = resolve_role_input(guild, role)
        if not resolved_role:
            await ctx.respond(
                "ロールを解決できませんでした。メンション・ID・ロール名のいずれかを指定してください。",
                ephemeral=True,
            )
            return

        config.verify_unverified_role_id = resolved_role.id
        config_store.save()
        await ctx.respond(
            f"未認証ロールを設定しました: {resolved_role.name}",
            ephemeral=True,
        )

    @bot.slash_command(description="入室認証コードを送信します")
    async def verify_resend(ctx: discord.ApplicationContext) -> None:
        if not ctx.guild or not isinstance(ctx.user, discord.Member):
            await ctx.respond("サーバー内で実行してください。", ephemeral=True)
            return

        await ctx.defer(ephemeral=True)
        _, message = await verification_manager.send_new_code(ctx.user)
        await ctx.followup.send(message, ephemeral=True)

    @bot.slash_command(description="入室認証コードを入力します")
    async def verify(
        ctx: discord.ApplicationContext,
        code: Option(str, "DMに届いた認証コード"),
    ) -> None:
        if not ctx.guild or not isinstance(ctx.user, discord.Member):
            await ctx.respond("サーバー内で実行してください。", ephemeral=True)
            return

        await ctx.defer(ephemeral=True)
        _, message = await verification_manager.verify_code(ctx.user, code)
        await ctx.followup.send(message, ephemeral=True)

    bot.add_application_command(spamguard)
    bot.add_application_command(security)
