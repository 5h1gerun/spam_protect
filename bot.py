import datetime as dt
import os
from typing import Any

import discord
from discord import Option
from discord.commands import SlashCommandGroup
from discord.ext import commands
from dotenv import load_dotenv

from spamguard import ConfigStore, MessageSnapshot, SpamDetector


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


load_dotenv()
config_path = os.getenv("SPAMGUARD_CONFIG_PATH", "config.json")
config_store = ConfigStore(config_path)
config_store.load()
detectors: dict[int, SpamDetector] = {}

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(intents=intents)
spamguard = SlashCommandGroup("spamguard", "SpamGuardの管理コマンド")


def can_manage(interaction: discord.ApplicationContext) -> bool:
    return bool(interaction.guild and interaction.user.guild_permissions.manage_guild)


async def ensure_manage_and_guild(
    ctx: discord.ApplicationContext,
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
    except discord.Forbidden:
        return None
    except discord.HTTPException:
        return None
    config.log_viewer_role_id = role.id
    config_store.save()
    return role


def format_action_status(status: str) -> str:
    mapping = {
        "ok": "成功",
        "forbidden": "権限不足",
        "http_error": "APIエラー",
        "not_supported": "未対応",
        "not_attempted": "未実行",
    }
    return mapping.get(status, status)


def format_reason_labels(reasons: list[str]) -> str:
    mapping = {
        "rapid_posting": "短時間の連投",
        "duplicate_messages": "同文連投",
        "url_spam": "URL乱投",
        "repeated_url_posts": "同一URL連投",
        "mention_spam": "過剰メンション",
        "new_account": "新規アカウント加点",
    }
    if not reasons:
        return "なし"
    return ", ".join(mapping.get(reason, reason) for reason in reasons)


async def log_spam_event(
    message: discord.Message,
    score: int,
    reasons: list[str],
    delete_status: str,
    timeout_status: str,
) -> None:
    config = config_store.get_guild_config(message.guild.id)
    if not config.log_channel_id:
        return

    channel = message.guild.get_channel(config.log_channel_id)
    if not channel or not isinstance(channel, discord.TextChannel):
        return

    reason_text = format_reason_labels(reasons)
    content_preview = message.content.strip() or "(本文なし)"
    if len(content_preview) > 300:
        content_preview = content_preview[:300] + "..."

    embed = discord.Embed(
        title="SpamGuard ログ",
        description="スパム判定によりモデレーションを実行しました。",
        color=discord.Color.orange(),
        timestamp=dt.datetime.now(dt.timezone.utc),
    )
    avatar_url = message.author.display_avatar.url
    embed.set_author(name=str(message.author), icon_url=avatar_url)
    embed.set_thumbnail(url=avatar_url)
    embed.add_field(
        name="対象ユーザー",
        value=f"{message.author.mention}\n`{message.author.id}`",
        inline=True,
    )
    embed.add_field(name="スコア", value=str(score), inline=True)
    embed.add_field(name="理由", value=reason_text, inline=False)
    embed.add_field(
        name="削除結果",
        value=format_action_status(delete_status),
        inline=True,
    )
    embed.add_field(
        name="タイムアウト結果",
        value=format_action_status(timeout_status),
        inline=True,
    )
    embed.add_field(
        name="投稿チャンネル",
        value=message.channel.mention,
        inline=True,
    )
    embed.add_field(name="投稿内容(先頭300文字)", value=content_preview, inline=False)

    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        pass
    except discord.HTTPException:
        pass


@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user}")


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot or not message.guild:
        return

    config = config_store.get_guild_config(message.guild.id)
    detector = detectors.setdefault(message.guild.id, SpamDetector(config))

    if message.channel.id in config.ignore_channel_ids:
        return

    author_roles = {role.id for role in getattr(message.author, "roles", [])}
    if author_roles.intersection(config.ignore_role_ids):
        return

    snapshot = MessageSnapshot(
        user_id=message.author.id,
        content=message.content,
        mention_count=len(message.mentions),
        created_at=dt.datetime.now(dt.timezone.utc),
        account_created_at=message.author.created_at,
    )
    result = detector.score(snapshot)

    if result.score >= config.score_threshold:
        delete_status = "not_attempted"
        timeout_status = "not_attempted"

        try:
            await message.delete()
            delete_status = "ok"
        except discord.Forbidden:
            delete_status = "forbidden"
        except discord.HTTPException:
            delete_status = "http_error"

        timeout_reason = "SpamGuard auto-moderation"
        try:
            await message.author.timeout_for(
                dt.timedelta(minutes=config.timeout_minutes), reason=timeout_reason
            )
            timeout_status = "ok"
        except discord.Forbidden:
            timeout_status = "forbidden"
        except discord.HTTPException:
            timeout_status = "http_error"
        except AttributeError:
            timeout_status = "not_supported"

        await log_spam_event(
            message=message,
            score=result.score,
            reasons=result.reasons,
            delete_status=delete_status,
            timeout_status=timeout_status,
        )

    await bot.process_commands(message)


@spamguard.command(description="現在のSpamGuard設定を表示します")
async def status(ctx: discord.ApplicationContext) -> None:
    _, config = await ensure_manage_and_guild(ctx)
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
        f"log_channel_id={config.log_channel_id}",
        f"log_viewer_role_id={getattr(config, 'log_viewer_role_id', None)}",
        f"ignore_role_ids={config.ignore_role_ids}",
        f"ignore_channel_ids={config.ignore_channel_ids}",
    ]
    await ctx.respond("\n".join(lines), ephemeral=True)


@spamguard.command(description="設定値を変更します")
async def set(
    ctx: discord.ApplicationContext,
    key: Option(str, "設定キー"),
    value: Option(str, "新しい値"),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return

    if not hasattr(config, key):
        await ctx.respond(f"不明なキーです: {key}", ephemeral=True)
        return

    if key in {"ignore_role_ids", "ignore_channel_ids"}:
        await ctx.respond(
            f"{key} は /spamguard ignore コマンドを使ってください。", ephemeral=True
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
async def bulk(
    ctx: discord.ApplicationContext,
    window_sec: Option(int, "連投判定ウィンドウ秒数", required=False, min_value=1) = None,
    max_msg_in_window: Option(
        int, "連投判定の投稿数閾値", required=False, min_value=1
    ) = None,
    duplicate_window_sec: Option(
        int, "同文判定ウィンドウ秒数", required=False, min_value=1
    ) = None,
    dup_threshold: Option(int, "同文判定回数閾値", required=False, min_value=1) = None,
    url_threshold: Option(
        int, "1メッセージ内URL数閾値", required=False, min_value=1
    ) = None,
    url_repeat_window_sec: Option(
        int, "同一URL監視秒数", required=False, min_value=1
    ) = None,
    url_repeat_threshold: Option(
        int, "同一URL投稿回数閾値", required=False, min_value=1
    ) = None,
    mention_threshold: Option(
        int, "メンション数閾値", required=False, min_value=1
    ) = None,
    score_threshold: Option(
        int, "スパム判定スコア閾値", required=False, min_value=1
    ) = None,
    timeout_minutes: Option(
        int, "タイムアウト分数", required=False, min_value=1
    ) = None,
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
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
    }
    for key, value in values.items():
        if value is None:
            continue
        setattr(config, key, value)
        updates.append(f"{key}={value}")

    if not updates:
        await ctx.respond(
            "更新する値が指定されていません。必要な項目だけ入力してください。",
            ephemeral=True,
        )
        return

    config_store.save()
    await ctx.respond("一括更新しました: " + ", ".join(updates), ephemeral=True)


async def apply_log_visibility_restriction(
    guild: discord.Guild,
    channel: discord.TextChannel,
    config: Any,
) -> tuple[bool, str]:
    me = guild.me
    if not me:
        return False, "Botメンバー情報を取得できませんでした。"
    if not me.guild_permissions.manage_roles:
        return False, "Botに Manage Roles 権限が必要です。"
    if not me.guild_permissions.manage_channels:
        return False, "Botに Manage Channels 権限が必要です。"

    role = await ensure_log_viewer_role(guild, config)
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
        await channel.edit(
            overwrites=overwrites,
            reason="SpamGuardログ閲覧制限の適用",
        )
    except discord.Forbidden:
        return False, "チャンネル権限の変更に失敗しました。"
    except discord.HTTPException:
        return False, "チャンネル更新中にAPIエラーが発生しました。"

    config.log_viewer_role_id = role.id
    return True, f"閲覧ロール: {role.mention}"


@setting.command(name="log_setup", description="ログチャンネル設定と閲覧制限をまとめて行います")
async def log_setup(
    ctx: discord.ApplicationContext,
    channel: Option(discord.TextChannel, "ログ出力チャンネル"),
    restrict: Option(bool, "管理者+専用ロールだけ閲覧可能にする", required=False) = True,
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return

    config.log_channel_id = channel.id
    message = f"ログチャンネルを設定しました: {channel.mention}"

    if restrict:
        ok, detail = await apply_log_visibility_restriction(guild, channel, config)
        if not ok:
            await ctx.respond(detail, ephemeral=True)
            return
        message = f"{message}\n閲覧制限を適用しました（{detail}）"
    config_store.save()
    await ctx.respond(message, ephemeral=True)


@setting.command(name="log_viewer", description="ログ閲覧ロールを付与/剥奪します")
async def log_viewer(
    ctx: discord.ApplicationContext,
    action: Option(str, "操作", choices=["add", "remove"]),
    member: Option(discord.Member, "対象ユーザー"),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return

    role = guild.get_role(getattr(config, "log_viewer_role_id", 0))
    if action == "add" and not role:
        role = await ensure_log_viewer_role(guild, config)
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
async def log_clear(ctx: discord.ApplicationContext) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.log_channel_id = None
    config_store.save()
    await ctx.respond("ログチャンネル設定を解除しました。", ephemeral=True)


ignore = spamguard.create_subgroup("ignore", "除外チャンネル・ロールを管理します")


@ignore.command(description="除外するチャンネルまたはロールを追加します")
async def add(
    ctx: discord.ApplicationContext,
    role: Option(discord.Role, required=False, description="除外するロール") = None,
    channel: Option(
        discord.TextChannel, required=False, description="除外するチャンネル"
    ) = None,
) -> None:
    _, config = await ensure_manage_and_guild(ctx)
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
        await ctx.respond(
            f"除外チャンネルを追加しました: {channel.mention}", ephemeral=True
        )


@ignore.command(description="除外中のチャンネルまたはロールを解除します")
async def remove(
    ctx: discord.ApplicationContext,
    role: Option(discord.Role, required=False, description="除外解除するロール") = None,
    channel: Option(
        discord.TextChannel, required=False, description="除外解除するチャンネル"
    ) = None,
) -> None:
    _, config = await ensure_manage_and_guild(ctx)
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
        await ctx.respond(
            f"除外チャンネルを解除しました: {channel.mention}", ephemeral=True
        )


bot.add_application_command(spamguard)


def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise RuntimeError("DISCORD_TOKEN is not set")
    bot.run(token)


if __name__ == "__main__":
    main()
