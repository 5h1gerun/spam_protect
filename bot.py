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


async def log_action(guild: discord.Guild, text: str) -> None:
    config = config_store.get_guild_config(guild.id)
    if not config.log_channel_id:
        return
    channel = guild.get_channel(config.log_channel_id)
    if channel and isinstance(channel, discord.TextChannel):
        try:
            await channel.send(text)
        except discord.Forbidden:
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

        reasons = ", ".join(result.reasons) if result.reasons else "unknown"
        await log_action(
            message.guild,
            (
                f"[SpamGuard] user={message.author}({message.author.id}) "
                f"score={result.score} reasons={reasons} "
                f"delete={delete_status} timeout={timeout_status}"
            ),
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


@setting.command(description="連投検知の設定")
async def rapid(
    ctx: discord.ApplicationContext,
    window_sec: Option(int, "判定ウィンドウ秒数", min_value=1),
    max_msg_in_window: Option(int, "ウィンドウ内の最大投稿数", min_value=1),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.window_sec = window_sec
    config.max_msg_in_window = max_msg_in_window
    config_store.save()
    await ctx.respond(
        f"連投検知設定を更新: window_sec={window_sec}, max_msg_in_window={max_msg_in_window}",
        ephemeral=True,
    )


@setting.command(description="同文連投検知の設定")
async def duplicate(
    ctx: discord.ApplicationContext,
    duplicate_window_sec: Option(int, "同文判定ウィンドウ秒数", min_value=1),
    dup_threshold: Option(int, "同文判定回数", min_value=1),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.duplicate_window_sec = duplicate_window_sec
    config.dup_threshold = dup_threshold
    config_store.save()
    await ctx.respond(
        f"同文連投設定を更新: duplicate_window_sec={duplicate_window_sec}, dup_threshold={dup_threshold}",
        ephemeral=True,
    )


@setting.command(description="URL検知の設定")
async def url(
    ctx: discord.ApplicationContext,
    url_threshold: Option(int, "1メッセージ内URL閾値", min_value=1),
    url_repeat_window_sec: Option(int, "同一URL監視秒数", min_value=1),
    url_repeat_threshold: Option(int, "同一URL投稿回数閾値", min_value=1),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.url_threshold = url_threshold
    config.url_repeat_window_sec = url_repeat_window_sec
    config.url_repeat_threshold = url_repeat_threshold
    config_store.save()
    await ctx.respond(
        (
            "URL設定を更新: "
            f"url_threshold={url_threshold}, "
            f"url_repeat_window_sec={url_repeat_window_sec}, "
            f"url_repeat_threshold={url_repeat_threshold}"
        ),
        ephemeral=True,
    )


@setting.command(description="メンション検知の設定")
async def mention(
    ctx: discord.ApplicationContext,
    mention_threshold: Option(int, "メンション数閾値", min_value=1),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.mention_threshold = mention_threshold
    config_store.save()
    await ctx.respond(
        f"メンション検知設定を更新: mention_threshold={mention_threshold}",
        ephemeral=True,
    )


@setting.command(description="スパム判定とタイムアウトの設定")
async def moderation(
    ctx: discord.ApplicationContext,
    score_threshold: Option(int, "スパム判定スコア閾値", min_value=1),
    timeout_minutes: Option(int, "タイムアウト分数", min_value=1),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.score_threshold = score_threshold
    config.timeout_minutes = timeout_minutes
    config_store.save()
    await ctx.respond(
        f"モデレーション設定を更新: score_threshold={score_threshold}, timeout_minutes={timeout_minutes}",
        ephemeral=True,
    )


@setting.command(name="log_channel_set", description="ログチャンネルを設定します")
async def log_channel_set(
    ctx: discord.ApplicationContext,
    channel: Option(discord.TextChannel, "ログ出力チャンネル"),
) -> None:
    guild, config = await ensure_manage_and_guild(ctx)
    if not guild or not config:
        return
    config.log_channel_id = channel.id
    config_store.save()
    await ctx.respond(f"ログチャンネルを設定しました: {channel.mention}", ephemeral=True)


@setting.command(name="log_channel_clear", description="ログチャンネル設定を解除します")
async def log_channel_clear(ctx: discord.ApplicationContext) -> None:
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
