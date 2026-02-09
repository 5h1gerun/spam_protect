import datetime as dt
import os
import re

import discord
from discord.ext import commands
from dotenv import load_dotenv

from spamguard.commands import register_commands
from spamguard.config import ConfigStore
from spamguard.security_runtime import SecurityRuntime
from spamguard.verification import VerificationManager

load_dotenv()

config_path = os.getenv("SPAMGUARD_CONFIG_PATH", "config.json")
config_store = ConfigStore(config_path)
config_store.load()

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(intents=intents)
security_runtime = SecurityRuntime(config_store)
verification_manager = VerificationManager(bot, config_store, security_runtime)
register_commands(bot, config_store, security_runtime, verification_manager)


@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user}")


@bot.event
async def on_member_join(member: discord.Member) -> None:
    detector = security_runtime.resolve_detector(member.guild.id)
    joined_at = member.joined_at or dt.datetime.now(dt.timezone.utc)
    detector.register_join(member.id, joined_at)
    await verification_manager.handle_member_join(member)


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot or not message.guild:
        return

    if verification_manager.is_pending(message.guild.id, message.author.id):
        config = config_store.get_guild_config(message.guild.id)
        verify_channel_id = config.verify_channel_id
        if verify_channel_id and message.channel.id == verify_channel_id:
            text = message.content.strip()
            match = re.fullmatch(r"(?:verify\s+)?(\d{6})", text, flags=re.IGNORECASE)
            if match:
                _, result_message = await verification_manager.verify_code(
                    message.author,
                    match.group(1),
                )
                try:
                    await message.channel.send(
                        f"{message.author.mention} {result_message}"
                    )
                except (discord.Forbidden, discord.HTTPException):
                    pass
                try:
                    await message.delete()
                except (discord.Forbidden, discord.HTTPException):
                    pass
                return

        try:
            await message.delete()
        except (discord.Forbidden, discord.HTTPException):
            pass
        return

    await security_runtime.handle_message(message)
    await bot.process_commands(message)


def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise RuntimeError("DISCORD_TOKEN is not set")
    bot.run(token)


if __name__ == "__main__":
    main()
