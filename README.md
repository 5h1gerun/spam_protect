# SpamGuard Bot (py-cord)

Discord server spam moderation bot based on the requirements in `Readme.md`.

## Features
- Spam scoring:
  - rapid posting
  - duplicate messages
  - URL flooding
  - excessive mentions
  - new account bonus score
- Auto moderation:
  - delete spam message
  - timeout offender
  - write moderation log
- Runtime configuration:
  - `/spamguard status`
  - `/spamguard setting rapid`
  - `/spamguard setting duplicate`
  - `/spamguard setting url`
  - `/spamguard setting mention`
  - `/spamguard setting moderation`
  - `/spamguard setting log_channel_set`
  - `/spamguard setting log_channel_clear`
  - `/spamguard ignore add <role/channel>`
  - `/spamguard ignore remove <role/channel>`

## Setup
1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Create `.env`:
```bash
cp .env.example .env
```
3. Create `config.json` from template:
```bash
cp config.example.json config.json
```
4. Set bot token in `.env`:
```env
DISCORD_TOKEN=your_token
SPAMGUARD_CONFIG_PATH=config.json
```
5. Run:
```bash
python bot.py
```

## Required Discord Permissions
- Read Messages
- Message Content Intent
- Manage Messages
- Moderate Members
- Send Messages

## Default Parameters
See `config.example.json` for default values.

## Test
```bash
pytest -q
```
