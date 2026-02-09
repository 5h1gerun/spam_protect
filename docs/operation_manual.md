# Operation Manual

## 1. Startup
- Ensure `.env` is configured.
- Run `python bot.py`.

## 2. Configuration
- Check settings: `/spamguard status`
- Update rapid-posting rules: `/spamguard setting rapid`
- Update duplicate-message rules: `/spamguard setting duplicate`
- Update URL rules: `/spamguard setting url`
- Update mention rule: `/spamguard setting mention`
- Update moderation rule: `/spamguard setting moderation`
- Set log channel: `/spamguard setting log_channel_set`
- Clear log channel: `/spamguard setting log_channel_clear`
- Add ignore target: `/spamguard ignore add role:<role>` or `/spamguard ignore add channel:<channel>`
- Remove ignore target: `/spamguard ignore remove role:<role>` or `/spamguard ignore remove channel:<channel>`

## 3. Incident Handling
- Spam actions are logged to `log_channel_id` if configured.
- If message deletion or timeout fails due to missing permission, bot continues running.

## 4. Maintenance
- Backup `config.json` regularly.
- Update dependencies periodically and run tests.
