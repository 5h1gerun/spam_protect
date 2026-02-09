from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SpamGuardConfig:
    window_sec: int = 12
    max_msg_in_window: int = 5
    duplicate_window_sec: int = 120
    dup_threshold: int = 3
    url_threshold: int = 2
    url_repeat_window_sec: int = 120
    url_repeat_threshold: int = 3
    mention_threshold: int = 4
    score_threshold: int = 6
    timeout_minutes: int = 10
    warning_threshold: int = 1
    timeout_threshold: int = 2
    ban_threshold: int = 4
    offense_window_sec: int = 86400
    ban_enabled: bool = False
    phishing_domains: list[str] = field(default_factory=list)
    suspicious_tlds: list[str] = field(
        default_factory=lambda: [
            "zip",
            "mov",
            "top",
            "click",
            "xyz",
            "gq",
            "tk",
        ]
    )
    allow_domains: list[str] = field(default_factory=list)
    raid_join_window_sec: int = 20
    raid_join_threshold: int = 6
    raid_message_window_sec: int = 20
    raid_new_user_message_threshold: int = 8
    new_member_window_sec: int = 1800
    verify_enabled: bool = True
    verify_channel_id: int | None = None
    verify_unverified_role_id: int | None = None
    verify_member_role_id: int | None = None
    verify_timeout_minutes: int = 10
    verify_max_attempts: int = 3
    verify_fail_action: str = "kick"
    log_channel_id: int | None = None
    log_viewer_role_id: int | None = None
    ignore_role_ids: list[int] = field(default_factory=list)
    ignore_channel_ids: list[int] = field(default_factory=list)
    whitelist_user_ids: list[int] = field(default_factory=list)
    whitelist_role_ids: list[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "SpamGuardConfig":
        # Ignore unknown keys so old/new config versions can coexist safely.
        known = {key: values[key] for key in cls.__dataclass_fields__ if key in values}
        return cls(**known)


class ConfigStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.default_config = SpamGuardConfig()
        self.guild_configs: dict[int, SpamGuardConfig] = {}

    def load(self) -> None:
        if not self.path.exists():
            self.save()
            return

        data = json.loads(self.path.read_text(encoding="utf-8"))

        # Backward-compatible migration from old single-config shape.
        if "defaults" not in data and "guilds" not in data:
            self.default_config = SpamGuardConfig.from_dict(data)
            self.guild_configs = {}
            self.save()
            return

        defaults = data.get("defaults", {})
        guilds = data.get("guilds", {})
        self.default_config = SpamGuardConfig.from_dict(defaults)
        self.guild_configs = {
            int(guild_id): SpamGuardConfig.from_dict(cfg)
            for guild_id, cfg in guilds.items()
        }

    def save(self) -> None:
        payload = {
            "defaults": asdict(self.default_config),
            "guilds": {
                str(guild_id): asdict(cfg)
                for guild_id, cfg in sorted(self.guild_configs.items())
            },
        }
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def get_guild_config(self, guild_id: int) -> SpamGuardConfig:
        if guild_id not in self.guild_configs:
            self.guild_configs[guild_id] = SpamGuardConfig(
                **deepcopy(asdict(self.default_config))
            )
            self.save()
        return self.guild_configs[guild_id]

    def set_guild_value(self, guild_id: int, key: str, value: Any) -> bool:
        cfg = self.get_guild_config(guild_id)
        if not hasattr(cfg, key):
            return False
        setattr(cfg, key, value)
        self.save()
        return True
