import json
from pathlib import Path

from spamguard.config import ConfigStore


def test_load_legacy_single_config_and_migrate(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"window_sec": 12, "score_threshold": 7, "log_channel_id": 12345}),
        encoding="utf-8",
    )

    store = ConfigStore(str(config_path))
    store.load()

    assert store.default_config.score_threshold == 7
    assert store.default_config.log_channel_id == 12345
    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert "defaults" in data
    assert "guilds" in data


def test_guild_specific_value_is_isolated(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    store = ConfigStore(str(config_path))
    store.load()

    guild_a = 1001
    guild_b = 2002

    assert store.get_guild_config(guild_a).log_channel_id is None
    assert store.get_guild_config(guild_b).log_channel_id is None

    ok = store.set_guild_value(guild_a, "log_channel_id", 99999)
    assert ok
    ok_role = store.set_guild_value(guild_a, "log_viewer_role_id", 77777)
    assert ok_role

    assert store.get_guild_config(guild_a).log_channel_id == 99999
    assert store.get_guild_config(guild_a).log_viewer_role_id == 77777
    assert store.get_guild_config(guild_b).log_channel_id is None
    assert store.get_guild_config(guild_b).log_viewer_role_id is None

    reloaded = ConfigStore(str(config_path))
    reloaded.load()
    assert reloaded.get_guild_config(guild_a).log_channel_id == 99999
    assert reloaded.get_guild_config(guild_a).log_viewer_role_id == 77777
    assert reloaded.get_guild_config(guild_b).log_channel_id is None
    assert reloaded.get_guild_config(guild_b).log_viewer_role_id is None
