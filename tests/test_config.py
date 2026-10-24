from pathlib import Path

import pytest

from discord_defender.__main__ import main
from discord_defender.config import ConfigError, config_from_dict, load_config

ROOT = Path(__file__).resolve().parent.parent


def test_example_config_is_valid():
    config = load_config(ROOT / "config.example.toml")
    assert config.actions.timeout_score == 100
    assert len(config.links.feeds) == 2


def test_ids_may_be_quoted_strings():
    config = config_from_dict({"server": {"guild_id": "123", "trusted_role_ids": ["4", 5]}})
    assert config.server.guild_id == 123 and config.server.trusted_role_ids == [4, 5]


@pytest.mark.parametrize(
    "data",
    [
        {"server": {"guild": 1}},  # typo
        {"nope": {}},
        {"actions": {"dry_run": "yes"}},
        {"actions": {"flag_score": 80, "delete_score": 70}},
        {"actions": {"honeypot_action": "explode"}},
        {"actions": {"timeout_minutes": 99999999}},
        {"links": {"extra_brands": [{"name": "X"}]}},
        {"weights": {"server_invite": "lots"}},
    ],
)
def test_invalid_configs_are_rejected_with_a_message(data):
    with pytest.raises(ConfigError):
        config_from_dict(data)


def test_floats_accept_whole_numbers():
    assert config_from_dict({"newcomers": {"member_hours": 1}}).newcomers.member_hours == 1.0


def test_extra_brand_is_used():
    from discord_defender.engine import Engine

    config = config_from_dict(
        {"links": {"extra_brands": [{"name": "State U", "keywords": ["stateuniv"], "domains": ["stateuniv.edu"]}]}}
    )
    links = Engine(config).links
    for host in ("stateuniv-login.com", "stateunlv.edu.verify.ru", "stateuniv.edu.sso-portal.net"):
        finding = links.classify_lookalike(host)
        assert finding is not None and finding.kind == "lookalike_domain", host
    assert links.classify_lookalike("canvas.stateuniv.edu") is None


def test_check_config_cli(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[server]\nguild_id = 1\nmod_log_channel_id = 2\n")
    assert main(["--config", str(cfg), "--check-config"]) == 0
    assert "is valid" in capsys.readouterr().out
    cfg.write_text("[server]\nguild = 1\n")
    assert main(["--config", str(cfg), "--check-config"]) == 2
