"""Configuration: a TOML file for settings, the environment for the bot token."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """The configuration file is missing or invalid."""


DEFAULT_FEEDS = [
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
    "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.txt",
]
DEFAULT_ALLOWLIST = ["discord.js.org", "discordjs.guide", "discordpy.readthedocs.io"]
HONEYPOT_ACTIONS = ("timeout", "softban", "ban")
MAX_TIMEOUT_MINUTES = 28 * 24 * 60  # Discord's limit


@dataclass
class ServerConfig:
    guild_id: int = 0
    mod_log_channel_id: int = 0
    trusted_role_ids: list[int] = field(default_factory=list)
    honeypot_channel_ids: list[int] = field(default_factory=list)
    ignored_channel_ids: list[int] = field(default_factory=list)
    allowed_invite_codes: list[str] = field(default_factory=list)


@dataclass
class ActionConfig:
    dry_run: bool = False
    flag_score: int = 40
    delete_score: int = 70
    timeout_score: int = 100
    timeout_minutes: int = 24 * 60
    purge_minutes: int = 15
    dm_user: bool = True
    honeypot_action: str = "timeout"
    alert_cooldown_seconds: int = 120


@dataclass
class NewcomerConfig:
    member_hours: float = 72.0
    account_days: float = 30.0
    bonus: int = 30


@dataclass
class DuplicateConfig:
    window_seconds: float = 120.0
    channel_threshold: int = 3
    repeat_threshold: int = 5
    min_length: int = 15


@dataclass
class BrandConfig:
    name: str = ""
    keywords: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


@dataclass
class LinkConfig:
    feeds: list[str] = field(default_factory=lambda: list(DEFAULT_FEEDS))
    refresh_hours: float = 6.0
    cache_path: str = "data/blocklist-cache.txt"
    blocklist: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    extra_brands: list[BrandConfig] = field(default_factory=list)


@dataclass
class RuleConfig:
    name: str = ""
    pattern: str = ""
    weight: int = 0
    description: str = ""


@dataclass
class HeuristicsConfig:
    enabled: bool = True
    max_score: int = 90
    disabled_rules: list[str] = field(default_factory=list)
    extra_rules: list[RuleConfig] = field(default_factory=list)


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    actions: ActionConfig = field(default_factory=ActionConfig)
    newcomers: NewcomerConfig = field(default_factory=NewcomerConfig)
    duplicates: DuplicateConfig = field(default_factory=DuplicateConfig)
    links: LinkConfig = field(default_factory=LinkConfig)
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    weights: dict[str, int] = field(default_factory=dict)


_NESTED_LISTS = {"extra_brands": BrandConfig, "extra_rules": RuleConfig}


def _coerce(name: str, value: Any, default: Any, where: str) -> Any:
    if name.endswith("_ids") and isinstance(value, list):
        try:
            return [int(v) for v in value]
        except (TypeError, ValueError):
            raise ConfigError(f"{where}: every entry must be a numeric Discord ID") from None
    if name.endswith("_id") and isinstance(value, str) and value.isdigit():
        return int(value)
    if name in _NESTED_LISTS:
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected a list of tables")
        return [_section(_NESTED_LISTS[name], item, f"{where}[{i}]") for i, item in enumerate(value)]
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected true or false")
    elif isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: expected a whole number")
    elif isinstance(default, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected a number")
        return float(value)
    elif isinstance(default, str):
        if not isinstance(value, str):
            raise ConfigError(f"{where}: expected text")
    elif isinstance(default, list):
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected a list")
    return value


def _section(cls: type, raw: Any, where: str) -> Any:
    if not isinstance(raw, dict):
        raise ConfigError(f"[{where}] must be a table")
    defaults = cls()
    known = {f.name for f in fields(cls)}
    kwargs = {}
    for key, value in raw.items():
        if key not in known:
            raise ConfigError(f"Unknown setting '{key}' in [{where}] (valid: {', '.join(sorted(known))})")
        kwargs[key] = _coerce(key, value, getattr(defaults, key), f"{where}.{key}")
    return cls(**kwargs)


def config_from_dict(data: dict[str, Any]) -> Config:
    known = {f.name for f in fields(Config)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"Unknown section(s): {', '.join(sorted(unknown))}")
    weights = data.get("weights", {})
    if not isinstance(weights, dict) or not all(
        isinstance(v, int) and not isinstance(v, bool) for v in weights.values()
    ):
        raise ConfigError("[weights] must map signal names to whole numbers")
    config = Config(
        server=_section(ServerConfig, data.get("server", {}), "server"),
        actions=_section(ActionConfig, data.get("actions", {}), "actions"),
        newcomers=_section(NewcomerConfig, data.get("newcomers", {}), "newcomers"),
        duplicates=_section(DuplicateConfig, data.get("duplicates", {}), "duplicates"),
        links=_section(LinkConfig, data.get("links", {}), "links"),
        heuristics=_section(HeuristicsConfig, data.get("heuristics", {}), "heuristics"),
        weights=dict(weights),
    )
    _validate(config)
    return config


def _validate(config: Config) -> None:
    a = config.actions
    if not 0 < a.flag_score <= a.delete_score <= a.timeout_score:
        raise ConfigError("[actions] scores must satisfy 0 < flag_score <= delete_score <= timeout_score")
    if not 1 <= a.timeout_minutes <= MAX_TIMEOUT_MINUTES:
        raise ConfigError(f"[actions] timeout_minutes must be between 1 and {MAX_TIMEOUT_MINUTES}")
    if a.honeypot_action not in HONEYPOT_ACTIONS:
        raise ConfigError(f"[actions] honeypot_action must be one of {', '.join(HONEYPOT_ACTIONS)}")
    d = config.duplicates
    if d.channel_threshold < 2 or d.repeat_threshold < 2:
        raise ConfigError("[duplicates] thresholds must be at least 2")
    for i, brand in enumerate(config.links.extra_brands):
        if not brand.name or not brand.keywords or not brand.domains:
            raise ConfigError(f"[[links.extra_brands]] #{i + 1} needs name, keywords and domains")
    for i, rule in enumerate(config.heuristics.extra_rules):
        if not rule.name or not rule.pattern:
            raise ConfigError(f"[[heuristics.extra_rules]] #{i + 1} needs a name and a pattern")


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        raise ConfigError(
            f"Config file not found: {path}. Copy config.example.toml to {path} and fill it in."
        ) from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return config_from_dict(data)
