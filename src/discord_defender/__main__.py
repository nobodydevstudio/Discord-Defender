"""Command-line entry point: ``discord-defender`` or ``python -m discord_defender``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .blocklist import BlocklistUpdater
from .config import Config, ConfigError, load_config
from .engine import Engine, MessageInfo


def load_dotenv(path: str | Path) -> None:
    """Minimal ``.env`` support so ``DISCORD_TOKEN`` can live next to the config."""
    path = Path(path)
    if not path.is_file():
        return
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        os.environ.setdefault(key, value.strip().strip("'\""))


def setup_problems(config: Config) -> list[str]:
    problems = []
    if not config.server.guild_id:
        problems.append("[server] guild_id is not set (right-click your server icon → Copy Server ID)")
    if not config.server.mod_log_channel_id:
        problems.append("[server] mod_log_channel_id is not set; there will be no alerts")
    return problems


def scan(config: Config, texts: list[str]) -> int:
    """Score messages offline, without connecting to Discord."""
    engine = Engine(config)
    updater = BlocklistUpdater(engine.blocklist, config.links.feeds, config.links.cache_path)
    if not updater.load_cache() and config.links.feeds:
        import aiohttp

        async def fetch() -> None:
            async with aiohttp.ClientSession(trust_env=True) as session:
                await updater.refresh(session)

        print("Downloading scam-domain feeds...", file=sys.stderr)
        asyncio.run(fetch())
    print(f"Blocklist: {len(engine.blocklist):,} entries\n")
    for text in texts:
        verdict = engine.evaluate(MessageInfo(message_id=0, channel_id=0, author_id=0, content=text), track=False)
        print(f"> {text}\n  {verdict.action.name} (score {verdict.score})")
        for signal in verdict.signals:
            print(f"    +{signal.weight:<4} {signal.detail}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="discord-defender", description="Spam and phishing protection for a Discord server."
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("DEFENDER_CONFIG", "config.toml"),
        help="path to the TOML config (default: config.toml or $DEFENDER_CONFIG)",
    )
    parser.add_argument("--check-config", action="store_true", help="validate the config and exit")
    parser.add_argument(
        "--scan", nargs="+", metavar="TEXT", help="score one or more messages offline and exit (no bot token needed)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    load_dotenv(".env")
    try:
        config = load_config(args.config) if args.scan is None or Path(args.config).exists() else Config()
        Engine(config)  # also validates [weights] and custom rules
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    if args.scan is not None:
        logging.basicConfig(level=logging.WARNING)
        return scan(config, args.scan)

    problems = setup_problems(config)
    if args.check_config:
        for problem in problems:
            print(f"warning: {problem}")
        mode = "dry run" if config.actions.dry_run else "enforcing"
        print(
            f"{args.config} is valid ({mode}, {len(config.server.honeypot_channel_ids)} honeypot channel(s), "
            f"{len(config.links.feeds)} blocklist feed(s))."
        )
        return 1 if not config.server.guild_id else 0
    if not config.server.guild_id:
        print(f"Config error: {problems[0]}", file=sys.stderr)
        return 2

    token = os.environ.get("DISCORD_TOKEN", "").strip()
    if not token:
        print("DISCORD_TOKEN is not set. Put it in the environment or in a .env file.", file=sys.stderr)
        return 2

    from .bot import DefenderBot

    for problem in problems:
        logging.getLogger("discord_defender").warning(problem)
    DefenderBot(config).run(token, log_level=logging.INFO, root_logger=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
