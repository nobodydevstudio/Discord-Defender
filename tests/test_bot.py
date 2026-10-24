"""Bot-layer tests with fake Discord objects (no network)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from discord_defender.bot import DefenderBot, collect_content, human_minutes, message_to_info
from discord_defender.config import Config
from discord_defender.engine import Action, Signal, Verdict

GUILD_ID = 1
LOG_CHANNEL = 50


def make_bot(**actions) -> DefenderBot:
    config = Config()
    config.server.guild_id = GUILD_ID
    config.server.mod_log_channel_id = LOG_CHANNEL
    for key, value in actions.items():
        setattr(config.actions, key, value)
    bot = DefenderBot(config)
    bot.log_channel = MagicMock()
    bot.log_channel.send = AsyncMock()
    bot.get_channel = lambda cid: bot.log_channel if cid == LOG_CHANNEL else None
    bot.get_guild = lambda gid: SimpleNamespace(name="ASCE")
    return bot


def make_member(*, timed_out=False):
    member = MagicMock(spec=discord.Member)
    member.id = 77
    member.mention = "<@77>"
    member.created_at = datetime.now(UTC) - timedelta(days=500)
    member.joined_at = datetime.now(UTC) - timedelta(days=100)
    member.bot = False
    member.is_timed_out.return_value = timed_out
    member.timeout = AsyncMock()
    member.send = AsyncMock()
    member.__str__.return_value = "student#0"
    return member


def make_message(member, content="hello", *, snapshots=()):
    other_channel = MagicMock()
    other_channel.get_partial_message.return_value.delete = AsyncMock()
    guild = MagicMock()
    guild.id = GUILD_ID
    guild.get_channel_or_thread.return_value = other_channel
    message = MagicMock()
    message.id = 1000
    message.content = content
    message.attachments = []
    message.message_snapshots = list(snapshots)
    message.author = member
    message.guild = guild
    message.channel = SimpleNamespace(id=10, mention="<#10>", parent_id=None)
    message.created_at = datetime.now(UTC)
    message.jump_url = "https://discord.com/channels/1/10/1000"
    message.delete = AsyncMock()
    return message, other_channel


TIMEOUT_VERDICT = Verdict(
    150, Action.TIMEOUT, [Signal("phishing_domain", 100, "Known scam link", True)], related=[(11, 900), (12, 901)]
)


def test_human_minutes():
    assert human_minutes(1440) == "1 day"
    assert human_minutes(120) == "2 hours"
    assert human_minutes(45) == "45 minutes"


def test_forwarded_messages_are_scanned():
    snap = SimpleNamespace(
        content="free nitro https://evil.example",
        attachments=[SimpleNamespace(filename="a.png", size=5, content_type="image/png")],
    )
    message, _ = make_message(make_member(), content="", snapshots=[snap])
    text, attachments = collect_content(message)
    assert "free nitro" in text and attachments[0].filename == "a.png"
    info = message_to_info(message, trusted=False)
    assert info.author_joined_at is not None and info.content == text


def test_timeout_verdict_deletes_times_out_dms_and_alerts():
    bot = make_bot()
    member = make_member()
    message, other_channel = make_message(member)
    info = message_to_info(message, trusted=False)
    outcome = asyncio.run(bot.enforce(message, info, TIMEOUT_VERDICT))
    message.delete.assert_awaited_once()
    assert other_channel.get_partial_message.return_value.delete.await_count == 2
    member.timeout.assert_awaited_once()
    assert member.timeout.await_args.args[0] == timedelta(minutes=1440)
    member.send.assert_awaited_once()
    assert "two-factor" in member.send.await_args.args[0]
    assert any("Timed out" in line for line in outcome)
    embed = bot.log_channel.send.await_args.kwargs["embed"]
    view = bot.log_channel.send.await_args.kwargs["view"]
    assert "Known scam link" in embed.fields[3].value
    assert [c.item.custom_id for c in view.children] == ["dd:untimeout:77", "dd:kick:77", "dd:ban:77"]


def test_dry_run_takes_no_action_but_still_alerts():
    bot = make_bot(dry_run=True)
    member = make_member()
    message, other_channel = make_message(member)
    outcome = asyncio.run(bot.enforce(message, message_to_info(message, trusted=False), TIMEOUT_VERDICT))
    message.delete.assert_not_awaited()
    member.timeout.assert_not_awaited()
    other_channel.get_partial_message.assert_not_called()
    assert outcome[0].startswith("🧪 Dry run")
    assert bot.log_channel.send.await_args.kwargs["embed"].title.startswith("🧪 [Dry run]")


def test_flag_leaves_message_and_offers_delete_button():
    bot = make_bot()
    member = make_member()
    message, _ = make_message(member)
    verdict = Verdict(45, Action.FLAG, [Signal("brand_domain", 50, "uses the Discord name")])
    asyncio.run(bot.enforce(message, message_to_info(message, trusted=False), verdict))
    message.delete.assert_not_awaited()
    view = bot.log_channel.send.await_args.kwargs["view"]
    assert view.children[0].item.custom_id == "dd:delete:77:10:1000"


def test_alert_flood_is_collapsed_until_it_escalates():
    bot = make_bot()
    assert bot._alert_allowed(5, Action.DELETE)
    assert not bot._alert_allowed(5, Action.DELETE)
    assert not bot._alert_allowed(5, Action.FLAG)
    assert bot._alert_allowed(5, Action.TIMEOUT)
    assert bot._alert_allowed(6, Action.FLAG)


def test_already_timed_out_member_is_not_timed_out_again():
    bot = make_bot()
    member = make_member(timed_out=True)
    message, _ = make_message(member)
    asyncio.run(bot.enforce(message, message_to_info(message, trusted=False), TIMEOUT_VERDICT))
    member.timeout.assert_not_awaited()


@pytest.mark.parametrize("perm_ok", [True, False])
def test_mod_buttons_require_the_matching_permission(perm_ok):
    bot = make_bot()
    guild = MagicMock()
    guild.ban = AsyncMock()
    interaction = MagicMock()
    interaction.guild = guild
    interaction.permissions = discord.Permissions(ban_members=perm_ok)
    interaction.user = SimpleNamespace(id=9, mention="<@9>", __str__=lambda self: "mod")
    interaction.response.send_message = AsyncMock()
    interaction.response.defer = AsyncMock()
    interaction.followup.send = AsyncMock()
    interaction.message = None
    asyncio.run(bot.handle_mod_button(interaction, "ban", 77, 0, 0))
    if perm_ok:
        guild.ban.assert_awaited_once()
        assert "Banned" in interaction.followup.send.await_args.args[0]
    else:
        guild.ban.assert_not_awaited()
        assert "Ban Members" in interaction.response.send_message.await_args.args[0]


def test_inspect_end_to_end_hijacked_account():
    bot = make_bot()
    bot.is_trusted = lambda member: False
    member = make_member()
    verdicts = []
    for i, channel_id in enumerate([10, 11, 12]):
        message, _ = make_message(member, content="Giving away my PS5 to the first person who DMs me!")
        message.id = 2000 + i
        message.channel = SimpleNamespace(id=channel_id, mention=f"<#{channel_id}>", parent_id=None)
        message.webhook_id = None
        message.is_system.return_value = False
        verdicts.append(asyncio.run(bot.inspect(message)))
    assert [v.action for v in verdicts[:2]] == [Action.NONE, Action.NONE]
    assert verdicts[2].action is Action.TIMEOUT
    message.delete.assert_awaited_once()
    member.timeout.assert_awaited_once()
    assert bot.stats["scanned"] == 3 and bot.stats["timeouts"] == 1


def test_messages_from_other_servers_and_bots_are_ignored():
    bot = make_bot()
    message, _ = make_message(make_member())
    message.webhook_id = None
    message.is_system.return_value = False
    message.guild.id = 999
    assert not bot.should_inspect(message)
    message.guild.id = GUILD_ID
    message.author.bot = True
    assert not bot.should_inspect(message)


def test_trust_rules():
    bot = make_bot()
    bot.config.server.trusted_role_ids = [555]
    member = make_member()
    member.guild = SimpleNamespace(owner_id=1)
    member.guild_permissions = discord.Permissions.none()
    member.roles = [SimpleNamespace(id=1)]
    assert not bot.is_trusted(member)
    member.roles.append(SimpleNamespace(id=555))
    assert bot.is_trusted(member)
    member.roles = []
    member.guild_permissions = discord.Permissions(manage_messages=True)
    assert bot.is_trusted(member)
    assert not bot.is_trusted(SimpleNamespace(id=3))  # a plain User (not a Member)
