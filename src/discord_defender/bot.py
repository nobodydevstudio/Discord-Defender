"""Discord glue: gateway events in, moderation actions and mod-log alerts out."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter, OrderedDict
from datetime import UTC, datetime, timedelta

import aiohttp
import discord
from discord import app_commands, ui

from .blocklist import BlocklistUpdater
from .config import Config
from .engine import Action, Attachment, Engine, MessageInfo, Verdict
from .links import extract_invite_codes
from .text import defang

log = logging.getLogger(__name__)

ACTION_LABELS = {
    Action.FLAG: "Flagged for review (message left up)",
    Action.DELETE: "Message deleted",
    Action.TIMEOUT: "Message deleted and member timed out",
}
ACTION_COLORS = {
    Action.NONE: discord.Color.blurple(),
    Action.FLAG: discord.Color.gold(),
    Action.DELETE: discord.Color.orange(),
    Action.TIMEOUT: discord.Color.red(),
}
BUTTON_PERMISSIONS = {
    "ban": "ban_members",
    "kick": "kick_members",
    "timeout": "moderate_members",
    "untimeout": "moderate_members",
    "delete": "manage_messages",
}


def human_minutes(minutes: int) -> str:
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day" + ("s" if days != 1 else "")
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour" + ("s" if hours != 1 else "")
    return f"{minutes} minute" + ("s" if minutes != 1 else "")


def compromised_account_dm(guild_name: str, outcome: str) -> str:
    return (
        f"Hi! Discord Defender in **{guild_name}** removed your recent message(s) and {outcome}, "
        "because they matched patterns used by spam and phishing bots. The server moderators "
        "have been notified and will review it.\n\n"
        "**If you didn't send those messages, your account has probably been taken over.** "
        'Most takeovers come from a stolen login token, often from a "game", "tool" or file '
        "someone asked you to try. To lock the attacker out:\n"
        "1. Change your Discord password (this signs out every other session).\n"
        "2. Turn on two-factor authentication (User Settings → My Account).\n"
        "3. Remove anything you don't recognise under User Settings → Authorized Apps.\n"
        "4. Run a malware scan on the computer you use Discord on.\n\n"
        "If this was a mistake, just message one of the server's moderators."
    )


def collect_content(message: discord.Message) -> tuple[str, list[Attachment]]:
    """Text and attachments of a message, including forwarded message snapshots."""
    parts = [message.content or ""]
    attachments = [Attachment(a.filename, a.size, a.content_type) for a in message.attachments]
    for snapshot in getattr(message, "message_snapshots", None) or ():
        parts.append(snapshot.content or "")
        attachments += [Attachment(a.filename, a.size, a.content_type) for a in snapshot.attachments]
    return "\n".join(p for p in parts if p), attachments


def message_to_info(
    message: discord.Message,
    *,
    trusted: bool,
    own_invites: frozenset[str] = frozenset(),
    is_edit: bool = False,
) -> MessageInfo:
    content, attachments = collect_content(message)
    author = message.author
    joined_at = getattr(author, "joined_at", None)
    return MessageInfo(
        message_id=message.id,
        channel_id=message.channel.id,
        parent_channel_id=getattr(message.channel, "parent_id", None),
        author_id=author.id,
        content=content,
        created_at=message.created_at.timestamp(),
        attachments=tuple(attachments),
        author_joined_at=joined_at.timestamp() if joined_at else None,
        author_created_at=author.created_at.timestamp(),
        author_trusted=trusted,
        own_invite_codes=own_invites,
        is_edit=is_edit,
    )


def build_alert_embed(
    *,
    title: str,
    author: discord.abc.User,
    channel_mention: str,
    content: str,
    attachments: list[Attachment],
    verdict: Verdict,
    outcome: list[str],
    message_id: int | None = None,
    jump_url: str | None = None,
) -> discord.Embed:
    embed = discord.Embed(
        title=title,
        description=f"```\n{defang(content) or '(no text)'}\n```",
        color=ACTION_COLORS[verdict.action],
        timestamp=datetime.now(UTC),
    )
    embed.add_field(name="Member", value=f"{author.mention} `{author}`\nID {author.id}", inline=True)
    created = discord.utils.format_dt(author.created_at, "R")
    joined_at = getattr(author, "joined_at", None)
    joined = discord.utils.format_dt(joined_at, "R") if joined_at else "unknown"
    embed.add_field(name="Account", value=f"Created {created}\nJoined {joined}", inline=True)
    where = channel_mention + (f"\n[Jump to message]({jump_url})" if jump_url else "")
    embed.add_field(name="Channel", value=where, inline=True)
    reasons = "\n".join(f"• {s.detail} (+{s.weight})" for s in verdict.signals) or "No automatic signals"
    embed.add_field(name=f"Why (score {verdict.score})", value=reasons[:1024], inline=False)
    if attachments:
        names = ", ".join(f"`{a.filename}`" for a in attachments[:10])
        embed.add_field(name="Attachments", value=names[:1024], inline=False)
    if outcome:
        embed.add_field(name="Outcome", value="\n".join(outcome)[:1024], inline=False)
    if message_id:
        embed.set_footer(text=f"Message ID {message_id}")
    return embed


class ModButton(ui.DynamicItem[ui.Button], template=r"dd:(?P<act>[a-z]+):(?P<uid>\d+)(?::(?P<cid>\d+):(?P<mid>\d+))?"):
    """Alert buttons. All state lives in the custom_id, so they keep working after restarts."""

    STYLES = {
        "ban": ("Ban", discord.ButtonStyle.danger),
        "kick": ("Kick", discord.ButtonStyle.secondary),
        "timeout": ("Time out", discord.ButtonStyle.secondary),
        "untimeout": ("False alarm: lift timeout", discord.ButtonStyle.success),
        "delete": ("Delete message", discord.ButtonStyle.secondary),
    }

    def __init__(self, act: str, user_id: int, channel_id: int = 0, message_id: int = 0) -> None:
        label, style = self.STYLES[act]
        custom_id = f"dd:{act}:{user_id}" + (f":{channel_id}:{message_id}" if message_id else "")
        super().__init__(ui.Button(label=label, style=style, custom_id=custom_id))
        self.act, self.user_id, self.channel_id, self.message_id = act, user_id, channel_id, message_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):  # noqa: ARG003 - discord.py signature
        g = match.groupdict()
        if g["act"] not in cls.STYLES:
            raise ValueError(f"unknown button action {g['act']!r}")
        return cls(g["act"], int(g["uid"]), int(g["cid"] or 0), int(g["mid"] or 0))

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.client.handle_mod_button(  # type: ignore[attr-defined]
            interaction, self.act, self.user_id, self.channel_id, self.message_id
        )


def alert_view(user_id: int, buttons: list[str], channel_id: int = 0, message_id: int = 0) -> ui.View:
    view = ui.View(timeout=None)
    for act in buttons:
        if act == "delete":
            view.add_item(ModButton(act, user_id, channel_id, message_id))
        else:
            view.add_item(ModButton(act, user_id))
    return view


class DefenderBot(discord.Client):
    def __init__(self, config: Config) -> None:
        intents = discord.Intents.default()
        intents.message_content = True  # privileged: enable it in the Developer Portal
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.config = config
        self.engine = Engine(config)
        self.updater = BlocklistUpdater(self.engine.blocklist, config.links.feeds, config.links.cache_path)
        self.tree = app_commands.CommandTree(self)
        self.stats: Counter[str] = Counter()
        self.started_at = time.time()
        self._http_session: aiohttp.ClientSession | None = None
        self._refresh_task: asyncio.Task | None = None
        self._invite_cache: OrderedDict[str, int | None] = OrderedDict()
        self._last_alert: dict[int, tuple[float, Action]] = {}
        self._last_report: dict[int, float] = {}

    # ----------------------------------------------------------------- lifecycle

    async def setup_hook(self) -> None:
        self.add_dynamic_items(ModButton)
        self.updater.load_cache()
        self._http_session = aiohttp.ClientSession(trust_env=True)
        self._refresh_task = asyncio.create_task(self._refresh_blocklist_forever())
        guild = discord.Object(id=self.config.server.guild_id)
        self.tree.add_command(
            app_commands.ContextMenu(name="Report to moderators", callback=self.report_message), guild=guild
        )
        self.tree.add_command(DefenderCommands(self), guild=guild)
        try:
            await self.tree.sync(guild=guild)
        except discord.HTTPException as exc:
            # Protection still works; only the slash/right-click commands are missing.
            log.warning(
                "Could not register commands (was the bot invited with the applications.commands scope?): %s", exc
            )

    async def close(self) -> None:
        if self._refresh_task:
            self._refresh_task.cancel()
        if self._http_session:
            await self._http_session.close()
        await super().close()

    async def _refresh_blocklist_forever(self) -> None:
        while True:
            try:
                await self.updater.refresh(self._http_session)
            except Exception:  # noqa: BLE001 - keep the loop alive
                log.exception("Blocklist refresh crashed")
            await asyncio.sleep(max(self.config.links.refresh_hours, 0.25) * 3600)

    async def on_ready(self) -> None:
        guild = self.get_guild(self.config.server.guild_id)
        mode = "DRY RUN (no actions taken)" if self.config.actions.dry_run else "enforcing"
        if guild is None:
            log.error(
                "Logged in as %s but not in guild %s - check guild_id and invite the bot",
                self.user,
                self.config.server.guild_id,
            )
            return
        log.info("Logged in as %s, protecting %s (%s), mode: %s", self.user, guild.name, guild.id, mode)
        if self.get_channel(self.config.server.mod_log_channel_id) is None:
            log.warning(
                "mod_log_channel_id %s not found - alerts will only go to the log",
                self.config.server.mod_log_channel_id,
            )
        me = guild.me
        missing = [
            p
            for p in ("manage_messages", "moderate_members", "read_message_history", "embed_links")
            if not getattr(me.guild_permissions, p)
        ]
        if missing:
            log.warning("Bot role is missing permissions: %s", ", ".join(missing))

    # ------------------------------------------------------------------ messages

    async def on_message(self, message: discord.Message) -> None:
        await self.inspect(message)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if before.content != after.content:  # ignore embed/link-preview updates
            await self.inspect(after, is_edit=True)

    def is_trusted(self, member: discord.abc.User) -> bool:
        if not isinstance(member, discord.Member):
            return False
        if member.guild.owner_id == member.id:
            return True
        perms = member.guild_permissions
        if perms.administrator or perms.manage_guild or perms.manage_messages or perms.moderate_members:
            return True
        trusted_roles = set(self.config.server.trusted_role_ids)
        return any(role.id in trusted_roles for role in member.roles)

    def should_inspect(self, message: discord.Message) -> bool:
        guild = message.guild
        if guild is None or guild.id != self.config.server.guild_id:
            return False
        if message.author.bot or message.webhook_id is not None or message.is_system():
            return False
        ignored = set(self.config.server.ignored_channel_ids)
        return message.channel.id not in ignored and getattr(message.channel, "parent_id", None) not in ignored

    async def inspect(self, message: discord.Message, *, is_edit: bool = False) -> Verdict | None:
        if not self.should_inspect(message):
            return None
        trusted = self.is_trusted(message.author)
        text, _ = collect_content(message)
        codes = extract_invite_codes(text)
        own = await self.own_invite_codes(codes) if codes and not trusted else frozenset()
        info = message_to_info(message, trusted=trusted, own_invites=own, is_edit=is_edit)
        verdict = self.engine.evaluate(info)
        self.stats["scanned"] += 1
        if verdict.action is Action.NONE:
            return verdict
        log.info(
            "%s by %s (%s) in #%s: %s",
            "Edit" if is_edit else "Message",
            message.author,
            message.author.id,
            getattr(message.channel, "name", message.channel.id),
            verdict.summary(),
        )
        await self.enforce(message, info, verdict)
        return verdict

    async def own_invite_codes(self, codes: list[str]) -> frozenset[str]:
        """Which of ``codes`` point at our own server (those are fine to post)."""
        own = set()
        for code in codes[:3]:
            if code in self._invite_cache:
                guild_id = self._invite_cache[code]
            else:
                try:
                    invite = await asyncio.wait_for(
                        self.fetch_invite(code, with_counts=False, with_expiration=False), timeout=3
                    )
                    guild_id = invite.guild.id if invite.guild else None
                except discord.NotFound:
                    guild_id = None
                except (TimeoutError, discord.HTTPException):
                    continue  # unknown; treat as external but don't cache
                self._invite_cache[code] = guild_id
                if len(self._invite_cache) > 1000:
                    self._invite_cache.popitem(last=False)
            if guild_id == self.config.server.guild_id:
                own.add(code)
        return frozenset(own)

    # --------------------------------------------------------------- enforcement

    async def enforce(self, message: discord.Message, info: MessageInfo, verdict: Verdict) -> list[str]:
        cfg = self.config.actions
        guild = message.guild
        member = message.author if isinstance(message.author, discord.Member) else None
        honeypot = verdict.has("honeypot")
        outcome: list[str] = []

        if cfg.dry_run:
            planned = ACTION_LABELS[verdict.action]
            if honeypot and cfg.honeypot_action != "timeout":
                planned = f"Honeypot {cfg.honeypot_action}"
            outcome.append(f"🧪 Dry run - would have done: {planned}")
            if verdict.related:
                outcome.append(f"🧪 Would also delete {len(verdict.related)} related message(s)")
            self.stats["dry_run"] += 1
        else:
            if verdict.action >= Action.DELETE:
                outcome.append(await self._delete(message))
                if verdict.related:
                    removed = await self._delete_related(guild, verdict.related)
                    outcome.append(f"🧹 Removed {removed} related message(s) from the last few minutes")
                self.stats["deleted"] += 1
            if honeypot and cfg.honeypot_action in ("softban", "ban"):
                outcome.append(
                    await self._ban_from_honeypot(guild, message.author, softban=cfg.honeypot_action == "softban")
                )
            elif verdict.action >= Action.TIMEOUT and member is not None:
                outcome.append(
                    await self._timeout(member, cfg.timeout_minutes, "Discord Defender: " + verdict.summary()[:400])
                )
            if verdict.action == Action.FLAG:
                self.stats["flagged"] += 1
        if honeypot:
            self.stats["honeypot"] += 1

        await self.send_alert(message, info, verdict, outcome)
        return outcome

    async def _delete(self, message: discord.Message) -> str:
        try:
            await message.delete()
            return "🗑️ Message deleted"
        except discord.NotFound:
            return "🗑️ Message was already gone"
        except discord.Forbidden:
            return "⚠️ Could not delete the message (missing Manage Messages)"

    async def _delete_related(self, guild: discord.Guild, related: list[tuple[int, int]]) -> int:
        async def delete_one(channel_id: int, message_id: int) -> bool:
            channel = guild.get_channel_or_thread(channel_id)
            if channel is None or not hasattr(channel, "get_partial_message"):
                return False
            try:
                await channel.get_partial_message(message_id).delete()
                return True
            except discord.HTTPException:
                return False

        results = await asyncio.gather(*(delete_one(c, m) for c, m in related[:50]))
        return sum(results)

    async def _timeout(self, member: discord.Member, minutes: int, reason: str) -> str:
        if member.is_timed_out():
            return "⏸️ Member was already timed out"
        try:
            await member.timeout(timedelta(minutes=minutes), reason=reason)
        except discord.Forbidden:
            return "⚠️ Could not time out (move the bot's role above theirs and grant Moderate Members)"
        except discord.HTTPException as exc:
            return f"⚠️ Timeout failed: {exc.text or exc}"
        self.stats["timeouts"] += 1
        text = f"⏸️ Timed out for {human_minutes(minutes)}"
        if self.config.actions.dm_user:
            text += await self._dm(member, f"you've been timed out for {human_minutes(minutes)}")
        return text

    async def _ban_from_honeypot(self, guild: discord.Guild, user: discord.abc.User, *, softban: bool) -> str:
        if self.config.actions.dm_user:
            outcome = (
                "removed you from the server (you can rejoin once your account is secure)"
                if softban
                else "banned you from the server"
            )
            await self._dm(user, outcome)
        try:
            await guild.ban(user, reason="Discord Defender: posted in honeypot channel", delete_message_seconds=3600)
            if softban:
                await guild.unban(user, reason="Discord Defender: softban (messages purged)")
                return "👢 Softbanned (kicked, last hour of messages purged; may rejoin)"
            return "🔨 Banned (last hour of messages purged)"
        except discord.Forbidden:
            return "⚠️ Could not ban (missing Ban Members or role too low)"
        except discord.HTTPException as exc:
            return f"⚠️ Ban failed: {exc.text or exc}"

    async def _dm(self, user: discord.abc.User, outcome: str) -> str:
        guild = self.get_guild(self.config.server.guild_id)
        try:
            await user.send(compromised_account_dm(guild.name if guild else "this server", outcome))
            return " (member was sent account-security tips)"
        except discord.HTTPException:
            return " (member's DMs are closed)"

    # -------------------------------------------------------------------- alerts

    def _alert_allowed(self, author_id: int, action: Action) -> bool:
        """Collapse alert floods: one alert per author per cooldown unless it escalates."""
        now = time.monotonic()
        last = self._last_alert.get(author_id)
        if last and now - last[0] < self.config.actions.alert_cooldown_seconds and action <= last[1]:
            return False
        self._last_alert[author_id] = (now, action)
        if len(self._last_alert) > 5000:
            cutoff = now - self.config.actions.alert_cooldown_seconds
            self._last_alert = {k: v for k, v in self._last_alert.items() if v[0] >= cutoff}
        return True

    async def send_alert(
        self, message: discord.Message, info: MessageInfo, verdict: Verdict, outcome: list[str]
    ) -> None:
        if not self._alert_allowed(message.author.id, verdict.action):
            self.stats["alerts_suppressed"] += 1
            return
        channel = self.get_channel(self.config.server.mod_log_channel_id)
        if channel is None:
            return
        title = "🍯 Honeypot triggered" if verdict.has("honeypot") else f"🛡️ {ACTION_LABELS[verdict.action]}"
        if self.config.actions.dry_run:
            title = "🧪 [Dry run] " + title
        still_there = verdict.action == Action.FLAG or self.config.actions.dry_run
        embed = build_alert_embed(
            title=title,
            author=message.author,
            channel_mention=message.channel.mention,
            content=info.content,
            attachments=list(info.attachments),
            verdict=verdict,
            outcome=outcome,
            message_id=message.id,
            jump_url=message.jump_url if still_there else None,
        )
        if verdict.action >= Action.TIMEOUT and not self.config.actions.dry_run:
            buttons = ["untimeout", "kick", "ban"]
        else:
            buttons = ["delete", "timeout", "ban"] if still_there else ["timeout", "kick", "ban"]
        view = alert_view(message.author.id, buttons, message.channel.id, message.id)
        try:
            await channel.send(embed=embed, view=view)
        except discord.HTTPException as exc:
            log.warning("Could not post alert to mod log: %s", exc)

    # ------------------------------------------------------------- mod buttons

    async def handle_mod_button(
        self, interaction: discord.Interaction, act: str, user_id: int, channel_id: int, message_id: int
    ) -> None:
        guild = interaction.guild
        perm = BUTTON_PERMISSIONS[act]
        if guild is None or not getattr(interaction.permissions, perm, False):
            await interaction.response.send_message(
                f"You need the **{perm.replace('_', ' ').title()}** permission for that.", ephemeral=True
            )
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        reason = f"Discord Defender: {act} by {interaction.user} ({interaction.user.id})"
        try:
            result = await self._run_mod_action(guild, act, user_id, channel_id, message_id, reason)
        except discord.NotFound:
            result = "Nothing to do - the member or message is already gone."
        except discord.Forbidden:
            result = "I'm not allowed to do that. Check that my role is above theirs and has the permission."
        if interaction.message is not None and interaction.message.embeds:
            embed = interaction.message.embeds[0]
            note = f"{result} - {interaction.user.mention} {discord.utils.format_dt(discord.utils.utcnow(), 'R')}"
            for i, f in enumerate(embed.fields):
                if f.name == "Moderator actions":
                    embed.set_field_at(i, name=f.name, value=(f.value + "\n" + note)[-1024:], inline=False)
                    break
            else:
                embed.add_field(name="Moderator actions", value=note[:1024], inline=False)
            try:
                await interaction.message.edit(embed=embed)
            except discord.HTTPException:
                pass
        await interaction.followup.send(result, ephemeral=True)

    async def _run_mod_action(
        self, guild: discord.Guild, act: str, user_id: int, channel_id: int, message_id: int, reason: str
    ) -> str:
        user = discord.Object(id=user_id)
        if act == "ban":
            await guild.ban(user, reason=reason, delete_message_seconds=86400)
            return f"🔨 Banned <@{user_id}> and removed their last 24h of messages."
        if act == "delete":
            channel = guild.get_channel_or_thread(channel_id)
            if channel is None or not hasattr(channel, "get_partial_message"):
                return "That channel no longer exists."
            await channel.get_partial_message(message_id).delete()
            return "🗑️ Message deleted."
        member = guild.get_member(user_id) or await guild.fetch_member(user_id)
        if act == "kick":
            await member.kick(reason=reason)
            return f"👢 Kicked <@{user_id}>."
        if act == "timeout":
            minutes = self.config.actions.timeout_minutes
            await member.timeout(timedelta(minutes=minutes), reason=reason)
            return f"⏸️ Timed out <@{user_id}> for {human_minutes(minutes)}."
        if act == "untimeout":
            await member.timeout(None, reason=reason)
            self.engine.tracker.forget(user_id)
            self.stats["false_alarms"] += 1
            return f"✅ Lifted the timeout for <@{user_id}>."
        raise ValueError(act)

    # ------------------------------------------------------------- member tools

    async def report_message(self, interaction: discord.Interaction, message: discord.Message) -> None:
        now = time.monotonic()
        if now - self._last_report.get(interaction.user.id, 0) < 20:
            await interaction.response.send_message("Thanks - please wait a moment between reports.", ephemeral=True)
            return
        self._last_report[interaction.user.id] = now
        channel = self.get_channel(self.config.server.mod_log_channel_id)
        if channel is None:
            await interaction.response.send_message("Reporting isn't set up on this server yet.", ephemeral=True)
            return
        info = message_to_info(message, trusted=False)
        verdict = self.engine.evaluate(info, track=False)
        embed = build_alert_embed(
            title="📣 Member report",
            author=message.author,
            channel_mention=message.channel.mention,
            content=info.content,
            attachments=list(info.attachments),
            verdict=Verdict(verdict.score, Action.FLAG, verdict.signals),
            outcome=[f"Reported by {interaction.user.mention}"],
            message_id=message.id,
            jump_url=message.jump_url,
        )
        view = alert_view(message.author.id, ["delete", "timeout", "ban"], message.channel.id, message.id)
        await channel.send(embed=embed, view=view)
        self.stats["reports"] += 1
        await interaction.response.send_message(
            "Thanks! The moderators have been notified. Never click links or download files "
            "from people you don't know, even if they look like Discord or Steam.",
            ephemeral=True,
        )


class DefenderCommands(app_commands.Group):
    def __init__(self, bot: DefenderBot) -> None:
        super().__init__(
            name="defender",
            description="Discord Defender moderator tools",
            default_permissions=discord.Permissions(manage_messages=True),
            guild_only=True,
        )
        self.bot = bot

    @app_commands.command(name="status", description="Show what Discord Defender is doing")
    async def status(self, interaction: discord.Interaction) -> None:
        bot, cfg = self.bot, self.bot.config
        updater = bot.updater
        refreshed = (
            discord.utils.format_dt(datetime.fromtimestamp(updater.last_refresh, UTC), "R")
            if updater.last_refresh
            else "not yet"
        )
        embed = discord.Embed(title="Discord Defender status", color=discord.Color.blurple())
        embed.add_field(name="Mode", value="🧪 Dry run" if cfg.actions.dry_run else "✅ Enforcing")
        embed.add_field(
            name="Up since", value=discord.utils.format_dt(datetime.fromtimestamp(bot.started_at, UTC), "R")
        )
        embed.add_field(
            name="Blocklist",
            value=f"{len(bot.engine.blocklist):,} domains\nrefreshed {refreshed}"
            + (f"\n⚠️ {len(updater.last_errors)} feed error(s)" if updater.last_errors else ""),
        )
        embed.add_field(name="Honeypots", value=str(len(cfg.server.honeypot_channel_ids)))
        counts = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in sorted(bot.stats.items())) or "nothing yet"
        embed.add_field(name="Since start", value=counts[:1024], inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="check", description="Test how a message would be scored (nothing is stored)")
    @app_commands.describe(text="Message text or link to test")
    async def check(self, interaction: discord.Interaction, text: str) -> None:
        info = MessageInfo(message_id=0, channel_id=0, author_id=0, content=text)
        verdict = self.bot.engine.evaluate(info, track=False)
        lines = [f"• {s.detail} (+{s.weight})" for s in verdict.signals] or ["• nothing suspicious"]
        await interaction.response.send_message(
            f"**{verdict.action.name}** - score {verdict.score}\n"
            + "\n".join(lines)
            + "\n-# Scored as an established member; newcomers get "
            f"+{self.bot.config.newcomers.bonus} when anything else matches.",
            ephemeral=True,
        )
