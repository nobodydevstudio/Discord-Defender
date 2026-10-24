# Discord Defender

Open-source, self-hosted spam and phishing protection for Discord servers. It was built for
student organisations whose servers get flooded with scams even with Discord's own safety
features turned on.

**It adds zero friction for people joining.** There's no CAPTCHA, no verification gate, no
"click this role to get in", and nothing a new member ever sees. Defender watches what
accounts *do* after they join and removes scams in seconds.

## Why spam gets past Discord's built-in protection

1. **Most spam comes from hijacked accounts of real members.** Token-stealing malware
   (usually a "game" or "tool" someone was asked to try) hands attackers working accounts
   that are already in your server. They're months old, have verified emails and pass
   every join check. Making joining harder punishes real students and doesn't stop these
   accounts at all.
2. **AutoMod judges each message on its own.** It can't tell that one account just posted
   the same thing in 12 channels in 10 seconds, which is the clearest sign of a hijacked
   account.
3. **Keyword filters are easy to dodge.** `frее nіtro` (with Cyrillic letters), `f||r||ee`,
   `ＦＲＥＥ` and zero-width spaces all get through literal word lists.
4. **Phishing domains are new every day** (`dlscord-gift.com`, `steamcommunlty.ru`,
   `discord.com.verify-account.ru`), and image-only scams carry no text to filter at all.

So Defender doesn't gate the front door. It checks behaviour and content after people join.

## What it catches

| Threat | How Defender handles it |
|---|---|
| Hijacked account blasting every channel | Spots the same post in several channels within two minutes, even when the attacker rotates screenshots so no two posts are identical. Deletes every copy, times the account out and DMs the owner how to recover it. |
| Hijacked account, first message | A **honeypot channel** ("bots only, don't post here"). Real members ignore it; spam scripts post everywhere, so they're caught on message one. |
| Phishing links | About 40,000 known scam domains from two community-maintained feeds, refreshed every 6 hours. **Lookalike detection** catches new domains before any list does: misspellings (`dlscord`, `steamcommunlty`), real names used as subdomains (`discord.com.evil.ru`), masked links (`[discord.com](https://evil…)`), punycode tricks. |
| Scam scripts | Phrase rules that see through disguises: free Nitro / Steam gifts, "selling my MacBook / tickets", crypto and casino promo codes, "I accidentally reported you", fake Discord staff, adult spam, "test my game" lures, and the **paid homework / exam-taking offers** endemic to student servers. |
| Malware | Program files (`.exe`, `.scr`, `.apk`, `.msi`, …) attached or linked, including links on Discord's own CDN. |
| Server ads | Invites to other servers. Invites to your own server are recognised automatically. |
| Scam DMs (bots can't read DMs) | A **Report to moderators** right-click action on any message, plus member-education text in the [settings guide](docs/discord-settings.md). |

Every message gets a score from the signals it trips:

- **Flag** (40+): moderators get an alert and the message stays up.
- **Delete** (70+): the message is removed and moderators are alerted.
- **Timeout** (100+): the message is removed, the account is timed out for 1 day, its posts
  from the last 15 minutes are cleaned up, and the owner gets account-recovery steps.

Each alert in your private mod-log channel has one-click buttons: **False alarm: lift timeout**,
**Kick**, **Ban**, **Delete message**. Moderators (anyone with Manage Messages) are trusted
automatically, and you can list officer roles as trusted too. For trusted members only
known-scam or lookalike links count. Newcomers get no extra scrutiny until a
message already looks suspicious. Details: [How it works](docs/how-it-works.md).

## Quick start (about 15 minutes)

You need Python 3.11+ *or* Docker, on a machine that stays on (see [Hosting](#hosting)).

### 1. Create the bot account

1. Go to <https://discord.com/developers/applications> → **New Application** (name it e.g.
   "ASCE Defender").
2. **Bot** tab → **Reset Token** → copy the token somewhere safe.
3. On the same tab, turn on **Message Content Intent**. No other privileged intents are needed.
4. Copy the **Application ID** from the **General Information** tab.

### 2. Invite it to your server

Open this URL with your Application ID filled in:

```
https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot+applications.commands&permissions=1374389627910
```

That grants View Channels, Send Messages (including in threads), Embed Links, Read Message
History, Manage Messages, Moderate Members (timeouts), Kick Members and Ban Members (the
last two are only used when a moderator clicks those buttons).

Then **Server Settings → Roles** and drag the new bot role **above your member roles**.
Discord won't let a bot time out anyone whose role is higher than its own.

### 3. Prepare two channels

- **`#mod-log`**: private, visible to officers only. Alerts go here.
- **`#do-not-post-here`** (recommended): the honeypot. Put it near the top of the channel
  list with the topic *"⚠️ Automated trap for spam bots. Posting here mutes you automatically."*
  Make sure members can see it and send messages in it.

Turn on **User Settings → Advanced → Developer Mode**, then right-click your server icon
and both channels → **Copy ID**.

### 4. Configure

```bash
git clone https://github.com/nobodydevstudio/Discord-Defender.git
cd Discord-Defender
cp config.example.toml config.toml   # fill in [server]: guild_id, mod_log_channel_id, honeypot_channel_ids
cp .env.example .env                 # paste the bot token after DISCORD_TOKEN=
```

Optionally add your officer role IDs to `trusted_role_ids`, and your university's login
domain under `[[links.extra_brands]]` (phishers love fake university sign-in pages).

### 5. Run

**Docker:**

```bash
mkdir -p data && docker compose up -d --build
docker compose logs -f    # should say "protecting <your server>"
```

**Plain Python:**

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .
discord-defender --check-config
discord-defender
```

To keep it running after you log out, use `systemd`, `tmux` or the Docker setup above.

### 6. Check it works

- In Discord, type `/defender status` to see the mode, blocklist size and counters.
- `/defender check text: free nitro https://dlscord-gift.com` shows how a message would be
  scored, without storing anything.
- From a terminal, with no bot needed: `discord-defender --scan "your message here"`.

> **Tip:** set `dry_run = true` in `config.toml` for the first few days. Alerts then show what
> Defender *would* have done without deleting anything. Once you trust it, set it to `false`.

## Hosting

Defender is one small process (about 60 MB of RAM, under a millisecond per message), but it
must run 24/7. Good options:

- your university's student-organisation or departmental hosting, if it offers VMs;
- a free-tier VM from a cloud provider (check their current terms);
- a Raspberry Pi or spare lab computer that stays on.

Don't run it on a personal laptop that sleeps. Treat the bot token like a password: if it
leaks, use **Reset Token** in the Developer Portal.

## Pair it with Discord's own settings

Defender complements Discord's built-in protection. [docs/discord-settings.md](docs/discord-settings.md)
is a checklist of native settings that cut spam **without** adding join friction (disabling
public replies from members' personal apps, 2FA for moderators, removing the `@everyone`
permission, and more), plus a pinned message you can post to teach members about DM scams.

## Tuning and false alarms

- A wrongly timed-out member: click **False alarm: lift timeout**. Defender also forgets their
  recent activity so it won't immediately re-trigger.
- A legitimate site keeps getting flagged: add it to `[links] allowlist`.
- A rule doesn't suit your server (for example you run a marketplace channel): add it to
  `[heuristics] disabled_rules`, or lower its points under `[weights]`.
- To make Defender stricter or more lenient overall, move the `flag_score` / `delete_score` /
  `timeout_score` thresholds.

Every signal and its points are listed in [docs/how-it-works.md](docs/how-it-works.md).

## Privacy

Messages are scored in memory and **never stored**. Defender remembers only short hashes of
each member's posts from the last 15 minutes (to spot copy-paste bursts) plus a cached copy
of the public blocklist. When it acts, the flagged message's text is copied into your
private mod-log channel so moderators can review it. Nothing is sent to third parties; the
only outbound requests are to Discord and to download the public blocklist feeds.

## Known limitations

- Bots can't read DMs. The report button and member education are the defence there.
- Text inside images isn't read. Image scams are caught by their burst behaviour or the
  honeypot, but a single scam screenshot posted once in one channel gets through.
- Phrase rules are English-only.
- One bot instance protects one server. Activity memory resets when the bot restarts.

## Development

```bash
pip install -e ".[dev]"
pytest          # 130+ tests, no Discord connection needed
ruff check . && ruff format --check .
```

The detection engine (`src/discord_defender/engine.py` and the modules it uses) has no
dependency on Discord's API, so it's easy to test. `bot.py` is the thin layer that talks to
Discord. Contributions are welcome, especially new scam patterns: please include a real
(anonymised) example and a test.

Scam domain data comes from
[nikolaischunk/discord-phishing-links](https://github.com/nikolaischunk/discord-phishing-links)
and [Discord-AntiScam/scam-links](https://github.com/Discord-AntiScam/scam-links). Thank you
to their maintainers.

## License

[MIT](LICENSE)
