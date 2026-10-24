# How Discord Defender works

Every message from a member (including edits and forwarded messages) goes through the same
pipeline:

1. **Normalise the text.** Fold look-alike letters from other alphabets (`frее nіtro` →
   `free nitro`), fancy Unicode fonts (`𝐟𝐫𝐞𝐞`, `ｆｒｅｅ`), zero-width characters and Markdown
   tricks (`f||r||ee`, `fr**ee**`).
2. **Collect signals.** Each check that fires adds a *signal* worth some points.
3. **Add up the score** and pick an action: flag (40+), delete (70+) or timeout (100+).
4. **Act and report.** Delete and time out as needed, then post an alert with action buttons
   to the mod-log channel.

The scoring engine (`engine.py`) has no dependency on Discord's API, so every rule is covered
by unit tests. You can try it on any text with `discord-defender --scan "…"` or
`/defender check`.

## Signals and their points

You can change any number in `config.toml` under `[weights]`, e.g. `server_invite = 20`.

### Behaviour

| Signal | Points | Fires when |
|---|---:|---|
| `honeypot` | 1000 | Someone posts in a honeypot channel (or a thread inside one). |
| `duplicate_burst` | 100 | The same message (same text and same attachment bytes) lands in **3+ channels within 2 minutes**. |
| `repeat_flood` | 80 | The same message is posted **5+ times within 2 minutes**, anywhere. |
| `similar_burst` | 70, +15 per extra channel | Posts with the same caption and the same number and kind of attachments, but *different* images, land in 3+ channels. This catches campaigns that rotate through hundreds of photos so no two posts are identical. At 5 channels it reaches 100 (timeout). |

Short text-only messages (under 15 characters, like "lol" or "thanks!") are never counted, so
people saying the same small thing in a few channels are left alone. When a burst is
detected, *every* copy is deleted, not just the latest one.

### Links

| Signal | Points | Fires when |
|---|---:|---|
| `phishing_domain` ★ | 100 | A link, or a domain written in plain text, is on the scam blocklist (about 40k domains, refreshed every 6 hours). |
| `lookalike_domain` ★ | 100 | A domain imitates Discord or Steam (or a brand you add): misspellings with up to 1–3 typos depending on name length (`dicsord`, `steamcommunlty`, `steancomnnunity`), digit/letter swaps (`d1scord`), real domains used as a prefix (`discord.com.verify.ru`, `steamcommunity.com-trade.ru`), Cyrillic letters in punycode, or the brand name plus a scam word such as gift, nitro, free, claim, verify, login or appeal (`discord-gift.vercel.app`). |
| `masked_link` | 60 | A Markdown link whose visible text names one domain while it really opens another: `[steamcommunity.com](https://evil…)`. |
| `brand_domain` | 50 | A non-official domain uses a protected name without other scam signs (`discordservers.com`). This is an alert only, unless something else adds up. |
| `executable_link` | 40 | A link to a program file (`.exe`, `.scr`, `.msi`, `.apk`, `.jar`, `.bat`, `.ps1`, `.iso`, …), **even on Discord's own CDN**, where a lot of malware is hosted. |
| `server_invite` | 40 | An invite to a different server. Invites to your own server are recognised automatically; add others to `allowed_invite_codes`. |
| `idn_domain` | 30 | An internationalised (`xn--`) domain. |
| `ip_link` | 30 | A link to a bare IP address. |
| `shortener` | 15 | A URL shortener such as bit.ly or tinyurl that hides the real destination. |

★ = *hard* signal: it counts even for trusted members, because those are exactly the accounts
attackers most want to hijack.

### Message content

Several rules can fire at once, but **phrase rules together are capped at 90 points**. That's
enough to delete a scam, but text alone never times out an established member. A timeout
needs a bad link, burst behaviour, or a brand-new account on top.

| Signal | Points | Example it catches |
|---|---:|---|
| `nitro_scam` | 40 | "free discord nitro for everyone" |
| `casino_promo` | 40 | "use promo code BEAST on this casino to withdraw" |
| `academic_services` | 40 | "I offer help with assignments, essays, online classes and exams, DM me" |
| `account_scam` | 40 | "I accidentally reported your account, contact discord staff to appeal" |
| `adult_spam` | 40 | OnlyFans / nudes / 18+ server ads |
| `executable_attachment` | 40 | `Game_Setup.exe` attached |
| `steam_scam` | 35 | "$50 steam gift card" |
| `crypto_scam` | 35 | "invest in bitcoin for guaranteed profits" |
| `money_promise` | 35 | "earn $800 per week", "passive income", "10x returns" |
| `mass_mention` | 30 | Message contains `@everyone` / `@here` (Discord blocks the ping, but spammers try anyway) |
| `mention_with_link` | 30 | …and also contains a link |
| `selling_bait` | 25 | "selling my MacBook / PS5 / Taylor Swift tickets" |
| `gift_card` | 25 | "free $100 Amazon gift card" |
| `game_test_lure` | 25 | "can you test my new game?" (the classic token-stealer lure) |
| `giveaway_bait` | 20 | "giving away my…", "first come first serve" |
| `dm_lure` | 15 | "DM me", "add me on Telegram" |
| `urgency` | 10 | "only 3 spots left", "act fast" |

The rules are deliberately written to leave normal club chat alone. All of these score 0
(see `tests/test_heuristics.py`): "free pizza at the meeting", "does anyone have the steam
tables for thermo?", "can anyone help with the statics homework?", "I can help with the
steel bridge project".

The academic-services rule needs *several* coursework words (assignments, essays, exams,
online classes, …) **plus** offer language ("I offer", "affordable", "guaranteed") or a
contact request. Students asking each other for homework help don't trip it.

## Who is treated differently

- **Trusted members** are the server owner, anyone with Administrator, Manage Server,
  Manage Messages or Moderate Members, and anyone with a role in `trusted_role_ids`. Only
  hard signals (★) count for them, so officers can cross-post announcements, share
  giveaway news or post in the honeypot to explain it.
- **Newcomers** are members who joined in the last 72 hours or whose Discord account is
  younger than 30 days. They get **+30** points, but only when a message already has a
  meaningful signal (worth 20+ points). A newcomer chatting normally scores exactly the same
  as everyone else: zero.
- **Bots, webhooks and system messages** are ignored. Members' own user-installed apps are
  best handled with Discord's *Use External Apps* permission (see the settings guide).

## What happens at each level

| Score | Action | Alert buttons |
|---|---|---|
| 40–69 | **Flag**: alert only, the message stays up | Delete message · Time out · Ban |
| 70–99 | **Delete** the message | Time out · Kick · Ban |
| 100+ | **Delete**, also delete every copy and the member's other posts from the last 15 minutes, **time out** for 1 day, DM them account-recovery steps | False alarm: lift timeout · Kick · Ban |
| honeypot | As 100+, or `softban` / `ban` if you set `honeypot_action` | |

Alerts are collapsed so a spamming account produces one alert per two minutes unless the
action escalates. Buttons check that the clicking moderator has the matching Discord
permission, and keep working after the bot restarts. Each click is noted on the alert with
who did it and when, so other moderators can see it's been handled.

**Dry run** (`dry_run = true`) runs everything except the actions: alerts say "would have
deleted / timed out". Use it for your first few days.

## How well the link checks work

Measured against the two public scam feeds (about 39,500 domains) **with the blocklist turned
off**, to see how many scam domains the lookalike check catches on its own:

- 88% of Discord- and Steam-themed scam domains are flagged by lookalike detection alone
  (73% as a hard `lookalike_domain`, the rest as the softer `brand_domain`). That matters
  because new scam domains appear before any list includes them.
- No `lookalike_domain` false positives on a sample of 100 legitimate sites students commonly
  share (Google Docs, Canvas, Zoom, GitHub, asce.org, steamdb.info, steam.com, stream.com,
  discogs.com, and others). A few sites that simply contain the word "discord" (such as
  discordservers.com) get the soft `brand_domain` flag.

## Adding your own protection

**Protect your university's login page** (a favourite phishing target):

```toml
[[links.extra_brands]]
name = "State University"
keywords = ["stateuniv"]          # the distinctive part of the domain
domains = ["stateuniv.edu"]       # the real domains; subdomains are included automatically
```

After that, `stateuniv-login.com`, `stateunlv.edu.verify.ru` and similar domains are treated
as lookalikes, while `canvas.stateuniv.edu` stays fine.

**Add a phrase rule** (Python regular expression, case-insensitive, run on normalised text):

```toml
[[heuristics.extra_rules]]
name = "fake_scholarship"
pattern = "scholarship.{0,40}(processing fee|pay to apply)"
weight = 40
description = "Fake scholarship fee scam"
```

**Turn a rule off** (for example if you run a marketplace channel):

```toml
[heuristics]
disabled_rules = ["selling_bait"]
```
