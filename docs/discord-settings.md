# Discord settings that cut spam without making joining harder

These native settings complement Discord Defender. None of them add a step for someone
joining your server. They're listed roughly in order of impact. Discord moves settings
around from time to time, so if a path below has changed, search the setting's name in
Discord's Help Center.

## 1. Stop members' personal apps from posting publicly

**Server Settings → Roles → @everyone → turn off "Use External Apps".**

Members can install apps on their own account and run them in any server. A hijacked
account can use one to post spam that looks like it came from a bot. With this permission
off, those apps still work but reply only to the person who used them, so nobody else sees
the output. You can turn it back on for an officer role if you need to.

## 2. Remove the mass-ping permission

**Server Settings → Roles → @everyone → turn off "Mention @everyone, @here, and All Roles".**

Scam posts almost always start with `@everyone`. Without the permission the ping does
nothing, and Defender still sees the attempt and scores it.

## 3. Require 2FA for moderators

**Server Settings → Safety Setup → Require 2FA for moderator actions** (the owner needs 2FA
on their own account first).

A hijacked officer account is the worst case: it can delete channels, ban people and post
announcements that everyone trusts. This doesn't affect regular members at all.

## 4. Turn on AutoMod's free filters

**Server Settings → Safety Setup → AutoMod.** Enable **Block Mention Spam** and **Block
Suspected Spam Content**, with alerts sent to your mod-log channel. They're blunt but free,
and Defender catches what they miss.

## 5. Turn on raid alerts

**Server Settings → Safety Setup → Raid Protection / Activity Alerts**, sent to your
mod-log channel. Discord only adds checks for new joiners while it believes a raid is
actually happening, so normal joining is unaffected.

## 6. Keep the verification level where it is

Raising it (phone verification and so on) is the most common reaction to spam. It doesn't
help against hijacked accounts, which already have verified emails and phones, but it does
stop some real students from joining. Leave it at **Low** (verified email) or wherever it is now.

## 7. Lock down webhooks and integrations

Make sure **Manage Webhooks** and **Manage Server** belong only to officers. Leaked webhook
URLs are another way spam gets into a channel without a member account.

## 8. During an active attack

- **Server Settings → Invites → Pause Invites** stops new joins temporarily while you clean up.
- Defender's `/defender status` shows what it's catching; check the mod-log channel and use
  the buttons.

## 9. Teach members about DM scams

Bots, including Defender, **cannot read DMs**, and that's where much phishing happens:
scammers copy the member list and message everyone. Pin a short message in `#welcome` or
`#rules`:

> 🛡️ **Stay safe from scams**
> • Officers will **never** DM you asking you to click a link, log in, download a file, or
> "test a game".
> • "Free Nitro", "I accidentally reported you", "selling my MacBook/tickets cheap" and
> "I can do your assignments/exams" messages are scams, even from a friend's account
> (it's probably been hacked).
> • See something suspicious in the server? **Right-click (or long-press) the message →
> Apps → Report to moderators.**
> • Got a scam DM? Don't click anything. Screenshot it and send it to an officer.
> • If your account starts posting things you didn't write: change your password, turn on
> 2FA, remove unknown apps in *Settings → Authorized Apps*, and scan your computer for
> malware.

## 10. Protect officer accounts

Attackers target the accounts with the most permissions. Every officer should:

- use 2FA (an authenticator app, not SMS, if possible);
- never run files or "games" sent by other people, the #1 way Discord accounts get stolen;
- check *User Settings → Authorized Apps* and *Devices* every so often;
- hand over server ownership and roles properly at officer transitions, and remove old
  officers' roles.
