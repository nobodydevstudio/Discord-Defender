"""The scoring engine: one message in, one verdict out.

The engine knows nothing about Discord's API, which keeps it easy to test and
to tune. Every piece of evidence becomes a :class:`Signal` with a weight; the
weights add up to a score, and the score picks an action:

======================  ===============================================
score >= flag_score     post an alert for moderators, leave the message
score >= delete_score   delete the message and alert
score >= timeout_score  delete, time the author out, purge their recent
                        messages, and alert
======================  ===============================================

"Hard" signals (a known scam domain, a lookalike domain) count for everyone;
the rest are ignored for trusted members such as officers and moderators.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum

from .blocklist import Blocklist
from .config import Config, ConfigError
from .heuristics import PhraseScanner, build_rules, prepare
from .links import DEFAULT_BRANDS, EXECUTABLE_EXTENSIONS, Brand, LinkAnalyzer
from .tracker import ActivityTracker, Seen, fingerprints

DEFAULT_WEIGHTS: dict[str, int] = {
    "honeypot": 1000,
    "phishing_domain": 100,
    "lookalike_domain": 100,
    "duplicate_burst": 100,
    "repeat_flood": 80,
    "similar_burst": 70,
    "masked_link": 60,
    "brand_domain": 50,
    "server_invite": 40,
    "executable_attachment": 40,
    "executable_link": 40,
    "mass_mention": 30,
    "mention_with_link": 30,
    "idn_domain": 30,
    "ip_link": 30,
    "shortener": 15,
}
HARD_SIGNALS = frozenset({"phishing_domain", "lookalike_domain"})
_MENTION_ATTEMPT_RE = re.compile(r"@(?:everyone|here)\b", re.IGNORECASE)


class Action(IntEnum):
    NONE = 0
    FLAG = 1
    DELETE = 2
    TIMEOUT = 3


@dataclass(frozen=True)
class Attachment:
    filename: str
    size: int
    content_type: str | None = None


@dataclass
class MessageInfo:
    """Everything the engine needs to know about a message."""

    message_id: int
    channel_id: int
    author_id: int
    content: str
    created_at: float = field(default_factory=time.time)
    attachments: Sequence[Attachment] = ()
    author_joined_at: float | None = None
    author_created_at: float | None = None
    author_trusted: bool = False
    own_invite_codes: frozenset[str] = frozenset()
    parent_channel_id: int | None = None  # set for messages inside threads
    is_edit: bool = False


@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    detail: str
    hard: bool = False


@dataclass
class Verdict:
    score: int
    action: Action
    signals: list[Signal]
    related: list[tuple[int, int]] = field(default_factory=list)  # (channel_id, message_id)

    def has(self, name: str) -> bool:
        return any(s.name == name for s in self.signals)

    def summary(self) -> str:
        reasons = "; ".join(f"{s.name}+{s.weight}" for s in self.signals) or "clean"
        return f"{self.action.name} score={self.score} ({reasons})"


class Engine:
    def __init__(
        self,
        config: Config,
        blocklist: Blocklist | None = None,
        tracker: ActivityTracker | None = None,
    ) -> None:
        self.config = config
        links = config.links
        brands = list(DEFAULT_BRANDS)
        brands += [Brand(b.name, tuple(b.keywords), tuple(b.domains)) for b in links.extra_brands]
        official = [d for b in brands for d in b.domains]

        self.blocklist = blocklist or Blocklist(extra=links.blocklist, allow=[*links.allowlist, *official])
        self.links = LinkAnalyzer(self.blocklist, brands=brands, allowlist=links.allowlist)

        try:
            rules = build_rules([vars(r) for r in config.heuristics.extra_rules], config.heuristics.disabled_rules)
        except re.error as exc:
            raise ConfigError(f"[[heuristics.extra_rules]] has an invalid regex: {exc}") from None
        self.phrases = PhraseScanner(rules if config.heuristics.enabled else [])

        self.weights = {**DEFAULT_WEIGHTS, **{r.name: r.weight for r in rules}}
        unknown = set(config.weights) - set(self.weights)
        if unknown:
            raise ConfigError(
                f"[weights] has unknown signal(s) {', '.join(sorted(unknown))}; "
                f"valid names: {', '.join(sorted(self.weights))}"
            )
        self.weights.update(config.weights)
        self._rule_names = {r.name for r in rules}

        d = config.duplicates
        self.tracker = tracker or ActivityTracker(
            window_seconds=d.window_seconds, retain_seconds=config.actions.purge_minutes * 60
        )
        self._honeypots = frozenset(config.server.honeypot_channel_ids)
        self._allowed_invites = frozenset(c.lower() for c in config.server.allowed_invite_codes)

    def _signal(self, name: str, detail: str, weight: int | None = None) -> Signal:
        w = self.weights[name] if weight is None else weight
        return Signal(name, w, detail, hard=name in HARD_SIGNALS)

    def evaluate(self, msg: MessageInfo, *, track: bool = True) -> Verdict:
        cfg = self.config
        now = msg.created_at
        signals: list[Signal] = []

        if msg.channel_id in self._honeypots or msg.parent_channel_id in self._honeypots:
            signals.append(self._signal("honeypot", "Posted in the honeypot channel"))

        report = self.links.analyze(msg.content)
        by_kind: dict[str, list[str]] = {}
        for finding in report.findings:
            by_kind.setdefault(finding.kind, []).append(finding.detail)
        for kind, details in by_kind.items():
            signals.append(self._signal(kind, "; ".join(dict.fromkeys(details))))

        invites = [
            c for c in report.invite_codes if c.lower() not in self._allowed_invites and c not in msg.own_invite_codes
        ]
        if invites:
            signals.append(self._signal("server_invite", f"Invite to another server ({', '.join(invites[:3])})"))

        mention_attempt = bool(_MENTION_ATTEMPT_RE.search(msg.content))
        has_link = bool(report.hosts or report.invite_codes)
        if mention_attempt:
            signals.append(self._signal("mass_mention", "Tried to ping @everyone/@here"))
            if has_link:
                signals.append(self._signal("mention_with_link", "Mass ping combined with a link"))

        programs = sorted(
            {a.filename for a in msg.attachments if a.filename.rsplit(".", 1)[-1].lower() in EXECUTABLE_EXTENSIONS}
        )
        if programs:
            signals.append(self._signal("executable_attachment", f"Program file attached: {', '.join(programs[:3])}"))

        prepared = prepare(msg.content)
        phrase_hits = self.phrases.scan(prepared)
        phrase_budget = cfg.heuristics.max_score
        for rule in phrase_hits:
            weight = min(self.weights[rule.name], max(phrase_budget, 0))
            phrase_budget -= weight
            if weight > 0:
                signals.append(Signal(rule.name, weight, rule.description))

        related: dict[tuple[int, int], None] = {}
        if track and not msg.is_edit:
            signals += self._burst_signals(msg, prepared, report.hosts, mention_attempt, related)

        if msg.author_trusted:
            signals = [s for s in signals if s.hard]
        elif any(s.weight >= 20 for s in signals) and self._is_newcomer(msg, now):
            # Only sharpens real evidence; newcomers chatting normally score zero.
            signals.append(Signal("newcomer", cfg.newcomers.bonus, "Recently joined or brand-new account"))

        score = sum(s.weight for s in signals)
        action = self._action_for(score)

        if action >= Action.TIMEOUT and track:
            since = now - cfg.actions.purge_minutes * 60
            for seen in self.tracker.recent(msg.author_id, since):
                related.setdefault((seen.channel_id, seen.message_id), None)
        related.pop((msg.channel_id, msg.message_id), None)
        if action < Action.DELETE:
            related.clear()
        return Verdict(score=score, action=action, signals=signals, related=list(related))

    def _burst_signals(self, msg, prepared, hosts, mention_attempt, related) -> list[Signal]:
        d = self.config.duplicates
        exact, shape = fingerprints(
            prepared, hosts, msg.attachments, min_length=d.min_length, mention_attempt=mention_attempt
        )
        if exact is None:
            return []
        stats = self.tracker.record(msg.author_id, Seen(msg.created_at, msg.channel_id, msg.message_id, exact, shape))
        window = int(d.window_seconds)
        signals = []
        if stats.exact_channels >= d.channel_threshold:
            signals.append(
                self._signal("duplicate_burst", f"Same message in {stats.exact_channels} channels within {window}s")
            )
            matches = stats.exact_matches
        elif stats.exact_count >= d.repeat_threshold:
            signals.append(
                self._signal("repeat_flood", f"Same message posted {stats.exact_count} times within {window}s")
            )
            matches = stats.exact_matches
        elif stats.shape_channels >= d.channel_threshold:
            extra = stats.shape_channels - d.channel_threshold
            weight = self.weights["similar_burst"] + 15 * extra
            signals.append(
                self._signal(
                    "similar_burst",
                    f"Near-identical posts with attachments in {stats.shape_channels} channels within {window}s",
                    weight,
                )
            )
            matches = stats.shape_matches
        else:
            matches = ()
        for seen in matches:
            related.setdefault((seen.channel_id, seen.message_id), None)
        return signals

    def _is_newcomer(self, msg: MessageInfo, now: float) -> bool:
        n = self.config.newcomers
        if msg.author_joined_at is not None and now - msg.author_joined_at < n.member_hours * 3600:
            return True
        return msg.author_created_at is not None and now - msg.author_created_at < n.account_days * 86400

    def _action_for(self, score: int) -> Action:
        a = self.config.actions
        if score >= a.timeout_score:
            return Action.TIMEOUT
        if score >= a.delete_score:
            return Action.DELETE
        if score >= a.flag_score:
            return Action.FLAG
        return Action.NONE
