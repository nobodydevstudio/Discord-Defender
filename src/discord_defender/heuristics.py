"""Phrase rules for the scam scripts that keep showing up in community servers.

Rules run on normalised text (see :mod:`text`), so ``FR𝐄𝐄 ＮＩＴＲＯ``, ``frее nіtro``
(Cyrillic) and ``f||r||ee n**i**tro`` all read as ``free nitro``.

Each rule only adds to a score. On its own a single rule is meant to be weak
enough that ordinary chat is never punished; it takes several rules, a bad
link, or spam-like behaviour together to remove a message.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .links import URL_RE
from .text import fold, squash, strip_discord_tokens


@dataclass(frozen=True)
class Rule:
    name: str
    weight: int
    description: str
    pattern: re.Pattern[str] | None = None
    check: Callable[[str], bool] | None = None

    def matches(self, text: str) -> bool:
        if self.pattern is not None and self.pattern.search(text):
            return True
        return self.check is not None and self.check(text)


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def prepare(text: str) -> str:
    """Normalise message text for phrase matching (links removed)."""
    text = URL_RE.sub(" ", fold(text))
    return squash(strip_discord_tokens(text))


_CONTACT = r"\b(?:dm|pm|message|text|inbox|hmu|contact|reach out to|hit) (?:me|us)\b|\bdm (?:for|if)\b"
_ACADEMIC_NOUNS = {
    "assignment": r"assignments?",
    "homework": r"homework",
    "essay": r"essays?",
    "exam": r"exams?",
    "quiz": r"quiz(?:zes)?",
    "class": r"online class(?:es)?",
    "lab": r"lab reports?",
    "thesis": r"thesis|dissertations?",
    "paper": r"(?:research|term) papers?",
    "coursework": r"coursework",
    "case": r"case stud(?:y|ies)",
}
_ACADEMIC_NOUN_RES = {k: _re(rf"\b(?:{v})\b") for k, v in _ACADEMIC_NOUNS.items()}
_ACADEMIC_OFFER = _re(
    r"\b(?:i|we) (?:can |will |also )?(?:offer|provide|handle|do|write|take|complete|"
    r"help(?: you)? with)\b|\b(?:affordable|cheap|reasonable (?:rates?|prices?)|guaranteed|"
    r"top grades?|a\+ guaranteed|professional|expert)\b"
)
_ACADEMIC_CONTACT = _re(_CONTACT + r"|\b(?:whatsapp|telegram)\b")
_ACADEMIC_DIRECT = _re(
    r"\b(?:do|take|write|complete) (?:your|ur) (?:homework|assignments?|essays?|exams?|"
    r"online class(?:es)?|quiz(?:zes)?|tests?)\b"
    r"|\b(?:pay|hire) (?:someone|me|us) to (?:do|take|write)\b"
    r"|\b(?:homework|assignment|essay|exam|thesis|dissertation) (?:writing |help )?services?\b"
)


def _academic_offer(text: str) -> bool:
    if _ACADEMIC_DIRECT.search(text):
        return True
    nouns = sum(1 for r in _ACADEMIC_NOUN_RES.values() if r.search(text))
    offer = bool(_ACADEMIC_OFFER.search(text))
    contact = bool(_ACADEMIC_CONTACT.search(text))
    return (nouns >= 3 and (offer or contact)) or (nouns >= 2 and offer and contact)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        "nitro_scam",
        40,
        "Free Nitro / gift bait",
        _re(
            r"\b(?:free|claim|gift(?:ed|ing)?|giveaway|giving away)\b.{0,40}\bnitro\b"
            r"|\bnitro\b.{0,40}\b(?:free|giveaway|gift|claim|for (?:all|everyone))\b"
        ),
    ),
    Rule(
        "steam_scam",
        35,
        "Steam gift / skins bait",
        _re(
            r"\bsteam (?:gift|wallet|card|giveaway|skins?|balance|code|key)s?\b"
            r"|\$ ?\d+ (?:steam|gift card)\b"
        ),
    ),
    Rule(
        "gift_card",
        25,
        "Gift card bait",
        _re(r"\b(?:free|claim|\$ ?\d{2,4})\b.{0,25}\b(?:gift ?cards?|amazon cards?|apple cards?)\b"),
    ),
    Rule(
        "giveaway_bait",
        20,
        "Giveaway bait",
        _re(
            r"\bgiving away (?:my|a|an|some|\d+|free)\b|\bfirst (?:come|\d+),? first serve"
            r"|\bfree to (?:whoever|anyone|the first)\b|\bwho(?:ever)? wants (?:it|them|one)\b"
        ),
    ),
    Rule(
        "selling_bait",
        25,
        "Too-good-to-be-true item for sale",
        _re(
            r"\b(?:selling|sell my|for sale)\b.{0,40}\b(?:mac ?book|laptop|ipad|iphone|ps[45]|"
            r"playstation|xbox|nintendo switch|switch oled|air ?pods|gaming pc|graphics card|"
            r"rtx ?\d{4}|tickets?)\b"
        ),
    ),
    Rule(
        "dm_lure",
        15,
        "Moves the conversation to DMs / another app",
        _re(
            _CONTACT + r"|\b(?:add|text|message) me on (?:whatsapp|telegram|snap(?:chat)?|signal|"
            r"instagram|wechat)\b|\b(?:whatsapp|telegram)\s*[:+]"
        ),
    ),
    Rule(
        "crypto_scam",
        35,
        "Crypto / investment scam",
        _re(
            r"\b(?:crypto|bitcoin|btc|eth|usdt|forex|nft)\b.{0,50}\b(?:invest(?:ing|ment)?|profits?|"
            r"returns?|trading signals|airdrop|mint|giveaway|bonus|casino|withdraw(?:al)?)\b"
            r"|\b(?:invest(?:ing|ment)?|profits?|airdrop|casino|withdraw(?:al)?)\b.{0,50}"
            r"\b(?:crypto|bitcoin|btc|eth|usdt|forex)\b"
        ),
    ),
    Rule(
        "money_promise",
        35,
        "Promises easy money",
        _re(
            r"\b(?:earn|make|making|made|get|profit of)\s*\$?\s?\d[\d,.]*\s?k?\s*(?:\$|usd|dollars?)?"
            r"\s*(?:a|per|every|each|in a|within)\s*(?:day|week|hour|month|24 ?h(?:ours|rs)?)\b"
            r"|\bpassive income\b|\b\d{2,3}x (?:returns?|profits?)\b"
            r"|\bguaranteed (?:profits?|returns?|income)\b"
        ),
    ),
    Rule(
        "casino_promo",
        40,
        "Casino promo-code scam",
        _re(
            r"\b(?:promo|bonus|referral) code\b.{0,60}\b(?:casino|bet|withdraw|crypto|usdt|balance)\b"
            r"|\b(?:casino|betting)\b.{0,40}\b(?:promo|bonus) code\b"
        ),
    ),
    Rule(
        "academic_services",
        40,
        "Paid homework / exam-taking service",
        check=_academic_offer,
    ),
    Rule(
        "account_scam",
        40,
        "Fake report / fake staff account threat",
        _re(
            r"\b(?:accidentally|mistakenly|by mistake)\b.{0,30}\breport(?:ed)?\b"
            r"|\byour (?:discord |steam )?account (?:will be|is going to be|has been|was|is) "
            r"(?:banned|disabled|terminated|suspended|deleted|flagged)\b"
            r"|\b(?:discord|steam) (?:staff|support|moderator|trust (?:and|&) safety)\b.{0,60}"
            r"\b(?:verify|contact|dm|add|appeal|ticket)\b"
        ),
    ),
    Rule(
        "adult_spam",
        40,
        "Adult-content spam",
        _re(
            r"\b(?:onlyfans|only fans|nudes?|n00ds|porn|sex ?cam|hot (?:girls|singles)|"
            r"nsfw (?:content|server|pics)|18\+ (?:content|server|pics))\b"
        ),
    ),
    Rule(
        "game_test_lure",
        25,
        '"Try my game" malware lure',
        _re(
            r"\b(?:try|test|check out|play|download)\b.{0,20}\b(?:my|our)\b.{0,15}\b(?:new )?"
            r"(?:game|app|beta)\b|\b(?:feedback|testers?)\b.{0,20}\b(?:my|our) (?:new )?game\b"
        ),
    ),
    Rule(
        "urgency",
        10,
        "Artificial urgency",
        _re(
            r"\b(?:limited (?:time|spots|offer)|only \d+ (?:left|spots|slots)|act fast|hurry up"
            r"|expires? (?:soon|today|in \d+)|first \d+ people)\b"
        ),
    ),
)


def build_rules(extra: Iterable[dict] = (), disabled: Iterable[str] = ()) -> list[Rule]:
    """Default rules minus ``disabled``, plus custom regex rules from the config."""
    disabled_set = set(disabled)
    rules = [r for r in DEFAULT_RULES if r.name not in disabled_set]
    for spec in extra:
        rules.append(
            Rule(spec["name"], int(spec["weight"]), spec.get("description") or spec["name"], _re(spec["pattern"]))
        )
    return rules


class PhraseScanner:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)

    def scan(self, prepared_text: str) -> list[Rule]:
        """Rules matching text already passed through :func:`prepare`."""
        if not prepared_text:
            return []
        return [rule for rule in self.rules if rule.matches(prepared_text)]
