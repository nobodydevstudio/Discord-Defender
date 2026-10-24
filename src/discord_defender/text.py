"""Text normalisation used by every detector.

Spammers dodge keyword filters with look-alike characters (``frее nіtro`` written
with Cyrillic letters), fancy Unicode fonts, zero-width spaces and Markdown
tricks such as ``f||r||ee``. Everything is folded to plain lowercase text before
any rule runs.
"""

from __future__ import annotations

import re
import unicodedata

# Characters that render as nothing but break up keywords.
# fmt: off
_INVISIBLE = dict.fromkeys(
    map(
        ord,
        "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200d\u200e\u200f"
        "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u3164\ufeff\uffa0",
    ),
    None,
)
# fmt: on

# Letters from other scripts that look like Latin ones. NFKC does not fold these.
# fmt: off
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic
        "а": "a", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i",
        "ј": "j", "к": "k", "ӏ": "l", "м": "m", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s",
        "т": "t", "у": "y", "ү": "y", "х": "x", "ԝ": "w",
        # Greek
        "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
        "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
        # Armenian and Latin extensions
        "օ": "o", "ս": "u", "ո": "n", "հ": "h", "ı": "i", "ɑ": "a", "ɡ": "g", "ʟ": "l",
    }
)
# fmt: on

_MARKDOWN = str.maketrans("", "", "*_~|`")
_DISCORD_TOKEN_RE = re.compile(r"<(?:a?:\w+:\d+|@[!&]?\d+|#\d+|/[\w -]+:\d+|t:\d+(?::\w)?)>")
_SPACE_RE = re.compile(r"\s+")


def clean(text: str) -> str:
    """NFKC-normalise and drop invisible characters, preserving case."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


def fold(text: str) -> str:
    """``clean`` plus case folding and confusable mapping. Keeps punctuation."""
    return clean(text).casefold().translate(_CONFUSABLES)


def strip_discord_tokens(text: str) -> str:
    """Remove user/role/channel mentions, custom emoji and timestamps."""
    return _DISCORD_TOKEN_RE.sub(" ", text)


def squash(text: str) -> str:
    """Remove Markdown formatting characters and collapse whitespace."""
    return _SPACE_RE.sub(" ", text.translate(_MARKDOWN)).strip()


def defang(text: str, limit: int = 1500) -> str:
    """Make message content safe to show moderators inside a code block."""
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", text)
    text = text.replace("```", "`\u200b`\u200b`")
    if len(text) > limit:
        text = text[:limit] + "…"
    return text
