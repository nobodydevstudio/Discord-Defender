"""Short-term memory of who posted what where.

Compromised accounts are the main source of spam in established servers: the
attacker's script posts the same message, or the same set of screenshots, into
every channel it can see within seconds. Discord's own filters judge each
message alone, so this is the gap we close.

Two fingerprints are kept per message:

* **exact** - text plus the byte size of each attachment, so re-uploads of the
  same image match;
* **shape** - text plus the *kind* of each attachment. Some campaigns rotate
  through hundreds of slightly different photos so that no two posts are
  identical, but the shape ("4 images, same caption") stays the same.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class AttachmentLike(Protocol):
    size: int
    content_type: str | None


@dataclass(frozen=True)
class Seen:
    at: float
    channel_id: int
    message_id: int
    exact: str | None
    shape: str | None


@dataclass(frozen=True)
class BurstStats:
    exact_channels: int
    exact_count: int
    shape_channels: int
    exact_matches: tuple[Seen, ...]
    shape_matches: tuple[Seen, ...]


def _digest(value: str) -> str:
    return hashlib.blake2b(value.encode("utf-8"), digest_size=12).hexdigest()


def fingerprints(
    prepared_text: str,
    hosts: Sequence[str],
    attachments: Sequence[AttachmentLike],
    *,
    min_length: int,
    mention_attempt: bool = False,
) -> tuple[str | None, str | None]:
    """Return ``(exact, shape)`` fingerprints, ``None`` for trivial messages.

    Short chatter such as "lol" or "thanks!" is never fingerprinted, so people
    saying the same small thing in several channels are left alone.
    """
    substantial = len(prepared_text) >= min_length or bool(hosts) or mention_attempt
    if not substantial and not attachments:
        return None, None
    base = prepared_text + "|" + ",".join(sorted(set(hosts)))
    sizes = ",".join(sorted(f"{a.size}:{a.content_type or ''}" for a in attachments))
    exact = _digest(base + "|" + sizes)
    shape = None
    if attachments and (len(attachments) >= 2 or substantial):
        kinds = ",".join(sorted((a.content_type or "file").split("/")[0] for a in attachments))
        shape = _digest(base + "|" + kinds)
    return exact, shape


class ActivityTracker:
    def __init__(self, window_seconds: float, retain_seconds: float, max_per_author: int = 100) -> None:
        self.window = window_seconds
        self.retain = max(retain_seconds, window_seconds)
        self.max_per_author = max_per_author
        self._by_author: dict[int, deque[Seen]] = {}
        self._last_cleanup = 0.0

    def __len__(self) -> int:
        return len(self._by_author)

    def record(self, author_id: int, seen: Seen) -> BurstStats:
        """Remember a message and report how often its fingerprints recently appeared."""
        history = self._by_author.get(author_id)
        if history is None:
            history = self._by_author[author_id] = deque(maxlen=self.max_per_author)
        self._prune(history, seen.at)
        history.append(seen)
        self._maybe_cleanup(seen.at)

        since = seen.at - self.window
        recent = [s for s in history if s.at >= since]
        exact = tuple(s for s in recent if seen.exact and s.exact == seen.exact)
        shape = tuple(s for s in recent if seen.shape and s.shape == seen.shape)
        return BurstStats(
            exact_channels=len({s.channel_id for s in exact}),
            exact_count=len(exact),
            shape_channels=len({s.channel_id for s in shape}),
            exact_matches=exact,
            shape_matches=shape,
        )

    def recent(self, author_id: int, since: float) -> list[Seen]:
        return [s for s in self._by_author.get(author_id, ()) if s.at >= since]

    def forget(self, author_id: int) -> None:
        self._by_author.pop(author_id, None)

    def _prune(self, history: deque[Seen], now: float) -> None:
        cutoff = now - self.retain
        while history and history[0].at < cutoff:
            history.popleft()

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        cutoff = now - self.retain
        for author_id in [a for a, h in self._by_author.items() if not h or h[-1].at < cutoff]:
            del self._by_author[author_id]
