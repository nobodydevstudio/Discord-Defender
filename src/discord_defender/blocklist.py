"""Known-scam domain list, fed by community-maintained public feeds."""

from __future__ import annotations

import json
import logging
import re
import time
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from .domains import MULTI_LABEL_SUFFIXES, in_domains, self_and_parents

log = logging.getLogger(__name__)

MAX_FEED_BYTES = 20 * 1024 * 1024
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


def normalize_entry(entry: str) -> str | None:
    """Turn a feed line into ``host`` or ``host/path``; ``None`` if unusable.

    Entries that would match a whole hosting platform (``vercel.app``) or a bare
    TLD are rejected, so a bad feed line can never block half the internet.
    """
    s = entry.strip().lower()
    if not s or s.startswith("#"):
        return None
    if " " in s or "\t" in s:  # hosts-file format: "0.0.0.0 evil.com"
        s = s.split()[-1]
    s = _SCHEME_RE.sub("", s).lstrip("*.")
    host, _, path = s.partition("/")
    host = host.split(":")[0].rstrip(".")
    while host.startswith("www."):
        host = host[4:]
    if not host or "." not in host or host in MULTI_LABEL_SUFFIXES:
        return None
    if not _HOST_RE.match(host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    path = path.split("?")[0].split("#")[0].rstrip("/")
    return f"{host}/{path}" if path else host


def parse_feed(raw: str) -> set[str]:
    """Parse a feed: JSON list, JSON ``{"domains": [...]}``, plain text or hosts file."""
    raw = raw.strip()
    if raw.startswith(("[", "{")):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("domains") or data.get("links") or data.get("data") or []
        items: Iterable[str] = (x for x in data if isinstance(x, str))
    else:
        items = (line.split("#", 1)[0] for line in raw.splitlines())
    entries = set()
    for item in items:
        entry = normalize_entry(item)
        if entry:
            entries.add(entry)
    return entries


class Blocklist:
    """Set of scam domains plus a few exact ``shortener/path`` URLs."""

    def __init__(self, extra: Iterable[str] = (), allow: Iterable[str] = ()) -> None:
        self._extra = {e for e in map(normalize_entry, extra) if e}
        self._allow = frozenset(a.strip().lower() for a in allow if a.strip())
        self._feed: set[str] = set()
        self._domains: set[str] = set()
        self._paths: dict[str, set[str]] = {}
        self._rebuild()

    def set_feed_entries(self, entries: Iterable[str]) -> None:
        self._feed = set(entries)
        self._rebuild()

    def _rebuild(self) -> None:
        domains: set[str] = set()
        paths: dict[str, set[str]] = defaultdict(set)
        for entry in self._feed | self._extra:
            host, _, path = entry.partition("/")
            if path:
                paths[host].add(path)
            else:
                domains.add(host)
        self._domains, self._paths = domains, dict(paths)

    def __len__(self) -> int:
        return len(self._domains) + sum(len(p) for p in self._paths.values())

    def match(self, host: str, path: str = "") -> str | None:
        """Return the matching entry for ``host``/``path``, or ``None``."""
        host = host.lower()
        if in_domains(host, self._allow):
            return None
        for candidate in self_and_parents(host):
            if candidate in self._domains:
                return candidate
        prefixes = self._paths.get(host)
        if prefixes:
            wanted = path.strip("/").lower()
            for prefix in prefixes:
                if wanted == prefix or wanted.startswith(prefix + "/"):
                    return f"{host}/{prefix}"
        return None


class BlocklistUpdater:
    """Downloads the feeds on a schedule and keeps a disk cache for fast restarts."""

    def __init__(self, blocklist: Blocklist, feeds: Iterable[str], cache_path: str | Path) -> None:
        self.blocklist = blocklist
        self.feeds = list(feeds)
        self.cache_path = Path(cache_path)
        self.last_refresh: float | None = None
        self.last_errors: list[str] = []
        self._per_feed: dict[str, set[str]] = {}

    def load_cache(self) -> int:
        try:
            raw = self.cache_path.read_text("utf-8")
        except FileNotFoundError:
            return 0
        except OSError as exc:
            log.warning("Could not read blocklist cache %s: %s", self.cache_path, exc)
            return 0
        self._per_feed["__cache__"] = parse_feed(raw)
        self._apply()
        log.info("Loaded %d cached blocklist entries", len(self.blocklist))
        return len(self.blocklist)

    async def refresh(self, session) -> int:
        """Fetch every feed with an ``aiohttp.ClientSession``; failed feeds keep old data."""
        import aiohttp

        errors = []
        for url in self.feeds:
            try:
                timeout = aiohttp.ClientTimeout(total=60)
                async with session.get(url, timeout=timeout) as resp:
                    resp.raise_for_status()
                    # content.read(n) returns whatever has arrived so far, so loop to EOF.
                    chunks, size = [], 0
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        size += len(chunk)
                        if size > MAX_FEED_BYTES:
                            raise ValueError("feed is larger than 20 MB")
                        chunks.append(chunk)
                entries = parse_feed(b"".join(chunks).decode("utf-8", errors="replace"))
                if not entries:
                    raise ValueError("feed was empty")
                self._per_feed[url] = entries
            except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the rest
                errors.append(f"{url}: {exc}")
                log.warning("Blocklist feed failed: %s: %s", url, exc)
        if all(url in self._per_feed for url in self.feeds):
            self._per_feed.pop("__cache__", None)
        self.last_errors = errors
        self.last_refresh = time.time()
        self._apply()
        self._write_cache()
        log.info("Blocklist refreshed: %d entries (%d feed errors)", len(self.blocklist), len(errors))
        return len(self.blocklist)

    def _apply(self) -> None:
        merged: set[str] = set()
        for entries in self._per_feed.values():
            merged |= entries
        self.blocklist.set_feed_entries(merged)

    def _write_cache(self) -> None:
        merged = sorted(set().union(*self._per_feed.values())) if self._per_feed else []
        if not merged:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text("\n".join(merged) + "\n", "utf-8")
            tmp.replace(self.cache_path)
        except OSError as exc:
            log.warning("Could not write blocklist cache %s: %s", self.cache_path, exc)
