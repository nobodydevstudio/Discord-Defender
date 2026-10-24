import asyncio
import json

import pytest

from discord_defender.blocklist import Blocklist, BlocklistUpdater, normalize_entry, parse_feed


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Evil.COM", "evil.com"),
        ("https://www.evil.com/", "evil.com"),
        ("www.www.evil.com", "evil.com"),
        ("*.evil.com", "evil.com"),
        ("0.0.0.0 evil.com", "evil.com"),
        ("bit.ly/3AbC?x=1", "bit.ly/3abc"),
        ("vercel.app", None),  # would block a whole hosting platform
        ("com", None),
        ("# comment", None),
        ("", None),
    ],
)
def test_normalize_entry(raw, expected):
    assert normalize_entry(raw) == expected


def test_parse_feed_formats():
    assert parse_feed(json.dumps({"domains": ["a.com", "b.com"]})) == {"a.com", "b.com"}
    assert parse_feed(json.dumps(["a.com", 5, "b.com"])) == {"a.com", "b.com"}
    assert parse_feed("a.com\n# comment\n\nb.com # trailing\n") == {"a.com", "b.com"}


def test_match_parents_paths_and_allowlist():
    bl = Blocklist(extra=["evil.com", "bit.ly/bad"], allow=["good.evil.com"])
    bl.set_feed_entries({"scam.ru"})
    assert bl.match("evil.com") == "evil.com"
    assert bl.match("login.evil.com") == "evil.com"
    assert bl.match("good.evil.com") is None
    assert bl.match("notevil.com") is None
    assert bl.match("x.scam.ru") == "scam.ru"
    assert bl.match("bit.ly", "/bad") == "bit.ly/bad"
    assert bl.match("bit.ly", "/bad/") == "bit.ly/bad"
    assert bl.match("bit.ly", "/badder") is None
    assert len(bl) == 3


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self.body, self.status = body, status
        self.content = self

    async def iter_chunked(self, size):
        # Deliberately tiny chunks, like a real network stream.
        for i in range(0, len(self.body), 4):
            yield self.body[i : i + 4]

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, timeout=None):
        return self.responses[url]


def test_updater_merges_feeds_keeps_old_data_on_failure_and_caches(tmp_path):
    cache = tmp_path / "data" / "cache.txt"
    bl = Blocklist()
    updater = BlocklistUpdater(bl, ["https://a", "https://b"], cache)
    session = FakeSession({"https://a": FakeResponse(b"one.com\ntwo.com"), "https://b": FakeResponse(b'["three.com"]')})
    assert asyncio.run(updater.refresh(session)) == 3
    assert cache.read_text().split() == ["one.com", "three.com", "two.com"]

    # Feed b goes down: its previous entries are kept.
    session.responses["https://b"] = FakeResponse(b"", status=503)
    asyncio.run(updater.refresh(session))
    assert bl.match("three.com") and len(updater.last_errors) == 1

    # A fresh process starts from the cache before any network access.
    bl2 = Blocklist()
    assert BlocklistUpdater(bl2, [], cache).load_cache() == 3
    assert bl2.match("two.com")
