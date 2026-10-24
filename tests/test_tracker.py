from discord_defender.engine import Attachment
from discord_defender.tracker import ActivityTracker, Seen, fingerprints

IMG = "image/png"


def test_short_chatter_is_not_fingerprinted():
    assert fingerprints("lol", [], [], min_length=15) == (None, None)


def test_links_and_attachments_make_messages_trackable():
    assert fingerprints("hi", ["evil.com"], [], min_length=15)[0] is not None
    assert fingerprints("", [], [Attachment("a.png", 10, IMG)], min_length=15)[0] is not None


def test_shape_ignores_image_bytes_but_exact_does_not():
    a = [Attachment(f"{i}.png", 1000 + i, IMG) for i in range(4)]
    b = [Attachment(f"{i}.jpg", 2000 + i, IMG) for i in range(4)]
    ea, sa = fingerprints("", [], a, min_length=15)
    eb, sb = fingerprints("", [], b, min_length=15)
    assert ea != eb and sa == sb


def test_cross_channel_counting_and_window():
    t = ActivityTracker(window_seconds=60, retain_seconds=600)
    for i, ch in enumerate([1, 2, 3]):
        stats = t.record(7, Seen(100 + i, ch, i, "x", None))
    assert stats.exact_channels == 3 and stats.exact_count == 3
    # Far outside the window, only the new message counts.
    stats = t.record(7, Seen(500, 4, 9, "x", None))
    assert stats.exact_channels == 1
    assert len(t.recent(7, since=0)) == 4
    t.forget(7)
    assert t.recent(7, since=0) == []


def test_idle_authors_are_cleaned_up():
    t = ActivityTracker(window_seconds=60, retain_seconds=60)
    t.record(1, Seen(0, 1, 1, "x", None))
    t.record(2, Seen(1000, 1, 2, "y", None))
    assert len(t) == 1
